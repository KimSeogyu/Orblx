#!/usr/bin/env python3
"""W25-42 diagnostic prober (not a gate). It runs on the HOST as its own process.

Run it inside one node network namespace only:
  nsenter --net=/proc/<node pid>/ns/net python3 diag-prober.py --out F --secs N IP...
The process stays in the host PID namespace and the host cgroup, so it does not share a
scheduler group, a docker exec session, or a binary with the in-container ping.

It sends one ICMP echo request to each target each --interval seconds (raw socket), and
writes one line for each send and each receive:
  s <target> <seq> <unix_ns> <mono_ns>
  r <target> <seq> <unix_ns> <mono_ns> <kernel_rx_unix_ns> <rtt_us>
kernel_rx_unix_ns is SO_TIMESTAMPNS (the time the kernel took the reply); rtt_us uses it.
"""
import argparse
import os
import select
import socket
import struct
import time

SO_TIMESTAMPNS = 35


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=0.05)
    ap.add_argument("--secs", type=float, required=True)
    ap.add_argument("targets", nargs="+")
    a = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    ident = (os.getpid() ^ 0x5A5A) & 0xFFFF
    sent = {}
    out = open(a.out, "w", buffering=1 << 16)
    out.write("# ident %d interval %s targets %s\n" % (ident, a.interval, " ".join(a.targets)))
    seq = 0
    start = time.monotonic()
    nxt = start
    last_flush = start
    while True:
        now = time.monotonic()
        if now - start >= a.secs:
            break
        if now >= nxt:
            seq = (seq + 1) & 0xFFFF
            payload = struct.pack("!d", time.time()) + b"w25-42" * 6
            for t in a.targets:
                hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
                pkt = struct.pack("!BBHHH", 8, 0, csum(hdr + payload), ident, seq) + payload
                t_ns, m_ns = time.time_ns(), time.monotonic_ns()
                try:
                    sock.sendto(pkt, (t, 0))
                    sent[(t, seq)] = t_ns
                    out.write("s %s %d %d %d\n" % (t, seq, t_ns, m_ns))
                except OSError as err:
                    out.write("x %s %d %d %d %s\n" % (t, seq, time.time_ns(), time.monotonic_ns(), err.errno))
            nxt += a.interval
            if nxt < now:
                nxt = now + a.interval
        wait = max(0.0, nxt - time.monotonic())
        r, _, _ = select.select([sock], [], [], wait)
        if r:
            while True:
                try:
                    data, anc, _, addr = sock.recvmsg(2048, 64, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    break
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 8:
                    continue
                typ, _, _, rid, rseq = struct.unpack("!BBHHH", data[ihl:ihl + 8])
                if typ != 0 or rid != ident:
                    continue
                kts = 0
                for lvl, kind, val in anc:
                    if lvl == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS and len(val) >= 16:
                        sec, nsec = struct.unpack("qq", val[:16])
                        kts = sec * 1_000_000_000 + nsec
                src = addr[0]
                st = sent.pop((src, rseq), None)
                rtt = (kts - st) // 1000 if (st and kts) else -1
                out.write("r %s %d %d %d %d %d\n" % (src, rseq, time.time_ns(), time.monotonic_ns(), kts, rtt))
        if time.monotonic() - last_flush >= 1.0:
            out.flush()
            last_flush = time.monotonic()
    out.close()


if __name__ == "__main__":
    main()

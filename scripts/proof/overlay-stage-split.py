#!/usr/bin/env python3
"""W25-41: split the one-way overlay time of each probe packet into datapath stages.

Usage: overlay-stage-split.py DP_A DP_B PROBE [LABEL]

DP_A and DP_B are the packet traces of nodes a and b (pkt_trace.rs). PROBE is the
output of tcp-rtt-probe.py on a. All containers use the same host clock.

Stages of one packet (sender node S, receiver node R):
  tun_hop        S TUN read -> S tun_dequeued (TUN thread channel, read_tun task)
  route_hop      S tun_dequeued -> S link_dequeued (link channel, session task)
  stream_write   S link_dequeued -> S stream_written (frame encode, QUIC stream write)
  quic_send      S link_dequeued -> first S udp_send after it (QUIC driver to sendmsg)
  wire           S udp_send -> last R udp_recv before frame_read (kernel UDP, veth)
  quic_recv      R udp_recv -> R frame_read (QUIC decrypt, stream read, session task wake)
  ticket         R frame_read -> R ticket_checked (per-frame ticket check)
  inbound        R ticket_checked -> R tun_enqueue (filter, inbound action)
  tun_write_hop  R tun_enqueue -> R TUN write (TUN thread channel, write)
  one_way        S TUN read -> R TUN write
The UDP match is by time (the QUIC payload is encrypted), so quic_send, wire and
quic_recv are approximate when packets overlap. The other stages match by the TCP
fields and the TCP sequence number.
"""
import sys
from bisect import bisect_left, bisect_right
from collections import defaultdict

SEND = ("read", "tun_dequeued", "link_dequeued", "stream_written")
RECV = ("frame_read", "ticket_checked", "tun_enqueue", "write")


def fields(line):
    parts = line.split()
    return {parts[i]: parts[i + 1] for i in range(2, len(parts) - 1, 2)}


def load(path):
    stages = defaultdict(dict)
    udp = defaultdict(list)
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[0] == "udp":
                udp[parts[1]].append(int(parts[3]))
            elif parts[0] == "dp":
                f = fields(line)
                key = (f["src"], f["dst"], f["flags"], f["len"], f.get("seq", ""))
                stages[key].setdefault(parts[1], int(f["at_us"]))
    for name in udp:
        udp[name].sort()
    return stages, udp


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * q))]


def ms(a, b):
    return None if a is None or b is None else (b - a) / 1000


def packet_rows(sender, receiver):
    s_stages, s_udp = sender
    r_stages, r_udp = receiver
    rows = []
    for key, s in s_stages.items():
        r = r_stages.get(key)
        if "read" not in s or not r or "write" not in r:
            continue
        send_at = None
        sends = s_udp.get("udp_send", [])
        i = bisect_left(sends, s.get("link_dequeued", s["read"]))
        if i < len(sends):
            send_at = sends[i]
        recv_at = None
        recvs = r_udp.get("udp_recv", [])
        if "frame_read" in r:
            j = bisect_right(recvs, r["frame_read"]) - 1
            if j >= 0 and (send_at is None or recvs[j] >= send_at):
                recv_at = recvs[j]
        rows.append({
            "tun_hop": ms(s["read"], s.get("tun_dequeued")),
            "route_hop": ms(s.get("tun_dequeued"), s.get("link_dequeued")),
            "stream_write": ms(s.get("link_dequeued"), s.get("stream_written")),
            "quic_send": ms(s.get("link_dequeued"), send_at),
            "wire": ms(send_at, recv_at),
            "quic_recv": ms(recv_at, r.get("frame_read")),
            "ticket": ms(r.get("frame_read"), r.get("ticket_checked")),
            "inbound": ms(r.get("ticket_checked"), r.get("tun_enqueue")),
            "tun_write_hop": ms(r.get("tun_enqueue"), r["write"]),
            "one_way": ms(s["read"], r["write"]),
        })
    return rows


NAMES = ("tun_hop", "route_hop", "stream_write", "quic_send", "wire", "quic_recv", "ticket",
         "inbound", "tun_write_hop", "one_way")


def summary(label, name, values):
    values = [v for v in values if v is not None]
    if not values:
        print(f"stage {label} {name}_ms n 0")
        return None
    print(
        f"stage {label} {name}_ms p50 {pct(values, .5):.3f} p90 {pct(values, .9):.3f} "
        f"p99 {pct(values, .99):.3f} max {max(values):.3f} n {len(values)}"
    )
    return pct(values, .5), pct(values, .99)


def main():
    dp_a, dp_b, probe_path = sys.argv[1:4]
    label = sys.argv[4] if len(sys.argv) > 4 else "run"
    a, b = load(dp_a), load(dp_b)
    a_to_b, b_to_a = packet_rows(a, b), packet_rows(b, a)
    both = a_to_b + b_to_a
    print(f"stage_rows {label} a_to_b {len(a_to_b)} b_to_a {len(b_to_a)}")
    for rows, direction in ((a_to_b, "a_to_b"), (b_to_a, "b_to_a"), (both, "both")):
        for name in NAMES:
            summary(f"{label} {direction}", name, [r[name] for r in rows])
    probes = {"total": [], "connect": [], "rtt": []}
    failed = 0
    with open(probe_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("probe n "):
                continue
            parts = line.split()
            f = {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}
            if f.get("result") != "ok":
                failed += 1
                continue
            start, connect, reply = int(f["start_us"]), int(f["connect_us"]), int(f["reply_us"])
            probes["total"].append((reply - start) / 1000)
            probes["connect"].append((connect - start) / 1000)
            probes["rtt"].append((reply - connect) / 1000)
    print(f"probe_rows {label} ok {len(probes['rtt'])} failed {failed}")
    for name, values in probes.items():
        if values:
            summary(label, "probe_" + name, values)
    one = [r["one_way"] for r in both if r["one_way"] is not None]
    if one and probes["rtt"]:
        p50, p99 = pct(one, .5), pct(one, .99)
        rtt99 = pct(probes["rtt"], .99)
        met = p50 <= 2 and p99 <= 10 and rtt99 <= 20 and failed == 0
        print(
            f"w25_41_target {label} one_way_p50_ms {p50:.3f} (<= 2) one_way_p99_ms {p99:.3f} (<= 10) "
            f"probe_rtt_p99_ms {rtt99:.3f} (<= 20) probe_failed {failed} result {'met' if met else 'missed'}"
        )
    else:
        print(f"w25_41_target {label} result missed (no data)")


if __name__ == "__main__":
    main()

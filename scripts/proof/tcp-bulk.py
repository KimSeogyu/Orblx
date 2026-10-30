#!/usr/bin/env python3
"""TCP bulk transfer and CPU tick tool for the orblx proofs.

server BIND PORT OUT   Accept one connection, read to EOF, write a result line to OUT.
client HOST PORT SECS  Send zero bytes in 64 KiB blocks for SECS seconds, then close.
cpu PATTERN SECS       Print the CPU ticks of each process whose command line has PATTERN,
                       and the CPU ticks of each thread name in that process.

The tool sends only zero bytes. It does not read or print secrets.
"""

import os
import socket
import sys
import time

BLOCK = 64 * 1024


def server(bind, port, out):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, int(port)))
    listener.listen(1)
    listener.settimeout(60)
    conn, _ = listener.accept()
    total = 0
    first = None
    last = None
    while True:
        data = conn.recv(BLOCK)
        if not data:
            break
        now = time.monotonic()
        if first is None:
            first = now
        last = now
        total += len(data)
    conn.close()
    seconds = (last - first) if first is not None and last > first else 0.0
    mbps = (total * 8 / seconds / 1e6) if seconds > 0 else 0.0
    with open(out, "w") as handle:
        handle.write("bytes %d seconds %.3f mbit_s %.2f\n" % (total, seconds, mbps))


def client(host, port, secs):
    conn = socket.create_connection((host, int(port)), timeout=10)
    block = bytes(BLOCK)
    end = time.monotonic() + float(secs)
    while time.monotonic() < end:
        conn.sendall(block)
    conn.shutdown(socket.SHUT_WR)
    conn.recv(1)
    conn.close()


def ticks(pattern):
    found = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as handle:
                cmd = handle.read().replace(b"\0", b" ").decode(errors="replace").strip()
            with open("/proc/%s/stat" % pid) as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if pattern in cmd and "tcp-bulk" not in cmd:
            # utime and stime are fields 14 and 15 of the stat line.
            found[pid] = (cmd, int(fields[11]) + int(fields[12]), thread_ticks(pid))
    return found


def thread_ticks(pid):
    """Return {thread name: ticks}. Threads with the same name add up."""
    names = {}
    try:
        tids = os.listdir("/proc/%s/task" % pid)
    except OSError:
        return names
    for tid in tids:
        try:
            with open("/proc/%s/task/%s/comm" % (pid, tid)) as handle:
                name = handle.read().strip()
            with open("/proc/%s/task/%s/stat" % (pid, tid)) as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        names[name] = names.get(name, 0) + int(fields[11]) + int(fields[12])
    return names


def cpu(pattern, secs):
    hz = os.sysconf("SC_CLK_TCK")
    before = ticks(pattern)
    time.sleep(float(secs))
    after = ticks(pattern)
    for pid, (cmd, end, threads) in sorted(after.items()):
        if pid not in before:
            continue
        used = end - before[pid][1]
        share = 100.0 * used / hz / float(secs)
        print("cpu pid %s ticks %d hz %d seconds %s cpu_pct %.2f cmd %s" % (pid, used, hz, secs, share, cmd.split(" --")[0]))
        old_threads = before[pid][2]
        for name, value in sorted(threads.items()):
            used = value - old_threads.get(name, value)
            share = 100.0 * used / hz / float(secs)
            print("thread pid %s name %s ticks %d cpu_pct %.2f" % (pid, name, used, share))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "server":
        server(*sys.argv[2:5])
    elif mode == "client":
        client(*sys.argv[2:5])
    elif mode == "cpu":
        cpu(*sys.argv[2:4])
    else:
        raise SystemExit("unknown mode")

#!/usr/bin/env python3
"""W25-42 diagnostic analysis (not a gate). Reads a TR_DIAG=1 TR_OUT_DIR.

Usage: diag-analyze.py --dir OUT --runlog RUN.log [--limit-ms 200]

For each window where a prober saw a reply gap above the limit (the in-container ping, or
the host prober), it prints:
  * each gap of each prober, with the ping send times of the missing seqs (-O lines and
    the send time = reply time - rtt of the first replies after the gap);
  * for each node: the counter deltas in the window, the longest time each counter did
    not move inside the window, the diag line cadence, beat_age and lag_max of the
    runtime probe, and the file-apply events near the window;
  * the host samples in the window (dt_ms, steal, iowait, PSI);
  * docker events in the window.
"""
import argparse
import glob
import os
import re
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
COUNTERS = ["tunr", "tunw", "rtin", "rtsend", "ptx", "prx", "pka"]


def kst(ms):
    return datetime.fromtimestamp(ms / 1000, KST).strftime("%H:%M:%S.%f")[:-3]


def gaps_of(times, limit):
    out = []
    for a, b in zip(times, times[1:]):
        if b - a > limit:
            out.append((a, b))
    return out


def parse_ping(path):
    rep, noans = [], []
    rx = re.compile(r"^\[(\d+\.\d+)\] .*icmp_seq=(\d+).*time=([\d.]+) ms")
    nx = re.compile(r"^\[(\d+\.\d+)\] no answer yet for icmp_seq=(\d+)")
    for line in open(path, errors="replace"):
        m = rx.match(line)
        if m:
            t = float(m.group(1)) * 1000
            rep.append((t, int(m.group(2)), float(m.group(3))))
            continue
        m = nx.match(line)
        if m:
            noans.append((float(m.group(1)) * 1000, int(m.group(2))))
    return rep, noans


def parse_hostprobe(path):
    sends, recvs = {}, {}
    for line in open(path, errors="replace"):
        f = line.split()
        if not f or f[0] == "#":
            continue
        if f[0] == "s":
            sends.setdefault(f[1], []).append((int(f[3]) / 1e6, int(f[2])))
        elif f[0] == "r":
            kts = int(f[5])
            t = kts / 1e6 if kts else int(f[3]) / 1e6
            recvs.setdefault(f[1], []).append((t, int(f[2]), int(f[6]) / 1000))
    return sends, recvs


def parse_diag(path):
    rows, events = [], []
    for line in open(path, errors="replace"):
        f = line.split()
        if not f:
            continue
        if f[0] == "d" and len(f) >= 3 + 2 * 10:
            r = {"t": int(f[1]), "mono": int(f[2]) / 1000}
            for i in range(3, len(f) - 1, 2):
                r[f[i]] = int(f[i + 1])
            rows.append(r)
        elif f[0] == "e":
            events.append((int(f[1]), " ".join(f[3:])))
    return rows, events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--runlog", required=True)
    ap.add_argument("--limit-ms", type=float, default=200)
    ap.add_argument("--pad-ms", type=float, default=300)
    a = ap.parse_args()
    ip2n = {}
    for line in open(a.runlog, errors="replace"):
        m = re.search(r"node (\S+) overlay (\S+) pid", line)
        if m:
            ip2n[m.group(2)] = m.group(1)
    nodes = sorted(set(ip2n.values()))
    gaps = []  # (from, to, prober, src, dst, detail)
    pings = {}
    for p in sorted(glob.glob(os.path.join(a.dir, "ping-*-*.txt"))):
        src, dst = os.path.basename(p)[5:-4].split("-", 1)
        rep, noans = parse_ping(p)
        pings[(src, dst)] = (rep, noans)
        for x, y in gaps_of([r[0] for r in rep], a.limit_ms):
            after = [r for r in rep if y <= r[0] < y + 400][:6]
            miss = [s for t, s in noans if x <= t <= y + 50]
            det = "first_after " + ",".join(
                f"seq{s}:rtt{rtt:.0f}:sent{kst(t - rtt)}" for t, s, rtt in after)
            det += f" no_answer_seqs {len(miss)}" + (f" {min(miss)}..{max(miss)}" if miss else "")
            gaps.append((x, y, "ping", src, dst, det))
    hp_send_gaps = []
    for p in sorted(glob.glob(os.path.join(a.dir, "hostprobe-*.txt"))):
        src = os.path.basename(p)[10:-4]
        sends, recvs = parse_hostprobe(p)
        for ip, ss in sends.items():
            for x, y in gaps_of([s[0] for s in ss], a.limit_ms):
                hp_send_gaps.append((x, y, src, ip2n.get(ip, ip)))
        for ip, rr in recvs.items():
            rr.sort()
            for x, y in gaps_of([r[0] for r in rr], a.limit_ms):
                after = [r for r in rr if y <= r[0] < y + 400][:6]
                det = "first_after " + ",".join(
                    f"seq{s}:rtt{rtt:.0f}:sent{kst(t - rtt)}" for t, s, rtt in after)
                gaps.append((x, y, "hostprobe", src, ip2n.get(ip, ip), det))
    diags = {}
    for n in nodes:
        p = os.path.join(a.dir, f"diag-{n}.txt")
        if os.path.exists(p):
            diags[n] = parse_diag(p)
    host = []
    hp = os.path.join(a.dir, "host-samples.txt")
    if os.path.exists(hp):
        for line in open(hp):
            f = line.split()
            if f and not f[0].startswith("#") and len(f) >= 10:
                host.append((int(f[1]), f))
    dev = []
    dp = os.path.join(a.dir, "docker-events.txt")
    if os.path.exists(dp):
        for line in open(dp, errors="replace"):
            f = line.split(None, 1)
            if f and f[0].isdigit():
                dev.append((int(f[0]) / 1e6, f[1].strip()))

    print(f"nodes {' '.join(f'{n}={ip}' for ip, n in sorted(ip2n.items(), key=lambda kv: kv[1]))}")
    print(f"ping_files {len(pings)} hostprobe_gaps {sum(1 for g in gaps if g[2] == 'hostprobe')} "
          f"ping_gaps {sum(1 for g in gaps if g[2] == 'ping')} hostprobe_send_gaps {len(hp_send_gaps)}")
    for n, (rows, ev) in diags.items():
        cad = max((b["t"] - a_["t"] for a_, b in zip(rows, rows[1:])), default=0)
        print(f"diag {n} lines {len(rows)} max_line_gap_ms {cad} max_beat_age_ms "
              f"{max((r['beat_age_ms'] for r in rows), default=0)} max_lag_ms "
              f"{max((r['lag_max_ms'] for r in rows), default=0)} events {len(ev)}")
    for x, y, src, dst in hp_send_gaps:
        print(f"hostprobe_send_gap {src}->{dst} {kst(x)}-{kst(y)} {y - x:.0f} ms (prober process itself late)")
    # Windows: union of gaps.
    wins = []
    for g in sorted(gaps):
        if wins and g[0] <= wins[-1][1] + a.pad_ms:
            wins[-1][1] = max(wins[-1][1], g[1])
            wins[-1][2].append(g)
        else:
            wins.append([g[0], g[1], [g]])
    for x, y, gs in wins:
        print(f"\n=== window {kst(x)} - {kst(y)} KST span {y - x:.0f} ms gaps {len(gs)} "
              f"(ping {sum(1 for g in gs if g[2] == 'ping')}, hostprobe {sum(1 for g in gs if g[2] == 'hostprobe')})")
        for g in gs:
            print(f"  gap {g[2]:9s} {g[3]}->{g[4]} {kst(g[0])}-{kst(g[1])} {g[1] - g[0]:.0f} ms {g[5]}")
        for n, (rows, ev) in diags.items():
            w = [r for r in rows if x - 100 <= r["t"] <= y + 100]
            if not w:
                print(f"  node {n} NO diag lines in window")
                continue
            d = {c: w[-1][c] - w[0][c] for c in COUNTERS}
            still = {}
            for c in COUNTERS:
                best, start = 0, w[0]["t"]
                for r0, r1 in zip(w, w[1:]):
                    if r1[c] != r0[c]:
                        best = max(best, r1["t"] - start)
                        start = r1["t"]
                best = max(best, w[-1]["t"] - start)
                still[c] = best
            cad = max((b["t"] - a_["t"] for a_, b in zip(w, w[1:])), default=0)
            print(f"  node {n} lines {len(w)} line_gap_max {cad} ms beat_age_max {max(r['beat_age_ms'] for r in w)} "
                  f"lag_max {max(r['lag_max_ms'] for r in w)} | delta " +
                  " ".join(f"{c} {d[c]}" for c in COUNTERS) + " | still_ms " +
                  " ".join(f"{c} {still[c]}" for c in COUNTERS))
            for t, text in ev:
                if x - 3000 <= t <= y + 1000:
                    print(f"    event {n} {kst(t)} {text}")
        hs = [f for t, f in host if x - 200 <= t <= y + 200]
        for f in hs:
            print("  host " + " ".join(f[:10]))
        for t, text in dev:
            if x - 5000 <= t <= y + 2000:
                print(f"  docker_event {kst(t)} {text}")


if __name__ == "__main__":
    main()

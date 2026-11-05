#!/usr/bin/env python3
"""W25-42 step 2 analysis (diagnostic, not a gate). Reads a TR_DIAG=2 TR_OUT_DIR.

Usage: sched-analyze.py --dir OUT [--limit-ms 200]

Implements the classification rule in w25-42-step2-METHOD.md. For each in-container ping
reply gap above the limit (a "stall"), grouped into windows of overlapping gaps:
  * the stalled ping processes and, per process, the CPU of the last sample before the gap,
    the CPUs and states sampled inside the gap, and run/wait time inside the gap;
  * the host prober gaps that overlap the window (same 12 directions, over the overlay);
  * the kernel orblx0 rx/tx counters of each node (/proc/<pid>/net/dev, read on the host):
    the longest stretch inside the window where a counter did not move;
  * per CPU: heartbeat lateness and /proc/stat tick accounting inside the window;
  * the sampler's own longest tick gap inside the window;
  * the scheduler trace events of comm "ping" in the window (CPU per event);
and prints one "classification" line per window. Host prober gaps with no in-container gap
are printed too (they would be product evidence).
"""
import argparse
import glob
import gzip
import os
import re
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


def kst(ms):
    return datetime.fromtimestamp(ms / 1000, KST).strftime("%H:%M:%S.%f")[:-3]


def gaps(times, limit):
    return [(a, b) for a, b in zip(times, times[1:]) if b - a > limit]


def ping_files(d):
    out = {}
    for p in sorted(glob.glob(os.path.join(d, "ping-*-*.txt"))):
        src, dst = os.path.basename(p)[5:-4].split("-", 1)
        rep, dst_ip = [], None
        for line in open(p, errors="replace"):
            if dst_ip is None and line.startswith("PING "):
                dst_ip = line.split()[1]
            m = re.match(r"^\[(\d+\.\d+)\] .*icmp_seq=(\d+)", line)
            if m and "time=" in line:
                rep.append(float(m.group(1)) * 1000)
        out[(src, dst)] = (dst_ip, rep)
    return out


def prober_files(d):
    """hostprobe-SRC.txt: r lines, kernel receive time (ns) in field 6."""
    out = {}
    for p in glob.glob(os.path.join(d, "hostprobe-*.txt")):
        src = os.path.basename(p)[10:-4]
        for line in open(p, errors="replace"):
            f = line.split()
            if f and f[0] == "r":
                t = int(f[5]) or int(f[3])
                out.setdefault((src, f[1]), []).append(t / 1e6)
    return out


def load_threads(d):
    meta, ticks, net = {}, [], []
    with gzip.open(os.path.join(d, "sched-threads.txt.gz"), "rt", errors="replace") as fh:
        for line in fh:
            f = line.split()
            if not f:
                continue
            if f[0] == "M":
                meta[f[2]] = (f[3], f[4], f[5] if len(f) > 5 else "")
            elif f[0] == "T":
                row = {}
                for x in f[3:]:
                    tid, sc, run, wait = x.split(":")
                    row[tid] = (sc[0], int(sc[1:]), int(run), int(wait))
                ticks.append((int(f[1]) / 1e6, row))
            elif f[0] == "N":
                row = {}
                for x in f[3:]:
                    n, rx, tx = x.split(":")
                    row[n] = (int(rx), int(tx))
                net.append((int(f[1]) / 1e6, row))
    return meta, ticks, net


def load_cpu(d):
    stat, late = [], []
    for line in open(os.path.join(d, "cpu-stat.txt")):
        f = line.split()
        if f and f[0] == "C":
            row = {}
            for x in f[3:]:
                c, v = x.split(":")
                row[int(c[3:])] = sum(int(y) for y in v.split(","))
            stat.append((int(f[1]) / 1e6, row))
    for line in open(os.path.join(d, "cpu-heartbeat.txt")):
        f = line.split()
        if f and f[0] == "L":
            end = int(f[2]) / 1e6
            late.append((int(f[1]), end - int(f[4]) / 1000, end))
    return stat, late


def trace_pings(d, lo_mono, hi_mono):
    p = os.path.join(d, "sched-trace.txt.gz")
    out = []
    if not os.path.exists(p):
        return out
    with gzip.open(p, "rt", errors="replace") as fh:
        for line in fh:
            m = re.match(r"\s*(\S+)-(\d+)\s+\[(\d+)\]\s+\S+\s+([\d.]+): (\w+): (.*)", line)
            if not m:
                continue
            ts = float(m.group(4)) * 1000
            if ts < lo_mono or ts > hi_mono:
                continue
            if "ping" in line:
                out.append((ts, int(m.group(3)), m.group(5), m.group(1), m.group(6)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--limit-ms", type=float, default=200)
    a = ap.parse_args()
    lim = a.limit_ms
    pings = ping_files(a.dir)
    probes = prober_files(a.dir)
    meta, ticks, net = load_threads(a.dir)
    stat, late = load_cpu(a.dir)
    ip2name = {ip: dst for (src, dst), (ip, _) in pings.items() if ip}
    # unix ms -> mono ms offset from the T lines (both clocks are sampled together).
    mono_off = None
    with gzip.open(os.path.join(a.dir, "sched-threads.txt.gz"), "rt") as fh:
        for line in fh:
            if line.startswith("T "):
                f = line.split()
                mono_off = int(f[2]) / 1e6 - int(f[1]) / 1e6
                break

    stalls = []
    for (src, dst), (ip, rep) in pings.items():
        for g in gaps(rep, lim):
            stalls.append((g[0], g[1], src, dst, ip))
    pgaps = []
    for (src, ip), ts in probes.items():
        for g in gaps(sorted(ts), lim):
            pgaps.append((g[0], g[1], src, ip2name.get(ip, ip)))
    print(f"stalls_in_container {len(stalls)} prober_gaps {len(pgaps)} limit_ms {lim:.0f}")
    for g in sorted(pgaps):
        print(f"PROBER_GAP {g[2]}->{g[3]} {g[1] - g[0]:.0f} ms {kst(g[0])}-{kst(g[1])}")

    # Group overlapping stalls into windows.
    wins = []
    for s in sorted(stalls):
        if wins and s[0] <= wins[-1]["hi"]:
            wins[-1]["hi"] = max(wins[-1]["hi"], s[1])
            wins[-1]["s"].append(s)
        else:
            wins.append({"lo": s[0], "hi": s[1], "s": [s]})

    ping_tids = {}
    for tid, (role, name, comm) in meta.items():
        if role == "ping" and "->" in name:
            src, ip = name.split("->", 1)
            ping_tids.setdefault((src, ip), []).append(tid)

    for w in wins:
        lo, hi = w["lo"], w["hi"]
        print(f"\n=== WINDOW {kst(lo)}-{kst(hi)} ({hi - lo:.0f} ms) ===")
        stalled_cpus, missing = [], False
        for (glo, ghi, src, dst, ip) in w["s"]:
            print(f"stall {src}->{dst} {ghi - glo:.0f} ms {kst(glo)}-{kst(ghi)}")
            tids = ping_tids.get((src, ip), [])
            if not tids:
                print("  no sampled ping process for this direction (missing data)")
                missing = True
            for tid in tids:
                before = [r[tid] for t, r in ticks if t <= glo and tid in r]
                inside = [(t, r[tid]) for t, r in ticks if glo < t < ghi and tid in r]
                if not before:
                    continue
                last = before[-1]
                run = sum(x[1][2] for x in inside)
                wait = sum(x[1][3] for x in inside)
                seen = sorted({f"{x[1][0]}{x[1][1]}" for x in inside})
                print(f"  tid {tid} last_before {last[0]}cpu{last[1]} inside_samples {len(inside)} "
                      f"states_cpus {','.join(seen) or '-'} run_us {run} wait_us {wait}")
                stalled_cpus.append(last[1])
        # Sampler self-gap.
        tt = [t for t, _ in ticks if lo - 100 <= t <= hi + 100]
        sg = max((b - x for x, b in zip(tt, tt[1:])), default=None)
        print(f"sampler ticks_in_window {len(tt)} max_tick_gap_ms {sg if sg is None else round(sg, 1)}")
        # Host prober overlap.
        ov = [g for g in pgaps if g[0] < hi and g[1] > lo]
        for g in ov:
            print(f"  prober_overlap {g[2]}->{g[3]} {g[1] - g[0]:.0f} ms")
        # Kernel TUN counters: longest still stretch inside the window per node and direction.
        rows = [(t, r) for t, r in net if lo - 50 <= t <= hi + 50]
        tun_stop = False
        nodes = sorted({n for _, r in rows for n in r})
        for n in nodes:
            for k, lab in ((0, "rx"), (1, "tx")):
                pts = [(t, r[n][k]) for t, r in rows if n in r]
                best, start = 0.0, None
                for (t0, v0), (t1, v1) in zip(pts, pts[1:]):
                    if v1 == v0:
                        start = t0 if start is None else start
                        best = max(best, t1 - start)
                    else:
                        start = None
                delta = pts[-1][1] - pts[0][1] if pts else 0
                print(f"  tun {n} {lab} delta {delta} max_still_ms {best:.0f}")
                if best > lim:
                    tun_stop = True
        # CPUs.
        frozen = set()
        for cpu, s0, s1 in late:
            if s0 < hi and s1 > lo:
                print(f"  heartbeat cpu{cpu} late {s1 - s0:.0f} ms {kst(s0)}-{kst(s1)}")
                if s1 - s0 >= 100:
                    frozen.add(cpu)
        srows = [(t, r) for t, r in stat if lo - 100 <= t <= hi + 100]
        for cpu in sorted({c for _, r in srows for c in r}):
            series = [r.get(cpu, 0) for _, r in srows]
            zero = sum(1 for v in series if v <= 1)
            print(f"  procstat cpu{cpu} ticks_per_100ms {series} low_samples {zero}")
            if zero * 100 >= lim:
                frozen.add(cpu)
        if mono_off is not None:
            for ev in trace_pings(a.dir, lo + mono_off - 100, hi + mono_off + 100)[:80]:
                print(f"  trace {ev[0] / 1000:.6f} [{ev[1]:03d}] {ev[2]} {ev[3]} {ev[4][:140]}")
        one_cpu = len(set(stalled_cpus)) == 1 and len(stalled_cpus) >= len(w["s"])
        if missing or not stalled_cpus or sg is None:
            cls = "UNCLASSIFIED (missing data)"
        elif ov or tun_stop:
            cls = "PRODUCT (host prober gap or kernel TUN counter stop over the limit)"
        elif one_cpu and stalled_cpus[0] in frozen:
            cls = f"HARNESS-VCPU (all stalled pings on cpu{stalled_cpus[0]}, that CPU frozen; probers and TUN continued)"
        else:
            cls = f"HARNESS-OTHER (probers and TUN continued; stalled CPUs {sorted(set(stalled_cpus))}, frozen CPUs {sorted(frozen)})"
        print(f"classification {cls}")


if __name__ == "__main__":
    main()

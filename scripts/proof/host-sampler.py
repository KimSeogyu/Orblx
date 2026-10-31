#!/usr/bin/env python3
"""Host stall sampler for the proofs (W25-26).

Every INTERVAL seconds, write one line with the deltas since the last line:
  kst_time epoch_ms dt_ms steal_ms iowait_ms cpu_some_ms io_some_ms io_full_ms
  mem_some_ms mem_full_ms [name:cpu_some_ms ...]
steal and iowait come from /proc/stat, summed over all CPUs (USER_HZ ticks to ms).
The *_ms PSI values come from the "total=" microseconds in /proc/pressure/{cpu,io,memory}.
name=path arguments add the cpu.pressure "some" delta of a cgroup v2 directory.
The sampler stops on SIGTERM or after --secs seconds.

Usage: host-sampler.py --out FILE [--interval 0.1] [--secs N] [name=cgroup_dir ...]
       host-sampler.py analyze --samples FILE --gaps FILE [--traces FILE] [thresholds]

analyze: a sample is a host stall window when one of these values is at or above its
threshold: steal_ms, iowait_ms, cpu_some_ms, io_full_ms, mem_some_ms. For each line
"src dst from_s to_s gap_ms" in --gaps, it prints the largest value of each field in the
samples whose window [epoch_ms - dt_ms, epoch_ms] touches [from, to], and "class
host_stall" if one of these samples is a stall window, else "class quiet_host".
--traces lines are "node epoch_ms text". The trace lines of the src and dst node from
1 s before the gap to 0.5 s after the gap are printed under the gap.
"""
import argparse
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
HZ = os.sysconf("SC_CLK_TCK")


def stat_ticks():
    with open("/proc/stat") as f:
        parts = f.readline().split()
    # cpu user nice system idle iowait irq softirq steal ...
    return int(parts[5]), int(parts[8])


def psi(path):
    out = {"some": 0, "full": 0}
    try:
        with open(path) as f:
            for line in f:
                kind, *fields = line.split()
                for field in fields:
                    if field.startswith("total="):
                        out[kind] = int(field[6:])
    except OSError:
        return None
    return out


def snapshot(cgroups):
    iowait, steal = stat_ticks()
    cpu = psi("/proc/pressure/cpu") or {"some": 0, "full": 0}
    io = psi("/proc/pressure/io") or {"some": 0, "full": 0}
    mem = psi("/proc/pressure/memory") or {"some": 0, "full": 0}
    cg = {}
    for name, path in cgroups:
        p = psi(os.path.join(path, "cpu.pressure"))
        cg[name] = None if p is None else p["some"]
    return time.time(), steal, iowait, cpu["some"], io["some"], io["full"], mem["some"], mem["full"], cg


FIELDS = ["steal_ms", "iowait_ms", "cpu_some_ms", "io_some_ms", "io_full_ms", "mem_some_ms", "mem_full_ms"]
STALL_KEYS = ["steal_ms", "iowait_ms", "cpu_some_ms", "io_full_ms", "mem_some_ms"]


def read_samples(path):
    rows = []
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            end = float(parts[1])
            row = {"kst": parts[0], "start": end - float(parts[2]), "end": end}
            for i, name in enumerate(FIELDS):
                row[name] = float(parts[3 + i])
            row["cg"] = {}
            for item in parts[10:]:
                name, _, val = item.partition(":")
                row["cg"][name] = None if val == "-" else float(val)
            rows.append(row)
    return rows


def analyze(argv):
    ap = argparse.ArgumentParser(prog="host-sampler.py analyze")
    ap.add_argument("--samples", required=True)
    ap.add_argument("--gaps", required=True)
    ap.add_argument("--traces")
    for key in STALL_KEYS:
        ap.add_argument("--" + key.replace("_", "-"), type=float, required=True)
    args = ap.parse_args(argv)
    limits = {key: getattr(args, key) for key in STALL_KEYS}
    rows = read_samples(args.samples)

    def stall(row):
        return [k for k in STALL_KEYS if row[k] >= limits[k]]

    traces = []
    if args.traces and os.path.exists(args.traces):
        with open(args.traces) as f:
            for line in f:
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[1].isdigit():
                    traces.append((parts[0], int(parts[1]), parts[2].rstrip()))
    windows = [r for r in rows if stall(r)]
    print("host_samples {} first {} last {} stall_windows {} limits {}".format(
        len(rows), rows[0]["kst"] if rows else "-", rows[-1]["kst"] if rows else "-", len(windows),
        " ".join(f"{k}>={v:g}" for k, v in limits.items())))
    for r in windows:
        print("host_stall_window kst {} {}".format(r["kst"], " ".join(f"{k} {r[k]:g}" for k in FIELDS)))
    host = quiet = 0
    with open(args.gaps) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 5:
                continue
            src, dst, a, b, gap = parts
            a_ms, b_ms = float(a) * 1000, float(b) * 1000
            hit = [r for r in rows if r["end"] >= a_ms and r["start"] <= b_ms]
            if not hit:
                print(f"gap_host pair {src}->{dst} from {a} to {b} gap_ms {gap} samples 0 class unknown")
                continue
            peak = {k: max(r[k] for r in hit) for k in FIELDS}
            cg = {}
            for r in hit:
                for n, v in r["cg"].items():
                    if v is not None:
                        cg[n] = max(cg.get(n, 0.0), v)
            cls = "host_stall" if any(stall(r) for r in hit) else "quiet_host"
            if cls == "host_stall":
                host += 1
            else:
                quiet += 1
            kst = datetime.fromtimestamp(float(a), KST).strftime("%H:%M:%S.%f")[:-3]
            print("gap_host pair {}->{} kst {} gap_ms {} samples {} {} node_cpu_some_ms {} class {}".format(
                src, dst, kst, gap, len(hit), " ".join(f"{k} {peak[k]:g}" for k in FIELDS),
                ",".join(f"{n}:{v:g}" for n, v in sorted(cg.items())) or "-", cls))
            for node, ms, text in traces:
                if node in (src, dst) and a_ms - 1000 <= ms <= b_ms + 500:
                    print(f"  gap_trace {node} {ms} {text}")
    print(f"gap_class host_stall {host} quiet_host {quiet}")
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "analyze":
        return analyze(sys.argv[2:])
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=0.1)
    ap.add_argument("--secs", type=float, default=0)
    ap.add_argument("cgroups", nargs="*")
    args = ap.parse_args()
    cgroups = [tuple(c.split("=", 1)) for c in args.cgroups]
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    start = time.monotonic()
    prev = snapshot(cgroups)
    nxt = time.monotonic()
    with open(args.out, "w", buffering=1) as out:
        out.write("# kst_time epoch_ms dt_ms steal_ms iowait_ms cpu_some_ms io_some_ms io_full_ms mem_some_ms mem_full_ms cgroup_cpu_some_ms...\n")
        while not stop:
            nxt += args.interval
            delay = nxt - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            cur = snapshot(cgroups)
            ms = lambda a, b: (a - b) / 1000.0
            ticks = lambda a, b: (a - b) * 1000.0 / HZ
            cg = " ".join(
                f"{n}:{'-' if cur[8][n] is None or prev[8][n] is None else f'{ms(cur[8][n], prev[8][n]):.1f}'}"
                for n, _ in cgroups
            )
            kst = datetime.fromtimestamp(cur[0], KST).strftime("%H:%M:%S.%f")[:-3]
            out.write(
                f"{kst} {cur[0] * 1000:.0f} {(cur[0] - prev[0]) * 1000:.0f} "
                f"{ticks(cur[1], prev[1]):.0f} {ticks(cur[2], prev[2]):.0f} "
                f"{ms(cur[3], prev[3]):.1f} {ms(cur[4], prev[4]):.1f} {ms(cur[5], prev[5]):.1f} "
                f"{ms(cur[6], prev[6]):.1f} {ms(cur[7], prev[7]):.1f}{' ' + cg if cg else ''}\n"
            )
            prev = cur
            if args.secs and time.monotonic() - start >= args.secs:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())

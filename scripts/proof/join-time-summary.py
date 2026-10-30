#!/usr/bin/env python3
"""The summary and the gate of the join-time proof.

Usage: join-time-summary.py JOINS_FILE N LIMIT_MS

JOINS_FILE has one line for each join that the proof started:
  join I ok enroll_to_first_packet_ms E listener_to_first_packet_ms L
  join I fail REASON...
The gate fails (exit 1) when:
- a join has a "fail" line (a timeout or an error),
- the file does not have exactly N joins, numbered 1 to N, each one time,
- a join has listener_to_first_packet_ms more than LIMIT_MS.
The script never drops a join. All values go into the median, the p95 and the max.
The median of an even n is the mean of the two middle values. The p95 is the nearest rank:
the value at rank ceil(0.95 * n) in ascending order.
enroll_to_first_packet_ms is report only. It has no limit.
A bad file or bad arguments give exit 2.
"""

import math
import re
import statistics
import sys

OK = re.compile(r"^join (\d+) ok enroll_to_first_packet_ms (\d+) listener_to_first_packet_ms (-?\d+)$")
FAIL = re.compile(r"^join (\d+) fail (.+)$")


def p95(values):
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def stats_line(n, name, values, tail):
    median = statistics.median(values)
    median_text = f"{median:.1f}" if median != int(median) else str(int(median))
    return f"join_time n {n} {name} median {median_text} p95 {p95(values)} max {max(values)} {tail}"


def main(argv):
    if len(argv) != 4:
        print("usage: join-time-summary.py JOINS_FILE N LIMIT_MS", file=sys.stderr)
        return 2
    try:
        want = int(argv[2])
        limit = int(argv[3])
        with open(argv[1], encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except (OSError, ValueError) as err:
        print(f"join_gate setup error: {err}", file=sys.stderr)
        return 2
    if want < 1:
        print("join_gate setup error: N must be 1 or more", file=sys.stderr)
        return 2
    seen = []
    enroll = []
    listener = []
    bad = []
    for line in lines:
        m = OK.match(line)
        if m:
            seen.append(int(m.group(1)))
            enroll.append(int(m.group(2)))
            value = int(m.group(3))
            listener.append(value)
            if value > limit:
                bad.append(f"join {m.group(1)} listener_to_first_packet_ms {value} is more than {limit}")
            if value < 0:
                bad.append(f"join {m.group(1)} has the first packet before the listener start ({value} ms)")
            continue
        m = FAIL.match(line)
        if m:
            seen.append(int(m.group(1)))
            bad.append(f"join {m.group(1)} failed: {m.group(2)}")
            continue
        print(f"join_gate setup error: bad line: {line}", file=sys.stderr)
        return 2
    if sorted(seen) != list(range(1, want + 1)):
        bad.append(f"the joins are {sorted(seen)}, not 1 to {want}: a partial run never passes")
    n = len(enroll)
    if n:
        print(stats_line(n, "enroll_to_first_packet_ms", enroll, "(report only, [C] Linux lab, one host)"))
        print(stats_line(n, "listener_to_first_packet_ms", listener, f"(limit {limit} ms for each join)"))
    for item in bad:
        print(f"join_gate FAIL: {item}")
    if bad:
        return 1
    print(f"join_gate ok: {n} of {want} joins reached the first packet, each {limit} ms or less from the listener start")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

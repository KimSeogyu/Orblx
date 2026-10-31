#!/usr/bin/env python3
"""W25-11: the table of the renew-gap.sh runs.

Usage: renew-gap-table.py OUT_DIR [--limit-ms MS] [--upto N] [--gate]

OUT_DIR has runN.ping (ping -D -O output), runN.renewals (svid_renewal lines) and runN.exit.
The renewal window of one renewal is from 5 s before to 5 s after its docker log time.
Each run also gets runN.samples.tsv in the W25-5 format (serial-rtt-table.py): every ping
sample with its time and the nearest SVID renewal of node-a or node-b.
One row per run: the pings, the lost pings, the renewals of each node during the pings,
the pings, lost pings and max ping in the renewal windows, the max ping of the run,
and the time from the max ping to the nearest renewal.
--gate: exit 1 unless every run exited 0, each node renewed 2 times or more during the pings,
and the renewal windows have pings, no lost ping and no ping above the limit.
Every number comes from a log line. A missing value is printed as "-".
"""

import datetime
import os
import re
import sys

INTERVAL = 0.05
BEFORE = 5.0
AFTER = 5.0
PATH = "node_a_node_b_direct"
REPLY_RE = re.compile(r"^\[(\d+\.\d+)\] \d+ bytes from \S+ icmp_seq=(\d+) ttl=\d+ time=([\d.]+) ms")
SUMMARY_RE = re.compile(r"^(\d+) packets transmitted, (\d+) received")
RENEW_RE = re.compile(r"^svid_renewal (\S+) (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$")


def renewal_epoch(stamp, frac):
    when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    value = when.timestamp()
    if frac:
        value += float("0." + frac)
    return value


def read_run(out, i):
    ping_path = os.path.join(out, f"run{i}.ping")
    if not os.path.exists(ping_path):
        return None
    replies = {}
    sent = None
    with open(ping_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = REPLY_RE.match(line)
            if match:
                recv, seq, rtt = float(match.group(1)), int(match.group(2)), float(match.group(3))
                replies[seq] = (recv - rtt / 1000.0, rtt)
                continue
            match = SUMMARY_RE.match(line)
            if match:
                sent = int(match.group(1))
    renewals = []
    renew_path = os.path.join(out, f"run{i}.renewals")
    if os.path.exists(renew_path):
        with open(renew_path, encoding="utf-8") as handle:
            for line in handle:
                match = RENEW_RE.match(line.strip())
                if match:
                    renewals.append((match.group(1), renewal_epoch(match.group(2), match.group(3))))
    code = None
    exit_path = os.path.join(out, f"run{i}.exit")
    if os.path.exists(exit_path):
        with open(exit_path, encoding="utf-8") as handle:
            text = handle.read().strip()
            code = int(text) if text.isdigit() else None
    return replies, sent, renewals, code


def send_time(seq, replies, base):
    if seq in replies:
        return replies[seq][0]
    return base + (seq - 1) * INTERVAL


def analyse(run):
    replies, sent, renewals, code = run
    row = {"exit": code, "sent": sent, "received": len(replies)}
    if not replies or sent is None:
        return row
    offsets = sorted(t - (s - 1) * INTERVAL for s, (t, _) in replies.items())
    base = offsets[len(offsets) // 2]
    first = send_time(1, replies, base)
    last = send_time(sent, replies, base)
    times = [r for _, r in renewals]
    row["lost"] = sent - len(replies)
    for node in ("node-a", "node-b"):
        row[node] = sum(1 for n, r in renewals if n == node and first <= r <= last)
    win_pings = win_lost = 0
    win_max = None
    for seq in range(1, sent + 1):
        at = send_time(seq, replies, base)
        if not any(r - BEFORE <= at <= r + AFTER for r in times):
            continue
        win_pings += 1
        if seq not in replies:
            win_lost += 1
            continue
        rtt = replies[seq][1]
        win_max = rtt if win_max is None else max(win_max, rtt)
    row["win_pings"], row["win_lost"], row["win_max"] = win_pings, win_lost, win_max
    seq_max, (at_max, rtt_max) = max(replies.items(), key=lambda item: item[1][1])
    row["max"] = rtt_max
    row["max_near"] = min((at_max - r for r in times), key=abs) if times else None
    return row


def write_samples(out, i, run):
    replies, _, renewals, _ = run
    marks = sorted((r, n) for n, r in renewals)
    with open(os.path.join(out, f"run{i}.samples.tsv"), "w", encoding="utf-8") as handle:
        handle.write("path\tseq\tms\tepoch\tnearest_renewal_container\tnearest_renewal_epoch\tdelta_s\n")
        for seq in sorted(replies):
            at, ms = replies[seq]
            near = min(marks, key=lambda m: abs(m[0] - at)) if marks else None
            handle.write("%s\t%d\t%.3f\t%.6f\t%s\t%s\t%s\n" % (
                PATH, seq, ms, at, near[1] if near else "-", "%.3f" % near[0] if near else "-",
                "%+.3f" % (at - near[0]) if near else "-"))


def fmt(value, digits=3):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def main(argv):
    out = argv[1]
    limit = 20.0
    upto = None
    gate = "--gate" in argv
    if "--limit-ms" in argv:
        limit = float(argv[argv.index("--limit-ms") + 1])
    if "--upto" in argv:
        upto = int(argv[argv.index("--upto") + 1])
    rows = []
    i = 1
    while upto is None or i <= upto:
        run = read_run(out, i)
        if run is None:
            if upto is None:
                break
            i += 1
            continue
        rows.append((i, analyse(run)))
        write_samples(out, i, run)
        i += 1
    print(f"| Run | Exit | Pings | Lost | Renewals a | Renewals b | Pings within 5 s of a renewal | Lost within 5 s | Max ms within 5 s | Max ms | Max to renewal s |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    failed = []
    for i, row in rows:
        print(
            f"| {i} | {fmt(row.get('exit'))} | {fmt(row.get('sent'))} | {fmt(row.get('lost'))} | "
            f"{fmt(row.get('node-a'))} | {fmt(row.get('node-b'))} | {fmt(row.get('win_pings'))} | "
            f"{fmt(row.get('win_lost'))} | {fmt(row.get('win_max'))} | {fmt(row.get('max'))} | "
            f"{fmt(row.get('max_near'), 1)} |"
        )
        ok = (
            row.get("exit") == 0
            and (row.get("node-a") or 0) >= 2
            and (row.get("node-b") or 0) >= 2
            and (row.get("win_pings") or 0) > 0
            and row.get("win_lost") == 0
            and row.get("win_max") is not None
            and row["win_max"] <= limit
        )
        if not ok:
            failed.append(i)
    if gate:
        if failed or not rows:
            print(f"renew_gap_gate fail runs {failed} limit_ms {limit}", file=sys.stderr)
            return 1
        print(f"renew_gap_gate ok runs {len(rows)} limit_ms {limit}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""W25-5: the table of the serial nat-realism runs.

Usage: serial-rtt-table.py OUT_DIR [--upto N] [--gate | --sym-gate | --kill-check | --last-row]

OUT_DIR has run1.log, run1.exit, and so on (serial-rtt.sh writes them).
One row per run: the max ping, the median ping and the lost pings over the W23-4 gate paths
(direct prc_prc, direct prc_prc at 0.23 s, relay prc_prc, relay sym_sym), and the contention
(proof_contention line of proof-lock.sh: the max number of other running orblx containers).
--gate: exit 1 unless every run has proof_ok, a max ping below the limit and 0 lost.
--sym-gate: the W23-4 sym relay throughput check (W25-12). Exit 1 unless at least
  ORBLX_SYM_GATE_RUNS (default 5) runs have a sym_sym relay bulk of at least ORBLX_SYM_GATE_SECS
  (default 29) seconds, and the median of these runs is at or above the W22 floor. Each run holds the
  proof lock, so no other proof runs at the same time. The line also gives the number of runs alone
  on the box (no other orblx container).
--last-row: print only the row of the last run (serial-rtt.sh prints it after each run).
--kill-check: exit 3 when the last run has a ping above the limit and no other orblx container ran.
Every number comes from a log line. A missing value is printed as "-".
Each run also gets runN.samples.tsv: every gate ping sample with its time and the nearest SVID
renewal (svid_renewal lines, nat-realism.sh prints them before cleanup). The "Renewal" column
gives the time from the max ping to the nearest renewal. A run without these lines shows "-".
"""

import bisect
import datetime
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("perf_summary", os.path.join(HERE, "perf-summary.py"))
perf_summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf_summary)

# W22: the sym_sym relay TCP throughput floor. The table reports it. It is not a --gate check.
# --sym-gate checks it with long samples only (W25-12: one 5 s sample has a spread of about 30%).
SYM_FLOOR_MBIT = float(os.environ.get("ORBLX_SERIAL_SYM_FLOOR_MBIT", "1113"))
SYM_GATE_RUNS = int(os.environ.get("ORBLX_SYM_GATE_RUNS", "5"))
SYM_GATE_SECS = float(os.environ.get("ORBLX_SYM_GATE_SECS", "29"))
SYM_SECS_RE = re.compile(r"^throughput sym_sym_relay bytes \d+ seconds ([0-9.]+) mbit_s", re.M)
LIMIT_MS = float(os.environ.get("ORBLX_SERIAL_SPIKE_MS", "20"))
GATE_PATHS = ["prc_prc_direct", "prc_prc_direct_i0.23", "prc_prc_relay", "sym_sym_relay"]
CONTENTION_RE = re.compile(
    r"^proof_contention \S+ samples (\d+) contended_samples (\d+) unknown_samples (\d+) "
    r"max_other_orblx_containers (\d+) max_load1 (\S+)$",
    re.M,
)
TIMES_RE = re.compile(r"^ping_times (relay_ping|direct_ping) (\S+) (\S+)$", re.M)
RTTS_RE = re.compile(r"^ping_rtts (relay_ping|direct_ping) (\S+) sent \S+ received \S+ ms (\S+)$", re.M)
RENEW_RE = re.compile(r"^svid_renewal (\S+) (\S+)$", re.M)
START_RE = re.compile(r"^proof_context \S+ phase start time (\S+) load (\S+) other_orblx_containers (\S+)", re.M)


def rfc3339_epoch(text):
    """Docker log time stamp (UTC, nanoseconds) to epoch seconds."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$", text)
    if not m:
        return None
    base = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return base.timestamp() + (float("0." + m.group(2)) if m.group(2) else 0.0)


def samples(text):
    """Every gate ping sample: (path, seq, ms, epoch), and the renewals: sorted (epoch, container)."""
    rtts = {(k, l): v for k, l, v in RTTS_RE.findall(text)}
    out = []
    for kind, label, times in TIMES_RE.findall(text):
        path = next((p for p, key in perf_summary.PING_PATHS.items() if key == (kind, label)), None)
        ms = rtts.get((kind, label), "none")
        if path is None or times == "none" or ms == "none":
            continue
        for t, v in zip(times.split(","), ms.split(",")):
            seq, at = t.split("@")
            out.append((path, int(seq), float(v), float(at)))
    renewals = sorted((e, n) for n, e in ((n, rfc3339_epoch(t)) for n, t in RENEW_RE.findall(text)) if e)
    return out, renewals


def nearest(renewals, at):
    if not renewals:
        return None
    keys = [r[0] for r in renewals]
    j = bisect.bisect_left(keys, at)
    cands = [renewals[k] for k in (j - 1, j) if 0 <= k < len(renewals)]
    return min(cands, key=lambda r: abs(r[0] - at))


def write_samples(out_dir, i, smp, renewals):
    with open(os.path.join(out_dir, "run%d.samples.tsv" % i), "w") as f:
        f.write("path\tseq\tms\tepoch\tnearest_renewal_container\tnearest_renewal_epoch\tdelta_s\n")
        for path, seq, ms, at in smp:
            r = nearest(renewals, at)
            f.write("%s\t%d\t%.3f\t%.6f\t%s\t%s\t%s\n" % (
                path, seq, ms, at, r[1] if r else "-", "%.3f" % r[0] if r else "-",
                "%+.3f" % (at - r[0]) if r else "-"))


def run_row(out_dir, i):
    with open(os.path.join(out_dir, "run%d.log" % i), errors="replace") as f:
        text = f.read()
    run = perf_summary.parse_log(text)
    code = None
    exit_path = os.path.join(out_dir, "run%d.exit" % i)
    if os.path.exists(exit_path):
        with open(exit_path) as f:
            code = int(f.read().strip() or "1")
    row = {"run": i, "exit": code, "proof_ok": run["proof_ok"], "paths": {}}
    maxes, lost, sent = [], 0, 0
    for path in GATE_PATHS:
        st = run["rtts"].get(path)
        if not st:
            continue
        row["paths"][path] = st
        if "max_ms" in st:
            maxes.append((st["max_ms"], path))
        if st.get("lost") is not None:
            lost += st["lost"]
            sent += st["sent"]
    row["max"] = max(maxes) if maxes else None
    row["lost"] = lost
    row["sent"] = sent
    row["complete"] = len(row["paths"]) == len(GATE_PATHS)
    row["sym_mbit"] = run["throughput"].get("sym_sym_relay")
    secs = SYM_SECS_RE.search(text)
    row["sym_secs"] = float(secs.group(1)) if secs else None
    m = CONTENTION_RE.findall(text)
    row["contention"] = m[-1] if m else None
    s = START_RE.search(text)
    row["start"] = s.groups() if s else None
    smp, renewals = samples(text)
    row["renewals"] = len(renewals)
    row["renewal_near_max"] = None
    row["has_times"] = bool(smp)
    row["renewal_scan"] = "svid_renewal_scan done" in text
    if smp:
        try:
            write_samples(out_dir, i, smp, renewals)
        except OSError:
            pass
        top = max(smp, key=lambda x: x[2])
        r = nearest(renewals, top[3])
        if r:
            row["renewal_near_max"] = (top[3] - r[0], r[1])
    return row


def contended(row):
    c = row["contention"]
    if c is None:
        return None
    return int(c[3]) > 0 or int(c[2]) > 0


def fmt_row(row):
    def med(path):
        st = row["paths"].get(path, {})
        return "%.3f" % st["median_ms"] if "median_ms" in st else "-"

    mx = "%.3f (%s)" % row["max"] if row["max"] else "-"
    c = row["contention"]
    cont = "-" if c is None else "%s (max %s other, %s/%s samples)" % (
        "contended" if contended(row) else "alone", c[3], c[1], c[0])
    start = "-" if row["start"] is None else "%s load %s other %s" % row["start"]
    rn = row.get("renewal_near_max")
    if rn is not None:
        renew = "%+.1f s (%s, %d renewals)" % (rn[0], rn[1], row["renewals"])
    elif row.get("has_times") and row.get("renewal_scan"):
        renew = "no renewal in the run"
    elif row.get("has_times"):
        renew = "not recorded"
    else:
        renew = "-"
    sym = "-" if row.get("sym_mbit") is None else "%.2f" % row["sym_mbit"]
    return "| %d | %s | %s | %s | %s | %s | %s | %d/%d | %s | %s | %s | %s | %s | %s |" % (
        row["run"], "ok" if row["proof_ok"] else "exit %s" % row["exit"], mx,
        med("prc_prc_direct"), med("prc_prc_direct_i0.23"), med("prc_prc_relay"), med("sym_sym_relay"), row["lost"], row["sent"],
        sym, "-" if c is None else c[4], cont, renew, start, "yes" if row["complete"] else "no")


def median(values):
    v = sorted(values)
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2


def sym_summary(rows):
    """The sym_sym relay throughput median over all runs and over the runs alone on the box."""
    parts = []
    for name, sel in (("all runs", rows), ("alone runs", [r for r in rows if contended(r) is False])):
        vals = [r["sym_mbit"] for r in sel if r.get("sym_mbit") is not None]
        if vals:
            med = median(vals)
            parts.append("%s: %d values, median %.2f Mbit/s, %s the W22 floor %.0f" % (
                name, len(vals), med, "at or above" if med >= SYM_FLOOR_MBIT else "BELOW", SYM_FLOOR_MBIT))
        else:
            parts.append("%s: no value" % name)
    return "sym_sym_relay throughput " + "; ".join(parts)


def sym_gate(rows):
    """W25-12: the sym relay median over the long runs, against the W22 floor."""
    long_rows = [r for r in rows if r.get("sym_mbit") is not None and (r.get("sym_secs") or 0) >= SYM_GATE_SECS]
    vals = sorted(r["sym_mbit"] for r in long_rows)
    alone = sum(1 for r in long_rows if contended(r) is False)
    if len(vals) < SYM_GATE_RUNS:
        print("sym_gate failed: %d runs with a sym bulk of at least %.0f s, need %d"
              % (len(vals), SYM_GATE_SECS, SYM_GATE_RUNS))
        return 1
    med = median(vals)
    verdict = "ok" if med >= SYM_FLOOR_MBIT else "failed"
    print("sym_gate %s: %d runs of at least %.0f s (%d alone), median %.2f Mbit/s (min %.2f, max %.2f), W22 floor %.0f"
          % (verdict, len(vals), SYM_GATE_SECS, alone, med, vals[0], vals[-1], SYM_FLOOR_MBIT))
    return 0 if verdict == "ok" else 1


def main(argv):
    out_dir = argv[1]
    upto = None
    if "--upto" in argv:
        upto = int(argv[argv.index("--upto") + 1])
    rows = []
    i = 1
    while os.path.exists(os.path.join(out_dir, "run%d.log" % i)) and (upto is None or i <= upto):
        rows.append(run_row(out_dir, i))
        i += 1
    if "--last-row" in argv:
        if rows:
            print(fmt_row(rows[-1]))
        return 0
    if "--kill-check" in argv:
        last = rows[-1] if rows else None
        if last and last["max"] and last["max"][0] > LIMIT_MS and contended(last) is False:
            return 3
        return 0
    if "--sym-gate" in argv:
        return sym_gate(rows)
    if "--gate" in argv:
        bad = [r["run"] for r in rows
               if not r["proof_ok"] or not r["complete"] or r["lost"] or not r["max"] or r["max"][0] >= LIMIT_MS]
        if bad or not rows:
            print("serial_rtt gate failed in runs %s (limit %s ms, 0 lost, proof_ok)" % (bad, LIMIT_MS))
            return 1
        print("serial_rtt gate ok: %d runs, every max ping below %s ms, 0 lost" % (len(rows), LIMIT_MS))
        return 0
    print("| Run | Result | Max ping ms (path) | Median direct | Median direct 0.23 s | Median prc relay | Median sym relay | "
          "Lost | Sym relay Mbit/s | Max load1 | Contention | Max ping vs nearest SVID renewal | Start | All paths |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for row in rows:
        print(fmt_row(row))
    print()
    print(sym_summary(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

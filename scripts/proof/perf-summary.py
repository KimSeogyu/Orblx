#!/usr/bin/env python3
"""Summarize the release nat-realism runs of the W24 perf watch.

Usage: perf-summary.py OUT_DIR

OUT_DIR has run1.log, run1.exit, run2.log, run2.exit, and so on.
The script writes OUT_DIR/perf-watch.json and OUT_DIR/perf-watch.md and prints the markdown.
The exit code is 1 when a run did not print proof_ok or when a CI gate did not pass in a run.

CI gates (W24-E2). A run fails when one of these is true:
- the relay ping median is more than the direct ping median + ORBLX_PERF_MEDIAN_SLACK_MS (1 ms),
- a ping on a path is lost,
- the TCP throughput of a path is missing or below ORBLX_PERF_MIN_MBIT (200 Mbit/s, W24-E4),
- more than ORBLX_PERF_MAX_SPIKES (3) pings of a path are more than ORBLX_PERF_SPIKE_MS (10 ms).
Report only: the median, p99 and max ping and the spike count of each path, and the box
avg gate (relay avg <= direct avg + 1 ms). The box merge gate in nat-realism.sh does not change.
Every number comes from a log line. The script does not make up a number.
All overlay numbers are [C] (containers on one host).
"""

import json
import os
import platform
import re
import statistics
import sys

# The relay gate paths and their labels in the nat-realism log.
RELAY_PATHS = {"prc_prc_relay": "prc_prc", "sym_sym_relay": "sym_sym"}
PATHS = ["plain", "prc_prc_direct", "prc_prc_relay", "sym_sym_relay"]
OUTLIER_MS = float(os.environ.get("ORBLX_PERF_OUTLIER_MS", "10"))
# The ping paths of the CI gates. Each has a ping_rtts line (kind, label) in the log.
PING_PATHS = {
    "prc_prc_direct": ("direct_ping", "prc_prc"),
    "prc_prc_direct_i0.23": ("direct_ping", "prc_prc_i0.23"),
    "prc_prc_relay": ("relay_ping", "prc_prc"),
    "sym_sym_relay": ("relay_ping", "sym_sym"),
}
DIRECT_PATH = "prc_prc_direct"
MEDIAN_SLACK_MS = float(os.environ.get("ORBLX_PERF_MEDIAN_SLACK_MS", "1"))
SPIKE_MS = float(os.environ.get("ORBLX_PERF_SPIKE_MS", "10"))
MAX_SPIKES = int(os.environ.get("ORBLX_PERF_MAX_SPIKES", "3"))
MIN_MBIT = float(os.environ.get("ORBLX_PERF_MIN_MBIT", "200"))
# The box avg gate of nat-realism.sh. The CI reports it and does not gate on it.
BOX_SLACK_MS = 1.0

SLOW_RE = re.compile(r"seq(\d+):([0-9.]+)@([0-9.]+)")


def parse_slow(text):
    return [{"seq": int(s), "ms": float(t), "at": float(a)} for s, t, a in SLOW_RE.findall(text)]


def percentile(sorted_values, q):
    """Linear interpolation between the closest ranks (the numpy default)."""
    n = len(sorted_values)
    pos = q * (n - 1)
    lo = int(pos)
    hi = min(lo + 1, n - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def ping_stats(sent, received, times):
    """Return the median, p99, max and spike count of one ping run."""
    entry = {"sent": sent, "received": received, "count": len(times)}
    entry["lost"] = (sent - received) if sent is not None and received is not None else None
    if times:
        ordered = sorted(times)
        entry["median_ms"] = round(statistics.median(ordered), 3)
        entry["p99_ms"] = round(percentile(ordered, 0.99), 3)
        entry["max_ms"] = ordered[-1]
        entry["spikes"] = sum(1 for t in ordered if t > SPIKE_MS)
    return entry


def parse_int(text):
    return int(text) if text.isdigit() else None


def parse_log(text):
    """Return the values of one run. A missing value stays missing."""
    run = {"proof_ok": False, "rtt": {}, "ping": {}, "throughput": {}, "gate": {}, "lost": {}, "rtts": {}}
    for line in text.splitlines():
        line = line.strip()
        if line == "proof_ok":
            run["proof_ok"] = True
            continue
        m = re.match(r"rtt plain_avg_ms ([0-9.]+) direct_avg_ms ([0-9.]+)", line)
        if m:
            run["rtt"]["plain"] = float(m.group(1))
            run["rtt"]["prc_prc_direct"] = float(m.group(2))
            continue
        m = re.match(r"(relay_ping|direct_ping) (\S+) median_ms ([0-9.]+) slowest (.*)$", line)
        if m:
            kind, label = m.group(1), m.group(2)
            if kind == "direct_ping" and label == "prc_prc":
                path = "prc_prc_direct"
            elif kind == "relay_ping" and label in RELAY_PATHS.values():
                path = label + "_relay"
            else:
                continue
            run["ping"][path] = {"median_ms": float(m.group(3)), "slowest": parse_slow(m.group(4))}
            continue
        m = re.match(r"ping_rtts (relay_ping|direct_ping) (\S+) sent (\S+) received (\S+) ms (\S+)$", line)
        if m:
            for path, key in PING_PATHS.items():
                if key == (m.group(1), m.group(2)):
                    times = [] if m.group(5) == "none" else [float(t) for t in m.group(5).split(",")]
                    run["rtts"][path] = ping_stats(parse_int(m.group(3)), parse_int(m.group(4)), times)
            continue
        m = re.match(
            r"relay_rtt (\S+) relay_avg_ms (\S+) direct_avg_ms ([0-9.]+) slack_ms ([0-9.]+) lost (\d+)/(\d+)(.*)$",
            line,
        )
        if m:
            path = m.group(1) + "_relay"
            if m.group(2) != "none":
                run["rtt"][path] = float(m.group(2))
            run["lost"][path] = "%s/%s" % (m.group(5), m.group(6))
            # The summary line repeats the gate line with "relay_gate ok".
            if "relay_gate ok" in m.group(7):
                run["gate"][path] = True
            run.setdefault("slack_ms", float(m.group(4)))
            continue
        m = re.match(r"(\S+) relay_gate ok$", line)
        if m and m.group(1) in RELAY_PATHS.values():
            run["gate"][m.group(1) + "_relay"] = True
            continue
        m = re.match(r"throughput (\S+) bytes \d+ seconds [0-9.]+ mbit_s ([0-9.]+)", line)
        if m and m.group(1) in PATHS:
            run["throughput"][m.group(1)] = float(m.group(2))
    run["rtt_gate_ok"] = all(run["gate"].get(p, False) for p in RELAY_PATHS)
    run["box_avg_gate_ok"] = all(
        p in run["rtt"] and DIRECT_PATH in run["rtt"] and run["rtt"][p] <= run["rtt"][DIRECT_PATH] + BOX_SLACK_MS
        for p in RELAY_PATHS
    )
    run["ci_failures"] = ci_failures(run)
    run["ci_gate_ok"] = not run["ci_failures"]
    return run


def ci_failures(run):
    """Return the list of the CI gate failures of one run. An empty list is a pass."""
    fails = []
    rtts = run["rtts"]
    for path in PING_PATHS:
        st = rtts.get(path)
        if not st or "median_ms" not in st:
            fails.append("%s: no ping_rtts line" % path)
            continue
        if st["lost"] is None or st["lost"] != 0 or st["count"] != st["sent"]:
            fails.append("%s: lost %s/%s" % (path, st["lost"], st["sent"]))
        if st["spikes"] > MAX_SPIKES:
            fails.append("%s: %d of %d pings above %s ms (limit %d)" % (
                path, st["spikes"], st["count"], SPIKE_MS, MAX_SPIKES))
    direct = rtts.get(DIRECT_PATH, {}).get("median_ms")
    for path in RELAY_PATHS:
        relay = rtts.get(path, {}).get("median_ms")
        if relay is not None and direct is not None and relay > direct + MEDIAN_SLACK_MS:
            fails.append("%s: median %.3f ms > direct median %.3f ms + %s ms" % (
                path, relay, direct, MEDIAN_SLACK_MS))
        lost = run["lost"].get(path)
        if lost is not None and not lost.startswith("0/"):
            fails.append("%s: relay_rtt lost %s" % (path, lost))
    for path in PATHS:
        tput = run["throughput"].get(path)
        if tput is None or tput < MIN_MBIT:
            fails.append("%s: throughput %s Mbit/s is below the floor %s Mbit/s" % (path, tput, MIN_MBIT))
    return fails


def stats(values):
    if not values:
        return None
    return {
        "values": values,
        "median": round(statistics.median(values), 3),
        "min": min(values),
        "max": max(values),
    }


def summarize(runs):
    paths = {}
    for path in PATHS:
        entry = {}
        rtt = [r["rtt"][path] for r in runs if path in r["rtt"]]
        if rtt:
            entry["rtt_avg_ms"] = stats(rtt)
        med = [r["ping"][path]["median_ms"] for r in runs if path in r["ping"]]
        if med:
            entry["ping_median_ms"] = stats(med)
        slow = []
        for r in runs:
            for s in r["ping"].get(path, {}).get("slowest", []):
                slow.append(dict(s, run=r["run"]))
        if slow:
            entry["slowest_pings"] = sorted(slow, key=lambda s: -s["ms"])
        per_run = [dict(r["rtts"][path], run=r["run"]) for r in runs if path in r["rtts"]]
        if per_run:
            entry["ping_stats"] = per_run
        tput = [r["throughput"][path] for r in runs if path in r["throughput"]]
        if tput:
            entry["throughput_mbit_s"] = stats(tput)
        if path in RELAY_PATHS:
            margin = [
                round(r["rtt"][path] - r["rtt"]["prc_prc_direct"], 3)
                for r in runs
                if path in r["rtt"] and "prc_prc_direct" in r["rtt"]
            ]
            if margin:
                entry["relay_minus_direct_ms"] = stats(margin)
            entry["lost"] = [r["lost"].get(path, "none") for r in runs]
        paths[path] = entry
    for path in PING_PATHS:
        if path not in paths:
            per_run = [dict(r["rtts"][path], run=r["run"]) for r in runs if path in r["rtts"]]
            paths[path] = {"ping_stats": per_run} if per_run else {}
    outliers = []
    for path in PATHS:
        for s in paths[path].get("slowest_pings", []):
            if s["ms"] >= OUTLIER_MS:
                outliers.append(dict(s, path=path))
    return {
        "runs": runs,
        "paths": paths,
        "rtt_gate_ok": bool(runs) and all(r["rtt_gate_ok"] for r in runs),
        "box_avg_gate_ok": bool(runs) and all(r["box_avg_gate_ok"] for r in runs),
        "ci_gate_ok": bool(runs) and all(r["ci_gate_ok"] for r in runs),
        "gates": {
            "median_slack_ms": MEDIAN_SLACK_MS,
            "spike_ms": SPIKE_MS,
            "max_spikes": MAX_SPIKES,
            "min_mbit": MIN_MBIT,
            "box_avg_slack_ms": BOX_SLACK_MS,
        },
        "proof_ok": bool(runs) and all(r["proof_ok"] and r["exit_code"] == 0 for r in runs),
        "outlier": {"threshold_ms": OUTLIER_MS, "found": bool(outliers), "pings": outliers},
    }


def host_info():
    info = {
        "label": "REAL host, [C] containers",
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
    }
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_NAME"):
        if os.environ.get(key):
            info[key.lower()] = os.environ[key]
    return info


def fmt(st, unit=""):
    if not st:
        return "none"
    return "%s (%s - %s)%s" % (st["median"], st["min"], st["max"], unit)


def markdown(summary):
    lines = ["# W24 perf watch", ""]
    host = summary.get("host", {})
    lines.append(
        "REAL host: %s, %s CPUs, kernel %s. All overlay numbers are [C] (containers on this host)."
        % (host.get("cpu", host.get("machine", "unknown")), host.get("cpus"), host.get("kernel"))
    )
    if host.get("github_sha"):
        lines.append("Commit `%s`, run %s." % (host["github_sha"], host.get("github_run_id")))
    lines.append("")
    g = summary["gates"]
    lines.append("Runs: %d. proof_ok on all runs: %s. CI gate on all runs: %s." % (
        len(summary["runs"]), summary["proof_ok"], summary["ci_gate_ok"]))
    lines.append("")
    lines.append(
        "CI gate: relay ping median <= direct ping median + %s ms, 0 lost, TCP >= %s Mbit/s on each path, "
        "at most %d pings above %s ms on each path."
        % (g["median_slack_ms"], g["min_mbit"], g["max_spikes"], g["spike_ms"]))
    lines.append(
        "Report only: box avg gate (relay avg <= direct avg + %s ms) on all runs: %s."
        % (g["box_avg_slack_ms"], summary["box_avg_gate_ok"]))
    lines.append("")
    lines.append("Ping of each run (ms). Spikes: pings above %s ms." % g["spike_ms"])
    lines.append("")
    lines.append("| Path | Run | median | p99 | max | spikes | lost |")
    lines.append("|---|---|---|---|---|---|---|")
    for path in PING_PATHS:
        for st in summary["paths"][path].get("ping_stats", []):
            lines.append("| %s | %d | %s | %s | %s | %s/%s | %s/%s |" % (
                path, st["run"], st.get("median_ms", "none"), st.get("p99_ms", "none"),
                st.get("max_ms", "none"), st.get("spikes", "none"), st["count"],
                st["lost"], st["sent"]))
    lines.append("")
    lines.append("Median (min - max) of the runs.")
    lines.append("")
    lines.append("| Path | RTT avg ms | ping median ms | relay - direct ms | TCP Mbit/s | lost |")
    lines.append("|---|---|---|---|---|---|")
    for path in PATHS:
        e = summary["paths"][path]
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            path,
            fmt(e.get("rtt_avg_ms")),
            fmt(e.get("ping_median_ms")),
            fmt(e.get("relay_minus_direct_ms")),
            fmt(e.get("throughput_mbit_s")),
            " ".join(e.get("lost", [])) or "-",
        ))
    lines.append("")
    lines.append("Slowest pings (3 per path and run, seq:ms):")
    lines.append("")
    for path in PATHS:
        slow = summary["paths"][path].get("slowest_pings")
        if slow:
            lines.append("- %s: %s" % (path, " ".join(
                "run%d/seq%d:%.3f" % (s["run"], s["seq"], s["ms"]) for s in slow)))
    lines.append("")
    o = summary["outlier"]
    if o["found"]:
        lines.append("Outlier (>= %s ms) found: %s" % (o["threshold_ms"], " ".join(
            "%s/run%d/seq%d:%.3f" % (s["path"], s["run"], s["seq"], s["ms"]) for s in o["pings"])))
    else:
        lines.append("Outlier (>= %s ms) found: no." % o["threshold_ms"])
    lines.append("")
    lines.append("| Run | exit | proof_ok | CI gate | box avg gate (report) | direct avg | prc relay avg | sym relay avg |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in summary["runs"]:
        lines.append("| %d | %s | %s | %s | %s | %s | %s | %s |" % (
            r["run"], r["exit_code"], r["proof_ok"], r["ci_gate_ok"], r["box_avg_gate_ok"],
            r["rtt"].get("prc_prc_direct", "none"),
            r["rtt"].get("prc_prc_relay", "none"),
            r["rtt"].get("sym_sym_relay", "none"),
        ))
    lines.append("")
    for r in summary["runs"]:
        for fail in r["ci_failures"]:
            lines.append("- run%d CI gate failure: %s" % (r["run"], fail))
    lines.append("")
    return "\n".join(lines)


def load_runs(out_dir):
    runs = []
    i = 1
    while os.path.exists(os.path.join(out_dir, "run%d.log" % i)):
        with open(os.path.join(out_dir, "run%d.log" % i), errors="replace") as f:
            run = parse_log(f.read())
        exit_path = os.path.join(out_dir, "run%d.exit" % i)
        code = None
        if os.path.exists(exit_path):
            with open(exit_path) as f:
                code = int(f.read().strip() or "1")
        run["run"] = i
        run["exit_code"] = code
        runs.append(run)
        i += 1
    return runs


def throughput_lines(summary):
    """Return one line for each throughput value: path, run, value, floor and result."""
    lines = ["cpu_model %s" % summary.get("host", {}).get("cpu", "unknown")]
    for r in summary["runs"]:
        for path in PATHS:
            tput = r["throughput"].get(path)
            if tput is None:
                lines.append("%s run%d none floor %g FAIL" % (path, r["run"], MIN_MBIT))
            else:
                lines.append("%s run%d %.2f Mbit/s floor %g %s" % (
                    path, r["run"], tput, MIN_MBIT, "PASS" if tput >= MIN_MBIT else "FAIL"))
    return lines


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_dir = argv[1]
    summary = summarize(load_runs(out_dir))
    summary["host"] = host_info()
    with open(os.path.join(out_dir, "perf-watch.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    text = markdown(summary)
    with open(os.path.join(out_dir, "perf-watch.md"), "w") as f:
        f.write(text)
    print(text)
    print("\n".join(throughput_lines(summary)))
    if not summary["runs"]:
        print("No run log was found.", file=sys.stderr)
        return 1
    if not summary["ci_gate_ok"]:
        print("The CI gate did not pass on every run.", file=sys.stderr)
        for r in summary["runs"]:
            for fail in r["ci_failures"]:
                print("run%d: %s" % (r["run"], fail), file=sys.stderr)
        return 1
    if not summary["proof_ok"]:
        print("A run did not print proof_ok.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

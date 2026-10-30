#!/usr/bin/env python3
"""Summarize the release nat-realism runs of the W24 perf watch.

Usage: perf-summary.py OUT_DIR

OUT_DIR has run1.log, run1.exit, run2.log, run2.exit, and so on.
The script writes OUT_DIR/perf-watch.json and OUT_DIR/perf-watch.md and prints the markdown.
The exit code is 1 when a run did not print proof_ok or when an RTT gate did not pass.
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

SLOW_RE = re.compile(r"seq(\d+):([0-9.]+)@([0-9.]+)")


def parse_slow(text):
    return [{"seq": int(s), "ms": float(t), "at": float(a)} for s, t, a in SLOW_RE.findall(text)]


def parse_log(text):
    """Return the values of one run. A missing value stays missing."""
    run = {"proof_ok": False, "rtt": {}, "ping": {}, "throughput": {}, "gate": {}, "lost": {}}
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
    return run


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
    outliers = []
    for path in PATHS:
        for s in paths[path].get("slowest_pings", []):
            if s["ms"] >= OUTLIER_MS:
                outliers.append(dict(s, path=path))
    return {
        "runs": runs,
        "paths": paths,
        "rtt_gate_ok": bool(runs) and all(r["rtt_gate_ok"] for r in runs),
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
    lines.append("Runs: %d. proof_ok on all runs: %s. RTT gate on all runs: %s." % (
        len(summary["runs"]), summary["proof_ok"], summary["rtt_gate_ok"]))
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
    lines.append("| Run | exit | proof_ok | RTT gate | direct avg | prc relay avg | sym relay avg |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in summary["runs"]:
        lines.append("| %d | %s | %s | %s | %s | %s | %s |" % (
            r["run"], r["exit_code"], r["proof_ok"], r["rtt_gate_ok"],
            r["rtt"].get("prc_prc_direct", "none"),
            r["rtt"].get("prc_prc_relay", "none"),
            r["rtt"].get("sym_sym_relay", "none"),
        ))
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
    if not summary["runs"]:
        print("No run log was found.", file=sys.stderr)
        return 1
    if not summary["rtt_gate_ok"]:
        print("The RTT gate did not pass on every run.", file=sys.stderr)
        return 1
    if not summary["proof_ok"]:
        print("A run did not print proof_ok.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

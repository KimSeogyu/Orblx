#!/usr/bin/env python3
"""Host stall sampler for the proofs (W25-26).

Every INTERVAL seconds, write one line with the deltas since the last line:
  kst_time epoch_ms dt_ms steal_ms iowait_ms cpu_some_ms io_some_ms io_full_ms
  mem_some_ms mem_full_ms [name:cgroup_cpu_some_ms ...] [clk_*_ns:VALUE ...]
steal and iowait come from /proc/stat, summed over all CPUs (USER_HZ ticks to ms).
The *_ms PSI values come from the "total=" microseconds in /proc/pressure/{cpu,io,memory}.
Those values are pressure stall time. They are not CPU time consumed.
name=path arguments add the cpu.pressure "some" delta of a cgroup v2 directory.
cgroup_cpu_some_ms is that stall time. It is not CPU time consumed.
Each line also stores CLOCK_REALTIME, CLOCK_MONOTONIC, and CLOCK_BOOTTIME.
The unit is nanoseconds. The three reads are sequential.
CLOCK_MONOTONIC does not include Linux suspend.
CLOCK_BOOTTIME includes Linux suspend.
A missing clock is the token unsupported. The sampler does not copy another clock.
The sampler stops on SIGTERM or after --secs seconds.

Usage: host-sampler.py --out FILE [--interval 0.1] [--secs N] [name=cgroup_dir ...]
       host-sampler.py analyze --samples FILE --gaps FILE [--traces FILE] [thresholds]
       host-sampler.py coverage --samples FILE --cadence-ms N [--mark name=epoch_s]

analyze: a sample is a host stall window when one host-level value is at or above its
threshold: steal_ms, iowait_ms, io_full_ms, mem_some_ms. cpu_some_ms and the per-container
cpu pressure are reported values only (Orblx itself can raise them), so they never make a
stall window. For each line
"src dst from_s to_s gap_ms" in --gaps, it prints the largest value of each field in the
samples whose window [epoch_ms - dt_ms, epoch_ms] touches [from, to], and "class
host_stall" if one of these samples is a stall window, else "class quiet_host".
--traces lines are "node epoch_ms text". The trace lines of the src and dst node from
1 s before the gap to 0.5 s after the gap are printed under the gap.
coverage reports unsampled intervals. It does not change the stall gates.
contention unknown_samples is not an input to coverage.
"""
import argparse
import os
import re
import signal
import sys
import time
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
HZ = os.sysconf("SC_CLK_TCK")
# A span at or above this length is a large unsampled interval.
LARGE_UNSAMPLED_NS = 1_000_000_000
# Monotonic and boottime elapsed across one capture must stay under this limit.
# A larger elapsed bracket means the reads are not one sample.
CAPTURE_BRACKET_MAX_NS = 50_000_000
CLOCK_NAMES = ("realtime", "monotonic", "boottime")
COLUMN_HEADER = (
    "# kst_time epoch_ms dt_ms steal_ms iowait_ms cpu_some_ms io_some_ms io_full_ms "
    "mem_some_ms mem_full_ms cgroup_cpu_some_ms...\n"
)
CLOCK_NOTES = """\
# clk_realtime_ns clk_monotonic_ns clk_boottime_ns are clock_gettime values in nanoseconds.
# clk_realtime_ns is CLOCK_REALTIME. It is wall time. It can step forward or backward.
# clk_monotonic_ns is CLOCK_MONOTONIC. It does not include Linux suspend. It does not follow a wall step.
# clk_boottime_ns is CLOCK_BOOTTIME. It includes Linux suspend. It does not follow a wall step.
# Each capture reads realtime, monotonic, and boottime, then reads those three clocks again.
# clk_capture_skew_ns is the later CLOCK_REALTIME minus the first CLOCK_REALTIME.
# A wall step during the capture can make clk_capture_skew_ns negative or very large.
# clk_capture_skew_ns is not an acquisition-duration bound.
# clk_capture_monotonic_ns and clk_capture_boottime_ns are the elapsed-clock bracket.
# A capture is not usable when that bracket is negative, too large, unsupported, or the realtime step disagrees with it.
# The raw realtime values stay in the file. The report does not rewrite them.
# A clock the host cannot read is the token unsupported. The sampler does not copy another clock into that field.
# No pattern of these three clocks identifies every hypervisor pause.
# cpu_some_ms io_some_ms io_full_ms mem_some_ms mem_full_ms are PSI stall time in milliseconds. They are not CPU time consumed.
# cgroup_cpu_some_ms is cgroup cpu.pressure some stall time in milliseconds. It is not CPU time consumed.
# dt_ms is the CLOCK_REALTIME gap in milliseconds. It is not a monotonic gap and it is not a boottime gap.
"""


def linux_clock_ids():
    return {
        "realtime": getattr(time, "CLOCK_REALTIME", None),
        "monotonic": getattr(time, "CLOCK_MONOTONIC", None),
        "boottime": getattr(time, "CLOCK_BOOTTIME", None),
    }


def read_named_clock(clock_gettime_ns, clock_id):
    if clock_id is None:
        return "unsupported"
    try:
        return int(clock_gettime_ns(clock_id))
    except OSError:
        return "unsupported"


def _read_trio(clock_gettime_ns, clock_ids):
    return {name: read_named_clock(clock_gettime_ns, clock_ids.get(name)) for name in CLOCK_NAMES}


def read_clock_sample(clock_gettime_ns, clock_ids):
    """Read two trios. The stored clocks are the first trio. The second trio is the bracket."""
    before = _read_trio(clock_gettime_ns, clock_ids)
    after = _read_trio(clock_gettime_ns, clock_ids)
    return {
        "realtime": before["realtime"],
        "monotonic": before["monotonic"],
        "boottime": before["boottime"],
        "capture_skew": clock_delta(before["realtime"], after["realtime"]),
        "capture_monotonic": clock_delta(before["monotonic"], after["monotonic"]),
        "capture_boottime": clock_delta(before["boottime"], after["boottime"]),
    }


def capture_status(sample):
    """Classify one capture. This does not change the stored realtime value."""
    skew = sample.get("capture_skew", "unsupported")
    monotonic = sample.get("capture_monotonic", "unsupported")
    boottime = sample.get("capture_boottime", "unsupported")
    if skew == "unsupported" or monotonic == "unsupported" or boottime == "unsupported":
        return "capture_unsupported"
    if monotonic < 0 or boottime < 0:
        return "capture_ambiguous"
    if monotonic > CAPTURE_BRACKET_MAX_NS or boottime > CAPTURE_BRACKET_MAX_NS:
        return "capture_ambiguous"
    if skew < 0 or skew > monotonic + CAPTURE_BRACKET_MAX_NS:
        return "capture_wall_step"
    if boottime > monotonic + CAPTURE_BRACKET_MAX_NS:
        return "capture_ambiguous"
    return "ok"


def clock_delta(prev, cur):
    if prev == "unsupported" or cur == "unsupported":
        return "unsupported"
    return cur - prev


def _small_limit_ns(cadence_ns):
    return cadence_ns * 5


def classify_deltas(deltas, cadence_ns):
    """Name one span. The name does not identify every hypervisor pause."""
    if any(deltas[name] == "unsupported" for name in CLOCK_NAMES):
        return "clock_unsupported"
    realtime = deltas["realtime"]
    monotonic = deltas["monotonic"]
    boottime = deltas["boottime"]
    if monotonic < 0 or boottime < 0:
        return "clock_backward"
    if realtime < 0:
        return "wall_backward"
    small = _small_limit_ns(cadence_ns)

    def is_small(value):
        return 0 <= value <= small

    def is_large(value):
        return value >= LARGE_UNSAMPLED_NS

    if is_large(realtime) and is_small(monotonic) and is_small(boottime):
        return "wall_forward"
    if is_small(monotonic) and is_large(boottime) and is_large(realtime):
        return "suspend_shaped"
    if is_large(realtime) and is_large(monotonic) and is_large(boottime):
        spread = max(realtime, monotonic, boottime) - min(realtime, monotonic, boottime)
        if spread <= max(small, LARGE_UNSAMPLED_NS // 20):
            return "unresolved_gap"
        return "mixed"
    if is_small(realtime) and is_small(monotonic) and is_small(boottime):
        return "cadence"
    return "mixed"


def _parse_clock(token):
    if token is None or token in ("unsupported", "na", "-"):
        return "unsupported"
    return int(token)


def _clock_token(value):
    if value == "unsupported":
        return "unsupported"
    return str(int(value))


def format_clock_fields(prev, cur):
    parts = []
    for name in CLOCK_NAMES:
        parts.append(f"clk_{name}_ns:{_clock_token(cur[name])}")
    parts.append(f"clk_capture_skew_ns:{_clock_token(cur['capture_skew'])}")
    parts.append(f"clk_capture_monotonic_ns:{_clock_token(cur.get('capture_monotonic', 'unsupported'))}")
    parts.append(f"clk_capture_boottime_ns:{_clock_token(cur.get('capture_boottime', 'unsupported'))}")
    for name in CLOCK_NAMES:
        parts.append(f"clk_{name}_dt_ns:{_clock_token(clock_delta(prev[name], cur[name]))}")
    return " ".join(parts)


def _num_or_none(token):
    try:
        return float(token)
    except (TypeError, ValueError):
        return None


def stat_ticks(proc_root="/proc"):
    with open(os.path.join(proc_root, "stat")) as f:
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


def read_cgroup_list(base, path):
    """Read name=dir lines. An empty dir stays empty. A missing file keeps the base list."""
    items = list(base)
    if not path:
        return items
    try:
        with open(path) as handle:
            text = handle.read()
    except OSError:
        return items
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, directory = line.split("=", 1)
        if not name:
            continue
        items = [item for item in items if item[0] != name]
        items.append((name, directory))
    return items


def snapshot(cgroups, clock_gettime_ns=None, clock_ids=None, proc_root="/proc"):
    if clock_gettime_ns is None:
        clock_gettime_ns = time.clock_gettime_ns
    if clock_ids is None:
        clock_ids = linux_clock_ids()
    clocks = read_clock_sample(clock_gettime_ns, clock_ids)
    iowait, steal = stat_ticks(proc_root)
    cpu = psi(os.path.join(proc_root, "pressure", "cpu")) or {"some": 0, "full": 0}
    io = psi(os.path.join(proc_root, "pressure", "io")) or {"some": 0, "full": 0}
    mem = psi(os.path.join(proc_root, "pressure", "memory")) or {"some": 0, "full": 0}
    cg = {}
    for name, path in cgroups:
        if not path:
            cg[name] = None
            continue
        p = psi(os.path.join(path, "cpu.pressure"))
        cg[name] = None if p is None else p["some"]
    wall = None if clocks["realtime"] == "unsupported" else clocks["realtime"] / 1e9
    return wall, steal, iowait, cpu["some"], io["some"], io["full"], mem["some"], mem["full"], cg, clocks


FIELDS = ["steal_ms", "iowait_ms", "cpu_some_ms", "io_some_ms", "io_full_ms", "mem_some_ms", "mem_full_ms"]
STALL_KEYS = ["steal_ms", "iowait_ms", "io_full_ms", "mem_some_ms"]


def read_samples(path):
    rows = []
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            end = _num_or_none(parts[1])
            dt = _num_or_none(parts[2])
            row = {
                "kst": parts[0],
                "start": None if end is None or dt is None else end - dt,
                "end": end,
            }
            for i, name in enumerate(FIELDS):
                row[name] = float(parts[3 + i])
            row["cg"] = {}
            row["clk"] = {}
            for item in parts[10:]:
                name, sep, val = item.partition(":")
                if name.startswith("clk_"):
                    row["clk"][name] = val
                    continue
                if sep != ":":
                    continue
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
            hit = [
                r for r in rows
                if r["end"] is not None and r["start"] is not None and r["end"] >= a_ms and r["start"] <= b_ms
            ]
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
            print("gap_host pair {}->{} kst {} gap_ms {} samples {} {} node_cpu_pressure_stall_ms {} class {}".format(
                src, dst, kst, gap, len(hit), " ".join(f"{k} {peak[k]:g}" for k in FIELDS),
                ",".join(f"{n}:{v:g}" for n, v in sorted(cg.items())) or "-", cls))
            for node, ms, text in traces:
                if node in (src, dst) and a_ms - 1000 <= ms <= b_ms + 500:
                    print(f"  gap_trace {node} {ms} {text}")
    print(f"gap_class host_stall {host} quiet_host {quiet}")
    return 0


def clocks_from_row(row):
    """Return absolute clocks in nanoseconds. Old files keep monotonic and boottime unsupported."""
    clk = row.get("clk") or {}
    if "clk_realtime_ns" in clk:
        return {
            "realtime": _parse_clock(clk.get("clk_realtime_ns")),
            "monotonic": _parse_clock(clk.get("clk_monotonic_ns")),
            "boottime": _parse_clock(clk.get("clk_boottime_ns")),
            "capture_skew": _parse_clock(clk.get("clk_capture_skew_ns")),
            "capture_monotonic": _parse_clock(clk.get("clk_capture_monotonic_ns")),
            "capture_boottime": _parse_clock(clk.get("clk_capture_boottime_ns")),
        }
    if row.get("end") is None:
        realtime = "unsupported"
    else:
        realtime = int(round(row["end"] * 1_000_000))
    return {
        "realtime": realtime,
        "monotonic": "unsupported",
        "boottime": "unsupported",
        "capture_skew": "unsupported",
        "capture_monotonic": "unsupported",
        "capture_boottime": "unsupported",
        "source": "realtime_epoch_ms_only",
    }


def _pairs(samples):
    return list(zip(samples, samples[1:]))


def _max_positive(spans, name):
    best = None
    for prev, cur, _pattern, deltas in spans:
        delta = deltas[name]
        if delta == "unsupported" or delta <= 0:
            continue
        if best is None or delta > best[0]:
            best = (delta, prev[name], cur[name])
    return best


def _span(prev, cur, cadence_ns):
    deltas = {name: clock_delta(prev[name], cur[name]) for name in CLOCK_NAMES}
    for sample in (prev, cur):
        status = capture_status(sample)
        if status != "ok":
            return status, deltas
    return classify_deltas(deltas, cadence_ns), deltas


def _overlaps(realtime_0, realtime_1, start_ns, end_ns):
    if realtime_0 == "unsupported" or realtime_1 == "unsupported":
        return False
    lo, hi = realtime_0, realtime_1
    if hi < lo:
        lo, hi = hi, lo
    return lo < end_ns and hi > start_ns


def window_verdict(samples, start_ns, end_ns, cadence_ns, unknown_samples=None):
    """Return (yes|no, reason). unknown_samples does not change the result.

    yes means the interval is covered at the sample cadence.
    It does not mean the host was observed continuously.
    A pause shorter than the cadence can sit inside one span.
    """
    del unknown_samples
    if end_ns < start_ns:
        return "no", "window_backward"
    if not samples:
        return "no", "no_samples"
    if len(samples) < 2:
        return "no", "unbracketed"
    for sample in samples:
        if any(sample.get(name) == "unsupported" for name in CLOCK_NAMES):
            return "no", "clock_unsupported"
    overlapped = False
    for prev, cur in _pairs(samples):
        pattern, _deltas = _span(prev, cur, cadence_ns)
        if not _overlaps(prev["realtime"], cur["realtime"], start_ns, end_ns):
            continue
        overlapped = True
        if pattern != "cadence":
            return "no", pattern
    first = samples[0]["realtime"]
    last = samples[-1]["realtime"]
    if first == "unsupported" or last == "unsupported":
        return "no", "clock_unsupported"
    if first > start_ns + cadence_ns:
        return "no", "leading_unsampled"
    if last + cadence_ns < end_ns:
        return "no", "trailing_unsampled"
    if not overlapped:
        return "no", "outside_or_unplaced"
    return "yes", "cadence"


def _window_lines(samples, cadence_ns, windows, bound):
    lines = []
    if bound is None:
        lines.append("observation_bound absent")
    else:
        verdict, reason = window_verdict(samples, bound[0], bound[1], cadence_ns, unknown_samples=0)
        lines.append(f"observation_bound fully_observed {verdict} reason {reason}")
    for label, start_ns, end_ns in windows:
        verdict, reason = window_verdict(samples, start_ns, end_ns, cadence_ns, unknown_samples=0)
        lines.append(f"observation_mark {label} fully_observed {verdict} reason {reason}")
    return lines


def format_coverage(samples, cadence_ns, windows, bound=None):
    """Report the whole run. windows are (label, start_ns, end_ns). bound is (start_ns, end_ns) or None."""
    lines = [
        f"observation_cadence_ns {int(cadence_ns)}",
        f"observation_large_unsampled_ns {LARGE_UNSAMPLED_NS}",
        f"observation_capture_bracket_max_ns {CAPTURE_BRACKET_MAX_NS}",
        f"observation_samples {len(samples)}",
        "observation_fully_observed_meaning one_cadence_spacing_not_continuous_observation",
        "observation_product_gate_unchanged reply_gap_ms 200",
        "observation_pattern_limit no_clock_pattern_identifies_every_hypervisor_pause",
        "observation_note contention_unknown_samples_do_not_mean_a_renewal_interval_was_fully_observed",
        "observation_pressure_note cgroup_cpu_some_ms_is_psi_stall_not_cpu_time_consumed",
    ]
    if len(samples) < 2:
        lines.append("observation_elapsed_realtime_ns unsupported")
        lines.append("observation_elapsed_monotonic_ns unsupported")
        lines.append("observation_elapsed_boottime_ns unsupported")
        lines.append("observation_max_unsampled_realtime_ns none")
        lines.append("observation_max_unsampled_monotonic_ns none")
        lines.append("observation_max_unsampled_boottime_ns none")
        lines.append("observation_large_spans 0")
        lines.extend(_window_lines(samples, cadence_ns, windows, bound))
        return lines
    spans = []
    counts = {}
    negative = {name: 0 for name in CLOCK_NAMES}
    min_negative = {name: None for name in CLOCK_NAMES}
    skews = []
    for prev, cur in _pairs(samples):
        pattern, deltas = _span(prev, cur, cadence_ns)
        spans.append((prev, cur, pattern, deltas))
        counts[pattern] = counts.get(pattern, 0) + 1
        for name in CLOCK_NAMES:
            delta = deltas[name]
            if delta != "unsupported" and delta < 0:
                negative[name] += 1
                if min_negative[name] is None or delta < min_negative[name]:
                    min_negative[name] = delta
        skew = cur.get("capture_skew", "unsupported")
        if skew != "unsupported":
            skews.append(skew)
    for name in CLOCK_NAMES:
        first = samples[0][name]
        last = samples[-1][name]
        if first == "unsupported" or last == "unsupported":
            lines.append(f"observation_elapsed_{name}_ns unsupported")
        else:
            elapsed = last - first
            if elapsed < 0:
                lines.append(f"observation_elapsed_{name}_ns {elapsed} sign backward")
            else:
                lines.append(f"observation_elapsed_{name}_ns {elapsed}")
    for name in CLOCK_NAMES:
        best = _max_positive(spans, name)
        if best is None:
            lines.append(f"observation_max_unsampled_{name}_ns none")
        else:
            delta, start, end = best
            lines.append(
                f"observation_max_unsampled_{name}_ns {delta} start_ns {start} end_ns {end}"
            )
        lines.append(f"observation_negative_{name}_spans {negative[name]}")
        if min_negative[name] is not None:
            lines.append(f"observation_min_{name}_dt_ns {min_negative[name]}")
    large = sum(1 for _p, _c, pattern, _d in spans if pattern != "cadence")
    lines.append(f"observation_large_spans {large}")
    if counts:
        lines.append(
            "observation_clock_pattern_counts "
            + " ".join(f"{name} {counts[name]}" for name in sorted(counts))
        )
    if skews:
        lines.append(f"observation_max_capture_skew_ns {max(skews)}")
        lines.append(f"observation_min_capture_skew_ns {min(skews)}")
    else:
        lines.append("observation_max_capture_skew_ns unsupported")
    lines.extend(_window_lines(samples, cadence_ns, windows, bound))
    return lines


def coverage_samples(path):
    rows = read_samples(path)
    return [clocks_from_row(row) for row in rows]


# This limit is 2x the 100 ms sample cadence. It is not the 200 ms reply-gap gate.
SAMPLER_SPAN_LIMIT_NS = 200_000_000
QUALIFY_EDGE_NS = 100_000_000
QUALIFY_DRIFT_NS = 50_000_000


def _capture_bracket_ns(sample):
    """Return the capture bracket in ns. A negative or missing bracket cannot qualify."""
    mono = sample.get("capture_monotonic", "unsupported")
    boot = sample.get("capture_boottime", "unsupported")
    if mono == "unsupported" or boot == "unsupported" or mono < 0 or boot < 0:
        return "unsupported"
    return max(mono, boot)


def qualify_observation(samples, start_ns, end_ns, early_fail=False, require_s=7200, installs=None):
    """Report whether the eligible interval is observed. This does not set a product verdict."""
    lines = [
        "qualification_separate_from_product_verdict yes",
        "qualification_sampler_span_limit_ms 200",
        "qualification_sampler_span_note not_the_reply_gap_gate",
        "qualification_edge_limit_ms 100",
        "qualification_drift_limit_ms 50",
        "qualification_drift_baseline first_eligible_sample",
        "qualification_drift_note both_capture_brackets_are_in_the_uncertainty",
        "qualification_duration_note setup_cleanup_and_run_end_padding_do_not_count",
    ]
    if early_fail:
        lines.append("qualification_window actual_start_to_failure")
        lines.append("qualification_duration_required_s 0")
    else:
        lines.append("qualification_window eligible_measurement")
        lines.append(f"qualification_duration_required_s {int(require_s)}")
    for item in installs or []:
        lines.append(f"qualification_install_before_expiry {item} observation_only")
    if installs:
        lines.append("qualification_install_before_expiry_note not_a_refusal_gate")
    reasons = []
    if start_ns is None or end_ns is None:
        reasons.append("eligible_interval_not_reached")
    elif end_ns < start_ns:
        reasons.append("window_backward")
    else:
        inside = [
            sample
            for sample in samples
            if sample.get("realtime") != "unsupported" and start_ns <= sample["realtime"] <= end_ns
        ]
        if len(inside) < 2:
            reasons.append("no_eligible_samples")
        else:
            first, last = inside[0], inside[-1]
            start_edge = first["realtime"] - start_ns
            end_edge = end_ns - last["realtime"]
            lines.append(f"qualification_start_edge_ns {start_edge}")
            lines.append(f"qualification_end_edge_ns {end_edge}")
            if start_edge > QUALIFY_EDGE_NS:
                reasons.append("start_edge")
            if end_edge > QUALIFY_EDGE_NS:
                reasons.append("end_edge")
            for name in CLOCK_NAMES:
                elapsed = clock_delta(first[name], last[name])
                lines.append(f"qualification_elapsed_{name}_ns {elapsed}")
                if elapsed == "unsupported" or elapsed < 0:
                    reasons.append(f"duration_{name}")
                elif not early_fail and elapsed < int(require_s) * 1_000_000_000:
                    reasons.append(f"duration_{name}")
            span_max = 0
            for prev, cur in zip(inside, inside[1:]):
                deltas = {name: clock_delta(prev[name], cur[name]) for name in CLOCK_NAMES}
                for name in CLOCK_NAMES:
                    delta = deltas[name]
                    # A backward step does not qualify, even when it is below the drift limit.
                    if delta != "unsupported" and delta < 0:
                        reasons.append("negative_delta")
                if capture_status(prev) != "ok" or capture_status(cur) != "ok":
                    continue
                for name in CLOCK_NAMES:
                    delta = deltas[name]
                    if delta != "unsupported" and delta > span_max:
                        span_max = delta
            # Drift uses the first eligible sample as the baseline.
            # A small step between neighbours can still leave the interval outside 50 ms.
            baseline = inside[0]
            worst_rt = None
            worst_boot = None
            base_bracket = _capture_bracket_ns(baseline)
            if capture_status(baseline) != "ok" or base_bracket == "unsupported":
                reasons.append("capture")
            else:
                for cur in inside[1:]:
                    cur_bracket = _capture_bracket_ns(cur)
                    if capture_status(cur) != "ok" or cur_bracket == "unsupported":
                        reasons.append("capture")
                        continue
                    deltas = {name: clock_delta(baseline[name], cur[name]) for name in CLOCK_NAMES}
                    if any(deltas[name] == "unsupported" for name in CLOCK_NAMES):
                        reasons.append("capture")
                        continue
                    uncertainty = base_bracket + cur_bracket
                    drift_rt = deltas["realtime"] - deltas["monotonic"]
                    drift_boot = deltas["boottime"] - deltas["monotonic"]
                    margin_rt = abs(drift_rt) + uncertainty
                    margin_boot = abs(drift_boot) + uncertainty
                    if worst_rt is None or margin_rt > worst_rt[0]:
                        worst_rt = (margin_rt, drift_rt, uncertainty)
                    if worst_boot is None or margin_boot > worst_boot[0]:
                        worst_boot = (margin_boot, drift_boot, uncertainty)
                    # A value on the 50 ms line does not qualify. Both brackets are in the sum.
                    if margin_rt >= QUALIFY_DRIFT_NS or margin_boot >= QUALIFY_DRIFT_NS:
                        reasons.append("drift")
            lines.append(f"qualification_sampler_span_max_ms {span_max / 1_000_000:.3f}")
            if span_max > SAMPLER_SPAN_LIMIT_NS:
                reasons.append("sampler_span")
            if worst_rt is not None:
                lines.append(f"qualification_drift_rt_mono_ns {worst_rt[1]}")
                lines.append(f"qualification_drift_rt_mono_uncertainty_ns {worst_rt[2]}")
            if worst_boot is not None:
                lines.append(f"qualification_drift_boot_mono_ns {worst_boot[1]}")
                lines.append(f"qualification_drift_boot_mono_uncertainty_ns {worst_boot[2]}")
    ordered = []
    for reason in reasons:
        if reason not in ordered:
            ordered.append(reason)
    if ordered:
        lines.append("qualification_clock no reason " + ",".join(ordered))
    else:
        lines.append("qualification_clock yes reason eligible_interval")
    return lines


def _read_status_file(path):
    """Return file text. A missing path is missing input, not an empty success."""
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read()


_EXPORT_SERVICES = ("stack.log", "coord", "owner", "a", "b", "c")


def acceptance_qualification(clock_text, event_text, export_text, artifact_text, coord_text):
    """Combine clock, event, install, and copy evidence. This does not set a product verdict.

    A missing or ambiguous input is unknown, never yes. Clock-only output stays on qualification_clock.
    """
    unknown = []
    failed = []
    if clock_text is None:
        unknown.append("clock_missing")
    else:
        clock_lines = [line for line in clock_text.splitlines() if line.startswith("qualification_clock ")]
        if len(clock_lines) != 1:
            unknown.append("clock_missing")
        elif not clock_lines[0].startswith("qualification_clock yes"):
            failed.append("clock")
    if event_text is None:
        unknown.append("events_missing")
    else:
        for line in event_text.splitlines():
            if line == "required_events unknown":
                unknown.append("events_unknown")
            elif line.startswith("required_renewal ") and not line.endswith(" present"):
                failed.append("renewal")
            elif line.startswith("required_install ") and not line.endswith(" before_expiry yes"):
                failed.append("install")
    if export_text is None:
        unknown.append("export_status_missing")
    else:
        found = {}
        for line in export_text.splitlines():
            parts = line.split()
            if len(parts) != 3 or parts[0] != "log_export":
                failed.append("export")
                continue
            found[parts[1]] = parts[2]
        for service in _EXPORT_SERVICES:
            if found.get(service) != "ok":
                failed.append("export")
    if artifact_text is None:
        unknown.append("artifact_status_missing")
    else:
        artifact_lines = [line for line in artifact_text.splitlines() if line.startswith("artifact ")]
        if "artifact ping_files kept" not in artifact_lines or "artifact big_gaps kept" not in artifact_lines:
            failed.append("artifact")
        if any(not line.endswith(" kept") for line in artifact_lines):
            failed.append("artifact")
    if coord_text is None:
        unknown.append("coord_log_status_missing")
    elif [line for line in coord_text.splitlines() if line.strip()] != ["coord_log ok"]:
        failed.append("coord_log")
    if unknown:
        ordered = []
        for reason in unknown + failed:
            if reason not in ordered:
                ordered.append(reason)
        return "qualification unknown reason " + ",".join(ordered)
    if failed:
        ordered = []
        for reason in failed:
            if reason not in ordered:
                ordered.append(reason)
        return "qualification no reason " + ",".join(ordered)
    return "qualification yes reason complete"


def parse_mark(text):
    name, sep, rest = text.partition("=")
    if sep != "=" or not name or not rest:
        raise ValueError(text)
    if ":" in rest:
        start_s, end_s = rest.split(":", 1)
        return name, int(float(start_s) * 1e9), int(float(end_s) * 1e9)
    start = int(float(rest) * 1e9)
    return name, start, start + 1_000_000_000


def coverage_main(argv):
    ap = argparse.ArgumentParser(prog="host-sampler.py coverage")
    ap.add_argument("--samples", required=True)
    ap.add_argument("--cadence-ms", type=float, required=True)
    ap.add_argument("--mark", action="append", default=[])
    ap.add_argument("--bound")
    ap.add_argument("--unknown-samples", type=int)
    ap.add_argument("--qualify", action="store_true")
    ap.add_argument("--qualify-start")
    ap.add_argument("--qualify-end")
    ap.add_argument("--qualify-early-fail", action="store_true")
    ap.add_argument("--qualify-require-s", type=int, default=7200)
    ap.add_argument("--install-before-expiry", action="append", default=[])
    args = ap.parse_args(argv)
    windows = [parse_mark(item) for item in args.mark]
    bound = None
    if args.bound:
        start_s, end_s = args.bound.split(":", 1)
        bound = (int(float(start_s) * 1e9), int(float(end_s) * 1e9))
    lines = format_coverage(
        coverage_samples(args.samples), args.cadence_ms * 1_000_000, windows, bound
    )
    if args.unknown_samples is not None:
        lines.append(f"observation_unknown_samples_ignored {args.unknown_samples}")
    if args.qualify or args.qualify_start or args.qualify_end or args.qualify_early_fail or args.install_before_expiry:
        start_ns = None if not args.qualify_start else int(float(args.qualify_start) * 1e9)
        end_ns = None if not args.qualify_end else int(float(args.qualify_end) * 1e9)
        lines.extend(
            qualify_observation(
                coverage_samples(args.samples),
                start_ns,
                end_ns,
                early_fail=args.qualify_early_fail,
                require_s=args.qualify_require_s,
                installs=args.install_before_expiry,
            )
        )
    print("\n".join(lines))
    return 0


def _wall_fields(cur, prev):
    if cur[0] is None or prev[0] is None:
        return "unsupported", "unsupported", "unsupported"
    kst = datetime.fromtimestamp(cur[0], KST).strftime("%H:%M:%S.%f")[:-3]
    epoch_ms = f"{cur[0] * 1000:.0f}"
    dt_ms = f"{(cur[0] - prev[0]) * 1000:.0f}"
    return kst, epoch_ms, dt_ms


def acceptance_main(argv):
    ap = argparse.ArgumentParser(prog="host-sampler.py acceptance")
    ap.add_argument("--coverage")
    ap.add_argument("--events")
    ap.add_argument("--export-status")
    ap.add_argument("--artifact-status")
    ap.add_argument("--coord-status")
    args = ap.parse_args(argv)
    print(
        acceptance_qualification(
            _read_status_file(args.coverage),
            _read_status_file(args.events),
            _read_status_file(args.export_status),
            _read_status_file(args.artifact_status),
            _read_status_file(args.coord_status),
        )
    )
    return 0


# W25-47 host-pause guard. These limits are fixed. The program does not read them from the environment.
# A value above the limit makes the run HOST_INVALID. A value equal to the limit stays inside the rule.
HOST_DRIFT_MAX_S = 5
HOST_GAP_MAX_S = 5
HOST_BOOT_MONO_JUMP_MAX_S = 5
# Cadence of this harness. The start command passes the same value as --interval.
# The guard checks this constant. It does not read an interval from the environment.
# A constant above 1 s is reason=sampler_interval_cfg.
HOST_SAMPLER_INTERVAL_S = 0.1
HOST_SAMPLER_INTERVAL_MAX_S = 1
# A sample at a distance of exactly 5.0 s is inside the fork neighbourhood. A larger distance is outside.
HOST_FORK_COVER_NS = 5_000_000_000
# Exit 5 is PROOF_FOREIGN_ABORT_EXIT in proof-lock.sh. This guard uses 6.
HOST_INVALID_EXIT = 6
_HOST_FORK_TEXT = "virtual machine fork"
_REASON_ORDER = (
    "data_missing",
    "drift",
    "gap",
    "boot_mono_jump",
    "sampler_interval_cfg",
    "sampler_median",
    "uncovered_fork",
)
# Raw dmesg only. "[seconds.fraction] message". ISO lines have no brackets and are ignored.
_RAW_DMESG_RE = re.compile(r"^\[(\d+)(?:\.(\d+))?\]\s*(.*)$")


def _fmt_seconds(value):
    if value is None:
        return "na"
    return f"{value:.3f}"


def _median(values):
    """Median of at least two deltas. Fewer than two deltas has no median."""
    if len(values) < 2:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _clock_ns(row, name):
    token = row.get("clk", {}).get(name)
    if token is None or token in ("unsupported", "na", "-"):
        return None
    try:
        return int(token)
    except ValueError:
        return None


def _utc_from_ns(ns):
    moment = datetime.fromtimestamp(ns / 1e9, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _raw_stamp_ns(line):
    """Return printk nanoseconds from a raw dmesg line, or None.

    printk stores local_clock(), which is sched_clock()
    (kernel/printk/printk.c, include/linux/sched/clock.h).
    util-linux dmesg maps that raw value with CLOCK_MONOTONIC when it prints iso or ctime.
    Both clocks omit suspend when sched_clock stops in suspend.
    They are not one counter. Short-run skew is microseconds to low milliseconds.
    NTP can move CLOCK_MONOTONIC by about 1 s per day at 12 ppm.
    On a nonstop TSC, sched_clock can include suspend while CLOCK_MONOTONIC does not.
    This guard compares the raw seconds with clk_monotonic_ns. It does not use wall time.
    """
    match = _RAW_DMESG_RE.match(line)
    if match is None:
        return None
    fraction = (match.group(2) or "")[:9]
    fraction = fraction.ljust(9, "0")
    return int(match.group(1)) * 1_000_000_000 + int(fraction)


def _host_events(rows):
    """Measure drift, the monotonic gap, and the boottime-minus-monotonic jump.

    The gap uses CLOCK_MONOTONIC between consecutive samples.
    dt_ms is CLOCK_REALTIME. A wall step is the drift rule, not a sampler gap.
    CLOCK_MONOTONIC advances when the sampler does not run. It does not follow a wall step.
    The jump is the change in (CLOCK_BOOTTIME - CLOCK_MONOTONIC) between consecutive samples.
    """
    if len(rows) < 2:
        return None
    clocks = []
    for row in rows:
        realtime = _clock_ns(row, "clk_realtime_ns")
        monotonic = _clock_ns(row, "clk_monotonic_ns")
        boottime = _clock_ns(row, "clk_boottime_ns")
        if realtime is None or monotonic is None or boottime is None:
            return None
        clocks.append((realtime, monotonic, boottime))
    drift_s = abs((clocks[-1][0] - clocks[0][0]) - (clocks[-1][1] - clocks[0][1])) / 1e9
    max_gap_s = 0.0
    max_jump_s = 0.0
    gap_event_ns = None
    jump_event_ns = None
    deltas = []
    for prev, cur in zip(clocks, clocks[1:]):
        mono_s = (cur[1] - prev[1]) / 1e9
        jump_s = abs((cur[2] - cur[1]) - (prev[2] - prev[1])) / 1e9
        if mono_s < 0:
            return None
        deltas.append(mono_s)
        if mono_s > max_gap_s:
            max_gap_s = mono_s
        if gap_event_ns is None and mono_s > HOST_GAP_MAX_S:
            gap_event_ns = prev[0]
        if jump_s > max_jump_s:
            max_jump_s = jump_s
        if jump_event_ns is None and jump_s > HOST_BOOT_MONO_JUMP_MAX_S:
            jump_event_ns = prev[0]
    return {
        "drift_s": drift_s,
        "max_gap_s": max_gap_s,
        "max_jump_s": max_jump_s,
        "median_s": _median(deltas),
        "clocks": clocks,
        "gap_event_ns": gap_event_ns,
        "jump_event_ns": jump_event_ns,
    }


def _bracket(clocks, fork_ns):
    """Gap and drift of the two samples that bracket the fork.

    The left sample is the latest CLOCK_MONOTONIC at or before the fork.
    The right sample is the earliest CLOCK_MONOTONIC at or after the fork.
    A sample on the fork has gap 0 and drift 0.
    """
    left = None
    right = None
    for item in clocks:
        if item[1] <= fork_ns:
            left = item
        if item[1] >= fork_ns and right is None:
            right = item
    if left is None or right is None or left[1] == right[1]:
        return 0.0, 0.0
    gap_s = (right[1] - left[1]) / 1e9
    drift_s = abs((right[0] - left[0]) - (right[1] - left[1])) / 1e9
    return gap_s, drift_s


def _forks_in_window(dmesg_text, clocks):
    """Forks whose raw time is inside the first-to-last monotonic sample.

    A fork is uncovered only when the 5 s before the fork and the 5 s after it
    both have no sample. A sample at the fork time covers both sides.
    A sample at exactly 5.0 s covers that side. A sample farther than 5.0 s does not.
    A fork outside the sampler monotonic window is not counted.
    """
    mono = [item[1] for item in clocks]
    start = mono[0]
    end = mono[-1]
    found = []
    for line in dmesg_text.splitlines():
        if _HOST_FORK_TEXT not in line:
            continue
        stamp_ns = _raw_stamp_ns(line)
        if stamp_ns is None or stamp_ns < start or stamp_ns > end:
            continue
        before = any(stamp_ns - HOST_FORK_COVER_NS <= sample <= stamp_ns for sample in mono)
        after = any(stamp_ns <= sample <= stamp_ns + HOST_FORK_COVER_NS for sample in mono)
        gap_s, drift_s = _bracket(clocks, stamp_ns)
        found.append(
            {
                "mono_ns": stamp_ns,
                "uncovered": not before and not after,
                "gap_s": gap_s,
                "drift_s": drift_s,
            }
        )
    found.sort(key=lambda item: item["mono_ns"])
    return found


def _fork_fail_delta_s(forks, fail_mono_ns):
    """Signed seconds from the nearest in-window fork at or before the FAIL, else the earliest fork."""
    if fail_mono_ns is None or not forks:
        return None
    earlier = [item["mono_ns"] for item in forks if item["mono_ns"] <= fail_mono_ns]
    chosen = max(earlier) if earlier else forks[0]["mono_ns"]
    return (fail_mono_ns - chosen) / 1e9


def _fmt_signed(value):
    if value is None:
        return "-"
    return f"{value:+.3f}"


def host_qualification_report(
    rows,
    dmesg_text,
    dmesg_readable,
    product_status,
    product_fail_utc,
    product_fail_seen=False,
    product_fail_mono_ns=None,
):
    """Return the one host_qualification line for this run.

    The window is the sampler lifetime: the first sample through the last sample.
    product_status is not a product FAIL. product_fail_seen is a real FAIL line.
    vm_fork=1 means an uncovered fork. A covered fork stays vm_fork=0.
    """
    del product_status
    reasons = []
    measured = _host_events(rows) if rows else None
    forks = None
    if HOST_SAMPLER_INTERVAL_S > HOST_SAMPLER_INTERVAL_MAX_S:
        reasons.append("sampler_interval_cfg")
    if measured is None:
        reasons.append("data_missing")
        drift_s = None
        max_gap_s = None
        max_jump_s = None
        median_s = None
        gap_event_ns = None
        jump_event_ns = None
    else:
        drift_s = measured["drift_s"]
        max_gap_s = measured["max_gap_s"]
        max_jump_s = measured["max_jump_s"]
        median_s = measured["median_s"]
        gap_event_ns = measured["gap_event_ns"]
        jump_event_ns = measured["jump_event_ns"]
        if drift_s > HOST_DRIFT_MAX_S:
            reasons.append("drift")
        if max_gap_s > HOST_GAP_MAX_S:
            reasons.append("gap")
        if max_jump_s > HOST_BOOT_MONO_JUMP_MAX_S:
            reasons.append("boot_mono_jump")
    if median_s is None or median_s > HOST_SAMPLER_INTERVAL_MAX_S:
        reasons.append("sampler_median")
    text = dmesg_text or ""
    if not dmesg_readable or text.strip() == "":
        if "data_missing" not in reasons:
            reasons.append("data_missing")
    elif measured is not None:
        forks = _forks_in_window(text, measured["clocks"])
        if any(item["uncovered"] for item in forks):
            reasons.append("uncovered_fork")
    ordered = [name for name in _REASON_ORDER if name in reasons]
    if forks is None:
        vm_fork = None
        fork_count = None
    else:
        vm_fork = 1 if any(item["uncovered"] for item in forks) else 0
        fork_count = len(forks)
    # seen follows --product-fail-seen only. A UTC string, "-", and an empty value do not set it.
    seen = "yes" if product_fail_seen else "no"
    utc_text = "" if product_fail_utc is None else str(product_fail_utc).strip()
    fail_utc = "-" if utc_text in ("", "-") else utc_text
    event_utc = _utc_from_ns(min(item for item in (gap_event_ns, jump_event_ns) if item is not None)) if any(
        item is not None for item in (gap_event_ns, jump_event_ns)
    ) else "-"
    delta = _fork_fail_delta_s(forks, product_fail_mono_ns) if seen == "yes" else None
    verdict = "invalid" if ordered else "ok"
    reason = ",".join(ordered) if ordered else "-"
    vm_text = "na" if vm_fork is None else str(vm_fork)
    count_text = "na" if fork_count is None else str(fork_count)
    parts = [
        f"host_qualification {verdict}",
        f"drift_s={_fmt_seconds(drift_s)} max={HOST_DRIFT_MAX_S}",
        f"max_gap_s={_fmt_seconds(max_gap_s)} max={HOST_GAP_MAX_S}",
        f"vm_fork={vm_text}",
        f"boot_mono_jump_s={_fmt_seconds(max_jump_s)} max={HOST_BOOT_MONO_JUMP_MAX_S}",
        f"sampler_interval_cfg_s={_fmt_seconds(HOST_SAMPLER_INTERVAL_S)} max={HOST_SAMPLER_INTERVAL_MAX_S}",
        f"sampler_median_s={_fmt_seconds(median_s)} max={HOST_SAMPLER_INTERVAL_MAX_S}",
        f"fork_count={count_text}",
    ]
    for index, fork in enumerate(forks or [], start=1):
        parts.append(f"fork_{index}_mono_s={fork['mono_ns'] / 1e9:.6f}")
        parts.append(f"fork_{index}_gap_s={fork['gap_s']:.3f}")
        parts.append(f"fork_{index}_drift_s={fork['drift_s']:.3f}")
    parts.extend(
        (
            f"reason={reason}",
            f"product_fail_seen {seen}",
            f"product_fail_utc={fail_utc}",
            f"host_event_utc={event_utc}",
            f"fork_fail_delta_s={_fmt_signed(delta)}",
        )
    )
    return " ".join(parts)


def host_pause_exit_code(product_status, line):
    """Keep exit 3, 4, and 5. Replace pass 0 and product FAIL 1 when the guard is invalid."""
    if line.startswith("host_qualification invalid ") and product_status in (0, 1):
        return HOST_INVALID_EXIT
    return product_status


def host_qualification_main(argv):
    ap = argparse.ArgumentParser(prog="host-sampler.py host-qualification")
    ap.add_argument("--samples")
    ap.add_argument("--dmesg")
    ap.add_argument("--dmesg-unreadable", action="store_true")
    ap.add_argument("--product-status", type=int, default=0)
    ap.add_argument("--product-fail-utc", default="")
    ap.add_argument("--product-fail-seen", action="store_true")
    ap.add_argument("--product-fail-mono-ns", default="")
    args = ap.parse_args(argv)
    rows = None
    if args.samples and os.path.isfile(args.samples):
        rows = read_samples(args.samples)
    dmesg_text = ""
    readable = not args.dmesg_unreadable
    if readable:
        if not args.dmesg or not os.path.isfile(args.dmesg):
            readable = False
        else:
            try:
                with open(args.dmesg, encoding="utf-8", errors="replace") as handle:
                    dmesg_text = handle.read()
            except OSError:
                readable = False
    fail_mono = None
    if args.product_fail_mono_ns:
        try:
            fail_mono = int(args.product_fail_mono_ns)
        except ValueError:
            fail_mono = None
    print(
        host_qualification_report(
            rows,
            dmesg_text,
            readable,
            args.product_status,
            args.product_fail_utc,
            product_fail_seen=args.product_fail_seen,
            product_fail_mono_ns=fail_mono,
        )
    )
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "analyze":
        return analyze(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "coverage":
        return coverage_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "acceptance":
        return acceptance_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "host-qualification":
        return host_qualification_main(sys.argv[2:])
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=0.1)
    ap.add_argument("--secs", type=float, default=0)
    ap.add_argument("--cgroup-file")
    ap.add_argument("cgroups", nargs="*")
    args = ap.parse_args()
    cgroups = [tuple(c.split("=", 1)) for c in args.cgroups]
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    start = time.monotonic()
    active = read_cgroup_list(cgroups, args.cgroup_file)
    prev = snapshot(active)
    nxt = time.monotonic()
    with open(args.out, "w", buffering=1) as out:
        out.write(COLUMN_HEADER)
        out.write(CLOCK_NOTES)
        while not stop:
            nxt += args.interval
            delay = nxt - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            active = read_cgroup_list(cgroups, args.cgroup_file)
            cur = snapshot(active)
            ms = lambda a, b: (a - b) / 1000.0
            ticks = lambda a, b: (a - b) * 1000.0 / HZ
            cg_parts = []
            for name, _directory in active:
                before = prev[8].get(name)
                after = cur[8].get(name)
                if before is None or after is None:
                    cg_parts.append(f"{name}:-")
                else:
                    cg_parts.append(f"{name}:{ms(after, before):.1f}")
            cg = " ".join(cg_parts)
            kst, epoch_ms, dt_ms = _wall_fields(cur, prev)
            clocks = format_clock_fields(prev[9], cur[9])
            out.write(
                f"{kst} {epoch_ms} {dt_ms} "
                f"{ticks(cur[1], prev[1]):.0f} {ticks(cur[2], prev[2]):.0f} "
                f"{ms(cur[3], prev[3]):.1f} {ms(cur[4], prev[4]):.1f} {ms(cur[5], prev[5]):.1f} "
                f"{ms(cur[6], prev[6]):.1f} {ms(cur[7], prev[7]):.1f}{' ' + cg if cg else ''} {clocks}\n"
            )
            prev = cur
            if args.secs and time.monotonic() - start >= args.secs:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())

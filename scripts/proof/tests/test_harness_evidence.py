"""Harness evidence for the acceptance soak.

Failure artifacts stay. A missing export is not complete.
Observation qualification stays separate from the product verdict.
"""

import builtins
import importlib.util
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(HERE)
RENEW = os.path.join(PROOF, "ticket-renewal.sh")
SOAK = os.path.join(PROOF, "coord-cert-soak.sh")
_SPEC = importlib.util.spec_from_file_location("host_sampler_evidence", os.path.join(PROOF, "host-sampler.py"))
host_sampler = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(host_sampler)

NS = 1_000_000_000
STEP = 100_000_000


def function_text(path, name):
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(name + "() {"))
    depth = 0
    out = []
    for line in lines[start:]:
        out.append(line)
        structural = line
        previous = None
        while structural != previous:
            previous = structural
            structural = re.sub(r"\$\{[^{}]*\}", "", structural)
        depth += structural.count("{") - structural.count("}")
        if depth == 0:
            return "".join(out)
    raise AssertionError(name)


def run_bash(script):
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def require_associative_arrays(test):
    probe = subprocess.run(
        ["bash", "-c", "declare -A probe=([a]=1)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        test.skipTest("this bash has no associative arrays")


def status_is_complete(path, service):
    """A missing file is not a complete export."""
    if not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8") as handle:
        return f"log_export {service} ok" in handle.read().splitlines()


def sample(realtime, monotonic, boottime, cap=1_000, skew=1_000):
    return {
        "realtime": realtime,
        "monotonic": monotonic,
        "boottime": boottime,
        "capture_skew": skew,
        "capture_monotonic": cap,
        "capture_boottime": cap,
    }


def cadence(start, seconds, step=STEP, drift=0, cap=1_000, skew=1_000):
    count = int(seconds * NS / step) + 1
    rows = []
    for index in range(count):
        rows.append(
            sample(
                start + index * step,
                10 * NS + index * step,
                20 * NS + index * step + drift * index,
                cap=cap,
                skew=skew,
            )
        )
    return rows


def qualify_text(rows, start, end, early_fail=False, require_s=7200, installs=None):
    return "\n".join(
        host_sampler.qualify_observation(
            rows, start, end, early_fail=early_fail, require_s=require_s, installs=installs
        )
    )


def verdict_line(text):
    for line in text.splitlines():
        if line.startswith("qualification_clock no reason") or line.startswith("qualification_clock yes reason"):
            return line
    raise AssertionError(text)


class FailureArtifactTest(unittest.TestCase):
    def test_failure_keeps_ping_and_gap_files(self):
        fn = function_text(RENEW, "persist_run_artifacts")
        script = "set -euo pipefail\n" + fn + r"""
work="$(mktemp -d)"
dest="$(mktemp -d)"
echo ping > "$work/ping-a-b.txt"
echo gap > "$work/big-gaps.txt"
PHASE_PING=1
PHASE_GAPS=1
persist_run_artifacts 1 "$dest" "$work"
test -s "$dest/ping-a-b.txt"
test -s "$dest/big-gaps.txt"
grep -qx 'artifact ping_files kept' "$dest/harness-artifacts.txt"
grep -qx 'artifact big_gaps kept' "$dest/harness-artifacts.txt"
empty="$(mktemp -d)"
PHASE_PING=0
PHASE_GAPS=0
persist_run_artifacts 1 "$empty" "$work"
test ! -e "$empty/ping-a-b.txt"
test ! -e "$empty/big-gaps.txt"
grep -qx 'artifact ping_files not_reached' "$empty/harness-artifacts.txt"
grep -qx 'artifact big_gaps not_reached' "$empty/harness-artifacts.txt"
success="$(mktemp -d)"
persist_run_artifacts 0 "$success" "$work"
test ! -e "$success/ping-a-b.txt"
grep -qx 'artifact ping_files not_reached' "$success/harness-artifacts.txt"
grep -qx 'artifact big_gaps not_reached' "$success/harness-artifacts.txt"
cp() { return 1; }
broken="$(mktemp -d)"
PHASE_PING=1
PHASE_GAPS=1
persist_run_artifacts 1 "$broken" "$work"
grep -qx 'artifact ping_files failed' "$broken/harness-artifacts.txt"
grep -qx 'artifact big_gaps failed' "$broken/harness-artifacts.txt"
! grep -q 'artifact ping_files kept' "$broken/harness-artifacts.txt"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_export_failure_and_missing_status_are_not_complete(self):
        require_associative_arrays(self)
        fn = function_text(RENEW, "export_service_logs") + "\n" + function_text(RENEW, "log_export_status")
        script = "set -euo pipefail\n" + fn + r"""
dc() { return 1; }
dest="$(mktemp -d)"
PHASE_COORD=0
declare -A PHASE_NODE=()
export_service_logs "$dest"
echo "$dest"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        dest = result.stdout.strip().splitlines()[-1]
        status = os.path.join(dest, "log-export-status.txt")
        with open(status, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        self.assertIn("log_export stack.log not_reached", lines)
        self.assertIn("log_export coord not_reached", lines)
        self.assertIn("log_export a not_reached", lines)
        self.assertFalse(os.path.exists(os.path.join(dest, "stack.log")))
        self.assertFalse(os.path.exists(os.path.join(dest, "a.log")))
        self.assertFalse(status_is_complete(status, "stack.log"))
        self.assertFalse(status_is_complete(os.path.join(dest, "missing-status.txt"), "stack.log"))

        failed = "set -euo pipefail\n" + fn + r"""
dc() { return 1; }
dest="$(mktemp -d)"
PHASE_COORD=1
declare -A PHASE_NODE=([owner]=1 [a]=0 [b]=0 [c]=0)
export_service_logs "$dest"
echo "$dest"
"""
        result = run_bash(failed)
        self.assertEqual(result.returncode, 0, result.stderr)
        dest = result.stdout.strip().splitlines()[-1]
        status = os.path.join(dest, "log-export-status.txt")
        with open(status, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        self.assertIn("log_export stack.log failed", lines)
        self.assertIn("log_export coord failed", lines)
        self.assertIn("log_export owner failed", lines)
        self.assertIn("log_export a not_reached", lines)
        self.assertNotIn("log_export stack.log ok", lines)
        self.assertNotIn("log_export owner ok", lines)
        self.assertFalse(status_is_complete(status, "stack.log"))
        self.assertFalse(status_is_complete(status, "a"))

    def test_coord_log_not_reached_is_not_an_empty_file(self):
        fn = function_text(SOAK, "persist_coord_log")
        script = "set -euo pipefail\n" + fn + r"""
dest="$(mktemp -d)"
work="$(mktemp -d)"
TR_OUT_DIR="$dest"
COORD_LOG="$work/coord.log"
COORD_FOLLOW_STARTED=0
persist_coord_log
test ! -e "$dest/coord.log"
grep -qx 'coord_log not_reached' "$dest/coord-log-status.txt"
echo kept > "$COORD_LOG"
COORD_FOLLOW_STARTED=1
persist_coord_log
grep -qx 'coord_log ok' "$dest/coord-log-status.txt"
grep -qx 'kept' "$dest/coord.log"
rm -f "$COORD_LOG"
persist_coord_log
grep -qx 'coord_log failed' "$dest/coord-log-status.txt"
cp() { return 1; }
echo kept > "$COORD_LOG"
persist_coord_log
grep -qx 'coord_log failed' "$dest/coord-log-status.txt"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


class CoverageMarkTest(unittest.TestCase):
    def test_missing_events_keep_the_nominal_schedule(self):
        require_associative_arrays(self)
        fn = function_text(RENEW, "observation_mark_lines")
        script = "set -euo pipefail\n" + fn + r"""
NODES=(a)
declare -A E0=([a]=10000)
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
PLANNED_BOUND_START=10300
PLANNED_BOUND_END=11200
ACTUAL_BOUND_START=10000.125
ACTUAL_BOUND_END=16935.500000000
observation_mark_lines
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("first-renewal-a-sched=9700:9701", lines)
        self.assertIn("missing-event-first-renewal-a=9700:9701", lines)
        self.assertIn("ticket-end-a-sched-1=10000:10001", lines)
        self.assertIn("missing-event-ticket-end-a-sched-1=10000:10001", lines)
        self.assertFalse(any("ticket-end-a-deadline-" in line for line in lines))
        self.assertFalse(any("-actual" in line for line in lines))
        self.assertIn("ticket-end-a-sched-2=10600:10601", lines)
        self.assertIn("missing-event-ticket-end-a-sched-2=10600:10601", lines)
        self.assertIn("missing-event-a-sched-2=10300:10600", lines)
        self.assertIn("missing-event-a-sched-3=10900:11200", lines)
        self.assertIn("planned-bound=10300:11200", lines)
        self.assertIn("actual-bound=10000.125:16935.500000000", lines)
        self.assertNotIn("first-renewal-a=9700:9701", lines)

    def test_first_renewal_and_seen_ticket_end(self):
        require_associative_arrays(self)
        fn = function_text(RENEW, "observation_mark_lines")
        script = "set -euo pipefail\n" + fn + r"""
NODES=(a)
declare -A E0=([a]=10000)
declare -A RENEWS=([a]="10300.5")
declare -A EXPIRIES=([a]="10000")
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
observation_mark_lines
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("first-renewal-a-sched=9700:9701", lines)
        self.assertTrue(any(line.startswith("first-renewal-a=10300.5:") for line in lines))
        self.assertNotIn("missing-event-first-renewal-a=9700:9701", lines)
        self.assertIn("ticket-end-a-deadline-1=10000:10001", lines)
        self.assertNotIn("ticket-end-a-actual-1=10000:10001", lines)
        self.assertFalse(any(line.startswith("ticket-end-") and "-actual-" in line for line in lines))
        self.assertNotIn("missing-event-ticket-end-a-sched-1=10000:10001", lines)
        self.assertNotIn("missing-event-a-sched-2=10300:10600", lines)
        self.assertIn("missing-event-a-sched-3=10900:11200", lines)
        self.assertIn("missing-event-ticket-end-a-sched-2=10600:10601", lines)

    def test_eligible_end_uses_failure_time_or_drops_run_end_padding(self):
        fn = function_text(RENEW, "eligible_end_unix")
        script = "set -euo pipefail\n" + fn + r"""
eligible_end_unix
ELIGIBLE_START=1000.5
RUN_END=10000
SKEW=60
eligible_end_unix
FAIL_AT=1500.25
eligible_end_unix
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["9935.000000000", "1500.25"])

    def test_the_ticket_end_label_is_the_scheduled_deadline(self):
        with open(RENEW, encoding="utf-8") as handle:
            src = handle.read()
        self.assertIn('ticket-end-${name}-deadline-${k}', src)
        self.assertNotIn('ticket-end-${name}-actual-${k}', src)
        self.assertIn("scheduled svid_expiry", src)


class QualificationTest(unittest.TestCase):
    def test_long_interval_can_qualify_without_a_product_verdict(self):
        rows = cadence(0, 7200, cap=1_000)
        text = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"], installs=["a=100"])
        self.assertIn("qualification_clock yes reason eligible_interval", text)
        self.assertNotIn("\nqualification yes", "\n" + text)
        self.assertIn("qualification_sampler_span_limit_ms 200", text)
        self.assertIn("qualification_sampler_span_note not_the_reply_gap_gate", text)
        self.assertIn("qualification_duration_required_s 7200", text)
        self.assertIn("qualification_install_before_expiry a=100 observation_only", text)
        self.assertIn("qualification_install_before_expiry_note not_a_refusal_gate", text)
        self.assertIn("qualification_separate_from_product_verdict yes", text)
        self.assertNotIn("reply_gap_ms", text)
        self.assertNotIn("proof_ok", text)
        self.assertNotIn("INVALID", text)
        self.assertNotIn("proof_infra_abort", text)
        self.assertNotIn("\nFAIL", "\n" + text)

    def test_short_interval_fails_duration_until_the_run_fails_early(self):
        rows = cadence(0, 1.0, cap=1_000)
        full = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"])
        verdict = verdict_line(full)
        self.assertIn("duration_realtime", verdict)
        self.assertIn("duration_monotonic", verdict)
        self.assertIn("duration_boottime", verdict)
        early = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"], early_fail=True)
        self.assertIn("qualification_clock yes reason eligible_interval", early)
        self.assertIn("qualification_window actual_start_to_failure", early)
        self.assertIn("qualification_duration_required_s 0", early)

    def test_edges_span_and_borderline_drift_do_not_qualify(self):
        rows = cadence(1_000 * NS, 0.4, cap=0, skew=0)
        late = qualify_text(rows, rows[0]["realtime"] - 150_000_000, rows[-1]["realtime"], early_fail=True)
        self.assertIn("start_edge", verdict_line(late))
        early_end = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"] + 150_000_000, early_fail=True)
        self.assertIn("end_edge", verdict_line(early_end))
        on_edge = qualify_text(
            rows, rows[0]["realtime"] - 100_000_000, rows[-1]["realtime"] + 100_000_000, early_fail=True
        )
        self.assertIn("qualification_clock yes reason eligible_interval", on_edge)

        wide = cadence(0, 0.4, step=250_000_000, cap=0, skew=0)
        spanned = qualify_text(wide, wide[0]["realtime"], wide[-1]["realtime"], early_fail=True)
        self.assertIn("sampler_span", verdict_line(spanned))
        self.assertIn("qualification_sampler_span_max_ms", spanned)

        exact = cadence(0, 0.2, step=200_000_000, cap=0, skew=0)
        exact_text = qualify_text(exact, exact[0]["realtime"], exact[-1]["realtime"], early_fail=True)
        self.assertIn("qualification_clock yes reason eligible_interval", exact_text)

        border = cadence(0, 0.2, cap=0, skew=0)
        border[1]["boottime"] += 50_000_000
        border_text = qualify_text(border, border[0]["realtime"], border[-1]["realtime"], early_fail=True)
        self.assertIn("drift", verdict_line(border_text))
        self.assertNotIn("qualification_clock yes reason eligible_interval", border_text)

        under = cadence(0, 0.2, cap=0, skew=0)
        under[1]["realtime"] += 49_999_999
        under_text = qualify_text(under, under[0]["realtime"], under[-1]["realtime"], early_fail=True)
        self.assertIn("qualification_clock yes reason eligible_interval", under_text)

    def test_interval_baseline_drift_rejects_a_slow_walk_and_the_50_ms_line(self):
        def walked(clock):
            rows = cadence(0, 0.3, cap=0, skew=0)
            for index, row in enumerate(rows):
                row[clock] += index * 20_000_000
            for prev, cur in zip(rows, rows[1:]):
                neighbour = abs((cur[clock] - prev[clock]) - (cur["monotonic"] - prev["monotonic"]))
                self.assertLess(neighbour, 50_000_000)
            end_drift = abs((rows[-1][clock] - rows[0][clock]) - (rows[-1]["monotonic"] - rows[0]["monotonic"]))
            self.assertGreater(end_drift, 50_000_000)
            text = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"], early_fail=True)
            self.assertIn("drift", verdict_line(text))
            self.assertIn("qualification_drift_baseline first_eligible_sample", text)
            self.assertNotIn("qualification_clock yes reason eligible_interval", text)

        walked("realtime")
        walked("boottime")

        stable = cadence(0, 0.4, cap=0, skew=0)
        stable_text = qualify_text(stable, stable[0]["realtime"], stable[-1]["realtime"], early_fail=True)
        self.assertIn("qualification_clock yes reason eligible_interval", stable_text)

        equal = cadence(0, 0.3, cap=0, skew=0)
        equal[-1]["realtime"] += 50_000_000
        equal_text = qualify_text(equal, equal[0]["realtime"], equal[-1]["realtime"], early_fail=True)
        self.assertIn("drift", verdict_line(equal_text))

        ambiguous = cadence(0, 0.2, cap=0, skew=0)
        ambiguous[1]["capture_monotonic"] = 60_000_000
        ambiguous[1]["capture_boottime"] = 60_000_000
        ambiguous_text = qualify_text(ambiguous, ambiguous[0]["realtime"], ambiguous[-1]["realtime"], early_fail=True)
        self.assertIn("capture", verdict_line(ambiguous_text))
        self.assertNotIn("qualification_clock yes reason eligible_interval", ambiguous_text)

        on_bracket = cadence(0, 0.2, cap=25_000_000, skew=0)
        bracket_text = qualify_text(on_bracket, on_bracket[0]["realtime"], on_bracket[-1]["realtime"], early_fail=True)
        self.assertIn("drift", verdict_line(bracket_text))

    def test_a_small_negative_adjacent_delta_does_not_qualify(self):
        base = 10 * NS
        rows = [
            sample(base, 10 * NS, 20 * NS, cap=0, skew=0),
            sample(base - 1, 10 * NS - 1, 20 * NS - 1, cap=0, skew=0),
            sample(base + STEP, 10 * NS + STEP, 20 * NS + STEP, cap=0, skew=0),
        ]
        text = qualify_text(rows, base - 1, base + STEP, early_fail=True)
        self.assertIn("negative_delta", verdict_line(text))
        self.assertNotIn("qualification_clock yes reason eligible_interval", text)

    def test_ambiguous_capture_and_fractional_bounds(self):
        rows = cadence(0, 0.2, cap=0, skew=0)
        rows[1]["capture_monotonic"] = 60_000_000
        rows[1]["capture_boottime"] = 60_000_000
        text = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"], early_fail=True)
        self.assertIn("capture", verdict_line(text))
        self.assertNotIn("qualification_clock yes reason eligible_interval", text)

        bracket = cadence(0, 0.2, cap=50_000_000, skew=0)
        bracket_text = qualify_text(bracket, bracket[0]["realtime"], bracket[-1]["realtime"], early_fail=True)
        self.assertIn("drift", verdict_line(bracket_text))

        missing = qualify_text(rows, None, None)
        self.assertIn("eligible_interval_not_reached", missing)
        self.assertNotIn("qualification_clock yes reason eligible_interval", missing)

        start_s = "100.15"
        start_ns = int(float(start_s) * NS)
        fractional = [
            sample(start_ns, 10 * NS, 20 * NS, cap=0, skew=0),
            sample(start_ns + STEP, 10 * NS + STEP, 20 * NS + STEP, cap=0, skew=0),
        ]
        parsed = qualify_text(fractional, start_ns, fractional[-1]["realtime"], early_fail=True)
        self.assertIn("qualification_clock yes reason eligible_interval", parsed)
        truncated = qualify_text(fractional, int(float(start_s)) * NS, fractional[-1]["realtime"], early_fail=True)
        self.assertIn("start_edge", verdict_line(truncated))

    def test_samples_before_the_eligible_start_do_not_extend_the_interval(self):
        rows = cadence(0, 10, cap=0, skew=0)
        start = rows[-11]["realtime"]
        end = rows[-1]["realtime"]
        text = qualify_text(rows, start, end, require_s=7200)
        verdict = verdict_line(text)
        self.assertIn("duration_realtime", verdict)
        self.assertNotIn("sampler_span", verdict)

    def test_missing_cgroup_directory_is_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cgroups.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("empty=\nmissing=/no/such/cgroup\n")
            self.assertEqual(
                host_sampler.read_cgroup_list([], path),
                [("empty", ""), ("missing", "/no/such/cgroup")],
            )
            proc = os.path.join(directory, "proc")
            os.makedirs(os.path.join(proc, "pressure"))
            with open(os.path.join(proc, "stat"), "w", encoding="utf-8") as handle:
                handle.write("cpu 0 0 0 0 111 0 0 222 0\n")
            for name, total in (("cpu", 333), ("io", 0), ("memory", 0)):
                with open(os.path.join(proc, "pressure", name), "w", encoding="utf-8") as handle:
                    handle.write(f"some avg10=0.00 avg60=0.00 avg300=0.00 total={total}\n")
                    handle.write("full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
            present = os.path.join(directory, "present-cgroup")
            os.makedirs(present)
            with open(os.path.join(present, "cpu.pressure"), "w", encoding="utf-8") as handle:
                handle.write("some avg10=0.00 avg60=0.00 avg300=0.00 total=444\n")
                handle.write("full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
            opened = []
            real_open = builtins.open

            def tracking_open(file, *args, **kwargs):
                opened.append(os.fspath(file))
                return real_open(file, *args, **kwargs)

            builtins.open = tracking_open
            try:
                shot = host_sampler.snapshot(
                    [("present", present), ("empty", ""), ("missing", os.path.join(directory, "missing-cgroup"))],
                    clock_gettime_ns=lambda _clock: 1,
                    clock_ids={"realtime": 0, "monotonic": 1, "boottime": 2},
                    proc_root=proc,
                )
            finally:
                builtins.open = real_open
        self.assertEqual(shot[1], 222)
        self.assertEqual(shot[2], 111)
        self.assertEqual(shot[3], 333)
        self.assertEqual(shot[8]["present"], 444)
        self.assertIsNone(shot[8]["empty"])
        self.assertIsNone(shot[8]["missing"])
        self.assertIn(os.path.join(proc, "stat"), opened)
        self.assertIn(os.path.join(present, "cpu.pressure"), opened)
        self.assertNotIn("/proc/stat", opened)
        self.assertNotIn("/proc/pressure/cpu", opened)
        self.assertNotIn("cpu.pressure", opened)
        self.assertFalse(any(item.startswith("/sys/fs/cgroup") for item in opened))


class InstallBindingTest(unittest.TestCase):
    def binding_lines(self, prelude):
        require_associative_arrays(self)
        fn = function_text(RENEW, "install_before_expiry_lines")
        script = "set -euo pipefail\n" + fn + "\n" + prelude + "\ninstall_before_expiry_lines\n"
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_initial_on_time_renewal_binds_to_e0(self):
        lines = self.binding_lines("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000")
declare -A RENEWS=([a]="9700")
""")
        self.assertIn("install_binding a renewal 9700 old_expiry 10000 before_expiry yes", lines)
        self.assertIn("a=9700", lines)

    def test_late_renewal_after_e0_does_not_use_e1(self):
        lines = self.binding_lines("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000 10900")
declare -A RENEWS=([a]="10010")
""")
        self.assertIn("install_binding a renewal 10010 old_expiry 10000 before_expiry no", lines)
        self.assertFalse(any("old_expiry 10900" in line for line in lines))
        self.assertFalse(any(line.endswith("before_expiry yes") for line in lines))

    def test_repeated_renewals_bind_in_order(self):
        lines = self.binding_lines("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000 10600 11200")
declare -A RENEWS=([a]="10300 9700")
""")
        self.assertIn("install_binding a renewal 9700 old_expiry 10000 before_expiry yes", lines)
        self.assertIn("install_binding a renewal 10300 old_expiry 10600 before_expiry yes", lines)
        self.assertFalse(any("old_expiry 11200" in line for line in lines))

    def test_missing_old_expiry_is_not_a_later_deadline(self):
        lines = self.binding_lines("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000")
declare -A RENEWS=([a]="9700 10300")
""")
        self.assertIn("install_binding a renewal 9700 old_expiry 10000 before_expiry yes", lines)
        self.assertIn("install_binding a renewal 10300 missing_old_expiry", lines)
        self.assertNotIn("a=10300", lines)

    def test_ambiguous_old_expiry_has_no_positive_binding(self):
        lines = self.binding_lines("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10900 10000")
declare -A RENEWS=([a]="9700")
""")
        self.assertEqual(lines, ["install_binding a ambiguous"])


class AcceptanceQualificationTest(unittest.TestCase):
    def setUp(self):
        self.functions = "\n".join(
            function_text(RENEW, name)
            for name in (
                "install_before_expiry_lines",
                "qualification_event_lines",
                "write_qualification_events",
                "log_export_status",
                "persist_run_artifacts",
            )
        )
        self.coord_fn = function_text(SOAK, "persist_coord_log")

    def run_events(self, prelude):
        require_associative_arrays(self)
        script = "set -euo pipefail\n" + self.functions + "\n" + prelude + "\nqualification_event_lines\n"
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def clock_file(self, dest):
        rows = cadence(9_000 * NS, 0.4, cap=0, skew=0)
        text = qualify_text(rows, rows[0]["realtime"], rows[-1]["realtime"], early_fail=True)
        self.assertIn("qualification_clock yes reason eligible_interval", text)
        with open(os.path.join(dest, "host-coverage.txt"), "w", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def write_ok_exports(self, dest):
        script = "set -euo pipefail\n" + function_text(RENEW, "log_export_status") + f"""
dest={dest!r}
: > "$dest/log-export-status.txt"
for svc in stack.log coord owner a b c; do
  log_export_status "$svc" 1 0 >> "$dest/log-export-status.txt"
done
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def write_ok_artifacts(self, dest):
        script = "set -euo pipefail\n" + function_text(RENEW, "persist_run_artifacts") + f"""
dest={dest!r}
work="$(mktemp -d)"
echo ping > "$work/ping-a-b.txt"
echo gap > "$work/big-gaps.txt"
PHASE_PING=1
PHASE_GAPS=1
persist_run_artifacts 0 "$dest" "$work"
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def write_ok_coord(self, dest):
        script = "set -euo pipefail\n" + self.coord_fn + f"""
dest={dest!r}
work="$(mktemp -d)"
echo coord > "$work/coord.log"
TR_OUT_DIR="$dest"
COORD_LOG="$work/coord.log"
COORD_FOLLOW_STARTED=1
persist_coord_log
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def accept(self, dest):
        result = subprocess.run(
            [
                sys.executable,
                os.path.join(PROOF, "host-sampler.py"),
                "acceptance",
                "--coverage",
                os.path.join(dest, "host-coverage.txt"),
                "--events",
                os.path.join(dest, "qualification-events.txt"),
                "--export-status",
                os.path.join(dest, "log-export-status.txt"),
                "--artifact-status",
                os.path.join(dest, "harness-artifacts.txt"),
                "--coord-status",
                os.path.join(dest, "coord-log-status.txt"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def prepare(self, prelude):
        require_associative_arrays(self)
        dest = tempfile.mkdtemp()
        self.clock_file(dest)
        script = (
            "set -euo pipefail\n"
            + self.functions
            + "\n"
            + prelude
            + f"\nwrite_qualification_events {shlex.quote(dest)}\n"
        )
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.write_ok_exports(dest)
        self.write_ok_artifacts(dest)
        self.write_ok_coord(dest)
        return dest

    def test_missing_renewal_cannot_qualify(self):
        dest = self.prepare("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000")
declare -A RENEWS=()
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
ACTUAL_BOUND_START=9600
ACTUAL_BOUND_END=9800
""")
        verdict = self.accept(dest)
        self.assertNotIn("qualification yes", verdict)
        self.assertIn("renewal", verdict)

    def test_missing_install_cannot_qualify(self):
        dest = self.prepare("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000")
declare -A RENEWS=([a]="9700 10300")
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
ACTUAL_BOUND_START=9600
ACTUAL_BOUND_END=10400
""")
        verdict = self.accept(dest)
        self.assertNotIn("qualification yes", verdict)
        self.assertIn("install", verdict)
        with open(os.path.join(dest, "qualification-events.txt"), encoding="utf-8") as handle:
            events = handle.read()
        self.assertIn("required_renewal a 10300 present", events)
        self.assertIn("required_install a 10300 missing_old_expiry", events)

    def test_failed_or_missing_status_cannot_qualify(self):
        dest = self.prepare("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000")
declare -A RENEWS=([a]="9700")
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
ACTUAL_BOUND_START=9600
ACTUAL_BOUND_END=9800
""")
        self.assertEqual(self.accept(dest), "qualification yes reason complete")
        os.remove(os.path.join(dest, "log-export-status.txt"))
        self.assertNotIn("qualification yes", self.accept(dest))
        lines = [
            "log_export stack.log failed",
            "log_export coord ok",
            "log_export owner ok",
            "log_export a ok",
            "log_export b ok",
            "log_export c ok",
        ]
        with open(os.path.join(dest, "log-export-status.txt"), "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        self.assertNotIn("qualification yes", self.accept(dest))
        self.write_ok_exports(dest)
        os.remove(os.path.join(dest, "harness-artifacts.txt"))
        self.assertNotIn("qualification yes", self.accept(dest))
        with open(os.path.join(dest, "harness-artifacts.txt"), "w", encoding="utf-8") as handle:
            handle.write("artifact ping_files failed\nartifact big_gaps kept\n")
        self.assertNotIn("qualification yes", self.accept(dest))
        self.write_ok_artifacts(dest)
        os.remove(os.path.join(dest, "coord-log-status.txt"))
        self.assertNotIn("qualification yes", self.accept(dest))
        with open(os.path.join(dest, "coord-log-status.txt"), "w", encoding="utf-8") as handle:
            handle.write("coord_log failed\n")
        self.assertNotIn("qualification yes", self.accept(dest))

    def test_an_early_stop_does_not_require_a_future_renewal(self):
        dest = self.prepare("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10000")
declare -A RENEWS=()
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
ACTUAL_BOUND_START=1000
ACTUAL_BOUND_END=2000
""")
        with open(os.path.join(dest, "qualification-events.txt"), encoding="utf-8") as handle:
            events = handle.read()
        self.assertNotIn("required_renewal", events)
        self.assertNotIn("required_install", events)
        self.assertEqual(self.accept(dest), "qualification yes reason complete")

    def test_ambiguous_old_expiry_cannot_qualify(self):
        dest = self.prepare("""
NODES=(a)
declare -A E0=([a]=10000)
declare -A EXPIRIES=([a]="10900 10000")
declare -A RENEWS=([a]="9700")
PERIOD=600
TR_SVID_TTL=900
TR_ENDS=3
ACTUAL_BOUND_START=9600
ACTUAL_BOUND_END=9800
""")
        verdict = self.accept(dest)
        self.assertNotIn("qualification yes", verdict)
        self.assertIn("install", verdict)


if __name__ == "__main__":
    unittest.main()

"""Three-clock host sample coverage.

A large unsampled renewal gap stays not fully observed.
contention unknown_samples does not change that result.
PSI stall time stays distinct from CPU time consumed.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(HERE)
_SPEC = importlib.util.spec_from_file_location("host_sampler", os.path.join(PROOF, "host-sampler.py"))
host_sampler = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(host_sampler)

NS = 1_000_000_000
CADENCE = 100_000_000
RENEW = os.path.join(PROOF, "ticket-renewal.sh")


def at(base, realtime, monotonic, boottime, skew=2000):
    return {
        "realtime": base["realtime"] + realtime,
        "monotonic": base["monotonic"] + monotonic,
        "boottime": base["boottime"] + boottime,
        "capture_skew": skew,
        "capture_monotonic": 2000,
        "capture_boottime": 2000,
    }


class HostClockCoverageTest(unittest.TestCase):
    def setUp(self):
        self.origin = {
            "realtime": 1_700_000_000 * NS,
            "monotonic": 10 * NS,
            "boottime": 12 * NS,
            "capture_skew": 1000,
        }

    def test_a_missing_clock_stays_unsupported(self):
        calls = {"n": 0}

        def clock_gettime_ns(clock_id):
            calls["n"] += 1
            if clock_id == 0:
                return 5000 + calls["n"]
            if clock_id == 1:
                return 50
            raise OSError("missing")

        sample = host_sampler.read_clock_sample(
            clock_gettime_ns,
            {"realtime": 0, "monotonic": 1, "boottime": 7},
        )
        self.assertEqual(sample["realtime"], 5001)
        self.assertEqual(sample["monotonic"], 50)
        self.assertEqual(sample["boottime"], "unsupported")
        self.assertNotEqual(sample["boottime"], sample["realtime"])
        self.assertGreater(sample["capture_skew"], 0)

    def test_normal_cadence_is_fully_observed(self):
        samples = [
            at(self.origin, 0, 0, 0),
            at(self.origin, CADENCE, CADENCE, CADENCE),
            at(self.origin, 2 * CADENCE, 2 * CADENCE, 2 * CADENCE),
        ]
        text = "\n".join(host_sampler.format_coverage(samples, CADENCE, [("owner", samples[0]["realtime"] + 50_000_000, samples[0]["realtime"] + 150_000_000)]))
        self.assertIn("observation_clock_pattern_counts cadence 2", text)
        self.assertIn("observation_mark owner fully_observed yes reason cadence", text)
        self.assertIn("observation_large_spans 0", text)
        self.assertIn("observation_elapsed_realtime_ns " + str(2 * CADENCE), text)

    def test_a_forward_wall_step_is_not_suspend(self):
        samples = [
            at(self.origin, 0, 0, 0),
            at(self.origin, 1304 * NS, CADENCE, CADENCE),
        ]
        pattern, deltas = host_sampler._span(samples[0], samples[1], CADENCE)
        self.assertEqual(pattern, "wall_forward")
        self.assertEqual(deltas["realtime"], 1304 * NS)
        verdict, reason = host_sampler.window_verdict(
            samples,
            samples[0]["realtime"] + 600 * NS,
            samples[0]["realtime"] + 900 * NS,
            CADENCE,
            unknown_samples=0,
        )
        self.assertEqual((verdict, reason), ("no", "wall_forward"))
        self.assertNotIn("hypervisor", pattern)

    def test_a_backward_wall_step_keeps_the_negative_delta(self):
        samples = [
            at(self.origin, 0, 0, 0),
            at(self.origin, -5 * NS, CADENCE, CADENCE),
        ]
        pattern, deltas = host_sampler._span(samples[0], samples[1], CADENCE)
        self.assertEqual(pattern, "wall_backward")
        self.assertEqual(deltas["realtime"], -5 * NS)
        text = "\n".join(host_sampler.format_coverage(samples, CADENCE, []))
        self.assertIn("observation_elapsed_realtime_ns -" + str(5 * NS) + " sign backward", text)
        self.assertIn("observation_negative_realtime_spans 1", text)
        self.assertIn("observation_min_realtime_dt_ns -" + str(5 * NS), text)
        self.assertIn("observation_max_unsampled_realtime_ns none", text)

    def test_a_long_gap_on_every_clock_stays_unresolved(self):
        samples = [
            at(self.origin, 0, 0, 0),
            at(self.origin, 1304 * NS, 1304 * NS, 1304 * NS),
        ]
        pattern, _deltas = host_sampler._span(samples[0], samples[1], CADENCE)
        self.assertEqual(pattern, "unresolved_gap")
        self.assertNotEqual(pattern, "hypervisor_pause")
        verdict, reason = host_sampler.window_verdict(
            samples,
            samples[0]["realtime"] + 600 * NS,
            samples[0]["realtime"] + 900 * NS,
            CADENCE,
            unknown_samples=0,
        )
        self.assertEqual((verdict, reason), ("no", "unresolved_gap"))
        text = "\n".join(host_sampler.format_coverage(samples, CADENCE, []))
        self.assertIn("observation_elapsed_realtime_ns " + str(1304 * NS), text)
        self.assertIn("observation_samples 2", text)
        self.assertIn("observation_clock_pattern_counts unresolved_gap 1", text)

    def test_suspend_shaped_spans_do_not_name_a_hypervisor_pause(self):
        samples = [
            at(self.origin, 0, 0, 0),
            at(self.origin, 1304 * NS, CADENCE, 1304 * NS),
        ]
        pattern, _deltas = host_sampler._span(samples[0], samples[1], CADENCE)
        self.assertEqual(pattern, "suspend_shaped")
        self.assertNotEqual(pattern, "hypervisor_pause")
        self.assertNotEqual(pattern, "wall_forward")

    def test_an_old_realtime_file_does_not_invent_the_other_clocks(self):
        gap_start = 1793912630897
        gap_end = 1793913935132
        expiry = 1793913478
        body = (
            "# kst_time epoch_ms dt_ms steal_ms iowait_ms cpu_some_ms io_some_ms io_full_ms mem_some_ms mem_full_ms cgroup_cpu_some_ms...\n"
            f"06:03:50.897 {gap_start} 100 0 0 1.1 0.0 0.0 0.0 0.0 owner:0.0\n"
            f"06:25:35.131 {gap_end} 1304234 20 0 1013.3 98.6 0.1 115.1 0.6 owner:741.0\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "host-samples.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.join(PROOF, "host-sampler.py"),
                    "coverage",
                    "--samples",
                    path,
                    "--cadence-ms",
                    "100",
                    "--mark",
                    f"owner={expiry}",
                    "--unknown-samples",
                    "0",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(path, encoding="utf-8") as handle:
                saved = handle.read()
        self.assertIn("1304234", saved)
        self.assertIn("observation_elapsed_monotonic_ns unsupported", result.stdout)
        self.assertIn("observation_elapsed_boottime_ns unsupported", result.stdout)
        self.assertIn("observation_mark owner fully_observed no", result.stdout)
        self.assertIn("observation_unknown_samples_ignored 0", result.stdout)
        self.assertIn(
            "contention_unknown_samples_do_not_mean_a_renewal_interval_was_fully_observed",
            result.stdout,
        )
        self.assertNotIn("clk_monotonic_ns:" + str(gap_end), result.stdout)

    def test_pressure_fields_are_not_labeled_as_cpu_time_consumed(self):
        notes = host_sampler.CLOCK_NOTES
        self.assertIn("PSI stall time", notes)
        self.assertIn("not CPU time consumed", notes)
        self.assertIn("cgroup cpu.pressure some stall time", notes)
        self.assertNotIn("CPU time consumed is cgroup_cpu_some_ms", notes)

    def test_the_proof_reports_coverage_without_using_unknown_samples(self):
        with open(RENEW, encoding="utf-8") as handle:
            src = handle.read()
        self.assertIn('cov_args=(coverage --samples "$samples" --cadence-ms 100)', src)
        self.assertIn('"${name}-sched-${k}=${renew}:${expiry}"', src)
        self.assertIn('--bound "${bound_start}:${bound_end}"', src)
        self.assertNotIn("--unknown-samples", src)
        self.assertIn("wait \"$SAMPLER_PID\"", src)
        self.assertIn(
            "observation_note contention_unknown_samples_do_not_mean_a_renewal_interval_was_fully_observed",
            src,
        )
        self.assertNotIn("stop_sampler\nreport_observation\ncheck_refusals", src)
        self.assertLess(
            src.index("stop_sampler\n  report_observation"),
            src.index('echo "=== gate 1: ticket ends crossed ==="'),
        )
        head, tail = src.split('echo "=== [C] start coordinator ==="', 1)
        self.assertIn("--cgroup-file", head)
        self.assertIn("--interval 0.1", head)
        self.assertNotIn("--interval 0.1", tail)
        between = src.split('echo "=== [C] wait for the ping runs to end ==="', 1)[1]
        between = between.split('echo "=== gate 1: ticket ends crossed ==="', 1)[0]
        self.assertNotIn("stop_sampler", between)
        self.assertNotIn("report_observation", between)
        self.assertEqual(src.count("(( crossed >= TR_ENDS ))"), 1)
        self.assertEqual(src.count("e + SKEW < RUN_END"), 1)
        self.assertIn('TR_GAP_MS="${TR_GAP_MS:-200}"', src)

    def test_a_wall_step_during_capture_is_not_fully_observed(self):
        start = at(self.origin, 0, 0, 0)
        end = at(self.origin, CADENCE, CADENCE, CADENCE)
        end["capture_skew"] = 1304 * NS
        samples = [start, end]
        pattern, deltas = host_sampler._span(samples[0], samples[1], CADENCE)
        self.assertEqual(pattern, "capture_wall_step")
        self.assertEqual(deltas["realtime"], CADENCE)
        self.assertEqual(end["capture_skew"], 1304 * NS)
        verdict, reason = host_sampler.window_verdict(
            samples, start["realtime"], end["realtime"], CADENCE, unknown_samples=0
        )
        self.assertEqual((verdict, reason), ("no", "capture_wall_step"))

    def test_a_backward_wall_step_during_capture_stays_raw(self):
        start = at(self.origin, 0, 0, 0)
        end = at(self.origin, CADENCE, CADENCE, CADENCE)
        end["capture_skew"] = -5 * NS
        pattern, _deltas = host_sampler._span(start, end, CADENCE)
        self.assertEqual(pattern, "capture_wall_step")
        self.assertEqual(end["capture_skew"], -5 * NS)
        text = "\n".join(
            host_sampler.format_coverage(
                [start, end],
                CADENCE,
                [("owner-sched-2", start["realtime"], end["realtime"])],
            )
        )
        self.assertIn("observation_mark owner-sched-2 fully_observed no reason capture_wall_step", text)
        self.assertIn("observation_min_capture_skew_ns -" + str(5 * NS), text)

    def test_a_wide_capture_bracket_is_ambiguous(self):
        start = at(self.origin, 0, 0, 0)
        end = at(self.origin, CADENCE, CADENCE, CADENCE)
        end["capture_skew"] = 2 * NS
        end["capture_monotonic"] = 2 * NS
        end["capture_boottime"] = 2 * NS
        pattern, _deltas = host_sampler._span(start, end, CADENCE)
        self.assertEqual(pattern, "capture_ambiguous")
        verdict, reason = host_sampler.window_verdict(
            [start, end], start["realtime"], end["realtime"], CADENCE, unknown_samples=0
        )
        self.assertEqual((verdict, reason), ("no", "capture_ambiguous"))

    def test_missing_edges_and_a_silent_renewal_are_not_fully_observed(self):
        start = at(self.origin, 10 * NS, 10 * NS, 10 * NS)
        end = at(self.origin, 10 * NS + CADENCE, 10 * NS + CADENCE, 10 * NS + CADENCE)
        samples = [start, end]
        window_start = self.origin["realtime"]
        window_end = self.origin["realtime"] + 20 * NS
        leading, leading_reason = host_sampler.window_verdict(
            samples, window_start, start["realtime"], CADENCE, unknown_samples=0
        )
        self.assertEqual((leading, leading_reason), ("no", "leading_unsampled"))
        trailing, trailing_reason = host_sampler.window_verdict(
            samples, start["realtime"], window_end, CADENCE, unknown_samples=0
        )
        self.assertEqual((trailing, trailing_reason), ("no", "trailing_unsampled"))
        silent, silent_reason = host_sampler.window_verdict(
            samples, window_start, window_end, CADENCE, unknown_samples=0
        )
        self.assertEqual(silent, "no")
        self.assertNotEqual(silent_reason, "cadence")
        empty = "\n".join(
            host_sampler.format_coverage([], CADENCE, [("owner-sched-2", window_start, window_end)])
        )
        self.assertIn("observation_mark owner-sched-2 fully_observed no reason no_samples", empty)
        self.assertNotIn("fully_observed yes", empty)
        one = "\n".join(
            host_sampler.format_coverage([start], CADENCE, [("owner-sched-2", window_start, window_end)])
        )
        self.assertIn("fully_observed no reason unbracketed", one)

    def test_unsupported_clocks_and_rollback_are_not_fully_observed(self):
        start = at(self.origin, 0, 0, 0)
        end = at(self.origin, CADENCE, CADENCE, CADENCE)
        end["monotonic"] = "unsupported"
        verdict, reason = host_sampler.window_verdict(
            [start, end], start["realtime"], end["realtime"], CADENCE, unknown_samples=0
        )
        self.assertEqual((verdict, reason), ("no", "clock_unsupported"))
        back = at(self.origin, -5 * NS, CADENCE, CADENCE)
        verdict, reason = host_sampler.window_verdict(
            [start, back],
            back["realtime"],
            start["realtime"],
            CADENCE,
            unknown_samples=0,
        )
        self.assertEqual(verdict, "no")
        self.assertNotEqual(reason, "cadence")


if __name__ == "__main__":
    unittest.main()

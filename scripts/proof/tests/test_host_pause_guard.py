"""W25-47 host-pause guard.

Drift, gap, and boot-minus-mono jump use a fixed 5 s limit. A value of 5 s stays inside that rule.
The configured sampler interval is a fixed 0.1 s constant. It must be at most 1 s.
The median CLOCK_MONOTONIC delta must be at most 1 s. A single gap uses the 5 s rule.
A fork is invalid only when the 5 s before it and the 5 s after it both have no sample.
A sample at exactly 5.0 s counts. A sample farther than 5.0 s does not.
Exit 5 stays the foreign-container abort. This guard uses exit 6. Setup before the sampler uses exit 7.
"""

import importlib.util
import os
import subprocess
import tempfile
import unittest

PROOF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
_SPEC = importlib.util.spec_from_file_location("host_sampler", os.path.join(PROOF, "host-sampler.py"))
host_sampler = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(host_sampler)

BASE_RT = 1_700_000_000_000_000_000
BASE_MONO = 50_000_000_000_000_000
BASE_BOOT = 50_000_000_000_000_000
QUIET_DMESG = "[1.000000] Linux version test\n"


def _ns(seconds):
    return int(round(seconds * 1_000_000_000))


def _line(realtime, monotonic, boottime):
    return (
        f"12:00:00.000 {realtime / 1e6:.0f} 100 0 0 0.0 0.0 0.0 0.0 0.0 "
        f"clk_realtime_ns:{realtime} clk_monotonic_ns:{monotonic} clk_boottime_ns:{boottime}"
    )


def _read(text):
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        return host_sampler.read_samples(path)
    finally:
        os.unlink(path)


def samples(points):
    text = "\n".join(
        _line(BASE_RT + _ns(rt), BASE_MONO + _ns(mono), BASE_BOOT + _ns(boot))
        for rt, mono, boot in points
    )
    return _read(text + "\n")


def rows(rt_s, mono_s, boot_s):
    return samples(((0, 0, 0), (rt_s, mono_s, boot_s)))


def absolute_samples(points):
    text = "\n".join(_line(rt, mono, boot) for rt, mono, boot in points)
    return _read(text + "\n")


def raw_fork_at(mono_ns):
    whole, frac = divmod(mono_ns, 1_000_000_000)
    return f"[{whole}.{frac:09d}] random: crng reseeded due to virtual machine fork\n"


def reason_of(line):
    return line.split("reason=", 1)[1].split()[0]


def report(sample_rows, dmesg, readable=True, status=0, fail_utc="", seen=False, fail_mono=None):
    return host_sampler.host_qualification_report(
        sample_rows,
        dmesg,
        readable,
        status,
        fail_utc,
        product_fail_seen=seen,
        product_fail_mono_ns=fail_mono,
    )


def first_raw_fork_ns(text):
    for line in text.splitlines():
        if "virtual machine fork" not in line:
            continue
        stamp = host_sampler._raw_stamp_ns(line)
        if stamp is not None:
            return stamp
    raise AssertionError("fixture has no raw fork line")


class HostPauseGuardTest(unittest.TestCase):
    def test_ok_with_a_small_observed_interval(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), QUIET_DMESG)
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("drift_s=0.000 max=5", line)
        self.assertIn("max_gap_s=0.100 max=5", line)
        self.assertIn("boot_mono_jump_s=0.000 max=5", line)
        self.assertIn("sampler_interval_cfg_s=0.100 max=1", line)
        self.assertIn("sampler_median_s=0.100 max=1", line)
        self.assertIn("vm_fork=0", line)
        self.assertIn("fork_count=0", line)
        self.assertIn("reason=-", line)
        self.assertIn("product_fail_seen no", line)
        self.assertIn("product_fail_utc=-", line)
        self.assertIn("host_event_utc=-", line)
        self.assertIn("fork_fail_delta_s=-", line)
        self.assertEqual(host_sampler.host_pause_exit_code(0, line), 0)

    def test_exact_5_s_rules_do_not_add_their_reason(self):
        # Two 1.0 s steps. Drift and the boot jump are exactly 5 s. The median is 1.0 s.
        line = report(samples(((0, 0, 0), (1, 1, 1), (7, 2, 7))), QUIET_DMESG)
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("drift_s=5.000 max=5", line)
        self.assertIn("boot_mono_jump_s=5.000 max=5", line)
        self.assertIn("sampler_median_s=1.000 max=1", line)
        self.assertEqual(reason_of(line), "-")

    def test_gap_of_exactly_5_s_stays_ok(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (5.1, 5.1, 5.1), (5.2, 5.2, 5.2))), QUIET_DMESG)
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("max_gap_s=5.000 max=5", line)
        self.assertIn("sampler_median_s=0.100 max=1", line)
        self.assertEqual(reason_of(line), "-")

    def test_one_4_9_s_gap_among_0_1_s_samples_stays_ok(self):
        line = report(
            samples(((0, 0, 0), (0.1, 0.1, 0.1), (5.0, 5.0, 5.0), (5.1, 5.1, 5.1))),
            QUIET_DMESG,
        )
        self.assertTrue(line.startswith("host_qualification ok "), line)
        self.assertIn("max_gap_s=4.900 max=5", line)
        self.assertIn("sampler_median_s=0.100 max=1", line)
        self.assertEqual(reason_of(line), "-")

    def test_one_5_1_s_gap_among_0_1_s_samples_is_a_gap_only(self):
        line = report(
            samples(((0, 0, 0), (0.1, 0.1, 0.1), (5.2, 5.2, 5.2), (5.3, 5.3, 5.3))),
            QUIET_DMESG,
        )
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("max_gap_s=5.100 max=5", line)
        self.assertIn("sampler_median_s=0.100 max=1", line)
        self.assertEqual(reason_of(line), "gap")
        self.assertNotIn("sampler_median", reason_of(line))

    def test_drift_above_5_s(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (5.201, 0.2, 0.2))), QUIET_DMESG)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("drift_s=5.001 max=5", line)
        self.assertEqual(reason_of(line), "drift")
        self.assertIn("host_event_utc=-", line)
        self.assertEqual(host_sampler.host_pause_exit_code(0, line), 6)

    def test_monotonic_gap_above_5_s(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (5.201, 5.201, 5.201), (5.301, 5.301, 5.301))), QUIET_DMESG)
        self.assertIn("max_gap_s=5.101 max=5", line)
        self.assertEqual(reason_of(line), "gap")
        self.assertIn("drift_s=0.000 max=5", line)
        self.assertIn("boot_mono_jump_s=0.000 max=5", line)
        self.assertIn("sampler_median_s=0.100 max=1", line)
        self.assertIn(f"host_event_utc={host_sampler._utc_from_ns(BASE_RT + _ns(0.1))}", line)
        self.assertEqual(host_sampler.host_pause_exit_code(0, line), 6)

    def test_median_delta_above_1_s(self):
        line = report(samples(((0, 0, 0), (1.2, 1.2, 1.2), (2.4, 2.4, 2.4))), QUIET_DMESG)
        self.assertIn("sampler_median_s=1.200 max=1", line)
        self.assertEqual(reason_of(line), "sampler_median")
        self.assertNotIn("gap", reason_of(line))
        self.assertEqual(host_sampler.HOST_SAMPLER_INTERVAL_S, 0.1)
        self.assertEqual(host_sampler.HOST_SAMPLER_INTERVAL_MAX_S, 1)

    def test_configured_interval_above_1_s(self):
        original = host_sampler.HOST_SAMPLER_INTERVAL_S
        host_sampler.HOST_SAMPLER_INTERVAL_S = 1.5
        try:
            line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), QUIET_DMESG)
        finally:
            host_sampler.HOST_SAMPLER_INTERVAL_S = original
        self.assertIn("sampler_interval_cfg_s=1.500 max=1", line)
        self.assertEqual(reason_of(line), "sampler_interval_cfg")

    def test_too_few_deltas_are_sampler_median(self):
        one_delta = report(rows(0.1, 0.1, 0.1), QUIET_DMESG)
        self.assertEqual(reason_of(one_delta), "sampler_median")
        self.assertIn("sampler_median_s=na max=1", one_delta)
        missing = report([], QUIET_DMESG)
        self.assertEqual(reason_of(missing), "data_missing,sampler_median")

    def test_covered_fork_stays_ok(self):
        fork_ns = BASE_MONO + _ns(0.1)
        line = report(samples(((0, 0, 0), (0.2, 0.2, 0.2), (0.3, 0.3, 0.3))), raw_fork_at(fork_ns))
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("vm_fork=0", line)
        self.assertIn("fork_count=1", line)
        self.assertIn(f"fork_1_mono_s={fork_ns / 1e9:.6f}", line)
        self.assertIn("fork_1_gap_s=0.200", line)
        self.assertIn("fork_1_drift_s=0.000", line)
        self.assertNotIn("uncovered_fork", reason_of(line))
        self.assertEqual(line.count("\n"), 0)

    def test_uncovered_fork_is_invalid(self):
        fork_ns = BASE_MONO + _ns(6)
        line = report(samples(((0, 0, 0), (12, 12, 12))), raw_fork_at(fork_ns))
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("vm_fork=1", line)
        self.assertIn("fork_count=1", line)
        self.assertIn("fork_1_gap_s=12.000", line)
        self.assertIn("uncovered_fork", reason_of(line))

    def test_fork_at_exactly_5_s_counts_as_coverage(self):
        # Inclusive. The sample 5.0 s before the fork covers that side.
        # The sample 5.1 s after the fork does not cover the after side.
        # One covered side is enough. The fork is not uncovered.
        # The 10.1 s spacing is still a gap and an interval failure.
        fork_ns = BASE_MONO + _ns(5)
        line = report(samples(((0, 0, 0), (10.1, 10.1, 10.1))), raw_fork_at(fork_ns))
        self.assertNotIn("uncovered_fork", reason_of(line))
        self.assertIn("vm_fork=0", line)
        self.assertEqual(reason_of(line), "gap,sampler_median")
        outside = report(samples(((0, 0, 0), (10.002, 10.002, 10.002))), raw_fork_at(BASE_MONO + _ns(5.001)))
        self.assertIn("uncovered_fork", reason_of(outside))

    def test_raw_fork_outside_the_window_stays_clear(self):
        fork_ns = BASE_MONO - _ns(1000)
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), raw_fork_at(fork_ns))
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("vm_fork=0", line)
        self.assertIn("fork_count=0", line)

    def test_old_fork_plus_a_wall_step_is_not_in_the_window(self):
        fork_ns = BASE_MONO - _ns(1000)
        line = report(samples(((0, 0, 0), (20.1, 0.1, 0.1), (20.2, 0.2, 0.2))), raw_fork_at(fork_ns))
        self.assertEqual(reason_of(line), "drift")
        self.assertIn("fork_count=0", line)
        self.assertIn("vm_fork=0", line)
        self.assertNotIn("uncovered_fork", reason_of(line))

    def test_padded_fork_stamp_inside_the_window_is_counted(self):
        text = "[   12.345678] random: crng reseeded due to virtual machine fork\n"
        stamp = host_sampler._raw_stamp_ns(text.strip())
        self.assertEqual(stamp, 12_345_678_000)
        step = 100_000_000
        covered = absolute_samples(
            (
                (BASE_RT, stamp - step, stamp - step),
                (BASE_RT + 2 * step, stamp + step, stamp + step),
                (BASE_RT + 3 * step, stamp + 2 * step, stamp + 2 * step),
            )
        )
        line = report(covered, text)
        self.assertTrue(line.startswith("host_qualification ok "), line)
        self.assertIn("fork_count=1", line)
        self.assertIn("vm_fork=0", line)
        self.assertIn("fork_1_mono_s=12.345678", line)
        wide = absolute_samples(
            (
                (BASE_RT, stamp - 6_000_000_000, stamp - 6_000_000_000),
                (BASE_RT + 500_000_000, stamp - 5_500_000_000, stamp - 5_500_000_000),
                (BASE_RT + 12_000_000_000, stamp + 6_000_000_000, stamp + 6_000_000_000),
            )
        )
        uncovered = report(wide, text)
        self.assertIn("fork_count=1", uncovered)
        self.assertIn("uncovered_fork", reason_of(uncovered))

    def test_unparseable_fork_line_is_data_missing(self):
        text = "2026-11-09T08:03:39,800899+09:00 random: crng reseeded due to virtual machine fork\n"
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), text)
        self.assertTrue(line.startswith("host_qualification invalid "), line)
        self.assertIn("data_missing", reason_of(line))
        with open(os.path.join(FIXTURES, "fork-lines-iso.txt"), encoding="utf-8") as handle:
            fixture = handle.read()
        fixture_line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), fixture)
        self.assertTrue(fixture_line.startswith("host_qualification invalid "), fixture_line)
        self.assertEqual(reason_of(fixture_line), "data_missing")

    def test_real_box_raw_with_covering_samples_is_ok(self):
        with open(os.path.join(FIXTURES, "box-dmesg-raw.txt"), encoding="utf-8") as handle:
            text = handle.read()
        stamp = first_raw_fork_ns(text)
        step = 100_000_000
        covered = absolute_samples(
            (
                (BASE_RT, stamp - step, stamp - step),
                (BASE_RT + 2 * step, stamp + step, stamp + step),
                (BASE_RT + 3 * step, stamp + 2 * step, stamp + 2 * step),
            )
        )
        line = report(covered, text)
        self.assertTrue(line.startswith("host_qualification ok "), line)
        self.assertIn("fork_count=1", line)
        self.assertIn("vm_fork=0", line)
        self.assertIn(f"fork_1_mono_s={stamp / 1e9:.6f}", line)
        self.assertIn("fork_1_gap_s=0.200", line)
        self.assertIn("fork_1_drift_s=0.000", line)
        self.assertNotIn("uncovered_fork", reason_of(line))

    def test_real_box_v2_gaps_keep_the_median_and_the_covered_fork(self):
        # 0.1 s rows, one 8.648 s gap, one 11.710 s gap, and a 5.001 s wall step.
        # The real fork sits in the first small steps, so both sides have a sample.
        with open(os.path.join(FIXTURES, "box-dmesg-raw.txt"), encoding="utf-8") as handle:
            text = handle.read()
        stamp = first_raw_fork_ns(text)
        small = 100_000_000
        gaps = [small] * 8 + [8_648_000_000] + [small] * 8 + [11_710_000_000] + [small] * 8
        mono = stamp - 1_000_000_000
        realtime = BASE_RT
        points = [(realtime, mono, mono)]
        for index, gap in enumerate(gaps):
            mono += gap
            realtime += gap
            if index == len(gaps) - 1:
                realtime += 5_001_000_000
            points.append((realtime, mono, mono))
        line = report(absolute_samples(points), text)
        self.assertTrue(line.startswith("host_qualification invalid "), line)
        self.assertEqual(reason_of(line), "drift,gap")
        self.assertIn("drift_s=5.001 max=5", line)
        self.assertIn("max_gap_s=11.710 max=5", line)
        self.assertIn("sampler_interval_cfg_s=0.100 max=1", line)
        self.assertIn("sampler_median_s=0.100 max=1", line)
        self.assertIn("vm_fork=0", line)
        self.assertIn("fork_count=1", line)
        self.assertNotIn("sampler_median", reason_of(line))
        self.assertNotIn("uncovered_fork", reason_of(line))

    def test_real_raw_forks_outside_the_sampler_window_stay_clear(self):
        with open(os.path.join(FIXTURES, "fork-lines-raw.txt"), encoding="utf-8") as handle:
            text = handle.read()
        line = report(
            absolute_samples(
                (
                    (BASE_RT, 1_000_000_000, 1_000_000_000),
                    (BASE_RT + 100_000_000, 1_100_000_000, 1_100_000_000),
                    (BASE_RT + 200_000_000, 1_200_000_000, 1_200_000_000),
                )
            ),
            text,
        )
        self.assertTrue(line.startswith("host_qualification ok "), line)
        self.assertIn("fork_count=0", line)
        self.assertIn("vm_fork=0", line)

    def test_boot_mono_jump_above_5_s(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 5.201))), QUIET_DMESG)
        self.assertIn("boot_mono_jump_s=5.001 max=5", line)
        self.assertEqual(reason_of(line), "boot_mono_jump")
        self.assertIn("drift_s=0.000 max=5", line)
        self.assertIn("max_gap_s=0.100 max=5", line)
        self.assertIn(f"host_event_utc={host_sampler._utc_from_ns(BASE_RT + _ns(0.1))}", line)

    def test_missing_samples_are_invalid(self):
        line = report([], QUIET_DMESG, readable=True)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("drift_s=na max=5", line)
        self.assertIn("max_gap_s=na max=5", line)
        self.assertIn("vm_fork=na", line)
        self.assertIn("fork_count=na", line)
        self.assertIn("sampler_interval_cfg_s=0.100 max=1", line)
        self.assertIn("sampler_median_s=na max=1", line)
        self.assertIn("boot_mono_jump_s=na max=5", line)
        self.assertEqual(reason_of(line), "data_missing,sampler_median")

    def test_empty_dmesg_is_invalid(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), "")
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertEqual(reason_of(line), "data_missing")
        self.assertIn("vm_fork=na", line)
        self.assertIn("drift_s=0.000 max=5", line)

    def test_unreadable_dmesg_is_invalid(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), "", readable=False)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertEqual(reason_of(line), "data_missing")
        self.assertIn("vm_fork=na", line)
        self.assertIn("drift_s=0.000 max=5", line)

    def test_status_1_without_a_fail_line_is_not_a_product_fail(self):
        line = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), QUIET_DMESG, status=1)
        self.assertIn("product_fail_seen no", line)
        self.assertIn("product_fail_utc=-", line)
        self.assertEqual(host_sampler.host_pause_exit_code(1, line), 1)

    def test_product_fail_and_host_invalid_keep_both_times(self):
        fail_utc = "2026-11-09T05:00:00.000Z"
        line = report(rows(5.001, 5.001, 5.001), QUIET_DMESG, status=1, fail_utc=fail_utc, seen=True)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("gap", reason_of(line))
        self.assertIn("product_fail_seen yes", line)
        self.assertIn(f"product_fail_utc={fail_utc}", line)
        self.assertIn(f"host_event_utc={host_sampler._utc_from_ns(BASE_RT)}", line)
        self.assertEqual(host_sampler.host_pause_exit_code(1, line), 6)
        self.assertEqual(line.count("\n"), 0)

    def test_qualified_fail_after_a_covered_fork_stays_fail(self):
        fork_ns = BASE_MONO + _ns(0.1)
        fail_utc = "2026-11-09T05:00:30.000Z"
        line = report(
            samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))),
            raw_fork_at(fork_ns),
            status=1,
            fail_utc=fail_utc,
            seen=True,
            fail_mono=fork_ns + _ns(30),
        )
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("fork_fail_delta_s=+30.000", line)
        self.assertIn("product_fail_seen yes", line)
        self.assertEqual(host_sampler.host_pause_exit_code(1, line), 1)
        earlier = report(
            samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))),
            raw_fork_at(fork_ns),
            status=1,
            fail_utc=fail_utc,
            seen=True,
            fail_mono=fork_ns - _ns(10),
        )
        self.assertIn("fork_fail_delta_s=-10.000", earlier)
        self.assertEqual(host_sampler.host_pause_exit_code(1, earlier), 1)

    def test_exit_code_keeps_other_statuses(self):
        invalid = report(rows(5.001, 5.001, 5.001), QUIET_DMESG)
        ok = report(samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))), QUIET_DMESG)
        self.assertEqual(host_sampler.host_pause_exit_code(1, ok), 1)
        self.assertEqual(host_sampler.host_pause_exit_code(3, invalid), 3)
        self.assertEqual(host_sampler.host_pause_exit_code(4, invalid), 4)
        self.assertEqual(host_sampler.host_pause_exit_code(5, invalid), 5)
        self.assertEqual(host_sampler.host_pause_exit_code(7, invalid), 7)
        self.assertEqual(host_sampler.HOST_INVALID_EXIT, 6)

    def test_cli_prints_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples_path = os.path.join(tmp, "samples.txt")
            dmesg = os.path.join(tmp, "dmesg.txt")
            empty = os.path.join(tmp, "empty.txt")
            with open(samples_path, "w", encoding="utf-8") as handle:
                handle.write(_line(BASE_RT, BASE_MONO, BASE_BOOT) + "\n")
                handle.write(_line(BASE_RT + _ns(0.1), BASE_MONO + _ns(0.1), BASE_BOOT + _ns(0.1)) + "\n")
                handle.write(_line(BASE_RT + _ns(0.2), BASE_MONO + _ns(0.2), BASE_BOOT + _ns(0.2)) + "\n")
            with open(dmesg, "w", encoding="utf-8") as handle:
                handle.write(QUIET_DMESG)
            with open(empty, "w", encoding="utf-8") as handle:
                handle.write("")
            result = subprocess.run(
                [
                    "python3",
                    os.path.join(PROOF, "host-sampler.py"),
                    "host-qualification",
                    "--samples",
                    samples_path,
                    "--dmesg",
                    dmesg,
                    "--product-status",
                    "0",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            empty_result = subprocess.run(
                [
                    "python3",
                    os.path.join(PROOF, "host-sampler.py"),
                    "host-qualification",
                    "--samples",
                    samples_path,
                    "--dmesg",
                    empty,
                    "--product-status",
                    "1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertTrue(result.stdout.startswith("host_qualification ok "))
        self.assertTrue(empty_result.stdout.startswith("host_qualification invalid "))
        self.assertIn("reason=data_missing", empty_result.stdout)
        self.assertIn("product_fail_seen no", empty_result.stdout)

    def _qualification_cli(self, extra):
        with tempfile.TemporaryDirectory() as tmp:
            samples_path = os.path.join(tmp, "samples.txt")
            dmesg = os.path.join(tmp, "dmesg.txt")
            fork_ns = BASE_MONO + _ns(0.1)
            with open(samples_path, "w", encoding="utf-8") as handle:
                handle.write(_line(BASE_RT, BASE_MONO, BASE_BOOT) + "\n")
                handle.write(_line(BASE_RT + _ns(0.1), BASE_MONO + _ns(0.1), BASE_BOOT + _ns(0.1)) + "\n")
                handle.write(_line(BASE_RT + _ns(0.2), BASE_MONO + _ns(0.2), BASE_BOOT + _ns(0.2)) + "\n")
            with open(dmesg, "w", encoding="utf-8") as handle:
                handle.write(raw_fork_at(fork_ns))
            result = subprocess.run(
                [
                    "python3",
                    os.path.join(PROOF, "host-sampler.py"),
                    "host-qualification",
                    *extra,
                    "--samples",
                    samples_path,
                    "--dmesg",
                    dmesg,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        return result.stdout.strip(), fork_ns

    def test_cli_status_0_with_a_dash_utc_is_not_a_product_fail(self):
        # The old harness always passed --product-fail-utc -. That dash must not set seen.
        line, _fork_ns = self._qualification_cli(["--product-status", "0", "--product-fail-utc", "-"])
        self.assertIn("product_fail_seen no", line)
        self.assertIn("product_fail_utc=-", line)
        self.assertIn("fork_fail_delta_s=-", line)
        harness, _fork_ns = self._qualification_cli(["--product-status", "0"])
        self.assertIn("product_fail_seen no", harness)
        self.assertIn("product_fail_utc=-", harness)
        self.assertIn("fork_fail_delta_s=-", harness)

    def test_cli_status_1_without_a_fail_line_is_not_a_product_fail(self):
        line, _fork_ns = self._qualification_cli(["--product-status", "1", "--product-fail-utc", "-"])
        self.assertIn("product_fail_seen no", line)
        self.assertIn("fork_fail_delta_s=-", line)
        harness, _fork_ns = self._qualification_cli(["--product-status", "1"])
        self.assertIn("product_fail_seen no", harness)

    def test_cli_real_fail_line_prints_the_delta(self):
        fail_utc = "2026-11-09T05:00:30.000Z"
        preview, fork_ns = self._qualification_cli(["--product-status", "0"])
        del preview
        line, fork_ns = self._qualification_cli(
            [
                "--product-status",
                "1",
                "--product-fail-seen",
                "--product-fail-utc",
                fail_utc,
                "--product-fail-mono-ns",
                str(fork_ns + _ns(30)),
            ]
        )
        self.assertIn("product_fail_seen yes", line)
        self.assertIn(f"product_fail_utc={fail_utc}", line)
        self.assertIn("fork_fail_delta_s=+30.000", line)

    def test_dash_utc_does_not_set_seen_or_the_delta(self):
        fork_ns = BASE_MONO + _ns(0.1)
        line = report(
            samples(((0, 0, 0), (0.1, 0.1, 0.1), (0.2, 0.2, 0.2))),
            raw_fork_at(fork_ns),
            status=0,
            fail_utc="-",
            seen=False,
            fail_mono=fork_ns + _ns(30),
        )
        self.assertIn("product_fail_seen no", line)
        self.assertIn("product_fail_utc=-", line)
        self.assertIn("fork_fail_delta_s=-", line)

    def test_host_pause_print_status_0_says_seen_no(self):
        renewal_path = os.path.join(PROOF, "ticket-renewal.sh")
        with open(renewal_path, encoding="utf-8") as handle:
            text = handle.read()
        start = text.index("host_pause_print() {")
        depth = 0
        end = start
        for index, char in enumerate(text[start:], start):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        body = text[start:end]
        repo = os.path.dirname(os.path.dirname(PROOF))
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            outd = os.path.join(tmp, "out")
            os.makedirs(bindir)
            os.makedirs(outd)
            with open(os.path.join(bindir, "dmesg"), "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nprintf '%s\\n' '[1.000000] Linux version test'\n")
            os.chmod(os.path.join(bindir, "dmesg"), 0o755)
            with open(os.path.join(outd, "host-samples.txt"), "w", encoding="utf-8") as handle:
                handle.write(_line(BASE_RT, BASE_MONO, BASE_BOOT) + "\n")
                handle.write(_line(BASE_RT + _ns(0.1), BASE_MONO + _ns(0.1), BASE_BOOT + _ns(0.1)) + "\n")
                handle.write(_line(BASE_RT + _ns(0.2), BASE_MONO + _ns(0.2), BASE_BOOT + _ns(0.2)) + "\n")
            script = (
                "set -euo pipefail\n"
                + body
                + "\n"
                + f'ROOT="{repo}"\n'
                + f'OUTD="{outd}"\n'
                + f'PATH="{bindir}:$PATH"\n'
                + "SAMPLER_STARTED=1\n"
                + "PRODUCT_FAIL_UTC=\n"
                + "PRODUCT_FAIL_MONO_NS=\n"
                + "HOST_PAUSE_EXIT=\n"
                + "host_pause_print 0\n"
            )
            result = subprocess.run(["bash", "-c", script], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("host_qualification ok "), result.stdout)
        self.assertIn("product_fail_seen no", result.stdout)
        self.assertIn("product_fail_utc=-", result.stdout)
        self.assertIn("fork_fail_delta_s=-", result.stdout)
        self.assertNotIn("product_fail_seen yes", result.stdout)

    def test_scripts_use_exit_6_and_keep_product_fail_text(self):
        with open(os.path.join(PROOF, "ticket-renewal.sh"), encoding="utf-8") as handle:
            renewal = handle.read()
        with open(os.path.join(PROOF, "coord-cert-soak.sh"), encoding="utf-8") as handle:
            soak = handle.read()
        with open(os.path.join(PROOF, "proof-lock.sh"), encoding="utf-8") as handle:
            lock = handle.read()
        self.assertIn("HOST_PAUSE_EXIT=6", renewal)
        self.assertIn("exit 6", renewal)
        self.assertIn("exit 7", renewal)
        self.assertIn("SETUP_EXIT=7", renewal)
        self.assertIn("SAMPLER_STARTED=1", renewal)
        self.assertIn("--time-format=raw", renewal)
        self.assertNotIn("time-format=iso", renewal)
        self.assertIn("set +e", renewal)
        self.assertIn('echo "FAIL: $*" >&2', renewal)
        self.assertIn("PRODUCT_FAIL_UTC=", renewal)
        self.assertIn("PRODUCT_FAIL_MONO_NS=", renewal)
        self.assertIn('args+=(--product-fail-seen --product-fail-utc "$utc")', renewal)
        self.assertNotIn('if [[ "$status" -eq 1 || -n "${PRODUCT_FAIL_UTC:-}" ]]; then', renewal)
        self.assertIn("soak_final_status", soak)
        self.assertIn('exit "$final"', soak)
        self.assertIn("exit 6", soak)
        self.assertNotIn("(( tr_status == 0 )) || fail", soak)
        self.assertNotIn('if [[ "$tr_status" -eq 6 ]]; then', soak)
        self.assertIn('gate_fail "ticket-renewal.sh failed (exit 1)."', soak)
        self.assertIn("PROOF_FOREIGN_ABORT_EXIT=5", lock)
        with open(os.path.join(PROOF, "host-sampler.py"), encoding="utf-8") as handle:
            sampler = handle.read()
        self.assertNotIn("os.environ", sampler)
        self.assertIn("HOST_SAMPLER_INTERVAL_S = 0.1", sampler)
        self.assertIn("HOST_SAMPLER_INTERVAL_MAX_S = 1", sampler)
        sampler_start = renewal.index('python3 "$ROOT/scripts/proof/host-sampler.py"')
        sampler_cmd = renewal[sampler_start:renewal.index("SAMPLER_PID", sampler_start)]
        self.assertNotIn("--interval", sampler_cmd)
        self.assertIn("default=HOST_SAMPLER_INTERVAL_S", sampler)
        self.assertNotIn("sampler_interval_s=", renewal)
        self.assertNotIn("sampler_interval_s=", soak)

    def test_soak_final_status_passes_child_codes(self):
        with open(os.path.join(PROOF, "coord-cert-soak.sh"), encoding="utf-8") as handle:
            text = handle.read()
        start = text.index("soak_final_status()")
        end = text.index("\n}\n", start)
        body = text[start:end + 2]
        script = body + """
for pair in 0:0:0 0:1:1 1:0:1 1:1:1 3:0:3 3:1:3 4:1:4 5:0:5 6:1:6 7:1:7; do
  IFS=: read -r tr gate want <<<"$pair"
  got="$(soak_final_status "$tr" "$gate")"
  test "$got" = "$want"
done
"""
        result = subprocess.run(["bash", "-c", script], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

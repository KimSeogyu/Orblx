"""W25-47 host-pause guard.

The limits are fixed at 5 s. A value above 5 s is invalid. A value of 5 s stays valid.
Exit 5 stays the foreign-container abort. This guard uses exit 6.
"""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from datetime import timezone

PROOF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SPEC = importlib.util.spec_from_file_location("host_sampler", os.path.join(PROOF, "host-sampler.py"))
host_sampler = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(host_sampler)

BASE_RT = 1_700_000_000_000_000_000
BASE_MONO = 50_000_000_000_000_000
BASE_BOOT = 50_000_000_000_000_000
UTC = timezone.utc


def _ns(seconds):
    return int(round(seconds * 1_000_000_000))


def _line(realtime, monotonic, boottime):
    return (
        f"12:00:00.000 {realtime / 1e6:.0f} 100 0 0 0.0 0.0 0.0 0.0 0.0 "
        f"clk_realtime_ns:{realtime} clk_monotonic_ns:{monotonic} clk_boottime_ns:{boottime}"
    )


def _read(text):
    rows = []
    # read_samples reads a path. Keep the fixture path local to this helper.
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        return host_sampler.read_samples(path)
    finally:
        os.unlink(path)


def rows(rt_s, mono_s, boot_s):
    text = "\n".join(
        (
            _line(BASE_RT, BASE_MONO, BASE_BOOT),
            _line(BASE_RT + _ns(rt_s), BASE_MONO + _ns(mono_s), BASE_BOOT + _ns(boot_s)),
        )
    )
    return _read(text)


def report(sample_rows, dmesg, readable=True, status=0, fail_utc=""):
    return host_sampler.host_qualification_report(
        sample_rows, dmesg, readable, status, fail_utc, local_tz=UTC
    )


class HostPauseGuardTest(unittest.TestCase):
    def test_ok_just_under_each_limit(self):
        # Drift, monotonic gap, and boot-minus-mono jump are each 4.999 s.
        line = report(rows(9.998, 4.999, 9.998), "")
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("drift_s=4.999 max=5", line)
        self.assertIn("max_gap_s=4.999 max=5", line)
        self.assertIn("boot_mono_jump_s=4.999 max=5", line)
        self.assertIn("vm_fork=0", line)
        self.assertIn("reason=-", line)
        self.assertIn("product_fail_seen no", line)
        self.assertIn("product_fail_utc=-", line)
        self.assertIn("host_event_utc=-", line)
        self.assertEqual(host_sampler.host_pause_exit_code(0, line), 0)

    def test_exact_limit_stays_ok(self):
        line = report(rows(10.0, 5.0, 10.0), "")
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("drift_s=5.000 max=5", line)
        self.assertIn("max_gap_s=5.000 max=5", line)
        self.assertIn("boot_mono_jump_s=5.000 max=5", line)

    def test_drift_above_5_s(self):
        line = report(rows(5.101, 0.1, 0.1), "")
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("drift_s=5.001 max=5", line)
        self.assertIn("reason=drift", line)
        self.assertNotIn("gap", line.split("reason=", 1)[1].split()[0])
        self.assertIn("host_event_utc=-", line)
        self.assertEqual(host_sampler.host_pause_exit_code(0, line), 6)

    def test_monotonic_gap_above_5_s(self):
        line = report(rows(5.001, 5.001, 5.001), "")
        self.assertIn("max_gap_s=5.001 max=5", line)
        self.assertIn("reason=gap", line)
        self.assertIn("drift_s=0.000 max=5", line)
        self.assertIn("boot_mono_jump_s=0.000 max=5", line)
        self.assertIn(f"host_event_utc={host_sampler._utc_from_ns(BASE_RT)}", line)
        self.assertEqual(host_sampler.host_pause_exit_code(0, line), 6)

    def test_vm_fork_inside_the_window(self):
        fork = "[2023-11-14T22:13:20.050Z] random: crng reseeded due to virtual machine fork"
        line = report(rows(0.1, 0.1, 0.1), fork)
        self.assertIn("vm_fork=1", line)
        self.assertIn("reason=vm_fork", line)
        self.assertIn("host_event_utc=2023-11-14T22:13:20.050Z", line)
        self.assertTrue(line.startswith("host_qualification invalid "))

    def test_vm_fork_outside_the_window_stays_clear(self):
        fork = "[2020-01-01T00:00:00Z] random: crng reseeded due to virtual machine fork"
        line = report(rows(0.1, 0.1, 0.1), fork)
        self.assertTrue(line.startswith("host_qualification ok "))
        self.assertIn("vm_fork=0", line)

    def test_boot_mono_jump_above_5_s(self):
        line = report(rows(0.1, 0.1, 5.101), "")
        self.assertIn("boot_mono_jump_s=5.001 max=5", line)
        self.assertIn("reason=boot_mono_jump", line)
        self.assertIn("drift_s=0.000 max=5", line)
        self.assertIn("max_gap_s=0.100 max=5", line)
        self.assertIn(f"host_event_utc={host_sampler._utc_from_ns(BASE_RT)}", line)

    def test_missing_samples_are_invalid(self):
        line = report([], "", readable=True)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("drift_s=na max=5", line)
        self.assertIn("max_gap_s=na max=5", line)
        self.assertIn("vm_fork=na", line)
        self.assertIn("boot_mono_jump_s=na max=5", line)
        self.assertIn("reason=data_missing", line)
        self.assertNotIn("host_qualification ok", line)

    def test_unreadable_dmesg_is_invalid(self):
        line = report(rows(0.1, 0.1, 0.1), "", readable=False)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("reason=data_missing", line)
        self.assertIn("vm_fork=na", line)
        self.assertIn("drift_s=0.000 max=5", line)

    def test_product_fail_and_host_invalid_keep_both_times(self):
        fail_utc = "2026-11-09T05:00:00.000Z"
        line = report(rows(5.001, 5.001, 5.001), "", status=1, fail_utc=fail_utc)
        self.assertTrue(line.startswith("host_qualification invalid "))
        self.assertIn("reason=gap", line)
        self.assertIn("product_fail_seen yes", line)
        self.assertIn(f"product_fail_utc={fail_utc}", line)
        self.assertIn(f"host_event_utc={host_sampler._utc_from_ns(BASE_RT)}", line)
        self.assertEqual(host_sampler.host_pause_exit_code(1, line), 6)
        self.assertEqual(line.count("\n"), 0)

    def test_exit_code_keeps_other_statuses(self):
        invalid = report(rows(5.001, 5.001, 5.001), "")
        ok = report(rows(0.1, 0.1, 0.1), "")
        self.assertEqual(host_sampler.host_pause_exit_code(1, ok), 1)
        self.assertEqual(host_sampler.host_pause_exit_code(3, invalid), 3)
        self.assertEqual(host_sampler.host_pause_exit_code(4, invalid), 4)
        self.assertEqual(host_sampler.host_pause_exit_code(5, invalid), 5)
        self.assertEqual(host_sampler.HOST_INVALID_EXIT, 6)

    def test_cli_prints_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples = os.path.join(tmp, "samples.txt")
            dmesg = os.path.join(tmp, "dmesg.txt")
            with open(samples, "w", encoding="utf-8") as handle:
                handle.write(_line(BASE_RT, BASE_MONO, BASE_BOOT) + "\n")
                handle.write(_line(BASE_RT + _ns(0.1), BASE_MONO + _ns(0.1), BASE_BOOT + _ns(0.1)) + "\n")
            with open(dmesg, "w", encoding="utf-8") as handle:
                handle.write("")
            result = subprocess.run(
                [
                    "python3",
                    os.path.join(PROOF, "host-sampler.py"),
                    "host-qualification",
                    "--samples",
                    samples,
                    "--dmesg",
                    dmesg,
                    "--product-status",
                    "0",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertTrue(result.stdout.startswith("host_qualification ok "))

    def test_scripts_use_exit_6_and_keep_product_fail_text(self):
        with open(os.path.join(PROOF, "ticket-renewal.sh"), encoding="utf-8") as handle:
            renewal = handle.read()
        with open(os.path.join(PROOF, "coord-cert-soak.sh"), encoding="utf-8") as handle:
            soak = handle.read()
        with open(os.path.join(PROOF, "proof-lock.sh"), encoding="utf-8") as handle:
            lock = handle.read()
        self.assertIn("HOST_PAUSE_EXIT=6", renewal)
        self.assertIn("exit 6", renewal)
        self.assertIn('echo "FAIL: $*" >&2', renewal)
        self.assertIn("PRODUCT_FAIL_UTC=", renewal)
        self.assertIn("exit 6", soak)
        self.assertIn("PROOF_FOREIGN_ABORT_EXIT=5", lock)
        with open(os.path.join(PROOF, "host-sampler.py"), encoding="utf-8") as handle:
            sampler = handle.read()
        self.assertNotIn("os.environ", sampler)


if __name__ == "__main__":
    unittest.main()

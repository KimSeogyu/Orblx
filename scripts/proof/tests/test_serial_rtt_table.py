"""W25-5: serial-rtt-table.py reads the gate pings and the contention of each run."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(os.path.dirname(HERE), "serial-rtt-table.py")


def log(max_ms, other, lost=0):
    rest = ",".join(["0.300"] * 49)
    received = 50 - lost
    lines = ["proof_context nat-realism:p phase start time 2026-10-30T20:00:00.000+0900 load 1.00/1.00/1.00 "
             "other_orblx_containers %d groups -" % other]
    for kind, label in (("direct_ping", "prc_prc"), ("direct_ping", "prc_prc_i0.23"),
                        ("relay_ping", "prc_prc"), ("relay_ping", "sym_sym")):
        lines.append("ping_rtts %s %s sent 50 received %d ms %s,%s" % (kind, label, received, rest, max_ms))
    lines.append("proof_contention nat-realism:p samples 10 contended_samples %d unknown_samples 0 "
                 "max_other_orblx_containers %d max_load1 2.50" % (10 if other else 0, other))
    lines.append("proof_ok")
    return "\n".join(lines) + "\n"


class SerialTableTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, i, text, code=0):
        with open(os.path.join(self.dir, "run%d.log" % i), "w") as f:
            f.write(text)
        with open(os.path.join(self.dir, "run%d.exit" % i), "w") as f:
            f.write("%d\n" % code)

    def run_table(self, *args):
        return subprocess.run([sys.executable, TABLE, self.dir, *args], capture_output=True, text=True)

    def test_gate_passes_below_the_limit(self):
        self.write(1, log("1.500", 0))
        self.write(2, log("19.900", 8))
        self.assertEqual(self.run_table("--gate").returncode, 0)
        table = self.run_table().stdout
        self.assertIn("| 1 | ok | 1.500 (", table)
        self.assertIn("alone (max 0 other", table)
        self.assertIn("contended (max 8 other", table)

    def test_gate_fails_on_a_spike_or_a_loss(self):
        self.write(1, log("25.000", 8))
        self.assertEqual(self.run_table("--gate").returncode, 1)
        self.write(1, log("1.000", 0, lost=1))
        self.assertEqual(self.run_table("--gate").returncode, 1)

    def test_kill_check_only_when_no_other_container_ran(self):
        self.write(1, log("25.000", 8))
        self.assertEqual(self.run_table("--kill-check").returncode, 0)
        self.write(1, log("25.000", 0))
        self.assertEqual(self.run_table("--kill-check").returncode, 3)

    def test_each_sample_gets_the_nearest_svid_renewal(self):
        # 2026-10-30T12:06:40.300Z is epoch 1793362000.3.
        self.write(1, "\n".join([
            "ping_rtts relay_ping prc_prc sent 3 received 3 ms 0.300,25.000,0.400",
            "ping_times relay_ping prc_prc 1@1793362000.100000,2@1793362000.300000,3@1793362000.500000",
            "svid_renewal orblx-x-node-a 2026-10-30T12:06:39.900000000Z",
            "svid_renewal orblx-x-node-b 2026-10-30T12:10:00.000000000Z",
            "svid_renewal_scan done",
            "proof_ok",
        ]) + "\n")
        table = self.run_table().stdout
        self.assertIn("| +0.4 s (orblx-x-node-a, 2 renewals) |", table)
        with open(os.path.join(self.dir, "run1.samples.tsv")) as f:
            rows = f.read().splitlines()
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[2].split("\t"),
                         ["prc_prc_relay", "2", "25.000", "1793362000.300000", "orblx-x-node-a",
                          "1793361999.900", "+0.400"])

    def test_a_run_without_renewal_lines_shows_a_dash(self):
        self.write(1, log("1.500", 0))
        self.assertIn("| - |", self.run_table().stdout)

    def test_a_run_with_sample_times_but_no_renewal_scan_is_not_recorded(self):
        self.write(1, "ping_rtts relay_ping prc_prc sent 1 received 1 ms 0.300\n"
                      "ping_times relay_ping prc_prc 1@1793362000.100000\nproof_ok\n")
        self.assertIn("| not recorded |", self.run_table().stdout)
        with open(os.path.join(self.dir, "run1.log"), "a") as f:
            f.write("svid_renewal_scan done\n")
        self.assertIn("| no renewal in the run |", self.run_table().stdout)

    def test_sym_throughput_median_against_the_w22_floor(self):
        self.write(1, log("1.0", 0) + "throughput sym_sym_relay bytes 1 seconds 5.0 mbit_s 1200.00\n")
        self.write(2, log("1.0", 3) + "throughput sym_sym_relay bytes 1 seconds 5.0 mbit_s 900.00\n")
        self.write(3, log("1.0", 0) + "throughput sym_sym_relay bytes 1 seconds 5.0 mbit_s 1000.00\n")
        out = self.run_table().stdout
        self.assertIn("| 1200.00 |", out)
        self.assertIn("all runs: 3 values, median 1000.00 Mbit/s, BELOW the W22 floor 1113", out)
        self.assertIn("alone runs: 2 values, median 1100.00 Mbit/s, BELOW the W22 floor 1113", out)


if __name__ == "__main__":
    unittest.main()

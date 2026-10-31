"""W25-16: the measured bulk packet rate, the host probe and the probe context. Report only."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(HERE)
TABLE = os.path.join(PROOF, "serial-rtt-table.py")
PROBE = os.path.join(PROOF, "host-probe.py")
NATR = os.path.join(PROOF, "nat-realism.sh")


def natr_function(name):
    """The text of one shell function of nat-realism.sh."""
    with open(NATR) as f:
        text = f.read()
    m = re.search(r"^%s\(\) \{\n.*?^\}\n" % re.escape(name), text, re.M | re.S)
    if not m:
        raise AssertionError("no function %s" % name)
    return m.group(0)


def bulk_pps(*args):
    script = natr_function("bulk_pps_line") + 'bulk_pps_line "$@"\n'
    return subprocess.run(["bash", "-c", script, "bash", *args], capture_output=True, text=True, check=True).stdout


class BulkPpsTest(unittest.TestCase):
    def test_pps_comes_from_the_counter_delta_and_the_bulk_seconds(self):
        out = bulk_pps("sym_sym_relay", "orblx0", "orblx0", "10 100", "40010 3000100", "500 7", "3000500 40007",
                       "100.0", "131.5", "bytes 4000000000 seconds 30.000 mbit_s 1066.67")
        self.assertEqual(out.strip(),
                         "bulk_pps sym_sym_relay client_dev orblx0 tx_packets 3000000 rx_packets 40000 "
                         "server_dev orblx0 rx_packets 3000000 tx_packets 40000 bulk_s 30.000 window_s 31.500 "
                         "pps 100000 client_tx_pps 100000")

    def test_missing_counter_prints_none(self):
        out = bulk_pps("plain", "", "eth0", "", "", "1 2", "3 4", "1", "2", "bytes 1 seconds 30.000 mbit_s 1")
        self.assertTrue(out.startswith("bulk_pps plain none client_dev - server_dev eth0"), out)

    def test_bulk_still_prints_the_throughput_line_first(self):
        body = natr_function("bulk")
        self.assertLess(body.index('echo "throughput ${label} ${out}"'), body.index("bulk_pps_line"))


class HostProbeTest(unittest.TestCase):
    def test_probe_prints_header_and_kst_rows(self):
        p = subprocess.Popen([sys.executable, PROBE, "0.2"], stdout=subprocess.PIPE, text=True)
        lines = [p.stdout.readline() for _ in range(3)]
        p.terminate()
        p.wait(timeout=5)
        p.stdout.close()
        head = lines[0].rstrip("\n").split("\t")
        self.assertEqual(head[:3], ["kst", "epoch", "interval_s"])
        for col in ("cpu_iowait_pct", "cpu_steal_pct", "psi_io_some_ms", "psi_io_full_ms", "psi_mem_some_ms",
                    "psi_mem_full_ms", "psi_cpu_some_ms", "disk_busy_pct"):
            self.assertIn(col, head)
        row = lines[1].rstrip("\n").split("\t")
        self.assertEqual(len(row), len(head))
        self.assertTrue(row[0].endswith("+09:00"), row[0])
        self.assertLess(abs(float(row[2]) - 0.2), 0.15)

    def test_interval_above_one_second_is_refused(self):
        self.assertEqual(subprocess.run([sys.executable, PROBE, "2"], capture_output=True).returncode, 2)


def run_log(spike_ms, at):
    rest = ",".join(["0.300"] * 49)
    times = ",".join("%d@%.6f" % (k + 1, at - 49 * 0.2 + k * 0.2) for k in range(50))
    lines = ["proof_context nat-realism:p phase start time 2026-10-31T21:00:00.000+0900 load 1.00/1.00/1.00 "
             "other_orblx_containers 0 groups -"]
    for kind, label in (("direct_ping", "prc_prc"), ("direct_ping", "prc_prc_i0.23"),
                        ("relay_ping", "prc_prc"), ("relay_ping", "sym_sym")):
        ms = rest + "," + (spike_ms if label == "sym_sym" else "0.300")
        lines.append("ping_rtts %s %s sent 50 received 50 ms %s" % (kind, label, ms))
        lines.append("ping_times %s %s %s" % (kind, label, times))
    lines.append("throughput sym_sym_relay bytes 4000000000 seconds 30.000 mbit_s 1066.67")
    lines.append("bulk_pps sym_sym_relay client_dev orblx0 tx_packets 3 rx_packets 1 server_dev orblx0 "
                 "rx_packets 3 tx_packets 1 bulk_s 30.000 window_s 31.000 pps 92084 client_tx_pps 92090")
    lines.append("proof_contention nat-realism:p samples 10 contended_samples 0 unknown_samples 0 "
                 "max_other_orblx_containers 0 max_load1 2.50")
    lines.append("proof_ok")
    return "\n".join(lines) + "\n"


class ProbeContextTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def table(self, *args):
        return subprocess.run([sys.executable, TABLE, self.dir, *args], capture_output=True, text=True)

    def test_pps_column_and_rows_around_the_spike(self):
        at = 1793450545.225
        with open(os.path.join(self.dir, "run1.log"), "w") as f:
            f.write(run_log("39.600", at))
        with open(os.path.join(self.dir, "run1.exit"), "w") as f:
            f.write("1\n")
        with open(os.path.join(self.dir, "run1.hostprobe.tsv"), "w") as f:
            f.write("kst\tepoch\tload1\n")
            for k in range(-40, 41):
                f.write("t\t%.3f\t1.0\n" % (at + k * 0.5))
        self.assertIn("| Sym relay pps |", self.table().stdout)
        self.assertIn("| 92084 |", self.table().stdout)
        out = self.table("--upto", "1", "--probe-context")
        self.assertEqual(out.returncode, 0)
        self.assertIn("host_probe_context run 1 max_ping 39.600 ms path sym_sym_relay seq 50 "
                      "at 2026-10-31T21:42:25.225+09:00", out.stdout)
        self.assertIn("above_limit yes", out.stdout)
        rows = [l for l in out.stdout.splitlines() if l.startswith("host_probe_row t\t")]
        self.assertEqual(len(rows), 15)  # -3 s .. +4 s at 0.5 s
        self.assertNotIn("stall", out.stdout.lower())

    def test_no_probe_file_is_reported(self):
        with open(os.path.join(self.dir, "run1.log"), "w") as f:
            f.write(run_log("1.000", 1793450545.225))
        out = self.table("--upto", "1", "--probe-context")
        self.assertIn("host_probe_context run 1 none (no run1.hostprobe.tsv)", out.stdout)

    def test_gates_do_not_read_pps_or_probe(self):
        with open(os.path.join(self.dir, "run1.log"), "w") as f:
            f.write(run_log("1.000", 1793450545.225).replace("pps 92084", "pps 1"))
        with open(os.path.join(self.dir, "run1.exit"), "w") as f:
            f.write("0\n")
        self.assertEqual(self.table("--gate").returncode, 0)


if __name__ == "__main__":
    unittest.main()

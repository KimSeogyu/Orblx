"""Tests for scripts/proof/perf-summary.py.

The fixture holds the result lines of the W23-4 branch run1 log (release nat-realism, [C]).
"""

import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("perf_summary", os.path.join(HERE, "..", "perf-summary.py"))
perf_summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf_summary)

with open(os.path.join(HERE, "nat-realism-w23-4-run1.txt")) as f:
    RUN1 = f.read()


def write_runs(out_dir, logs):
    for i, (text, code) in enumerate(logs, 1):
        with open(os.path.join(out_dir, "run%d.log" % i), "w") as f:
            f.write(text)
        with open(os.path.join(out_dir, "run%d.exit" % i), "w") as f:
            f.write("%d\n" % code)


class PerfSummaryTest(unittest.TestCase):
    def test_a_passing_log_gives_the_numbers_and_the_outlier(self):
        with tempfile.TemporaryDirectory() as out:
            write_runs(out, [(RUN1, 0)])
            self.assertEqual(perf_summary.main(["perf-summary", out]), 0)
            with open(os.path.join(out, "perf-watch.json")) as f:
                summary = json.load(f)
            self.assertTrue(summary["rtt_gate_ok"])
            relay = summary["paths"]["prc_prc_relay"]
            self.assertEqual(relay["rtt_avg_ms"]["median"], 1.541)
            self.assertEqual(relay["lost"], ["0/50"])
            self.assertEqual(relay["slowest_pings"][0]["ms"], 22.1)
            self.assertEqual(summary["paths"]["prc_prc_direct"]["throughput_mbit_s"]["median"], 1412.29)
            self.assertTrue(summary["outlier"]["found"])
            self.assertTrue(os.path.exists(os.path.join(out, "perf-watch.md")))

    def test_a_missing_relay_gate_line_fails(self):
        text = "\n".join(l for l in RUN1.splitlines() if "prc_prc relay_gate ok" not in l and not l.startswith("relay_rtt prc_prc"))
        with tempfile.TemporaryDirectory() as out:
            write_runs(out, [(RUN1, 0), (text, 1)])
            self.assertEqual(perf_summary.main(["perf-summary", out]), 1)
            with open(os.path.join(out, "perf-watch.json")) as f:
                summary = json.load(f)
            self.assertFalse(summary["rtt_gate_ok"])
            self.assertEqual(summary["paths"]["prc_prc_relay"]["lost"], ["0/50", "none"])

    def test_no_run_fails(self):
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(perf_summary.main(["perf-summary", out]), 1)


if __name__ == "__main__":
    unittest.main()

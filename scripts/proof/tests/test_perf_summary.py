"""Tests for scripts/proof/perf-summary.py.

The fixture holds the result lines of the W23-4 branch run1 log (release nat-realism, [C]).
That log has no ping_rtts lines. The tests add SYNTHETIC ping_rtts lines (made for the test,
not measured) to check the CI gates.
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

LABELS = {
    "prc_prc_direct": ("direct_ping", "prc_prc"),
    "prc_prc_direct_i0.23": ("direct_ping", "prc_prc_i0.23"),
    "prc_prc_relay": ("relay_ping", "prc_prc"),
    "sym_sym_relay": ("relay_ping", "sym_sym"),
}


def rtts_line(path, times, sent=50, received=None):
    kind, label = LABELS[path]
    received = len(times) if received is None else received
    return "ping_rtts %s %s sent %d received %d ms %s" % (
        kind, label, sent, received, ",".join("%.3f" % t for t in times))


def synthetic(direct=0.2, relay=0.3, override=None):
    """RUN1 plus SYNTHETIC ping_rtts lines: 50 pings at a flat value on each path."""
    lines = {
        "prc_prc_direct": rtts_line("prc_prc_direct", [direct] * 50),
        "prc_prc_direct_i0.23": rtts_line("prc_prc_direct_i0.23", [direct] * 50),
        "prc_prc_relay": rtts_line("prc_prc_relay", [relay] * 50),
        "sym_sym_relay": rtts_line("sym_sym_relay", [relay] * 50),
    }
    lines.update(override or {})
    return RUN1 + "\n" + "\n".join(lines.values()) + "\n"


def write_runs(out_dir, logs):
    for i, (text, code) in enumerate(logs, 1):
        with open(os.path.join(out_dir, "run%d.log" % i), "w") as f:
            f.write(text)
        with open(os.path.join(out_dir, "run%d.exit" % i), "w") as f:
            f.write("%d\n" % code)


def run_summary(logs):
    with tempfile.TemporaryDirectory() as out:
        write_runs(out, logs)
        code = perf_summary.main(["perf-summary", out])
        with open(os.path.join(out, "perf-watch.json")) as f:
            summary = json.load(f)
        with open(os.path.join(out, "perf-watch.md")) as f:
            text = f.read()
    return code, summary, text


class PerfSummaryTest(unittest.TestCase):
    def test_a_passing_log_gives_the_numbers_and_the_outlier(self):
        code, summary, text = run_summary([(synthetic(), 0)])
        self.assertEqual(code, 0)
        self.assertTrue(summary["ci_gate_ok"])
        self.assertTrue(summary["rtt_gate_ok"])
        relay = summary["paths"]["prc_prc_relay"]
        self.assertEqual(relay["rtt_avg_ms"]["median"], 1.541)
        self.assertEqual(relay["lost"], ["0/50"])
        self.assertEqual(relay["slowest_pings"][0]["ms"], 22.1)
        self.assertEqual(summary["paths"]["prc_prc_direct"]["throughput_mbit_s"]["median"], 1412.29)
        self.assertTrue(summary["outlier"]["found"])
        self.assertIn("| prc_prc_relay | 1 | 0.3 | 0.3 | 0.3 | 0/50 | 0/50 |", text)

    def test_the_stats_give_median_p99_max_and_spikes(self):
        times = [0.2] * 47 + [11.0, 43.4, 251.0]
        code, summary, _ = run_summary([(synthetic(override={"sym_sym_relay": rtts_line("sym_sym_relay", times)}), 0)])
        self.assertEqual(code, 0)
        st = summary["paths"]["sym_sym_relay"]["ping_stats"][0]
        self.assertEqual(st["median_ms"], 0.2)
        self.assertEqual(st["max_ms"], 251.0)
        self.assertEqual(st["spikes"], 3)
        # Linear p99 of 50 values: v[48] + 0.51 * (v[49] - v[48]).
        self.assertEqual(st["p99_ms"], round(43.4 + 0.51 * (251.0 - 43.4), 3))

    def test_one_spike_fails_the_box_avg_gate_but_not_the_ci_gate(self):
        times = [0.2] * 49 + [251.0]
        text = synthetic(override={"sym_sym_relay": rtts_line("sym_sym_relay", times)})
        text = text.replace("relay_rtt sym_sym relay_avg_ms 1.001", "relay_rtt sym_sym relay_avg_ms 5.216")
        code, summary, _ = run_summary([(text, 0)])
        self.assertEqual(code, 0)
        self.assertFalse(summary["box_avg_gate_ok"])
        self.assertTrue(summary["ci_gate_ok"])

    def test_four_spikes_on_a_path_fail(self):
        times = [0.2] * 46 + [12.0] * 4
        override = {"prc_prc_direct_i0.23": rtts_line("prc_prc_direct_i0.23", times)}
        code, summary, _ = run_summary([(synthetic(), 0), (synthetic(override=override), 0)])
        self.assertEqual(code, 1)
        self.assertTrue(summary["runs"][0]["ci_gate_ok"])
        self.assertFalse(summary["runs"][1]["ci_gate_ok"])
        self.assertIn("4 of 50 pings above", summary["runs"][1]["ci_failures"][0])

    def test_a_relay_median_above_direct_plus_1_ms_fails(self):
        code, summary, _ = run_summary([(synthetic(direct=0.2, relay=1.3), 0)])
        self.assertEqual(code, 1)
        self.assertEqual(len(summary["runs"][0]["ci_failures"]), 2)

    def test_a_lost_ping_fails(self):
        override = {"prc_prc_direct": rtts_line("prc_prc_direct", [0.2] * 49, received=49)}
        code, summary, _ = run_summary([(synthetic(override=override), 0)])
        self.assertEqual(code, 1)
        self.assertIn("prc_prc_direct: lost 1/50", summary["runs"][0]["ci_failures"])

    def test_a_missing_throughput_fails(self):
        text = "\n".join(l for l in synthetic().splitlines() if not l.startswith("throughput sym_sym_relay"))
        code, summary, _ = run_summary([(text, 0)])
        self.assertEqual(code, 1)
        self.assertIn("sym_sym_relay: throughput None", summary["runs"][0]["ci_failures"][0])

    def test_a_throughput_below_300_mbit_fails(self):
        text = synthetic().replace("throughput prc_prc_direct bytes 883294208 seconds 5.003 mbit_s 1412.29",
                                   "throughput prc_prc_direct bytes 175500000 seconds 5.000 mbit_s 280.83")
        code, summary, _ = run_summary([(text, 0)])
        self.assertEqual(code, 1)
        self.assertIn("prc_prc_direct: throughput 280.83 Mbit/s is below the floor 300.0 Mbit/s",
                      summary["runs"][0]["ci_failures"])

    def test_a_throughput_of_300_mbit_passes(self):
        text = synthetic().replace("mbit_s 1412.29", "mbit_s 300.00")
        code, summary, _ = run_summary([(text, 0)])
        self.assertEqual(code, 0)

    def test_a_log_without_ping_rtts_fails(self):
        code, summary, _ = run_summary([(RUN1, 0)])
        self.assertEqual(code, 1)
        self.assertFalse(summary["ci_gate_ok"])

    def test_a_missing_relay_gate_line_fails(self):
        text = "\n".join(
            l for l in synthetic().splitlines()
            if "prc_prc relay_gate ok" not in l and not l.startswith("relay_rtt prc_prc")
            and not l.startswith("proof_ok"))
        code, summary, _ = run_summary([(synthetic(), 0), (text, 1)])
        self.assertEqual(code, 1)
        self.assertFalse(summary["rtt_gate_ok"])
        self.assertFalse(summary["proof_ok"])
        self.assertEqual(summary["paths"]["prc_prc_relay"]["lost"], ["0/50", "none"])

    def test_no_run_fails(self):
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(perf_summary.main(["perf-summary", out]), 1)


if __name__ == "__main__":
    unittest.main()

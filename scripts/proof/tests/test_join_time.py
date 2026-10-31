"""The join-time proof gate (scripts/proof/join-time-summary.py) and its wiring.

The summary takes every join that the proof started. The negative tests check that a join
that fails (a timeout or an error), a missing join, or a join that is slow from the
listener start makes the gate fail, and that no join is dropped from the numbers.
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(HERE)
SUMMARY = os.path.join(PROOF, "join-time-summary.py")
SCRIPT = os.path.join(PROOF, "join-time.sh")
MANIFEST = os.path.join(PROOF, "sweep-manifest.txt")


def ok(i, enroll, listener):
    return f"join {i} ok enroll_to_first_packet_ms {enroll} listener_to_first_packet_ms {listener}"


class JoinTimeSummaryTest(unittest.TestCase):
    def run_summary(self, lines, n, limit=2000):
        with tempfile.NamedTemporaryFile("w", prefix="orblx-join-time-test-", delete=False) as f:
            f.write("\n".join(lines) + "\n")
            path = f.name
        try:
            return subprocess.run([sys.executable, SUMMARY, path, str(n), str(limit)],
                                  capture_output=True, text=True)
        finally:
            os.unlink(path)

    def test_twenty_good_joins_pass_and_print_n_median_p95_max_of_both_values(self):
        lines = [ok(i, 1000 + i * 10, 100 + i) for i in range(1, 21)]
        out = self.run_summary(lines, 20)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        # 20 values 1010..1200: the median is the mean of 1100 and 1110, p95 is rank 19.
        self.assertIn("join_time n 20 enroll_to_first_packet_ms median 1105 p95 1190 max 1200", out.stdout)
        self.assertIn("join_time n 20 listener_to_first_packet_ms median 110.5 p95 119 max 120", out.stdout)
        self.assertRegex(out.stdout, r"(?m)^join_gate ok: 20 of 20 joins")

    def test_negative_a_failed_join_fails_the_gate(self):
        lines = [ok(i, 1000, 300) for i in range(1, 20)]
        lines.append("join 20 fail node a got no reply from b in 30 s (timeout)")
        out = self.run_summary(lines, 20)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("join_gate FAIL: join 20 failed: node a got no reply from b in 30 s (timeout)", out.stdout)
        self.assertNotIn("join_gate ok", out.stdout)

    def test_negative_a_slow_join_from_the_listener_fails_and_stays_in_the_numbers(self):
        lines = [ok(i, 1000, 300) for i in range(1, 20)] + [ok(20, 5000, 2001)]
        out = self.run_summary(lines, 20)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("join 20 listener_to_first_packet_ms 2001 is more than 2000", out.stdout)
        self.assertIn("listener_to_first_packet_ms median 300 p95 300 max 2001", out.stdout)
        self.assertIn("enroll_to_first_packet_ms median 1000 p95 1000 max 5000", out.stdout)

    def test_a_slow_enroll_alone_is_report_only(self):
        lines = [ok(i, 9000, 300) for i in range(1, 21)]
        self.assertEqual(self.run_summary(lines, 20).returncode, 0)

    def test_negative_a_partial_run_never_passes(self):
        out = self.run_summary([ok(i, 1000, 300) for i in range(1, 20)], 20)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("a partial run never passes", out.stdout)
        dup = [ok(i, 1000, 300) for i in range(1, 20)] + [ok(19, 1000, 300)]
        self.assertEqual(self.run_summary(dup, 20).returncode, 1)

    def test_a_bad_line_is_a_setup_error(self):
        self.assertEqual(self.run_summary(["join 1 maybe"], 1).returncode, 2)
        self.assertEqual(self.run_summary([ok(1, 1, 1)], 0).returncode, 2)


class JoinTimeWiringTest(unittest.TestCase):
    def setUp(self):
        with open(SCRIPT) as f:
            self.src = f.read()

    def test_the_sweep_manifest_runs_the_proof_as_a_gate(self):
        with open(MANIFEST) as f:
            lines = [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
        self.assertTrue(any(l.startswith("gate|join-time|") and l.endswith("|join-time") for l in lines))
        self.assertTrue(any(l.startswith("proof|join-time|scripts/proof/join-time.sh|") for l in lines))

    def test_each_join_has_its_own_project_and_a_clean_start(self):
        body = self.src[self.src.index("one_join() {"):]
        self.assertIn('export JOIN_PROJECT="${BASE}-j${i}"', body)
        clean = body.index('proof_compose_clean "$JOIN_PROJECT"')
        self.assertLess(clean, body.index("dc up -d"))
        self.assertIn('jw="$WORKROOT/j${i}"', body)

    def test_proof_ok_needs_the_summary_gate_of_all_joins(self):
        tail = self.src[self.src.index('for i in $(seq 1 "$N")'):]
        self.assertRegex(tail, r'summary \|\| \{[^}]*exit 1; \}\necho "proof_ok"')
        self.assertEqual(len(re.findall(r'echo "proof_ok"', self.src)), 1)


if __name__ == "__main__":
    unittest.main()

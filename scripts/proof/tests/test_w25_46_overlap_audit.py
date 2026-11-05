"""W25-46 overlap audit: dedupe, soak real end, and the 09:10-09:15 re-judge."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import w25_46_overlap_audit as audit

FIXTURE = os.path.join(HERE, "fixtures", "w25-46-0910")
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
AUDIT_TXT = os.path.join(REPO, "docs", "w25-46-overlap-audit.txt")


def _write(directory: str, name: str, text: str) -> None:
    with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
        handle.write(text)


class OverlapAuditTest(unittest.TestCase):
    def test_duplicate_logs_with_the_same_acquire_time_and_pid_are_one_holder(self) -> None:
        runs = audit.load_dir(FIXTURE)
        copies = [run for run in runs if run.label == "ssh-renew"]
        self.assertEqual(len(copies), 2)
        self.assertEqual(audit.dedupe_key(copies[0]), audit.dedupe_key(copies[1]))
        self.assertEqual(audit.overlap_pair_count(copies, use_dedupe=False), 1)
        self.assertEqual(audit.overlap_pair_count(copies, use_dedupe=True), 0)
        self.assertEqual(len(audit.dedupe(runs)), len(runs) - 1)

    def test_the_soak_end_is_proof_cancel_and_the_plan_end_stays_unused(self) -> None:
        runs = audit.load_dir(FIXTURE)
        soak = next(run for run in runs if run.label == "coord-cert-soak")
        self.assertEqual(audit.fmt_ts(soak.plan_end), "2026-11-05T09:30:00.000+0900")
        self.assertEqual(audit.real_end_source(soak), "proof_cancel")
        self.assertEqual(audit.fmt_ts(audit.real_end(soak)), "2026-11-05T09:10:25.000+0900")
        self.assertEqual(soak.pid, 2065982)
        self.assertEqual(audit.overlap_pair_count(runs, use_dedupe=True), 0)

    def test_a_missing_release_does_not_take_the_nominal_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _write(
                directory,
                "open.log",
                "proof_lock open-soak acquired at 2026-11-05T08:40:00.000+0900 after 1 ms, file /workspace/.orblx-proof.lock\n"
                "proof_plan_end 2026-11-05T09:30:00.000+0900\n",
            )
            _write(
                directory,
                "next.log",
                "proof_lock next acquired at 2026-11-05T09:10:35.126+0900 after 1 ms, file /workspace/.orblx-proof.lock\n"
                "proof_lock next released at 2026-11-05T09:12:00.000+0900 pid=9\n",
            )
            runs = audit.load_dir(directory)
            open_run = next(run for run in runs if run.label == "open-soak")
            self.assertIsNone(audit.real_end(open_run))
            self.assertEqual(audit.real_end_source(open_run), "none")
            self.assertEqual(audit.overlap_pair_count(runs, use_dedupe=True), 0)

    def test_the_0910_window_matches_the_recorded_verdict(self) -> None:
        text = audit.render(audit.load_dir(FIXTURE))
        with open(AUDIT_TXT, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), text)
        self.assertIn("overlap_pairs=0\n", text)
        self.assertIn(
            "rejudge policy-scale acquire=2026-11-05T09:10:35.126+0900 "
            "log=w25-34-proof-policy-scale-2876d63.log verdict=INVALID "
            "reason=soak_containers_still_running contended_samples=3 other=1\n",
            text,
        )
        self.assertIn(
            "rejudge deny-damage acquire=2026-11-05T09:13:31.657+0900 "
            "log=w25-38-deny-damage.log verdict=VALID_for_container_overlap "
            "reason=clear contended_samples=0 other=0\n",
            text,
        )
        self.assertIn(
            "rejudge policy-scale acquire=2026-11-05T09:14:40.000+0900 "
            "log=w25-34-proof-policy-scale-091440.log verdict=VALID_for_container_overlap "
            "reason=clear contended_samples=0 other=0\n",
            text,
        )
        self.assertNotIn("ssh-renew", text.split("rejudge_window", 1)[1])

    def test_a_colon_offset_parses_to_the_same_instant(self) -> None:
        self.assertEqual(
            audit.parse_ts("2026-11-05T09:10:25+09:00"),
            audit.parse_ts("2026-11-05T09:10:25.000+0900"),
        )


if __name__ == "__main__":
    unittest.main()

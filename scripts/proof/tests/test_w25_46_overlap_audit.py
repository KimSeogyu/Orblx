"""W25-46 overlap audit: dedupe, soak real end, and the 09:10-09:15 re-judge."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import w25_46_overlap_audit as audit

FIXTURE = os.path.join(HERE, "fixtures", "w25-46-0910")
RAW = os.path.join(HERE, "fixtures", "w25-46-raw")
UNTIL = os.path.join(HERE, "fixtures", "w25-46-until")
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
AUDIT_TXT = os.path.join(REPO, "docs", "w25-46-overlap-audit.txt")
SOURCE_DIR = "/workspace/orblx-w18-proof"


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
        self.assertIn("cutoff=2026-10-31T17:23:11.000+0900\n", text)
        self.assertIn("runs_before=6\n", text)
        self.assertIn("runs_after_dedupe=5\n", text)
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

    def test_raw_logs_dedupe_the_ssh_copy_and_take_the_cancel_file(self) -> None:
        runs = audit.load_dir(RAW)
        copies = [
            run
            for run in runs
            if run.label == "ssh-renew" and audit.fmt_ts(run.acquire) == "2026-10-31T21:05:46.638+0900"
        ]
        self.assertEqual(len(copies), 2)
        self.assertIsNone(copies[0].pid)
        self.assertEqual(audit.dedupe_key(copies[0]), audit.dedupe_key(copies[1]))
        selected = audit.after_cutoff(runs, audit.parse_ts(audit.DEFAULT_CUTOFF))
        self.assertEqual(len(selected), 7)
        self.assertEqual(len(audit.dedupe(selected)), 6)
        soak = next(run for run in runs if run.label == "coord-cert-soak")
        self.assertEqual(soak.pid, 2065982)
        self.assertEqual(soak.cancel_source, "w25-42-step2-cancel-20261105-091025.log")
        self.assertEqual(soak.cancel_line, 1)
        self.assertEqual(audit.fmt_ts(soak.cancel), "2026-11-05T09:10:25.000+0900")
        self.assertEqual(soak.lock_released_line, 2)
        text = audit.render(runs, source_dir=SOURCE_DIR)
        with open(AUDIT_TXT, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), text)
        self.assertIn(
            "No real 2-holder flock window. "
            "Container overlap: yes (policy-scale 09:10:35 INVALID).\n",
            text,
        )
        self.assertIn("path=w25-34-proof-policy-scale-2876d63.log:169\n", text)
        self.assertIn("path=w25-34-proof-policy-scale-2876d63.log:170\n", text)
        self.assertIn(
            "path=w25-42-step2-cancel-20261105-091025.log:2 "
            "note=after_flock_free cancel_script_log_latency\n",
            text,
        )
        self.assertIn("until=\n", text)
        self.assertNotIn("containers_removed_about", text)
        self.assertNotIn("09:10:41", text)

    def test_a_subdirectory_copy_is_one_holder_and_until_drops_a_later_acquire(self) -> None:
        runs = audit.load_dir(UNTIL)
        sources = {run.source for run in runs}
        self.assertIn("w25-45-152-gate-a.log", sources)
        self.assertIn("w25-45-152/main-side.log", sources)
        pair = [
            run
            for run in runs
            if audit.fmt_ts(run.acquire) == "2026-11-05T16:44:21.995+0900"
        ]
        self.assertEqual(len(pair), 2)
        self.assertEqual({run.label for run in pair}, {"gate-a"})
        self.assertEqual(len(audit.dedupe(pair)), 1)
        open_text = audit.render(runs)
        self.assertIn("until=\n", open_text)
        self.assertIn("runs_before=3\n", open_text)
        self.assertIn("runs_after_dedupe=2\n", open_text)
        self.assertIn("duplicate_logs=1\n", open_text)
        closed = audit.render(runs, until=audit.parse_ts("2026-11-05T10:05:23+09:00"))
        self.assertIn("until=2026-11-05T10:05:23.000+0900\n", closed)
        self.assertIn("runs_before=1\n", closed)
        self.assertIn("runs_after_dedupe=1\n", closed)
        self.assertNotIn("16:44:21.995", closed)
        kept = audit.at_or_before(
            audit.after_cutoff(runs, audit.parse_ts(audit.DEFAULT_CUTOFF)),
            audit.parse_ts("2026-11-05T10:05:23+09:00"),
        )
        self.assertEqual([run.source for run in kept], ["early.log"])

    def test_a_colon_offset_parses_to_the_same_instant(self) -> None:
        self.assertEqual(
            audit.parse_ts("2026-11-05T09:10:25+09:00"),
            audit.parse_ts("2026-11-05T09:10:25.000+0900"),
        )


if __name__ == "__main__":
    unittest.main()

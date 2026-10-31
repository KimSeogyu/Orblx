"""W25-17 proof sweep runner: the manifest maps every shipped row to its proofs, the sweep runs
each proof once, keeps going after a failure, names the failed rows, and exits non-zero when a
proof failed or a shipped row has no proof. --plan lists the rows and a time estimate.

The test uses ORBLX_SWEEP_TEST_ROOT: no git, no build, no sudo, no Docker.
The proofs are small shell scripts in a temporary checkout.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWEEP = os.path.join(HERE, "..", "release-sweep.sh")
REAL_MANIFEST = os.path.join(HERE, "..", "sweep-manifest.txt")
REAL_ROWS = os.path.join(HERE, "..", "..", "..", "docs", "matrix-rows.txt")

PROOFS = {
    "ok.sh": "echo step one\necho proof_ok\n",
    "fail.sh": "echo step one\necho 'error: the peer did not answer'\necho later line\nexit 3\n",
    "skip.sh": "echo 'The proof needs root. The script skips the proof.'\nexit 0\n",
    "pipe.sh": "set -o pipefail\nseq 1 200000 | cat >/dev/null\necho 'proof_ok extra 1'\n",
    "lock.sh": "echo held=${ORBLX_PROOF_LOCK_HELD:-none}\necho proof_ok\n",
    "quiet.sh": "echo 'nothing to see'\nexit 5\n",
    "steps.sh": "mkdir -p target/st\nprintf 'step a line\\nproof_ok\\n' >target/st/run1.log\n"
                "printf 'step b line\\n' >target/st/run2.log\necho 'gate_x ok: 2 runs'\n",
    "gatefail.sh": "echo proof_ok\necho 'gate_x failed: median low'\n",
    "natr.sh": "echo 'steady_warn prc_prc sample 140 ms over 100 ms'\necho proof_ok\n",
    "natrq.sh": "echo 'prc_prc steady lost 0/20 max_ms 40 limit_ms 1000'\necho proof_ok\n",
    "ssh.sh": "echo 'proof_ticket_guard FAIL ssh: the manifest proof makes lab tickets'\nexit 1\n",
    "old.sh": 'OLD_ORBLX="${OLD_ORBLX:?set OLD_ORBLX}"\necho "old=$OLD_ORBLX"\necho proof_ok\n',
    "slow.sh": "sleep 5\necho proof_ok\n",
    "loud.sh": "seq 1 100000\necho 'to stderr' >&2\nprintf 'no newline at end'\necho\necho proof_ok\n",
}

ALL = """
row|1|Mesh|ok
row|2|Two proofs, one fails|ok fail
row|4|Skip|skip
row|5|Missing script|missing
row|6|Pipe|pipe
row|7|Lock|lock
row|8|Quiet|quiet
row|9|Loud|loud
gate|G1|A gate|steps gatefail
proof|ok|scripts/proof/ok.sh|-|-
proof|fail|scripts/proof/fail.sh|-|-
proof|skip|scripts/proof/skip.sh|-|-
proof|missing|scripts/proof/missing.sh|-|-
proof|pipe|scripts/proof/pipe.sh|-|-
proof|lock|scripts/proof/lock.sh|-|-
proof|quiet|scripts/proof/quiet.sh|-|-
proof|loud|scripts/proof/loud.sh|-|-
proof|steps|scripts/proof/steps.sh|-|-|^gate_x ok: |target/st/run*.log
proof|gatefail|scripts/proof/gatefail.sh|-|-|^gate_x ok: 
"""

GOOD = """
row|1|Mesh|ok
row|3|Lock|lock ok
proof|ok|scripts/proof/ok.sh|-|-
proof|lock|scripts/proof/lock.sh|-|-
"""

NATR = """
row|29|SVID|nat-realism
gate|G1|A gate|steps
proof|nat-realism|scripts/proof/natr.sh|-|-
proof|steps|scripts/proof/steps.sh|-|-|^gate_x ok: |target/st/run*.log
"""

SKIP_MARK = "not in rc.3 sweep: no coordinator SSH certs"

# W25-27 PO ruling 2026-10-31: the SSH rows stay partial for rc.3. The fake ssh proof fails
# like the real one does (the lab-ticket guard), so a run that does not skip it fails.
SSH = GOOD + """partial|40|Tailscale SSH|ssh
partial|41|SSH session recording|ssh
proof|ssh|scripts/proof/ssh.sh|-|-
"""

PIN = "d9704cfb2f63bebbd3890f5b1accff30b2cace1f"
OLD = GOOD + "row|32|User approval|old\nproof|old|scripts/proof/old.sh|OLD_ORBLX=@OLD:%s@|-\n"

SWEEP_LINE = re.compile(r"^(proof_(lock|context|contention) |release_sweep: )")


class ReleaseSweepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "root")
        self.out = os.path.join(self.tmp, "out")
        os.makedirs(os.path.join(self.root, "scripts", "proof"))
        for name, body in PROOFS.items():
            with open(os.path.join(self.root, "scripts", "proof", name), "w") as f:
                f.write("#!/usr/bin/env bash\n" + body)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    @staticmethod
    def rows_for(manifest, notes=None):
        """The rows file that matches MANIFEST: each row line shipped, each partial line partial.
        NOTES maps a row id to its 4th field."""
        notes = notes or {}
        out = []
        for line in manifest.splitlines():
            kind = line.split("|")[0]
            if kind in ("row", "partial"):
                status = "shipped" if kind == "row" else "partial"
                rid = line.split("|")[1]
                cells = [rid, status, line.split("|")[2]] + ([notes[rid]] if rid in notes else [])
                out.append("|".join(cells))
        return "# test rows\n" + "\n".join(out) + "\n"

    def run_sweep(self, manifest, only=None, mode=None, plan=False, min_free_gb=None, rows=None,
                  extra_env=None):
        path = os.path.join(self.tmp, "manifest.txt")
        with open(path, "w") as f:
            f.write(manifest)
        # W25-27: the rows file. By default the test root has one that matches the manifest.
        os.makedirs(os.path.join(self.root, "docs"), exist_ok=True)
        with open(os.path.join(self.root, "docs", "matrix-rows.txt"), "w") as f:
            f.write(self.rows_for(manifest))
        env = dict(os.environ)
        env.update({
            "ORBLX_SWEEP_TEST_ROOT": self.root,
            "ORBLX_SWEEP_OUT": self.out,
            "ORBLX_SWEEP_MANIFEST": path,
            "ORBLX_PROOF_LOCK": os.path.join(self.tmp, "proof.lock"),
            "ORBLX_SWEEP_TIMEOUT": "60",
            "ORBLX_SWEEP_MIN_FREE_GB": "0",
        })
        env.pop("OLD_ORBLX", None)
        env["ORBLX_SWEEP_WORK"] = os.path.join(self.tmp, "work")
        env.update(extra_env or {})
        if only is not None:
            env["ORBLX_SWEEP_ONLY"] = only
        if mode is not None:
            env["ORBLX_SWEEP_LOCK_MODE"] = mode
        if min_free_gb is not None:
            env["ORBLX_SWEEP_MIN_FREE_GB"] = min_free_gb
        if rows is not None:
            rows_path = os.path.join(self.tmp, "rows.txt")
            with open(rows_path, "w") as f:
                f.write(rows)
            env["ORBLX_SWEEP_ROWS"] = rows_path
        args = ["bash", SWEEP] + (["--plan"] if plan else []) + ["testsha"]
        return subprocess.run(args, env=env, capture_output=True, text=True)

    def rows(self):
        """(row, proof) -> the cells of the summary line."""
        with open(os.path.join(self.out, "rc3-sweep-testsha.md")) as f:
            lines = [l for l in f.read().splitlines() if l.startswith("| ") and not l.startswith("| row ")]
        out = {}
        for l in lines:
            cells = [c.strip() for c in re.split(r"(?<!\\)\|", l)[1:-1]]
            out[(cells[0], cells[2])] = cells
        return out

    def table(self):
        with open(os.path.join(self.out, "rc3-sweep-testsha.md")) as f:
            return f.read()

    def test_every_proof_runs_and_the_failed_rows_are_named(self):
        out = self.run_sweep(ALL)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        rows = self.rows()
        self.assertEqual(rows[("1", "ok")][3], "proof_ok")
        self.assertEqual(rows[("2", "ok")][3], "proof_ok")
        self.assertIn("FAIL (exit 3): error: the peer did not answer", rows[("2", "fail")][3])
        self.assertIn("FAIL (exit 0, no proof_ok line)", rows[("4", "skip")][3])
        self.assertIn("FAIL (exit 127): release_sweep: No such file scripts/proof/missing.sh", rows[("5", "missing")][3])
        self.assertEqual(rows[("6", "pipe")][3], "proof_ok")
        self.assertIn("FAIL (exit 5): (no error line; last line) nothing to see", rows[("8", "quiet")][3])
        self.assertEqual(rows[("G1", "steps")][3], "proof_ok")
        self.assertIn("FAIL (exit 0, no pass line ^gate_x ok: ): gate_x failed: median low", rows[("G1", "gatefail")][3])
        # The log path, the time, and the proof_contention cell.
        self.assertEqual(rows[("1", "ok")][4], os.path.join(self.out, "rc3-sweep-testsha-ok.log"))
        self.assertRegex(rows[("1", "ok")][5], r"^\d+ s \(run (\d+|\?) s, lock wait (\d+|\?) s\)$")
        if shutil.which("flock"):
            self.assertRegex(rows[("1", "ok")][5], r"run \d+ s, lock wait \d+ s")
            self.assertRegex(rows[("1", "ok")][6], r"^samples \d+ contended_samples \d+")
        self.assertIn("Failed rows: 2, 4, 5, 8, G1.", self.table())
        self.assertIn("Proofs run: 10. Failed proofs: 5.", out.stdout)

    def test_negative_one_failing_proof_fails_the_sweep_and_names_its_row(self):
        self.assertEqual(self.run_sweep(GOOD).returncode, 0)
        with open(os.path.join(self.root, "scripts", "proof", "lock.sh"), "w") as f:
            f.write("#!/usr/bin/env bash\necho 'FAIL: injected'\nexit 1\n")
        out = self.run_sweep(GOOD)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("Failed rows: 3.", self.table())
        self.assertIn("FAIL (exit 1): FAIL: injected", self.rows()[("3", "lock")][3])
        self.assertEqual(self.rows()[("1", "ok")][3], "proof_ok")

    def test_a_shipped_row_with_no_proof_fails_the_sweep(self):
        out = self.run_sweep(GOOD.replace("row|3|Lock|lock ok", "row|3|Lock|lock ok\nrow|28|Key expiry|-"))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("| 28 | Key expiry | - | FAIL: no proof for this shipped row |", self.table())
        self.assertIn("Failed rows: 28.", self.table())

    def test_a_bad_manifest_is_a_setup_error(self):
        self.assertEqual(self.run_sweep(GOOD.replace("lock ok", "lock ok nope")).returncode, 2)
        self.assertEqual(self.run_sweep(GOOD + "proof|extra|scripts/proof/ok.sh|-|-\n").returncode, 2)
        self.assertEqual(self.run_sweep(GOOD, only="nope").returncode, 2)

    def test_a_partial_run_never_passes(self):
        out = self.run_sweep(GOOD, only="ok")
        self.assertEqual(out.returncode, 3, out.stdout + out.stderr)
        self.assertIn("not run (ORBLX_SWEEP_ONLY)", self.rows()[("3", "lock")][3])
        self.assertIn("Partial run", self.table())

    def test_the_proof_runs_under_the_lock(self):
        out = self.run_sweep(GOOD, only="lock")
        self.assertEqual(out.returncode, 3, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-lock.log")) as f:
            log = f.read()
        if shutil.which("flock"):
            self.assertIn("proof_lock rc3-sweep:lock acquired", log)
            self.assertIn("proof_lock rc3-sweep:lock released", log)
            self.assertNotIn("held=none", log)

    def test_sweep_lock_mode_holds_one_lock_for_all_proofs(self):
        out = self.run_sweep(GOOD, mode="sweep")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-lock.log")) as f:
            log = f.read()
        if shutil.which("flock"):
            self.assertIn("proof_lock rc3-sweep:testsha acquired", out.stdout)
            self.assertIn("proof_lock rc3-sweep:lock held by the parent proof", log)
            self.assertNotIn("held=none", log)

    def test_the_log_keeps_the_full_unfiltered_proof_output(self):
        out = self.run_sweep(ALL, only="loud steps")
        self.assertEqual(out.returncode, 3, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-loud.log")) as f:
            body = [l for l in f.read().splitlines() if not SWEEP_LINE.match(l)]
        self.assertEqual(body[:100000], [str(i) for i in range(1, 100001)])
        self.assertEqual(body[100000:], ["to stderr", "no newline at end", "proof_ok"])
        with open(os.path.join(self.out, "rc3-sweep-testsha-steps.log")) as f:
            log = f.read()
        self.assertIn("=== release_sweep: step log target/st/run1.log (full) ===\nstep a line\nproof_ok\n", log)
        self.assertIn("=== release_sweep: step log target/st/run2.log (full) ===\nstep b line\n", log)

    def test_plan_lists_every_row_and_proof_and_a_time_estimate(self):
        self.assertEqual(self.run_sweep(GOOD).returncode, 0)
        out = self.run_sweep(GOOD + "row|28|Key expiry|-\n", plan=True)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("| 1 | Mesh | ok | scripts/proof/ok.sh |", out.stdout)
        self.assertIn("| 3 | Lock | lock | scripts/proof/lock.sh |", out.stdout)
        self.assertIn("| 3 | Lock | ok | scripts/proof/ok.sh |", out.stdout)
        self.assertIn("| 28 | Key expiry | - | FAIL: no proof for this shipped row |", out.stdout)
        self.assertIn("Plan FAIL: rows 28.", out.stdout)
        self.assertRegex(out.stdout, r"Estimate: \d+ s \(\d+ min\) for the \d+ proofs with a measure")
        if shutil.which("flock"):
            self.assertRegex(out.stdout, r"\| ok \| 1, 3 \| \d+ \| .*rc3-sweep-testsha-ok\.log \|")

    def test_a_steady_warn_rate_over_one_percent_is_reported_and_does_not_fail(self):
        out = self.run_sweep(NATR)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("steady_warn: 1 of 3 nat-realism runs have a steady_warn line (33.3%). Report only.", out.stdout)
        self.assertIn("steady_warn_rate over 1%: root-cause item (1 of 3 nat-realism runs, 33.3%)", out.stdout)
        self.assertIn("Failed rows: none.", self.table())
        out = self.run_sweep(NATR.replace("natr.sh", "natrq.sh"))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("steady_warn: 0 of 3 nat-realism runs have a steady_warn line (0.0%).", out.stdout)
        self.assertNotIn("steady_warn_rate over 1%", out.stdout)

    def test_too_little_free_disk_stops_the_run_before_any_proof(self):
        out = self.run_sweep(GOOD, min_free_gb="999999999")
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertRegex(out.stderr, r"disk FAIL: only \d+ GB free at .*; the sweep needs at least 999999999 GB free")
        self.assertIn("never counts", out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.out, "rc3-sweep-testsha-ok.log")))
        self.assertEqual(self.run_sweep(GOOD, min_free_gb="lots").returncode, 2)
        self.assertEqual(self.run_sweep(GOOD, min_free_gb="0").returncode, 0)

    def test_the_real_manifest_maps_every_shipped_row(self):
        with open(REAL_MANIFEST) as f:
            lines = [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
        rows = {l.split("|")[1]: l.split("|")[3] for l in lines if l.startswith("row|")}
        partial = {l.split("|")[1]: l.split("|")[3] for l in lines if l.startswith("partial|")}
        proofs = {l.split("|")[1] for l in lines if l.startswith("proof|")}
        # W25-27: the shipped rows of docs/matrix-rows.txt (Page snapshot 2026-10-31 08:10 KST
        # and the PO list). Rows 28 and 29 are not shipped: 28 has no sweep line, 29 is partial.
        self.assertEqual(sorted(rows, key=int), ["19", "21", "24", "30", "31", "32", "33", "35", "38", "45",
                                                 "49", "51", "52", "53", "58", "62", "66"])
        self.assertEqual(sorted(partial, key=int), ["1", "9", "10", "11", "16", "17", "29", "40", "41",
                                                    "54", "61"])
        self.assertNotIn("28", rows)
        self.assertNotIn("28", partial)
        self.assertIn("policy-sync", partial["17"].split())
        self.assertIn("svid-renew", partial["29"].split())
        for row, names in list(rows.items()) + list(partial.items()):
            self.assertNotEqual(names, "-", row)
            for name in names.split():
                self.assertIn(name, proofs, row)

    def test_the_real_manifest_matches_the_real_rows_file(self):
        with open(REAL_ROWS) as f:
            status = {l.split("|")[0]: l.split("|")[1] for l in f if l.strip() and not l.startswith("#")}
        self.assertEqual(len(status), 66)
        for row in ["1", "9", "10", "11", "16", "17", "28", "29", "40", "41", "43", "44", "54", "61"]:
            self.assertEqual(status[row], "partial", row)
        with open(REAL_MANIFEST) as f:
            lines = [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
        shipped = {l.split("|")[1] for l in lines if l.startswith("row|")}
        self.assertEqual(shipped, {r for r, s in status.items() if s == "shipped"})
        for l in lines:
            if l.startswith("partial|"):
                self.assertEqual(status[l.split("|")[1]], "partial", l)

    def test_a_proof_timeout_word_sets_the_time_of_that_proof_only(self):
        # W25-33: ORBLX_SWEEP_PROOF_TIMEOUT=N in the ENV field of one proof.
        manifest = GOOD + "row|5|Slow|slow\nproof|slow|scripts/proof/slow.sh|ORBLX_SWEEP_PROOF_TIMEOUT=1|-\n"
        out = self.run_sweep(manifest)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("FAIL (exit 124, timeout 1 s)", self.rows()[("5", "slow")][3])
        self.assertEqual(self.rows()[("1", "ok")][3], "proof_ok")
        out = self.run_sweep(manifest.replace("TIMEOUT=1|", "TIMEOUT=30|"))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.rows()[("5", "slow")][3], "proof_ok")

    def test_negative_a_bad_proof_timeout_word_is_a_setup_error(self):
        for bad in ["0", "1.5", "x", ""]:
            manifest = GOOD + "row|5|Slow|slow\nproof|slow|scripts/proof/slow.sh|ORBLX_SWEEP_PROOF_TIMEOUT=%s|-\n" % bad
            out = self.run_sweep(manifest, plan=True)
            self.assertEqual(out.returncode, 2, bad + out.stdout + out.stderr)
            self.assertIn("ORBLX_SWEEP_PROOF_TIMEOUT must be a whole number", out.stdout + out.stderr)

    def test_the_real_manifest_gives_the_coordinator_soak_its_own_time(self):
        # W25-33: the soak runs 2 h or more from the coordinator start, more than the default
        # 3600 s of ORBLX_SWEEP_TIMEOUT.
        with open(REAL_MANIFEST) as f:
            lines = [l.rstrip("\n") for l in f if l.startswith("proof|coord-cert-soak|")]
        self.assertEqual(len(lines), 1)
        words = lines[0].split("|")[3].split()
        self.assertIn("ORBLX_SWEEP_PROOF_TIMEOUT=9000", words)
        self.assertEqual(lines[0].split("|")[5], "^proof_ok coord-cert-soak$")

    def test_negative_rows_mismatch_stops_the_sweep_before_any_proof(self):
        good_rows = self.rows_for(GOOD)
        cases = [
            # The manifest says shipped, the rows file says partial.
            (good_rows.replace("3|shipped", "3|partial"), "row 3: manifest row, rows file partial"),
            # The rows file has a shipped row with no manifest line.
            (good_rows + "7|shipped|Seven\n", "row 7: rows file shipped, no manifest row line"),
            # The manifest has a row that the rows file does not list.
            (good_rows.replace("1|shipped|Mesh\n", ""), "row 1: manifest row, rows file not in the rows file"),
        ]
        for rows, want in cases:
            for plan in (False, True):
                shutil.rmtree(self.out, ignore_errors=True)
                out = self.run_sweep(GOOD, rows=rows, plan=plan)
                self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
                self.assertIn("rows mismatch", out.stderr)
                self.assertIn(want, out.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.out, "rc3-sweep-testsha-ok.log")))
        # A partial manifest line for a shipped row is a mismatch too.
        out = self.run_sweep(GOOD.replace("row|3|", "partial|3|"), rows=good_rows)
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("row 3: manifest partial, rows file shipped", out.stderr)
        # The same manifest with a matching rows file runs.
        self.assertEqual(self.run_sweep(GOOD, rows=good_rows).returncode, 0)

    def test_no_rows_file_or_a_bad_one_is_a_setup_error(self):
        out = self.run_sweep(GOOD, rows="")
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        out = self.run_sweep(GOOD, rows=self.rows_for(GOOD) + "4|done|Bad status\n")
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("rows: bad status", out.stderr)
        out = self.run_sweep(GOOD, rows=self.rows_for(GOOD) + "1|shipped|Twice\n")
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("row 1 is listed twice", out.stderr)

    def test_a_partial_row_runs_its_proofs_and_reports_them(self):
        manifest = GOOD + "partial|29|SVID|lock\n"
        out = self.run_sweep(manifest)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.rows()[("29 (partial)", "lock")][3], "proof_ok")
        with open(os.path.join(self.root, "scripts", "proof", "lock.sh"), "w") as f:
            f.write("#!/usr/bin/env bash\necho 'FAIL: injected'\nexit 1\n")
        out = self.run_sweep(manifest)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("Failed rows: 3, 29.", self.table())
        # A partial row with no proof is not a sweep row.
        self.assertEqual(self.run_sweep(GOOD + "partial|28|Key expiry|-\n").returncode, 2)


    def test_the_ssh_proof_is_skipped_only_when_the_rows_file_has_the_mark(self):
        marked = self.rows_for(SSH, {"40": SKIP_MARK, "41": SKIP_MARK})
        for plan in (True, False):  # the run last: its summary is read below
            shutil.rmtree(self.out, ignore_errors=True)
            out = self.run_sweep(SSH, rows=marked, plan=plan)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("release_sweep skip: proof ssh (rows 40 41 ): " + SKIP_MARK, out.stdout)
            self.assertFalse(os.path.exists(os.path.join(self.out, "rc3-sweep-testsha-ssh.log")))
        rows = self.rows()
        for row in ("40 (partial)", "41 (partial)"):
            self.assertEqual(rows[(row, "ssh")][3], "skipped (%s)" % SKIP_MARK)
        self.assertEqual(rows[("1", "ok")][3], "proof_ok")
        self.assertIn("Failed rows: none.", self.table())
        self.assertIn("Skipped (rows file mark): 1.", self.table())

    def test_negative_without_the_mark_the_ssh_proof_runs_and_fails(self):
        cases = [
            self.rows_for(SSH),                       # no mark
            self.rows_for(SSH, {"40": SKIP_MARK}),    # the mark on one of the two rows only
        ]
        for rows in cases:
            shutil.rmtree(self.out, ignore_errors=True)
            out = self.run_sweep(SSH, rows=rows)
            self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
            self.assertNotIn("skip: proof ssh", out.stdout)
            self.assertTrue(os.path.exists(os.path.join(self.out, "rc3-sweep-testsha-ssh.log")))
            self.assertIn("Failed rows: 40, 41.", self.table())

    def test_negative_ssh_row_40_or_41_claiming_shipped_stops_the_sweep(self):
        marked = {"40": SKIP_MARK, "41": SKIP_MARK}
        for row in ("40", "41"):
            # The rows file claims shipped (the manifest still says partial).
            rows = self.rows_for(SSH, marked).replace(row + "|partial|", row + "|shipped|")
            rows = rows.replace("|" + SKIP_MARK, "")
            for plan in (False, True):
                out = self.run_sweep(SSH, rows=rows, plan=plan)
                self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
                self.assertIn("rows: row %s (SSH) claims shipped" % row, out.stderr)
            # Both files claim shipped.
            manifest = SSH.replace("partial|%s|" % row, "row|%s|" % row)
            out = self.run_sweep(manifest, rows=self.rows_for(manifest))
            self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
            self.assertIn("(SSH) claims shipped", out.stderr)
            # Only the manifest claims shipped.
            out = self.run_sweep(manifest, rows=self.rows_for(SSH, marked))
            self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
            self.assertIn("manifest: row %s (SSH) claims shipped" % row, out.stderr)
            self.assertFalse(os.path.exists(os.path.join(self.out, "rc3-sweep-testsha-ok.log")))

    def test_negative_a_bad_4th_field_or_the_mark_on_a_shipped_row_is_a_setup_error(self):
        out = self.run_sweep(SSH, rows=self.rows_for(SSH, {"40": "skip me", "41": SKIP_MARK}))
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("rows: row 40 has an unknown 4th field", out.stderr)
        out = self.run_sweep(SSH, rows=self.rows_for(SSH, {"1": SKIP_MARK, "40": SKIP_MARK, "41": SKIP_MARK}))
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("rows: row 1 is shipped and has the skip mark", out.stderr)

    def test_the_real_rows_file_marks_both_ssh_rows(self):
        with open(REAL_ROWS) as f:
            lines = [l.rstrip("\n").split("|") for l in f if l.strip() and not l.startswith("#")]
        marked = sorted(c[0] for c in lines if len(c) > 3)
        self.assertEqual(marked, ["40", "41"])
        for c in lines:
            if c[0] in ("40", "41"):
                self.assertEqual(c[1:], ["partial", c[2], SKIP_MARK])


    def test_plan_shows_the_old_binary_build_step_of_a_pinned_proof(self):
        out = self.run_sweep(OLD % PIN, plan=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        want = "| old | build old orblx (debug) at %s in a temp worktree, cache %s |" % (
            PIN, os.path.join(self.tmp, "work", "old-orblx", PIN, "orblx"))
        self.assertIn(want, out.stdout)
        # OLD_ORBLX from the caller wins: no build.
        out = self.run_sweep(OLD % PIN, plan=True, extra_env={"OLD_ORBLX": "/bin/true"})
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("| old | OLD_ORBLX from the environment: /bin/true (no build) |", out.stdout)
        # A plan with no pinned proof has no old-binary table.
        self.assertNotIn("old-binary step", self.run_sweep(GOOD, plan=True).stdout)

    def test_negative_a_missing_or_bad_old_binary_pin_stops_the_sweep(self):
        cases = [
            (GOOD + "row|32|User approval|old\nproof|old|scripts/proof/old.sh|-|-\n",
             "proof old needs OLD_ORBLX (its script requires it), and its manifest line has no"),
            (OLD % PIN[:8], "bad old-binary pin '%s'" % PIN[:8]),
            (OLD % PIN.upper(), "bad old-binary pin"),
            (OLD % ("g" + PIN[1:]), "bad old-binary pin"),
            (OLD % "", "bad old-binary pin ''"),
            (OLD.replace("OLD_ORBLX=@OLD:", "OTHER=@OLD:") % PIN, "must be the value of OLD_ORBLX"),
        ]
        for manifest, want in cases:
            for plan in (True, False):
                shutil.rmtree(self.out, ignore_errors=True)
                out = self.run_sweep(manifest, plan=plan)
                self.assertEqual(out.returncode, 2, want + out.stdout + out.stderr)
                self.assertIn(want, out.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.out, "rc3-sweep-testsha-ok.log")))

    def test_the_proof_gets_the_old_binary_and_a_bad_OLD_ORBLX_stops_the_run(self):
        fake = os.path.join(self.tmp, "old-orblx")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(fake, 0o755)
        out = self.run_sweep(OLD % PIN, extra_env={"OLD_ORBLX": fake})
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-old.log")) as f:
            self.assertIn("old=" + fake + "\n", f.read())
        # With no OLD_ORBLX the proof gets the cache path of the pin.
        out = self.run_sweep(OLD % PIN)
        with open(os.path.join(self.out, "rc3-sweep-testsha-old.log")) as f:
            self.assertIn("old=" + os.path.join(self.tmp, "work", "old-orblx", PIN, "orblx"), f.read())
        out = self.run_sweep(OLD % PIN, extra_env={"OLD_ORBLX": os.path.join(self.tmp, "nothing")})
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("is not an executable file", out.stderr)

    def test_the_real_manifest_pins_user_approval_to_the_pre_w25_15_commit(self):
        with open(REAL_MANIFEST) as f:
            line = [l.rstrip("\n") for l in f if l.startswith("proof|user-approval|")]
        self.assertEqual(len(line), 1)
        self.assertEqual(line[0].split("|")[3], "OLD_ORBLX=@OLD:%s@" % PIN)


if __name__ == "__main__":
    unittest.main()

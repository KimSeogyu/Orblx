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

from fake_docker import fake_cargo_home, with_fake_docker

HERE = os.path.dirname(os.path.abspath(__file__))
SWEEP = os.path.join(HERE, "..", "release-sweep.sh")
REAL_MANIFEST = os.path.join(HERE, "..", "sweep-manifest.txt")

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

    def run_sweep(self, manifest, only=None, mode=None, plan=False, min_free_gb=None):
        path = os.path.join(self.tmp, "manifest.txt")
        with open(path, "w") as f:
            f.write(manifest)
        # W25-35: the sampler of the proof lock uses a docker stand-in, which prints no names.
        env = with_fake_docker(dict(os.environ))
        env.update({
            "ORBLX_SWEEP_TEST_ROOT": self.root,
            "ORBLX_SWEEP_OUT": self.out,
            "ORBLX_SWEEP_MANIFEST": path,
            "ORBLX_PROOF_LOCK": os.path.join(self.tmp, "proof.lock"),
            "ORBLX_SWEEP_TIMEOUT": "60",
            "ORBLX_SWEEP_MIN_FREE_GB": "0",
            # release-sweep.sh sets PATH for each proof; its first dir is "$CARGO_HOME/bin".
            "CARGO_HOME": fake_cargo_home(),
        })
        if only is not None:
            env["ORBLX_SWEEP_ONLY"] = only
        if mode is not None:
            env["ORBLX_SWEEP_LOCK_MODE"] = mode
        if min_free_gb is not None:
            env["ORBLX_SWEEP_MIN_FREE_GB"] = min_free_gb
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
        proofs = {l.split("|")[1] for l in lines if l.startswith("proof|")}
        for row in ["1", "9", "10", "11", "16", "17", "19", "21", "24", "28", "29", "30", "31", "33", "35",
                    "38", "40", "41", "45", "49", "51", "52", "53", "54", "58", "61", "62"]:
            self.assertIn(row, rows)
        self.assertIn("policy-sync", rows["17"].split())
        for row, names in rows.items():
            for name in names.split():
                if name != "-":
                    self.assertIn(name, proofs, row)


if __name__ == "__main__":
    unittest.main()

"""rc.3 release sweep: the sweep runs every proof, keeps going after a failure,
writes one table row for each proof, and exits 1 when a proof failed.

The test uses ORBLX_SWEEP_TEST_ROOT: no git, no build, no sudo, no Docker.
The proofs are small shell scripts in a temporary checkout.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWEEP = os.path.join(HERE, "..", "release-sweep.sh")

PROOFS = {
    "ok.sh": "echo step one\necho proof_ok\n",
    "fail.sh": "echo step one\necho 'error: the peer did not answer'\necho later line\nexit 3\n",
    "skip.sh": "echo 'The proof needs root. The script skips the proof.'\nexit 0\n",
    "pipe.sh": "set -o pipefail\nseq 1 200000 | cat >/dev/null\necho 'proof_ok extra 1'\n",
    "lock.sh": "echo held=${ORBLX_PROOF_LOCK_HELD:-none}\necho proof_ok\n",
    "quiet.sh": "echo 'nothing to see'\nexit 5\n",
    "steps.sh": "mkdir -p target/st\nprintf 'step a line\\nproof_ok\\n' >target/st/run1.log\nprintf 'step b line\\n' >target/st/run2.log\necho 'gate_x ok: 2 runs'\n",
    "gatefail.sh": "echo proof_ok\necho 'gate_x failed: median low'\n",
    "loud.sh": "seq 1 100000\necho 'to stderr' >&2\nprintf 'no newline at end'\necho\necho proof_ok\n",
}

LIST = "\n".join([
    "ok|scripts/proof/ok.sh|1, 2|-|-",
    "fail|scripts/proof/fail.sh|3|-|-",
    "skip|scripts/proof/skip.sh|4|-|-",
    "missing|scripts/proof/missing.sh|5|-|-",
    "pipe|scripts/proof/pipe.sh|6|-|-",
    "lock|scripts/proof/lock.sh|7|-|-",
    "quiet|scripts/proof/quiet.sh|8|-|-",
    "loud|scripts/proof/loud.sh|9|-|-",
])
GATE_LIST = "\n".join([
    "steps|scripts/proof/steps.sh|gate|-|-|^gate_x ok: |target/st/run*.log",
    "gatefail|scripts/proof/gatefail.sh|gate|-|-|^gate_x ok: ",
])


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

    def run_sweep(self, only=None, mode=None, plist=LIST):
        env = dict(os.environ)
        env.update({
            "ORBLX_SWEEP_TEST_ROOT": self.root,
            "ORBLX_SWEEP_OUT": self.out,
            "ORBLX_SWEEP_LIST": plist,
            "ORBLX_PROOF_LOCK": os.path.join(self.tmp, "proof.lock"),
            "ORBLX_SWEEP_TIMEOUT": "60",
        })
        if only is not None:
            env["ORBLX_SWEEP_ONLY"] = only
        if mode is not None:
            env["ORBLX_SWEEP_LOCK_MODE"] = mode
        return subprocess.run(["bash", SWEEP, "testsha"], env=env, capture_output=True, text=True)

    def rows(self):
        with open(os.path.join(self.out, "rc3-sweep-testsha.md")) as f:
            lines = [l for l in f.read().splitlines() if l.startswith("| ") and not l.startswith("| proof ")]
        return {l.split(" | ")[0][2:]: l for l in lines}

    def test_every_proof_runs_and_a_failure_fails_the_sweep(self):
        out = self.run_sweep()
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        rows = self.rows()
        self.assertEqual(sorted(rows), sorted(["ok", "fail", "skip", "missing", "pipe", "lock", "quiet", "loud"]))
        self.assertTrue(rows["ok"].endswith("| proof_ok |"))
        self.assertIn("| 1, 2 |", rows["ok"])
        self.assertIn(os.path.join(self.out, "rc3-sweep-testsha-ok.log"), rows["ok"])
        self.assertIn("FAIL (exit 3): error: the peer did not answer", rows["fail"])
        self.assertIn("FAIL (exit 0, no proof_ok line)", rows["skip"])
        self.assertIn("FAIL (exit 127): release_sweep: No such file scripts/proof/missing.sh", rows["missing"])
        self.assertTrue(rows["pipe"].endswith("| proof_ok |"))
        self.assertIn("FAIL (exit 5): (no error line; last line) nothing to see", rows["quiet"])
        self.assertIn("Proofs: 8. Failed: 4.", out.stdout)

    def test_the_proof_runs_under_the_lock(self):
        out = self.run_sweep(only="lock")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-lock.log")) as f:
            log = f.read()
        if shutil.which("flock"):
            self.assertIn("proof_lock rc3-sweep:lock acquired", log)
            self.assertIn("proof_lock rc3-sweep:lock released", log)
            self.assertNotIn("held=none", log)
        self.assertEqual(list(self.rows()), ["lock"])

    def test_sweep_lock_mode_holds_one_lock_for_all_proofs(self):
        out = self.run_sweep(only="lock ok", mode="sweep")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-lock.log")) as f:
            log = f.read()
        if shutil.which("flock"):
            self.assertIn("proof_lock rc3-sweep:testsha acquired", out.stdout)
            self.assertIn("proof_lock rc3-sweep:lock held by the parent proof", log)
            self.assertNotIn("held=none", log)
        self.assertEqual(sorted(self.rows()), ["lock", "ok"])

    def test_the_log_keeps_the_full_unfiltered_proof_output(self):
        out = self.run_sweep(only="loud")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(os.path.join(self.out, "rc3-sweep-testsha-loud.log")) as f:
            lines = f.read().splitlines()
        body = [l for l in lines if not l.startswith(("proof_lock ", "proof_context ", "proof_contention ", "release_sweep: "))]
        self.assertEqual(body[:100000], [str(i) for i in range(1, 100001)])
        self.assertEqual(body[100000:], ["to stderr", "no newline at end", "proof_ok"])

    def test_a_pass_line_and_step_logs_of_a_proof(self):
        out = self.run_sweep(plist=GATE_LIST)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        rows = self.rows()
        self.assertTrue(rows["steps"].endswith("| proof_ok |"), rows["steps"])
        # proof_ok alone is not the pass line of this proof.
        self.assertIn("FAIL (exit 0, no pass line ^gate_x ok: ): gate_x failed: median low", rows["gatefail"])
        with open(os.path.join(self.out, "rc3-sweep-testsha-steps.log")) as f:
            log = f.read()
        self.assertIn("=== release_sweep: step log target/st/run1.log (full) ===\nstep a line\nproof_ok\n", log)
        self.assertIn("=== release_sweep: step log target/st/run2.log (full) ===\nstep b line\n", log)

    def test_unknown_proof_name_is_refused(self):
        out = self.run_sweep(only="nope")
        self.assertEqual(out.returncode, 2)


if __name__ == "__main__":
    unittest.main()

"""W25-14b: proof_disk_check in proof-lock.sh runs before the lock and before any build.

Below the minimum, or when the free space is not known, the proof prints a proof_infra_abort
line and stops with exit status 4. Status 3 stays proof_contention_invalid.
"""

import glob
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from fake_docker import with_fake_docker

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF_DIR = os.path.dirname(HERE)
LOCK_SH = os.path.join(PROOF_DIR, "proof-lock.sh")

SCRIPT = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take disk-test orblx-test-
echo proof_step_ran
"""


class ProofDiskCheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.env = with_fake_docker(dict(
            os.environ,
            LOCK_SH=LOCK_SH,
            ORBLX_PROOF_LOCK=os.path.join(self.dir, "proof.lock"),
            ORBLX_PROOF_SAMPLE_SECS="1",
        ))
        self.env.pop("ORBLX_PROOF_LOCK_HELD", None)
        self.env.pop("PROOF_MIN_FREE_GIB", None)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_proof(self, **extra):
        env = dict(self.env, **extra)
        return subprocess.run(["bash", "-c", SCRIPT], env=env, capture_output=True,
                              text=True, timeout=60)

    def assert_abort(self, result, reason):
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertRegex(result.stderr,
                         rf"(?m)^proof_infra_abort disk-test reason={reason}\b.*No proof step ran\.$")
        self.assertNotIn("proof_step_ran", result.stdout)
        self.assertNotIn("proof_lock disk-test acquired", result.stdout)

    def test_low_disk_aborts_before_the_lock(self):
        result = self.run_proof(PROOF_MIN_FREE_GIB="12", FAKE_DF_AVAIL_KIB=str(11 * 1048576))
        self.assert_abort(result, "disk_low")
        self.assertIn("free_gib=11 min_gib=12", result.stderr)

    def test_unknown_disk_aborts(self):
        self.assert_abort(self.run_proof(PROOF_MIN_FREE_GIB="12", FAKE_DF_FAIL="1"),
                          "disk_unknown")

    def test_unset_minimum_aborts(self):
        self.assert_abort(self.run_proof(), "min_unset")

    def test_minimum_below_the_floor_aborts(self):
        result = self.run_proof(PROOF_MIN_FREE_GIB="11")
        self.assert_abort(result, "min_below_floor")
        self.assertIn("floor_gib=12", result.stderr)

    @unittest.skipUnless(shutil.which("flock"), "flock(1) is not installed")
    def test_enough_disk_runs_the_proof(self):
        result = self.run_proof(PROOF_MIN_FREE_GIB="12", FAKE_DF_AVAIL_KIB=str(12 * 1048576))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("proof_step_ran", result.stdout)
        self.assertNotIn("proof_infra_abort", result.stderr)

    def test_the_abort_status_is_not_the_invalid_status(self):
        src = open(LOCK_SH).read()
        self.assertIn("PROOF_DISK_FLOOR_GIB=12", src)
        self.assertIn("PROOF_INFRA_ABORT_EXIT=4", src)
        take = src.index("proof_lock_take() {")
        self.assertLess(src.index('proof_disk_check "$1"', take),
                        src.index("proof_lock_file", take))

    def test_each_proof_sets_its_minimum_before_the_lock_and_the_build(self):
        checked = 0
        for path in sorted(glob.glob(os.path.join(PROOF_DIR, "*.sh"))):
            src = open(path).read()
            if os.path.basename(path) == "proof-lock.sh" or "proof_lock_take" not in src:
                continue
            checked += 1
            name = os.path.basename(path)
            m = re.search(r"(?m)^(?:export )?PROOF_MIN_FREE_GIB=(\d+)", src)
            self.assertIsNotNone(m, name)
            self.assertGreaterEqual(int(m.group(1)), 12, name)
            self.assertIn("reason", src[m.start() - 200:m.end() + 200], name)
            take = re.search(r"(?m)^\s*proof_lock_take ", src)
            self.assertLess(m.start(), take.start(), name)
            if name == "release-sweep.sh":
                # The sweep checks 30 GB itself before its build (exit 2). Its proofs check again.
                continue
            build = re.search(r"(?m)^\s*(cargo build|docker build|sudo -n docker build)", src)
            if build:
                calls = [x.start() for x in re.finditer(r"(?m)^\s*proof_lock_take ", src)]
                # The build is in a function or at top level. Either way the lock call comes
                # first in run order when it comes first in the file or the function is called
                # after it.
                if calls[0] > build.start():
                    funcs = re.findall(r"(?m)^(\w+)\(\) \{", src[:build.start()])
                    self.assertTrue(funcs, name)
                    first_call = re.search(rf"(?m)^\s*{funcs[-1]}\b(?!\(\))", src)
                    self.assertIsNotNone(first_call, name)
                    self.assertLess(calls[0], first_call.start(), name)
        self.assertGreater(checked, 40)


if __name__ == "__main__":
    unittest.main()

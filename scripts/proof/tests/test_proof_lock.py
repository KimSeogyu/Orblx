"""W25-5: the box proof lock runs two proofs one after the other.

Two shells source proof-lock.sh with the same lock file and hold it for a short time.
The test checks that the hold intervals do not overlap, that the second shell waits
and prints the holder, and that each shell prints the proof_context lines.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK_SH = os.path.join(os.path.dirname(HERE), "proof-lock.sh")

HOLDER = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take "$LABEL" orblx-test-
echo "hold_start $LABEL $(date +%s%3N)"
# A proof may wait for all of its own jobs. The sampler must not be one of them.
sleep "$HOLD" &
wait
echo "hold_end $LABEL $(date +%s%3N)"
"""

CHILD = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take child orblx-test-
echo child_ran
"""


@unittest.skipUnless(shutil.which("flock"), "flock(1) is not installed")
class ProofLockTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.env = dict(os.environ)
        self.env.update(
            LOCK_SH=LOCK_SH,
            ORBLX_PROOF_LOCK=os.path.join(self.dir, "proof.lock"),
            ORBLX_PROOF_LOCK_NOTE_SECS="1",
            ORBLX_PROOF_SAMPLE_SECS="1",
        )
        self.env.pop("ORBLX_PROOF_LOCK_HELD", None)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def start(self, label, hold):
        env = dict(self.env, LABEL=label, HOLD=str(hold))
        return subprocess.Popen(
            ["bash", "-c", HOLDER], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

    @staticmethod
    def times(out, label):
        start = int(re.search(rf"^hold_start {label} (\d+)$", out, re.M).group(1))
        end = int(re.search(rf"^hold_end {label} (\d+)$", out, re.M).group(1))
        return start, end

    def test_two_proofs_run_one_after_the_other(self):
        first = self.start("one", 2.5)
        # communicate() has a timeout, so a wait for the sampler fails the test.
        time.sleep(0.3)
        second = self.start("two", 0.2)
        out_one, _ = first.communicate(timeout=60)
        out_two, _ = second.communicate(timeout=60)
        self.assertEqual(first.returncode, 0, out_one)
        self.assertEqual(second.returncode, 0, out_two)
        one = self.times(out_one, "one")
        two = self.times(out_two, "two")
        self.assertGreaterEqual(two[0], one[1], f"overlap: one {one} two {two}")
        self.assertIn("proof_lock two waiting", out_two)
        self.assertIn("label=one", out_two)
        self.assertIn("still waiting", out_two)
        for out, label in ((out_one, "one"), (out_two, "two")):
            for phase in ("queued", "start", "end"):
                self.assertRegex(out, rf"proof_context {label} phase {phase} time \S+ load \S+ other_orblx_containers (\d+|unknown)")
            self.assertRegex(out, rf"proof_contention {label} samples \d+ contended_samples \d+ unknown_samples \d+")
            self.assertIn(f"proof_lock {label} released", out)

    def test_a_child_of_the_holder_does_not_wait(self):
        parent = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take parent orblx-test-
bash -c "$CHILD"
"""
        env = dict(self.env, CHILD=CHILD)
        out = subprocess.run(
            ["bash", "-c", parent], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30
        ).stdout
        self.assertIn("proof_lock child held by the parent proof", out)
        self.assertIn("child_ran", out)

    def test_a_stale_held_value_does_not_skip_the_lock(self):
        env = dict(self.env, ORBLX_PROOF_LOCK_HELD="1")
        out = subprocess.run(
            ["bash", "-c", CHILD], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30
        ).stdout
        self.assertIn("proof_lock child acquired", out)

    def test_the_lock_is_free_after_the_holder_ends(self):
        first = self.start("one", 0.1)
        first.communicate(timeout=30)
        free = subprocess.run(["flock", "-n", self.env["ORBLX_PROOF_LOCK"], "true"])
        self.assertEqual(free.returncode, 0)


if __name__ == "__main__":
    unittest.main()

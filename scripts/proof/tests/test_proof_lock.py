"""W25-5: the box proof lock runs two proofs one after the other.

Two shells source proof-lock.sh with the same lock file and hold it for a short time.
The test checks that the hold intervals do not overlap, that the second shell waits
and prints the holder, and that each shell prints the proof_context lines.
"""

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from fake_docker import FAILS, SUDO, SUDO_FAILS, with_fake_docker

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK_SH = os.path.join(os.path.dirname(HERE), "proof-lock.sh")

# Hold lines use a monotonic clock. `date +%s%3N` is CLOCK_REALTIME: a step
# backward between hold_end and the next hold_start looks like overlap
# (run 41940783765, 204 ms) while the fifo flock is still held by the first proof.
HOLDER = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take "$LABEL" orblx-test
hold_ms() {
  if [[ -r /proc/uptime ]]; then
    awk '{printf "%d\n", $1 * 1000}' /proc/uptime
  else
    python3 -c 'import time; print(time.monotonic_ns() // 1000000)'
  fi
}
echo "hold_start $LABEL $(hold_ms)"
# A proof may wait for all of its own jobs. The sampler must not be one of them.
sleep "$HOLD" &
wait
echo "hold_end $LABEL $(hold_ms)"
"""

CHILD = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take child orblx-test
echo child_ran
"""


@unittest.skipUnless(shutil.which("flock"), "flock(1) is not installed")
class ProofLockTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.env = dict(os.environ)
        self.env.update(
            LOCK_SH=LOCK_SH,
            PROOF_MIN_FREE_GIB="15",
            ORBLX_PROOF_LOCK=os.path.join(self.dir, "proof.lock"),
            ORBLX_PROOF_LOCK_NOTE_SECS="1",
            ORBLX_PROOF_SAMPLE_SECS="1",
        )
        self.env.pop("ORBLX_PROOF_LOCK_HELD", None)
        # W25-35: the sampler uses this docker stand-in, which prints no names.
        self.env = with_fake_docker(self.env)

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
        # W25-14: the waiter prints the wait time, the queue position, and the holder.
        self.assertGreaterEqual(len(re.findall(r"waiting for lock, \d+ s, position \d+, .*holder: label=one", out_two)), 2, out_two)
        for out, label in ((out_one, "one"), (out_two, "two")):
            for phase in ("queued", "start", "end"):
                self.assertRegex(out, rf"proof_context {label} phase {phase} time \S+ load \S+ other_orblx_containers (\d+|unknown)")
            self.assertRegex(out, rf"proof_contention {label} samples \d+ contended_samples \d+ unknown_samples \d+")
            self.assertIn(f"proof_lock {label} released", out)

    def test_the_hold_clock_stays_monotonic_when_realtime_steps_backward(self):
        # The old holder used `date +%s%3N` for both lines. This stands in for that
        # clock and steps backward. hold_ms must not follow it.
        found = re.search(r"(hold_ms\(\) \{.*?^\})", HOLDER, re.M | re.S)
        self.assertIsNotNone(found, HOLDER)
        bin_dir = os.path.join(self.dir, "bin")
        os.makedirs(bin_dir)
        seq = os.path.join(self.dir, "date-seq")
        with open(os.path.join(bin_dir, "date"), "w") as fh:
            fh.write(
                "#!/bin/sh\n"
                'n=2000000000000\n'
                '[ -f "$FAKE_DATE_SEQ" ] && n=$(cat "$FAKE_DATE_SEQ")\n'
                'echo "$n"\n'
                'echo $((n - 500)) >"$FAKE_DATE_SEQ"\n'
            )
        os.chmod(os.path.join(bin_dir, "date"), 0o755)
        env = dict(self.env, PATH=bin_dir + os.pathsep + self.env.get("PATH", ""), FAKE_DATE_SEQ=seq)

        def read_hold():
            out = subprocess.check_output(["bash", "-c", found.group(1) + "\nhold_ms\n"], env=env, text=True)
            return int(out.strip())

        first = read_hold()
        second = read_hold()
        self.assertGreaterEqual(second, first)
        realtime = [
            int(subprocess.check_output(["date", "+%s%3N"], env=env, text=True).strip())
            for _ in range(2)
        ]
        self.assertLess(realtime[1], realtime[0])

    def test_a_child_of_the_holder_does_not_wait(self):
        parent = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take parent orblx-test
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

    def run_holder(self, env, label, hold):
        env = dict(env, LABEL=label, HOLD=str(hold))
        return subprocess.run(["bash", "-c", HOLDER], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=60)

    def test_a_run_with_unknown_samples_fails_and_says_it_is_not_valid(self):
        # W25-35 + W25-46: when docker ps fails at acquire, proof_foreign_check aborts with
        # containers_unknown (exit 5) before any proof step. The lock is released.
        env = with_fake_docker(self.env, docker=FAILS, sudo=SUDO_FAILS)
        res = self.run_holder(env, "blind", 1.5)
        self.assertEqual(res.returncode, 5, res.stdout)
        self.assertIn("proof_infra_abort blind reason=containers_unknown names=none. No proof step ran.",
                      res.stdout + (res.stderr or ""))
        self.assertIn("other_orblx_containers unknown", res.stdout)
        self.assertIn("proof_lock blind released", res.stdout)
        free = subprocess.run(["flock", "-n", self.env["ORBLX_PROOF_LOCK"], "true"])
        self.assertEqual(free.returncode, 0)

    @unittest.skipIf(os.geteuid() == 0, "the sudo fallback is for a user that is not root")
    def test_the_sampler_uses_sudo_when_the_user_cannot_use_docker(self):
        # W25-35 + W25-46: sudo -n docker is used when docker ps fails. A foreign orblx
        # container at acquire aborts with foreign_containers (exit 5). That proves the
        # sudo path returned names (not containers_unknown).
        docker = (
            "#!/bin/sh\n"
            '[ -n "$FAKE_VIA_SUDO" ] || exit 1\n'
            'printf "orblx-other-1\tother-project\n"\n'
            'printf "other-app\t\n"\n'
        )
        env = with_fake_docker(self.env, docker=docker, sudo=SUDO)
        res = self.run_holder(env, "seen", 1.5)
        self.assertEqual(res.returncode, 5, res.stdout)
        self.assertIn("proof_infra_abort seen reason=foreign_containers names=orblx-other-1",
                      res.stdout + (res.stderr or ""))
        self.assertIn("proof_lock seen released", res.stdout)
        free = subprocess.run(["flock", "-n", self.env["ORBLX_PROOF_LOCK"], "true"])
        self.assertEqual(free.returncode, 0)


    def test_a_run_with_known_samples_has_no_invalid_line(self):
        res = self.run_holder(self.env, "clear", 1.5)
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertRegex(res.stdout, r"(?m)^proof_contention clear samples [1-9]\d* contended_samples 0 unknown_samples 0 ")
        self.assertNotIn("proof_contention_invalid", res.stdout)


    def test_a_killed_holder_gets_a_release_line_with_its_pid(self):
        # W25-46: SIGKILL skips the EXIT trap. The next taker must print
        # "proof_lock LABEL released at TIME pid=PID reason=killed_holder_cleared_by_next".
        holder = self.start("victim", 30)
        time.sleep(0.5)
        out_so_far = ""
        # Wait until the holder has the lock and wrote its holder file.
        victim_pid = None
        for _ in range(50):
            time.sleep(0.1)
            if holder.poll() is not None:
                break
            holder_file = self.env["ORBLX_PROOF_LOCK"] + ".holder"
            if os.path.isfile(holder_file):
                with open(holder_file) as hf:
                    text = hf.read()
                if "label=victim" in text and "pid=" in text:
                    m = re.search(r"(?m)^pid=(\d+)$", text)
                    if m:
                        victim_pid = int(m.group(1))
                        break
        else:
            holder.kill()
            self.fail("holder did not write the holder file")
        self.assertIsNotNone(victim_pid)
        holder.kill()  # SIGKILL: no EXIT trap, no proof_lock_end
        holder.wait(timeout=10)
        # Next taker clears the dead holder record and must log the release.
        res = self.run_holder(self.env, "next", 0.2)
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertRegex(
            res.stdout,
            rf"(?m)^proof_lock victim released at \S+ pid={victim_pid} reason=killed_holder_cleared_by_next$",
            res.stdout,
        )
        self.assertRegex(
            res.stdout,
            r"(?m)^proof_lock next released at \S+ pid=\d+$",
            res.stdout,
        )

    def test_sigkill_with_live_containers_aborts_before_the_proof_step(self):
        # The killed-holder release line is test_a_killed_holder_gets_a_release_line_with_its_pid.
        # The foreign abort before a proof step is test_proof_foreign_check.py. This test chains
        # them: SIGKILL leaves the holder's compose rows up, and the next proof_lock_take must
        # abort before its proof step.
        docker = (
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then\n'
            "  printf 'orblx-victim-1\\torblx-victim\\n'\n"
            "  exit 0\n"
            "fi\n"
            "exit 0\n"
        )
        env = with_fake_docker(self.env, docker=docker)
        script = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take "$LABEL" "$OWN"
echo "proof_step_ran $LABEL"
sleep "$HOLD"
"""
        holder_env = dict(env, LABEL="victim", OWN="orblx-victim", HOLD="30")
        holder = subprocess.Popen(
            ["bash", "-c", script],
            env=holder_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        victim_pid = None
        try:
            for _ in range(50):
                time.sleep(0.1)
                if holder.poll() is not None:
                    break
                holder_file = env["ORBLX_PROOF_LOCK"] + ".holder"
                if os.path.isfile(holder_file):
                    with open(holder_file) as handle:
                        text = handle.read()
                    if "label=victim" in text:
                        found = re.search(r"(?m)^pid=(\d+)$", text)
                        if found:
                            victim_pid = int(found.group(1))
                            break
            else:
                self.fail("holder did not write the holder file")
            self.assertIsNotNone(victim_pid)
            # SIGKILL the holder and the children that inherited the lock fd.
            # A child sleep would keep the flock after the shell dies.
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=10)
            if holder.stdout is not None:
                holder.stdout.close()
        except Exception:
            if holder.poll() is None:
                os.killpg(holder.pid, signal.SIGKILL)
            if holder.stdout is not None:
                holder.stdout.close()
            raise
        next_env = dict(env, LABEL="next", OWN="orblx-next", HOLD="0.2")
        result = subprocess.run(
            ["bash", "-c", script],
            env=next_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        combined = result.stdout or ""
        self.assertEqual(result.returncode, 5, combined)
        self.assertIn(
            "proof_infra_abort next reason=foreign_containers names=orblx-victim-1. No proof step ran.",
            combined,
        )
        self.assertNotIn("proof_step_ran next", combined)
        self.assertNotIn("phase start", combined)
        self.assertRegex(
            combined,
            rf"(?m)^proof_lock victim released at \S+ pid={victim_pid} reason=killed_holder_cleared_by_next$",
        )
        free = subprocess.run(["flock", "-n", env["ORBLX_PROOF_LOCK"], "true"])
        self.assertEqual(free.returncode, 0)

    def test_the_lock_is_free_after_the_holder_ends(self):
        first = self.start("one", 0.1)
        first.communicate(timeout=30)
        free = subprocess.run(["flock", "-n", self.env["ORBLX_PROOF_LOCK"], "true"])
        self.assertEqual(free.returncode, 0)


if __name__ == "__main__":
    unittest.main()

"""W25-19: proof lock fairness.

The tests check that:
- the ticket is made before the first proof_context line (that line runs docker ps, which can be slow);
- a proof from an old checkout (a plain flock of the lock file) cannot pass a FIFO waiter;
- a W25-14 waiter (an old checkout with the ticket queue) keeps its place in the queue;
- a proof that runs under a plain flock of the lock file stops at once with a message;
- that check stays fast when an ancestor has many fds;
- no proof script on this branch calls flock itself.
The old libraries are copies of scripts/proof/proof-lock.sh at d0ddf7f (W25-5) and 9d53d3c (W25-14).
"""

import fcntl
import glob
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest

from fake_docker import with_fake_docker

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
LIB = os.path.join(REPO, "scripts", "proof", "proof-lock.sh")
LIB_W25_5 = os.path.join(HERE, "fixtures", "proof-lock-w25-5-d0ddf7f.sh")
LIB_W25_14 = os.path.join(HERE, "fixtures", "proof-lock-w25-14-9d53d3c.sh")

# A stand-in proof: take the lock, write start and end times, hold the lock for $3 s.
PROOF = (
    '. "$0"; trap proof_lock_end EXIT; proof_lock_take "$1"; '
    'echo "start $1 $(date +%s%3N)" >>"$2"; sleep "$3"; echo "end $1 $(date +%s%3N)" >>"$2"'
)

HAS_FLOCK = shutil.which("flock") is not None and os.path.isdir("/proc/self/fdinfo")


@unittest.skipUnless(HAS_FLOCK, "flock(1) or /proc/PID/fdinfo is not on this host")
class ProofLockFairnessTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lock = os.path.join(self.dir, "proof.lock")
        self.order = os.path.join(self.dir, "order")
        self.env = dict(os.environ, ORBLX_PROOF_LOCK=self.lock, ORBLX_PROOF_LOCK_NOTE_SECS="1",
                        ORBLX_PROOF_SAMPLE_SECS="1", PROOF_MIN_FREE_GIB="15")
        self.env.pop("ORBLX_PROOF_LOCK_HELD", None)
        # W25-35: the sampler uses a docker stand-in, which prints no names.
        self.env = with_fake_docker(self.env)
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        shutil.rmtree(self.dir, ignore_errors=True)

    def start(self, lib, label, hold, mark):
        """Start a stand-in proof and read its output until the line that contains mark."""
        proc = subprocess.Popen(["bash", "-c", PROOF, lib, label, self.order, str(hold)], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.procs.append(proc)
        head = ""
        while mark not in head:
            line = proc.stdout.readline()
            self.assertTrue(line, f"{label} ended before {mark!r}: {head}")
            head += line
        return proc, head

    def finish(self, started):
        outs = []
        for proc, head in started:
            out = head + proc.communicate(timeout=60)[0]
            self.assertEqual(proc.returncode, 0, out)
            outs.append(out)
        with open(self.order) as f:
            events = [line.split() for line in f.read().split("\n") if line]
        # One proof at a time: each start comes after the end of the one before.
        self.assertEqual([e[0] for e in events], ["start", "end"] * len(started), events)
        return events, outs

    @staticmethod
    def first_docker_call_saw(env, lib, queue):
        """Run proof_lock_take once with a docker stand-in that counts the tickets in the queue."""
        bin_dir = tempfile.mkdtemp()
        seen = os.path.join(bin_dir, "seen")
        with open(os.path.join(bin_dir, "docker"), "w") as f:
            f.write(f'#!/bin/sh\nls "{queue}" 2>/dev/null | wc -l >>"{seen}"\nexit 1\n')
        os.chmod(os.path.join(bin_dir, "docker"), 0o755)
        env = dict(env, PATH=bin_dir + os.pathsep + env["PATH"])
        res = subprocess.run(["bash", "-c", '. "$0"; trap proof_lock_end EXIT; proof_lock_take ticket', lib],
                             env=env, capture_output=True, text=True, timeout=30)
        with open(seen) as f:
            counts = [int(x) for x in f.read().split()]
        shutil.rmtree(bin_dir, ignore_errors=True)
        return res, counts

    def test_the_ticket_is_made_before_the_first_proof_context_line(self):
        res, counts = self.first_docker_call_saw(self.env, LIB, self.lock + ".queue")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(counts[0], 1, "the first docker ps call ran before the ticket was made")
        # The W25-14 library made the ticket after that call. The check sees the difference.
        old_env = dict(self.env, ORBLX_PROOF_LOCK=os.path.join(self.dir, "old.lock"))
        _, old_counts = self.first_docker_call_saw(old_env, LIB_W25_14, old_env["ORBLX_PROOF_LOCK"] + ".queue")
        self.assertEqual(old_counts[0], 0)

    def test_a_plain_flock_proof_from_an_old_checkout_does_not_pass_a_fifo_waiter(self):
        holder = self.start(LIB, "holder", 2, "proof_lock holder acquired")
        waiter = self.start(LIB, "waiter", 1, "proof_context waiter phase queued")
        # The W25-5 library prints "waiting" after its first flock -n fails, then blocks in flock.
        old = self.start(LIB_W25_5, "old", 1, "proof_lock old waiting")
        events, outs = self.finish([holder, waiter, old])
        starts = [e[1] for e in events if e[0] == "start"]
        self.assertEqual(starts, ["holder", "waiter", "old"])
        times = {(e[0], e[1]): int(e[2]) for e in events}
        # The first waiter waits only for the run that holds the lock.
        self.assertLess(times[("start", "waiter")] - times[("end", "holder")], 1500, events)

    def test_a_w25_14_waiter_keeps_its_place_and_nothing_hangs(self):
        holder = self.start(LIB, "holder", 2, "proof_lock holder acquired")
        w14 = self.start(LIB_W25_14, "w14", 1, "proof_lock w14 waiting for lock")
        waiter = self.start(LIB, "waiter", 1, "proof_context waiter phase queued")
        events, _ = self.finish([holder, w14, waiter])
        self.assertEqual([e[1] for e in events if e[0] == "start"], ["holder", "w14", "waiter"])

    def test_a_fifo_waiter_goes_after_an_old_holder(self):
        old = self.start(LIB_W25_5, "old", 2, "proof_lock old acquired")
        waiter = self.start(LIB, "waiter", 1, "proof_context waiter phase queued")
        events, _ = self.finish([old, waiter])
        self.assertEqual([e[1] for e in events if e[0] == "start"], ["old", "waiter"])

    def test_the_lock_file_is_free_after_the_last_holder_ends(self):
        self.finish([self.start(LIB, "one", 0, "proof_lock one acquired")])
        free = subprocess.run(["flock", "-n", self.lock, "true"])
        self.assertEqual(free.returncode, 0)

    def test_a_proof_under_a_plain_flock_stops_at_once_with_a_message(self):
        open(self.lock, "a").close()
        began = time.monotonic()
        res = subprocess.run(["flock", self.lock, "bash", "-c", PROOF, LIB, "wrapped", self.order, "0"],
                             env=self.env, capture_output=True, text=True, timeout=30)
        took = time.monotonic() - began
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertRegex(res.stderr, r"proof_lock wrapped FAIL: process \d+ .* holds .* with a plain flock, "
                                     r"not with the FIFO queue\. .*Use proof_lock_take")
        self.assertFalse(os.path.exists(self.order), "the wrapped proof ran")
        self.assertLess(took, 5.0)

    def test_the_plain_flock_check_is_fast_under_a_parent_with_many_fds(self):
        # A CI runner can be an ancestor with hundreds of fds. The check must not make one
        # grep per fd: that took 0.7 s with 600 fds and made the W25-5 waiter test fail on CI.
        open(self.lock, "a").close()
        check = ('. "$0"; s=$(date +%s%3N); p="$(proof_lock_plain_parent "$1")"; rc=$?; '
                 'echo "rc=$rc ms=$(( $(date +%s%3N) - s )) pid=${p%% *}"')
        fds = [os.open(os.devnull, os.O_RDONLY) for _ in range(2000)]
        held = os.open(self.lock, os.O_RDWR)
        try:
            free = subprocess.run(["bash", "-c", check, LIB, self.lock], env=self.env,
                                  capture_output=True, text=True, timeout=30)
            fcntl.flock(held, fcntl.LOCK_EX)
            plain = subprocess.run(["bash", "-c", check, LIB, self.lock], env=self.env,
                                   capture_output=True, text=True, timeout=30)
        finally:
            os.close(held)
            for fd in fds:
                os.close(fd)
        m = re.search(r"rc=(\d+) ms=(\d+) pid=", free.stdout)
        self.assertIsNotNone(m, free.stdout + free.stderr)
        self.assertEqual(m.group(1), "1", free.stdout)
        self.assertLess(int(m.group(2)), 500, free.stdout)
        # The check still finds an ancestor that holds the lock among its many fds.
        self.assertIn("rc=0 ", plain.stdout, plain.stdout + plain.stderr)
        self.assertIn(f"pid={os.getpid()}", plain.stdout)


class NoPlainFlockTest(unittest.TestCase):
    def test_no_proof_script_calls_flock_itself(self):
        paths = glob.glob(os.path.join(REPO, "scripts", "proof", "*.sh"))
        paths += glob.glob(os.path.join(REPO, "scripts", "*.sh"))
        paths += glob.glob(os.path.join(REPO, "examples", "*", "proof", "*.sh"))
        self.assertTrue(paths)
        for path in sorted(paths):
            if os.path.basename(path) == "proof-lock.sh":
                continue
            with open(path) as f:
                for n, line in enumerate(f, 1):
                    code = line.split("#", 1)[0]
                    with self.subTest(path=os.path.relpath(path, REPO), line=n):
                        self.assertIsNone(re.search(r"\bflock\b", code),
                                          "take the proof lock with proof_lock_take, not with flock")


if __name__ == "__main__":
    unittest.main()

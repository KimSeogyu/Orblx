"""W25-5: the box proof lock runs two proofs one after the other.

Two shells source proof-lock.sh with the same lock file and hold it for a short time.
The test checks that the hold intervals do not overlap, that the second shell waits
and prints the holder, and that each shell prints the proof_context lines.
"""

import errno
import os
import re
import select
import shutil
import signal
import subprocess
import tempfile
import threading
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

# The shell stops inside the critical section until the parent writes the go fifo.
# ENTER_FIFO is opened by the parent first, so the enter write does not block.
ORDERED = r"""
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
printf '%s enter\n' "$LABEL" >> "$ORDER_FILE"
printf 'in\n' > "$ENTER_FIFO"
IFS= read -r _ < "$GO_FIFO"
echo "hold_end $LABEL $(hold_ms)"
printf '%s leave\n' "$LABEL" >> "$ORDER_FILE"
"""

_WAIT_LINE = re.compile(
    r"^proof_lock two waiting for lock, \d+ s, position (\d+), at \S+, file (\S+), holder: label=one\b",
    re.M,
)
# major and minor are hex. The kernel prints at least two digits (00:2f:2).
_FLOCK_DEV = re.compile(
    r"FLOCK\s+ADVISORY\s+WRITE\s+\d+\s+([0-9A-Fa-f]+):([0-9A-Fa-f]+):(\d+)\b"
)


def parse_flock_dev(row):
    """Return (major, minor, inode) from one fdinfo lock row, or None."""
    match = _FLOCK_DEV.search(row)
    if match is None:
        return None
    return (int(match.group(1), 16), int(match.group(2), 16), int(match.group(3), 10))


def proc_fdinfo_available(root="/proc"):
    return os.path.isdir(os.path.join(root, "self", "fdinfo"))


def release_go(go_fifo, proc, timeout):
    """Open the go fifo for write and send one line.

    A blocking open waits forever when the child has already exited.
    Non-blocking open returns ENXIO when no reader exists. A dead child
    fails before that open.
    """
    if proc.poll() is not None:
        raise AssertionError(f"child {proc.pid} exited {proc.returncode} before the go fifo was opened")
    deadline = time.monotonic() + timeout
    while True:
        if proc.poll() is not None:
            raise AssertionError(f"child {proc.pid} exited {proc.returncode} before the go fifo was opened")
        try:
            fd = os.open(go_fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as err:
            if err.errno != errno.ENXIO:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"no reader for {go_fifo} within {timeout}s; child {proc.poll()}")
            time.sleep(0.02)
            continue
        try:
            os.write(fd, b"go\n")
        finally:
            os.close(fd)
        return


def stop_owned(procs, fds, keeper_file=None):
    """Stop the shells this test started, their process group, and that test's keeper.

    The keeper calls setsid, so it is not in the shell group. Its pid is read
    from the keeper file under this test's lock path. The cmdline must contain
    that path. No other process is signaled.
    """
    for proc in procs:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
    if keeper_file and os.path.isfile(keeper_file):
        _stop_recorded_keeper(keeper_file)
    for proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    for proc in procs:
        if proc.stdout is not None and not proc.stdout.closed:
            proc.stdout.close()
        if proc.stderr is not None and proc.stderr is not proc.stdout and not proc.stderr.closed:
            proc.stderr.close()
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def _stop_recorded_keeper(path):
    with open(path) as fh:
        text = fh.read()
    match = re.search(r"(?m)^pid=(\d+)$", text)
    if match is None:
        return
    pid = int(match.group(1))
    lock_path = path[: -len(".keeper")] if path.endswith(".keeper") else ""
    if not lock_path:
        return
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmd = fh.read()
    except OSError:
        return
    if lock_path.encode() not in cmd:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.02)


class _Output:
    """Stdout collected while the shell is still running."""

    def __init__(self):
        self.ready = threading.Condition()
        self._buf = bytearray()
        self.thread = None

    def drain(self, pipe):
        def run():
            while True:
                data = pipe.read(4096)
                with self.ready:
                    if data:
                        self._buf.extend(data)
                    self.ready.notify_all()
                if not data:
                    return

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def text(self):
        with self.ready:
            return bytes(self._buf).decode("utf-8", "replace")


class ProofLockHandoffTest(unittest.TestCase):
    """Checks that do not need the proof lock binary."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.procs = []
        self.fds = []

    def tearDown(self):
        stop_owned(self.procs, self.fds)
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_a_zero_padded_device_matches_by_number(self):
        # minor 0x0a is below 0x10. The row pads both components to two digits.
        # The old unpadded token 0:a:99 is not in the row.
        row = "lock:\t1: FLOCK  ADVISORY  WRITE 0 00:0a:99 0 EOF"
        self.assertNotIn("0:a:99", row)
        self.assertEqual(parse_flock_dev(row), (0, 10, 99))
        self.assertIsNone(parse_flock_dev("lock:\t1: POSIX  ADVISORY  WRITE 0 00:0a:99 0 EOF"))

    @unittest.skipUnless(
        proc_fdinfo_available() and os.path.isdir("/dev/shm"),
        "a live padded fdinfo row is Linux /dev/shm evidence",
    )
    def test_a_live_fdinfo_row_with_a_small_major_is_padded(self):
        path = os.path.join("/dev/shm", f"orblx-proof-lock-pad-{os.getpid()}")
        open(path, "a").close()
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        proc = subprocess.Popen(["flock", path, "sleep", "30"], start_new_session=True)
        self.procs.append(proc)
        deadline = time.monotonic() + 5
        row = None
        fd_name = None
        while time.monotonic() < deadline and row is None:
            fd_name, row = _flock_row(proc.pid, path)
            if row is None:
                time.sleep(0.02)
        st = os.stat(path)
        self.assertIsNotNone(row, f"no flock row for {path}")
        print(f"live-fdinfo fd={fd_name} {row}")
        found = _FLOCK_DEV.search(row)
        self.assertIsNotNone(found, row)
        token = f"{found.group(1)}:{found.group(2)}:{found.group(3)}"
        unpadded = f"{os.major(st.st_dev):x}:{os.minor(st.st_dev):x}:{st.st_ino}"
        self.assertLess(os.major(st.st_dev), 0x10)
        # The field is 00:2f:N. The unpadded form 0:2f:N is a different token.
        self.assertNotEqual(token, unpadded, row)
        self.assertEqual(parse_flock_dev(row), (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino))

    def test_proc_fdinfo_absence_is_not_exclusion(self):
        root = os.path.join(self.dir, "noproc")
        os.makedirs(root)
        self.assertFalse(proc_fdinfo_available(root))
        if os.path.isdir("/proc/self/fdinfo"):
            self.assertTrue(proc_fdinfo_available())

    def test_release_returns_when_the_child_is_already_dead(self):
        go = os.path.join(self.dir, "dead.go")
        os.mkfifo(go)
        proc = subprocess.Popen(["bash", "-c", "exit 7"], stdout=subprocess.PIPE, start_new_session=True)
        self.procs.append(proc)
        proc.wait(timeout=5)
        started = time.monotonic()
        with self.assertRaises(AssertionError) as caught:
            release_go(go, proc, 5)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1, elapsed)
        self.assertIn(f"child {proc.pid} exited 7", str(caught.exception))

    def test_cleanup_stops_the_descendant_and_closes_the_fd(self):
        desc = os.path.join(self.dir, "desc")
        proc = subprocess.Popen(
            ["bash", "-c", 'sleep 60 & echo "$!" > "$DESC"; wait'],
            env=dict(os.environ, DESC=desc),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.procs.append(proc)
        deadline = time.monotonic() + 5
        gpid = None
        while time.monotonic() < deadline and gpid is None:
            if os.path.isfile(desc) and os.path.getsize(desc) > 0:
                with open(desc) as fh:
                    gpid = int(fh.read().strip())
                break
            time.sleep(0.02)
        self.assertIsNotNone(gpid, "the descendant pid was not written")
        held = os.open(os.path.join(self.dir, "held"), os.O_RDWR | os.O_CREAT, 0o600)
        self.fds.append(held)
        started = time.monotonic()
        stop_owned(self.procs, self.fds)
        self.procs = []
        self.fds = []
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNotNone(proc.poll())
        gone = time.monotonic() + 2
        while time.monotonic() < gone:
            try:
                os.kill(gpid, 0)
            except OSError:
                break
        else:
            self.fail(f"descendant {gpid} is still running")
        with self.assertRaises(OSError):
            os.fstat(held)


def _flock_row(pid, path):
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    want = (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
    fd_dir = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_dir):
        return None, None
    for name in os.listdir(fd_dir):
        try:
            got = os.stat(os.path.join(fd_dir, name))
            with open(f"/proc/{pid}/fdinfo/{name}") as fh:
                info = fh.read()
        except OSError:
            continue
        if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
            continue
        for row in info.splitlines():
            if row.startswith("lock:") and parse_flock_dev(row) == want:
                return name, row
    return None, None


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
        # The two shells block inside the critical section on private fifos.
        # The parent releases each one. It does not reap the first shell before
        # the second shell enters. A note-line count is not the exclusion check:
        # the waiter line is accepted only while the first shell still holds the
        # write flock on the production fifo inode.
        order_path = os.path.join(self.dir, "order")
        open(order_path, "w").close()
        one_enter = os.path.join(self.dir, "one.enter")
        one_go = os.path.join(self.dir, "one.go")
        two_enter = os.path.join(self.dir, "two.enter")
        two_go = os.path.join(self.dir, "two.go")
        for path in (one_enter, one_go, two_enter, two_go):
            os.mkfifo(path)
        one_enter_fd = os.open(one_enter, os.O_RDWR)
        two_enter_fd = os.open(two_enter, os.O_RDWR)
        procs = []
        try:
            one = self._start_ordered("one", order_path, one_enter, one_go)
            procs.append(one)
            one_out = _Output()
            one_out.drain(one.stdout)
            self._read_handshake(one_enter_fd, one, one_out, "one did not enter the critical section")
            fifo = self.env["ORBLX_PROOF_LOCK"] + ".fifo"
            # /proc fdinfo is Linux evidence. The order and context checks below
            # still run when it is absent. Absence is not treated as exclusion.
            if proc_fdinfo_available():
                one_fd, one_lock = self._write_flock(one.pid, fifo)
                self.assertEqual(
                    one_fd,
                    "9",
                    "the shell fd for the fifo is not PROOF_LOCK_FD\n" + self._fd_report(one.pid, fifo) + one_out.text(),
                )
                print(f"fifo-fdinfo fd={one_fd} {one_lock}")
            two = self._start_ordered("two", order_path, two_enter, two_go)
            procs.append(two)
            two_out = _Output()
            two_out.drain(two.stdout)
            waited = self._wait_for_output(
                two,
                two_out,
                lambda text: _WAIT_LINE.search(text),
                "two did not print a waiter line while one held the lock\n" + one_out.text(),
            )
            # Re-check before the release. This read does not take the flock.
            if proc_fdinfo_available():
                one_fd, one_lock = self._write_flock(one.pid, fifo)
                two_fd, two_lock = self._write_flock(two.pid, fifo)
                self.assertEqual(
                    one_fd,
                    "9",
                    "one lost fd 9 before release\n" + self._fd_report(one.pid, fifo),
                )
                self.assertIsNotNone(one_lock, self._fd_report(one.pid, fifo))
                self.assertIsNone(
                    two_lock,
                    "two holds the fifo flock before one is released\n"
                    + self._fd_report(two.pid, fifo)
                    + two_out.text(),
                )
                self.assertIsNone(two_fd, two_lock)
            release_go(one_go, one, 5)
            self._read_handshake(two_enter_fd, two, two_out, "two did not enter after one left the critical section")
            # two is inside the critical section. one may still be exiting.
            # Do not wait for one here: reaping is not the order under test.
            order = self._order_lines(order_path)
            self.assertIn("one leave", order, order)
            self.assertIn("two enter", order, order)
            self.assertLess(order.index("one leave"), order.index("two enter"), order)
            release_go(two_go, two, 5)
            out_one = self._finish(one, one_out)
            out_two = self._finish(two, two_out)
        finally:
            stop_owned(procs, [one_enter_fd, two_enter_fd], self.env["ORBLX_PROOF_LOCK"] + ".keeper")
        self.assertEqual(one.returncode, 0, out_one)
        self.assertEqual(two.returncode, 0, out_two)
        one_times = self.times(out_one, "one")
        two_times = self.times(out_two, "two")
        self.assertGreaterEqual(two_times[0], one_times[1], f"overlap: one {one_times} two {two_times}")
        order = self._order_lines(order_path)
        self.assertEqual(
            order,
            ["one enter", "one leave", "two enter", "two leave"],
            order,
        )
        self.assertEqual(waited.group(1), "1", waited.group(0))
        self.assertEqual(waited.group(2), self.env["ORBLX_PROOF_LOCK"], waited.group(0))
        self.assertIn("holder: label=one", waited.group(0))
        for out, label in ((out_one, "one"), (out_two, "two")):
            for phase in ("queued", "start", "end"):
                self.assertRegex(out, rf"proof_context {label} phase {phase} time \S+ load \S+ other_orblx_containers (\d+|unknown)")
            self.assertRegex(out, rf"proof_contention {label} samples \d+ contended_samples \d+ unknown_samples \d+")
            self.assertIn(f"proof_lock {label} released", out)

    def _start_ordered(self, label, order_path, enter_fifo, go_fifo):
        env = dict(
            self.env,
            LABEL=label,
            ORDER_FILE=order_path,
            ENTER_FIFO=enter_fifo,
            GO_FIFO=go_fifo,
        )
        return subprocess.Popen(
            ["bash", "-c", ORDERED],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )

    def _write_flock(self, pid, path):
        """Return (fd number, lock row) for a write flock on path's inode.

        The fd is identified by ``stat`` device and inode, then the lock row's
        major, minor, and inode are parsed as numbers. A zero-padded token
        still matches. This does not call flock.
        """
        return _flock_row(pid, path)

    def _fd_report(self, pid, path):
        lines = [f"pid {pid} path {path}"]
        try:
            st = os.stat(path)
            lines.append(f"stat dev {os.major(st.st_dev):x}:{os.minor(st.st_dev):x} ino {st.st_ino}")
        except OSError as err:
            return f"{path} stat failed: {err}\n"
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_dir):
            return "\n".join(lines) + "\nno fd table\n"
        for name in sorted(os.listdir(fd_dir)):
            try:
                got = os.stat(os.path.join(fd_dir, name))
            except OSError:
                continue
            if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
                continue
            try:
                with open(f"/proc/{pid}/fdinfo/{name}") as fh:
                    info = fh.read().strip()
            except OSError as err:
                info = str(err)
            lines.append(f"fd {name}\n{info}")
        return "\n".join(lines) + "\n"

    def _read_handshake(self, fd, proc, output, detail):
        deadline = time.monotonic() + 30
        data = b""
        while b"in\n" not in data:
            remain = deadline - time.monotonic()
            if remain <= 0 or proc.poll() is not None:
                self.fail(f"{detail}\nexit {proc.poll()}\n{output.text()}")
            ready, _, _ = select.select([fd], [], [], min(remain, 1))
            if not ready:
                continue
            piece = os.read(fd, 64)
            if not piece:
                self.fail(f"{detail}\nfifo closed\n{output.text()}")
            data += piece

    def _wait_for_output(self, proc, output, pred, detail):
        deadline = time.monotonic() + 30
        while True:
            found = pred(output.text())
            if found:
                return found
            if time.monotonic() >= deadline or proc.poll() is not None:
                self.fail(f"{detail}\nexit {proc.poll()}\n{output.text()}")
            with output.ready:
                output.ready.wait(0.2)

    def _release(self, go_fifo):
        fd = os.open(go_fifo, os.O_WRONLY)
        try:
            os.write(fd, b"go\n")
        finally:
            os.close(fd)

    def _finish(self, proc, output):
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.wait(timeout=5)
            self.fail(f"the shell did not exit\n{output.text()}")
        output.thread.join(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
        return output.text()

    @staticmethod
    def _order_lines(path):
        with open(path) as fh:
            return [line.strip() for line in fh if line.strip()]

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

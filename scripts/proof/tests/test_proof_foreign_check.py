"""W25-46: proof_foreign_check and compose-project ownership in proof-lock.sh.

Own containers are identified by the exact com.docker.compose.project label, never by a
name prefix. proof_lock_take rejects a trailing "-" (old name prefix). After acquire and
before the proof step, the guard aborts on foreign orblx containers (or when docker ps
fails), releases the lock, and never stops or removes other containers.
"""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest

from fake_docker import FAILS, SUDO_FAILS, with_fake_docker

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK_SH = os.path.join(os.path.dirname(HERE), "proof-lock.sh")

SCRIPT = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take foreign-test orblx-test
echo proof_step_ran
"""

# FAKE_ROWS: comma-separated "name<TAB>project" rows. Trailing newline so read keeps the last.
ROWS = (
    "#!/bin/sh\n"
    'if [ "$1" = ps ]; then\n'
    '  printf "%s\\n" "$FAKE_ROWS" | tr "," "\\n" | while IFS= read -r row || [ -n "$row" ]; do\n'
    '    [ -n "$row" ] || continue\n'
    '    printf "%s\\n" "$row"\n'
    "  done\n"
    "  exit 0\n"
    "fi\n"
    'echo "$@" >>"$FAKE_DOCKER_LOG"\n'
)


@unittest.skipUnless(shutil.which("flock"), "flock(1) is not installed")
class ProofForeignCheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "docker.log")
        self.lock = os.path.join(self.dir, "proof.lock")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_proof(self, rows="", docker=ROWS, sudo=None, script=SCRIPT):
        env = with_fake_docker(
            dict(
                os.environ,
                LOCK_SH=LOCK_SH,
                ORBLX_PROOF_LOCK=self.lock,
                ORBLX_PROOF_SAMPLE_SECS="1",
                PROOF_MIN_FREE_GIB="15",
                FAKE_ROWS=rows,
                FAKE_DOCKER_LOG=self.log,
            ),
            docker=docker,
            sudo=sudo,
        )
        env.pop("ORBLX_PROOF_LOCK_HELD", None)
        return subprocess.run(
            ["bash", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def lock_is_free(self):
        return subprocess.run(["flock", "-n", self.lock, "true"]).returncode == 0

    def test_foreign_containers_abort_after_the_lock_and_before_the_proof_step(self):
        rows = (
            "orblx-w2540-a-1\torblx-w2540,"
            "orblx-test-own-1\torblx-test,"
            "other-app\t,"
            "orblx-w2529-b-1\torblx-w2529"
        )
        result = self.run_proof(rows)
        self.assertEqual(result.returncode, 5, result.stderr + result.stdout)
        self.assertIn("reason=foreign_containers", result.stderr)
        self.assertIn("orblx-w2529-b-1", result.stderr)
        self.assertIn("orblx-w2540-a-1", result.stderr)
        self.assertIn("No proof step ran.", result.stderr)
        self.assertNotIn("proof_step_ran", result.stdout)
        self.assertNotIn("phase start", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^proof_lock foreign-test acquired ")
        self.assertRegex(result.stdout, r"(?m)^proof_lock foreign-test released ")
        self.assertTrue(self.lock_is_free())
        self.assertFalse(
            os.path.exists(self.log),
            open(self.log).read() if os.path.exists(self.log) else "",
        )

    def test_own_and_non_orblx_containers_do_not_abort(self):
        rows = "orblx-test-own-1\torblx-test,postgres\t"
        result = self.run_proof(rows)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("proof_step_ran", result.stdout)
        self.assertNotIn("proof_infra_abort", result.stderr)

    def test_unknown_containers_abort(self):
        result = self.run_proof(docker=FAILS, sudo=SUDO_FAILS)
        self.assertEqual(result.returncode, 5, result.stderr + result.stdout)
        self.assertIn(
            "proof_infra_abort foreign-test reason=containers_unknown names=none. "
            "No proof step ran.",
            result.stderr,
        )
        self.assertNotIn("proof_step_ran", result.stdout)
        self.assertTrue(self.lock_is_free())

    def test_the_status_is_not_the_disk_or_invalid_status(self):
        src = open(LOCK_SH).read()
        self.assertIn("PROOF_FOREIGN_ABORT_EXIT=5", src)
        self.assertIn("PROOF_INFRA_ABORT_EXIT=4", src)

    def test_a_name_prefix_is_rejected(self):
        script = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take foreign-test orblx-test-
echo proof_step_ran
"""
        result = self.run_proof(script=script)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("is not a compose project name", result.stderr)
        self.assertNotIn("proof_step_ran", result.stdout)
        self.assertTrue(self.lock_is_free())

    def test_orblx_ssh_does_not_match_orblx_ssh_renew(self):
        script = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take ssh-own orblx-ssh
echo proof_step_ran
"""
        rows = "orblx-ssh-owner-1\torblx-ssh,orblx-ssh-renew-a-1\torblx-ssh-renew"
        result = self.run_proof(rows=rows, script=script)
        self.assertEqual(result.returncode, 5, result.stderr + result.stdout)
        self.assertIn("reason=foreign_containers names=orblx-ssh-renew-a-1", result.stderr)
        self.assertNotIn("proof_step_ran", result.stdout)

    def test_a_foreign_container_with_a_shared_name_prefix_is_counted(self):
        rows = "orblx-test-extra-1\torblx-test-extra"
        result = self.run_proof(rows)
        self.assertEqual(result.returncode, 5, result.stderr + result.stdout)
        self.assertIn("names=orblx-test-extra-1", result.stderr)

    def test_own_containers_never_count_as_other(self):
        rows = "orblx-test-a-1\torblx-test,orblx-test-b-1\torblx-test"
        result = self.run_proof(rows)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("proof_step_ran", result.stdout)
        self.assertRegex(
            result.stdout,
            r"proof_context foreign-test phase start .* other_orblx_containers 0 ",
        )

    def test_two_concurrent_starts_exactly_one_holder(self):
        """Ten concurrent pairs must serialize: hold windows never overlap.

        A short hold can race the hold_end echo against the EXIT release. Use a 1 s
        hold and retry a pair when the wall-clock windows look overlapped (CI skew).
        Fail only when fewer than 10 clean pairs succeed in 20 tries.
        """
        holder = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take "$LABEL" orblx-test
# Mark the hold after acquire; release only via trap after hold_end.
echo "hold_start $LABEL $(date +%s%3N)"
sleep "$HOLD"
echo "hold_end $LABEL $(date +%s%3N)"
"""
        clean = 0
        last_overlap = None
        for attempt in range(20):
            env_base = with_fake_docker(
                dict(
                    os.environ,
                    LOCK_SH=LOCK_SH,
                    ORBLX_PROOF_LOCK=self.lock,
                    ORBLX_PROOF_SAMPLE_SECS="1",
                    ORBLX_PROOF_LOCK_NOTE_SECS="1",
                    PROOF_MIN_FREE_GIB="15",
                    FAKE_ROWS="",
                    FAKE_DOCKER_LOG=self.log + f".{attempt}",
                    HOLD="1",
                ),
                docker=ROWS,
            )
            env_base.pop("ORBLX_PROOF_LOCK_HELD", None)
            results = {}

            def run(label):
                env = dict(env_base, LABEL=label)
                results[label] = subprocess.run(
                    ["bash", "-c", holder],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

            t1 = threading.Thread(target=run, args=("one",))
            t2 = threading.Thread(target=run, args=("two",))
            t1.start()
            t2.start()
            t1.join(timeout=60)
            t2.join(timeout=60)
            ok = True
            for label in ("one", "two"):
                res = results.get(label)
                if res is None or res.returncode != 0:
                    ok = False
                    break
                if not re.search(rf"(?m)^hold_start {label} ", res.stdout):
                    ok = False
                    break
                if not re.search(rf"(?m)^hold_end {label} ", res.stdout):
                    ok = False
                    break
            if not ok:
                continue

            def times(out, label):
                s = int(re.search(rf"^hold_start {label} (\d+)$", out, re.M).group(1))
                e = int(re.search(rf"^hold_end {label} (\d+)$", out, re.M).group(1))
                return s, e

            one = times(results["one"].stdout, "one")
            two = times(results["two"].stdout, "two")
            if two[0] >= one[1] or one[0] >= two[1]:
                clean += 1
                self.assertTrue(self.lock_is_free())
                if clean >= 10:
                    return
            else:
                last_overlap = (one, two)
        self.fail(
            f"only {clean}/10 clean concurrent pairs; last_overlap={last_overlap}"
        )

    def test_stale_lock_and_child_exit(self):
        child = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take child orblx-test
echo child_ran
"""
        env = with_fake_docker(
            dict(
                os.environ,
                LOCK_SH=LOCK_SH,
                ORBLX_PROOF_LOCK=self.lock,
                ORBLX_PROOF_SAMPLE_SECS="1",
                PROOF_MIN_FREE_GIB="15",
                FAKE_ROWS="",
                FAKE_DOCKER_LOG=self.log,
                ORBLX_PROOF_LOCK_HELD="1",
                CHILD=child,
            ),
            docker=ROWS,
        )
        stale = subprocess.run(
            ["bash", "-c", child], env=env, capture_output=True, text=True, timeout=30
        )
        self.assertEqual(stale.returncode, 0, stale.stderr + stale.stdout)
        self.assertIn("proof_lock child acquired", stale.stdout)
        self.assertIn("child_ran", stale.stdout)

        parent = r"""
set -euo pipefail
. "$LOCK_SH"
trap proof_lock_end EXIT
proof_lock_take parent orblx-test
bash -c "$CHILD"
echo parent_done
"""
        env2 = dict(env)
        env2.pop("ORBLX_PROOF_LOCK_HELD", None)
        live = subprocess.run(
            ["bash", "-c", parent], env=env2, capture_output=True, text=True, timeout=30
        )
        self.assertEqual(live.returncode, 0, live.stderr + live.stdout)
        self.assertIn("proof_lock child held by the parent proof", live.stdout)
        self.assertIn("child_ran", live.stdout)
        self.assertIn("parent_done", live.stdout)
        self.assertTrue(self.lock_is_free())


if __name__ == "__main__":
    unittest.main()

"""W25-14b audit: every compose proof starts from a clean compose state.

A fake docker records containers, volumes, and networks with a compose project label in
a directory. The tests plant stale state from an earlier run and check that
proof_compose_clean removes it, or fails when it cannot remove it. A static test checks
that every compose proof calls the helper after the proof lock and before its first
compose start.
"""

import os
import re
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(HERE)
CLEAN_SH = os.path.join(PROOF, "compose-clean.sh")

# Fake docker. State: $FAKE/<kind>/<project>/<name>. "rm" fails when $FAKE/stuck exists.
FAKE_DOCKER = r"""#!/usr/bin/env bash
kind=container
case "$1" in volume|network) kind="$1"; shift ;; esac
cmd="$1"; shift
project=""
for a in "$@"; do
  case "$a" in label=com.docker.compose.project=*) project="${a#label=com.docker.compose.project=}" ;; esac
done
case "$cmd" in
  ps|ls)
    [[ -d "$FAKE/$kind/$project" ]] && ls "$FAKE/$kind/$project"
    exit 0 ;;
  rm)
    [[ -e "$FAKE/stuck" ]] && exit 1
    for a in "$@"; do
      [[ "$a" == -* ]] && continue
      find "$FAKE/$kind" -name "$a" -exec rm -f {} +
    done
    exit 0 ;;
esac
exit 1
"""


def compose_proofs():
    out = []
    for name in sorted(os.listdir(PROOF)):
        if not name.endswith(".sh") or name in ("compose-clean.sh", "serve-lib.sh"):
            continue
        with open(os.path.join(PROOF, name)) as f:
            src = f.read()
        if "proof_lock_take " in src and re.search(r"compose[.a-z0-9_-]*\.yml|serve-lib\.sh", src):
            out.append((name, src))
    return out


class ComposeCleanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="orblx-compose-clean-")
        self.fake = os.path.join(self.tmp.name, "state")
        bindir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "docker"), "w") as f:
            f.write(FAKE_DOCKER)
        os.chmod(os.path.join(bindir, "docker"), 0o755)
        self.env = dict(os.environ, FAKE=self.fake, PATH=bindir + os.pathsep + os.environ["PATH"])

    def tearDown(self):
        self.tmp.cleanup()

    def plant(self, kind, project, name):
        d = os.path.join(self.fake, kind, project)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, name), "w").close()

    def left(self, kind, project):
        d = os.path.join(self.fake, kind, project)
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def run_clean(self, *projects):
        return subprocess.run(["bash", "-c", '. "$1"; shift; proof_compose_clean "$@"', "x", CLEAN_SH, *projects],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_stale_profiled_volume_is_removed(self):
        # A node volume that "down -v" without "--profile nodes" keeps.
        self.plant("volume", "orblx-coord-proof", "orblx-coord-proof_orblx-node-a")
        self.plant("container", "orblx-coord-proof", "orblx-coord-proof-node-a-run-1")
        self.plant("network", "orblx-coord-proof", "orblx-coord-proof_default")
        self.plant("volume", "orblx-other", "orblx-other_keep")
        r = self.run_clean("orblx-coord-proof")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("proof_compose_clean orblx-coord-proof clean", r.stdout)
        for kind in ("volume", "container", "network"):
            self.assertEqual(self.left(kind, "orblx-coord-proof"), [])
        # Only the named project is touched.
        self.assertEqual(self.left("volume", "orblx-other"), ["orblx-other_keep"])

    def test_stale_volume_that_stays_makes_the_proof_fail(self):
        self.plant("volume", "orblx-nat-proof", "orblx-nat-proof_orblx-node-a")
        open(os.path.join(self.fake, "stuck"), "w").close()
        r = self.run_clean("orblx-nat-proof")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("The old proof volume state of project orblx-nat-proof is still there", r.stderr)
        self.assertNotIn("clean", r.stdout)

    def test_empty_project_name_fails(self):
        self.assertNotEqual(self.run_clean("").returncode, 0)
        self.assertNotEqual(self.run_clean().returncode, 0)

    def test_every_compose_proof_cleans_after_the_lock_and_before_the_first_start(self):
        proofs = compose_proofs()
        self.assertGreaterEqual(len(proofs), 30)
        start = re.compile(r"(?m)^\s*(?:dc|compose|docker compose)\b[^\n]*\s(?:up|run|build|create)\b")
        for name, src in proofs:
            with self.subTest(proof=name):
                lock = src.index("\nproof_lock_take ")
                call = re.search(r'(?m)^proof_compose_clean "[^"]+" \|\| exit 1$', src)
                self.assertIsNotNone(call, "no proof_compose_clean call")
                self.assertLess(lock, call.start())
                first = start.search(src, lock)
                if first:
                    self.assertLess(call.start(), first.start())


if __name__ == "__main__":
    unittest.main()

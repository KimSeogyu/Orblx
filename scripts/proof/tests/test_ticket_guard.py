"""W25-27 lab-ticket guard (ticket-guard.sh, sourced by proof-lock.sh).

The runtime guard reads ticket.bin in a node state directory and fails unless the
coordinator issued it. The static guard fails a manifest proof whose script makes lab
tickets (node-issue) as soon as it takes the proof lock. The negative tests build a lab
ticket (issuer coord/w18, the "orblx node-issue" issuer) and a fake manifest proof.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF_DIR = os.path.dirname(HERE)
GUARD_SH = os.path.join(PROOF_DIR, "ticket-guard.sh")
LOCK_SH = os.path.join(PROOF_DIR, "proof-lock.sh")
REPO = os.path.dirname(os.path.dirname(PROOF_DIR))
MANIFEST = os.path.join(PROOF_DIR, "sweep-manifest.txt")
CONVERTED = ["w18-linux-daemon", "w18-names", "subnet", "split-dns", "exit-node", "svid-renew", "ssh"]


def counted(text):
    data = text.encode()
    return struct.pack(">H", len(data)) + data


def ticket(issuer, subject, life):
    now = int(time.time())
    body = bytes([1]) + counted(issuer) + counted(subject)
    body += struct.pack(">QQ", now, now + life)
    body += counted("0.0.0.0/0") + bytes([0]) + struct.pack(">H", 0) + bytes([0]) + bytes(16)
    return body + bytes(64)


class TicketGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def state(self, name, issuer, life=900, node_name=None):
        path = os.path.join(self.tmp, name)
        os.makedirs(path)
        with open(os.path.join(path, "ticket.bin"), "wb") as f:
            f.write(ticket(issuer, "spiffe://orblx.local/node/" + name, life))
        with open(os.path.join(path, "node-name"), "w") as f:
            f.write((node_name or name) + "\n")
        return path

    def guard(self, *dirs):
        script = '. "$1"; shift; proof_ticket_guard coord "$@"'
        return subprocess.run(["bash", "-c", script, "guard", GUARD_SH] + list(dirs),
                              capture_output=True, text=True)

    def test_a_coordinator_ticket_passes(self):
        out = self.guard(self.state("a", "spiffe://orblx.local/coord/coord"))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertRegex(out.stdout, r"proof_ticket_guard node a issuer spiffe://orblx.local/coord/coord life_s 900 expires \d+ ok")

    def test_negative_a_lab_ticket_fails(self):
        good = self.state("a", "spiffe://orblx.local/coord/coord")
        lab = self.state("b", "spiffe://orblx.local/coord/w18")
        out = self.guard(good, lab)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("issuer spiffe://orblx.local/coord/w18 is not spiffe://orblx.local/coord/coord", out.stderr)
        self.assertIn("node a issuer", out.stdout)

    def test_negative_a_longer_life_a_wrong_subject_or_no_ticket_fails(self):
        out = self.guard(self.state("a", "spiffe://orblx.local/coord/coord", life=901))
        self.assertEqual(out.returncode, 1)
        self.assertIn("ticket life 901 s is not 1 to 900 s", out.stderr)
        out = self.guard(self.state("b", "spiffe://orblx.local/coord/coord", node_name="c"))
        self.assertEqual(out.returncode, 1)
        self.assertIn("subject spiffe://orblx.local/node/b is not spiffe://orblx.local/node/c", out.stderr)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        out = self.guard(empty)
        self.assertEqual(out.returncode, 1)
        self.assertIn("ticket.bin is missing or not valid", out.stderr)

    def fake_repo(self, body):
        root = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(root, "scripts", "proof"))
        manifest = os.path.join(root, "scripts", "proof", "sweep-manifest.txt")
        with open(manifest, "w") as f:
            f.write("row|1|Mesh|lab\nproof|lab|scripts/proof/lab.sh|-|-\n")
        script = os.path.join(root, "scripts", "proof", "lab.sh")
        with open(script, "w") as f:
            f.write(body)
        return manifest, script

    def run_proof(self, manifest, script):
        env = dict(os.environ, ORBLX_PROOF_MANIFEST=manifest, LOCK_SH=LOCK_SH,
                   ORBLX_PROOF_LOCK=os.path.join(self.tmp, "proof.lock"))
        env.pop("ORBLX_PROOF_LOCK_HELD", None)
        return subprocess.run(["bash", script], env=env, capture_output=True, text=True)

    PROOF = ('set -euo pipefail\n. "$LOCK_SH"\ntrap proof_lock_end EXIT\n'
             'proof_lock_take lab\n%s\necho proof_ok\n')

    def test_negative_a_manifest_proof_that_makes_lab_tickets_fails_at_the_lock(self):
        manifest, script = self.fake_repo(self.PROOF % '"$bin" node-issue --out "$work" --node a=100.64.0.1')
        out = self.run_proof(manifest, script)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("proof_ticket_guard FAIL lab: the manifest proof makes lab tickets", out.stderr)
        self.assertNotIn("proof_ok", out.stdout)
        self.assertNotIn("acquired", out.stdout)

    def test_a_manifest_proof_without_lab_tickets_runs(self):
        manifest, script = self.fake_repo(self.PROOF % "echo enroll")
        out = self.run_proof(manifest, script)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("proof_ticket_guard lab static ok", out.stdout)
        self.assertIn("proof_ok", out.stdout)

    def test_a_script_outside_the_manifest_is_not_checked(self):
        manifest, _ = self.fake_repo("")
        other = os.path.join(os.path.dirname(manifest), "other.sh")
        with open(other, "w") as f:
            f.write(self.PROOF % "echo node-issue")
        out = self.run_proof(manifest, other)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_the_converted_proofs_use_coordinator_tickets(self):
        scripts = {}
        with open(MANIFEST) as f:
            for line in f:
                parts = line.rstrip("\n").split("|")
                if parts[0] == "proof":
                    scripts[parts[1]] = os.path.join(REPO, parts[2])
        for name in CONVERTED:
            with open(scripts[name]) as f:
                text = f.read()
            for marker in ("node-issue", "direct-issue", "connector issue"):
                self.assertNotIn(marker, text, name)
            self.assertIn("proof_ticket_guard coord ", text, name)


if __name__ == "__main__":
    unittest.main()

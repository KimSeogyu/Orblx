"""W25-35: a proof with a ms limit must build a release binary.

A debug binary is slower than the release binary. A latency or gap gate that passes on a
debug build does not prove the release. This check reads each proof script in scripts/proof:
- The script has a ms limit when it has a *LIMIT_MS name, a "limit_ms" output, an
  "X_ms -le N" test, or an "(( x_ms <= LIMIT ))" test.
- The script builds debug when it has a "/debug/" path, or a "cargo build" line with no
  "--release" and no profile variable with the default release (PROFILE="${X:-release}").
KNOWN_DEBUG holds the proofs with a ms limit that still build debug on the day of this check.
The list can only get shorter: a new proof with a ms limit that builds debug fails, and a proof
that changes to release must leave the list.
"""

import os
import re
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PROOF_DIR = os.path.join(REPO, "scripts", "proof")

# Shared libraries, not proofs.
LIBRARIES = {"pipe-lib.sh", "serve-lib.sh", "stage-image.sh", "proof-lock.sh"}

MS_LIMIT = re.compile(
    r"\b[A-Z_]*LIMIT_MS\b"
    r"|\blimit_ms\b"
    r"|_ms\}?\"?\s+-le\s+\"?[0-9$]"
    r"|\(\(\s*[a-z_]+_ms\s*<=?\s*[A-Z0-9_]+\s*\)\)"
)
RELEASE_DEFAULT = re.compile(r"=\"\$\{[A-Z_]+:-release\}\"")
CARGO_BUILD = re.compile(r"^(\S+=\S+\s+)*cargo build\b")

# The W25-35 batch. Each of these must build release.
BATCH = {
    "ha-routers.sh",
    "siem-streaming.sh",
    "node-share.sh",
    "user-approval.sh",
    "policy-scale.sh",
    "policy-sync.sh",
}
# These proofs print "rustc_version" before their release build.
PRINTS_RUSTC = {"ha-routers.sh", "siem-streaming.sh", "node-share.sh", "user-approval.sh"}

# Proofs with a ms limit that still build debug (W25-35 audit). Do not add a name.
KNOWN_DEBUG = {
    "agent-gateway.sh",
    "agent-grant.sh",
    "agent-python-sdk.sh",
    "api-tokens.sh",
    "audit-webhooks.sh",
    "datapath-acl.sh",
    "nat-realism.sh",
    "revoke-all.sh",
    "split-dns.sh",
}


def has_ms_limit(text):
    return MS_LIMIT.search(text) is not None


def builds_debug(text):
    if "/debug/" in text:
        return True
    release_default = RELEASE_DEFAULT.search(text) is not None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or not CARGO_BUILD.match(s):
            continue
        if "--release" in s or release_default:
            continue
        return True
    return False


def proofs():
    out = {}
    for name in sorted(os.listdir(PROOF_DIR)):
        if name.endswith(".sh") and name not in LIBRARIES:
            with open(os.path.join(PROOF_DIR, name), encoding="utf-8") as f:
                out[name] = f.read()
    return out


class TestCheck(unittest.TestCase):
    """The check finds a debug build and accepts a release build."""

    def test_debug_build_with_a_limit_is_found(self):
        text = 'LIMIT_MS=1000\ncargo build -p orblx-cli --bin orblx --locked\nbin="$ROOT/target/debug/orblx"\n'
        self.assertTrue(has_ms_limit(text))
        self.assertTrue(builds_debug(text))

    def test_cargo_build_with_no_release_flag_is_found(self):
        self.assertTrue(builds_debug("  cargo build -p orblx-cli --bin orblx --locked\n"))
        self.assertTrue(builds_debug('X=1 cargo build -p orblx-cli\nP="${P:-debug}"\n'))

    def test_release_build_is_accepted(self):
        self.assertFalse(builds_debug("cargo build --release -p orblx-cli --bin orblx --locked\n"))
        text = 'PROFILE="${ORBLX_P:-release}"\nif x; then\n  cargo build --release -p a\nelse\n  cargo build -p a\nfi\nb="$T/$PROFILE/orblx"\n'
        self.assertFalse(builds_debug(text))

    def test_limit_forms(self):
        for text in ("REACH_LIMIT_MS=2000\n", 'echo "limit_ms 5"\n', '[[ "$drop_ms" -le 1000 ]]\n',
                     "(( deny_ms <= LIMIT_MS ))\n"):
            self.assertTrue(has_ms_limit(text), text)
        self.assertFalse(has_ms_limit("IDLE_LIMIT_PCT=0.5\n"))


class TestProofs(unittest.TestCase):
    """The proof scripts in the repo."""

    def setUp(self):
        self.proofs = proofs()

    def test_a_proof_with_a_ms_limit_builds_release(self):
        debug = {n for n, t in self.proofs.items() if has_ms_limit(t) and builds_debug(t)}
        self.assertEqual(sorted(debug - KNOWN_DEBUG), [], "a proof with a ms limit builds debug")
        self.assertEqual(sorted(KNOWN_DEBUG - debug), [],
                         "these proofs build release now (or have no ms limit): remove them from KNOWN_DEBUG")

    def test_the_batch_builds_release(self):
        for name in sorted(BATCH):
            self.assertIn(name, self.proofs)
            self.assertNotIn(name, KNOWN_DEBUG)
            self.assertFalse(builds_debug(self.proofs[name]), name)

    def test_the_batch_prints_rustc_and_the_cargo_profile(self):
        for name in sorted(PRINTS_RUSTC):
            text = self.proofs[name]
            self.assertTrue('echo "rustc_version $(rustc -V)"' in text, name + ": no rustc_version line")
            builds = [l.strip() for l in text.splitlines() if CARGO_BUILD.match(l.strip())]
            self.assertTrue(builds, name)
            for line in builds:
                # Without -q, cargo prints its "Finished `release` profile" line in the log.
                self.assertIn("--release", line, name)
                self.assertNotRegex(line, r"(^|\s)-q(\s|$)|--quiet", name)


if __name__ == "__main__":
    unittest.main()

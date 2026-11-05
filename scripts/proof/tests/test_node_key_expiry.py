"""W25-20: the node key expiry proof reads its time limits from clock.rs.

The test takes the clock_secs function out of node-key-expiry.sh and runs it on the real
clock.rs, on a copy with a different MAX_SKEW, and on a copy with no MAX_SKEW. The proof
must follow the code value and must stop when the constant is missing.
"""

import os
import re
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SCRIPT = os.path.join(ROOT, "scripts", "proof", "node-key-expiry.sh")
CLOCK = os.path.join(ROOT, "crates", "orblx-identity", "src", "clock.rs")


def clock_function():
    with open(SCRIPT) as f:
        text = f.read()
    match = re.search(r"^clock_secs\(\) \{\n.*?^\}\n", text, re.S | re.M)
    if match is None:
        raise AssertionError("node-key-expiry.sh has no clock_secs function")
    return match.group(0)


def run_clock(clock_path, name):
    body = 'fail() { echo "FAIL: $*" >&2; exit 1; }\n' + clock_function()
    body += 'CLOCK="$1"\nclock_secs "$2"\n'
    return subprocess.run(["bash", "-c", body, "clock", clock_path, name],
                          capture_output=True, text=True)


def code_secs(text, name):
    match = re.search(r"^pub const %s: Duration = Duration::from_secs\(([0-9 *]+)\);$" % name,
                      text, re.M)
    if match is None:
        raise AssertionError(name + " is not in clock.rs")
    value = 1
    for part in match.group(1).split("*"):
        value *= int(part)
    return value


class NodeKeyExpiryConstants(unittest.TestCase):
    def test_the_proof_reads_the_code_limits(self):
        with open(CLOCK) as f:
            text = f.read()
        for name in ["MAX_SKEW", "MAX_USER_TTL", "MAX_AGENT_TTL"]:
            out = run_clock(CLOCK, name)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(int(out.stdout.strip()), code_secs(text, name), name)

    def test_a_changed_skew_changes_the_proof_value(self):
        with open(CLOCK) as f:
            text = f.read()
        changed = re.sub(r"^pub const MAX_SKEW: Duration = Duration::from_secs\([0-9]+\);$",
                         "pub const MAX_SKEW: Duration = Duration::from_secs(90);", text, flags=re.M)
        self.assertNotEqual(changed, text)
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write(changed)
        try:
            out = run_clock(f.name, "MAX_SKEW")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout.strip(), "90")
        finally:
            os.unlink(f.name)

    def test_a_missing_constant_stops_the_proof(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write("pub const OTHER: u64 = 1;\n")
        try:
            out = run_clock(f.name, "MAX_SKEW")
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("MAX_SKEW is not in", out.stderr)
        finally:
            os.unlink(f.name)

    def test_the_proof_does_not_hardcode_the_skew(self):
        with open(SCRIPT) as f:
            text = f.read()
        self.assertIn('SKEW="$(clock_secs MAX_SKEW)"', text)
        self.assertNotRegex(text, r"(?m)^\s*SKEW=[0-9]")
        self.assertNotIn("+ 60", text)


if __name__ == "__main__":
    unittest.main()

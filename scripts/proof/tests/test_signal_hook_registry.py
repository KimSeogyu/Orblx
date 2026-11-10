"""The signal-hook-registry check fails when Cargo.lock has two versions."""
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "..", "..", "check-signal-hook-registry.sh")
LOCK = os.path.join(HERE, "..", "..", "..", "Cargo.lock")


def run_check(lock_path):
    return subprocess.run(
        ["bash", CHECK, lock_path, "lock-only"],
        capture_output=True,
        text=True,
    )


class SignalHookRegistryTest(unittest.TestCase):
    def test_two_versions_fail(self):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        self.addCleanup(os.remove, handle.name)
        handle.write(
            '\n'.join(
                [
                    "[[package]]",
                    'name = "signal-hook-registry"',
                    'version = "1.4.8"',
                    "",
                    "[[package]]",
                    'name = "signal-hook-registry"',
                    'version = "1.4.2"',
                    "",
                ]
            )
        )
        handle.close()
        out = run_check(handle.name)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("version count is 2", out.stderr)

    def test_one_version_passes(self):
        out = run_check(LOCK)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("signal-hook-registry version 1.4.8", out.stdout)

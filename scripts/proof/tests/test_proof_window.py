"""W25-39 (B): proof_window_contention reports the load and the contention in the measured window."""

import os
import subprocess
import tempfile
import unittest

LOCK_SH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "proof-lock.sh")


def window(rows, start, end):
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write("".join(f"{ms} {count} {load}\n" for ms, count, load in rows))
        path = handle.name
    try:
        script = f'. "{LOCK_SH}"; PROOF_LOCK_SAMPLES="{path}"; proof_window_contention loop {start} {end}'
        out = subprocess.run(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return out.returncode, out.stdout.strip()
    finally:
        os.unlink(path)


class ProofWindowTest(unittest.TestCase):
    def test_only_the_samples_in_the_window_count(self):
        # The busy sample and the high load are before the window.
        code, line = window([(1000, 2, "9.50"), (2000, 0, "1.20"), (3000, 0, "0.80"), (4000, 0, "1.00")], 2000, 3500)
        self.assertEqual(code, 0, line)
        self.assertIn("samples 2 contended_samples 0 unknown_samples 0", line)
        self.assertIn("load1_min 0.80 load1_mean 1.00 load1_max 1.20 result valid", line)

    def test_a_contended_or_unknown_sample_in_the_window_fails(self):
        code, line = window([(2000, 1, "1.0")], 1000, 3000)
        self.assertEqual(code, 1)
        self.assertIn("contended_samples 1", line)
        self.assertIn("result invalid", line)
        code, line = window([(2000, -1, "1.0")], 1000, 3000)
        self.assertEqual(code, 1)
        self.assertIn("unknown_samples 1", line)

    def test_a_window_with_no_sample_fails(self):
        code, line = window([(5000, 0, "1.0")], 1000, 3000)
        self.assertEqual(code, 1)
        self.assertIn("samples 0", line)
        self.assertIn("result invalid", line)


if __name__ == "__main__":
    unittest.main()

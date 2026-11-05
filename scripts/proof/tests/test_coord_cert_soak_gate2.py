"""Gate 2 of coord-cert-soak.sh.

Main prints `coord svid <uri>` and does not print the coordinator leaf lines.
No leaf line makes gate 2 N/A. A leaf line keeps the end-count check.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOAK = os.path.join(os.path.dirname(HERE), "coord-cert-soak.sh")


def function_text(name):
    with open(SOAK, encoding="utf-8") as handle:
        lines = handle.read().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(name + "() {"))
    depth = 0
    out = []
    for line in lines[start:]:
        out.append(line)
        depth += line.count("{") - line.count("}")
        if depth == 0:
            return "".join(out)
    raise AssertionError(name)


def run_gate(log_text, ends, need):
    work = tempfile.mkdtemp()
    path = os.path.join(work, "coord.log")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(log_text)
        script = (
            "set -euo pipefail\n"
            "fail() { echo \"FAIL: $*\" >&2; exit 1; }\n"
            + function_text("coord_cert_gate2_check")
            + "\ncoord_cert_gate2_check \"$1\" \"$2\" \"$3\"\n"
        )
        return subprocess.run(
            ["bash", "-c", script, "bash", path, str(ends), str(need)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)


class CoordCertGate2Test(unittest.TestCase):
    def test_the_script_prints_the_counts_before_gate_2(self):
        with open(SOAK, encoding="utf-8") as handle:
            src = handle.read()
        counts = src.index(
            'echo "coord_svid_ends_crossed ${ends} coord_svid_renewals ${renewals} '
        )
        gate2 = src.index('coord_cert_gate2_check "$COORD_LOG" "$ends" "$SOAK_COORD_ENDS"')
        gate4 = src.index('(( soak_run_s >= SOAK_S ))')
        self.assertLess(counts, gate2)
        self.assertLess(gate2, gate4)
        self.assertEqual(src.count("gate2 N/A reason=main_lacks_coord_svid_expiry_lines"), 1)

    def test_no_leaf_lines_print_na(self):
        log = (
            "2026-11-05T00:00:00.000000000Z coord listen 0.0.0.0:443\n"
            "2026-11-05T00:00:00.100000000Z coord svid spiffe://orblx.local/coord/coord\n"
        )
        result = run_gate(log, ends=0, need=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "gate2 N/A reason=main_lacks_coord_svid_expiry_lines\n")
        self.assertEqual(result.stderr, "")

    def test_leaf_lines_below_the_limit_fail(self):
        log = (
            "2026-11-05T00:00:00.000000000Z coord listen 0.0.0.0:443\n"
            "2026-11-05T00:15:00.000000000Z coord svid expiry 1000\n"
        )
        result = run_gate(log, ends=1, need=3)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("gate2 N/A", result.stdout)
        self.assertIn("The run crossed 1 coordinator leaf ends, not 3.", result.stderr)


if __name__ == "__main__":
    unittest.main()

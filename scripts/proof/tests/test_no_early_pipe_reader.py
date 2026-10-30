"""W24-E4b: the nat-realism and perf-watch scripts must not end a pipe reader early.

Under set -o pipefail, a reader that exits before the end of its input (grep -q, grep -m,
head, awk with exit) makes the writer get SIGPIPE (exit 141), and the pipe fails.
Main perf-watch run 41070530507 run2 stopped with exit 141 at
`docker logs ... | awk '... {...; exit}'` in the prc_sym case.
"""

import os
import re
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.join(HERE, "..")
SCRIPTS = ["nat-realism.sh", "perf-watch.sh"]
BAD = [
    re.compile(r"\|\s*head\b"),
    re.compile(r"\|\s*grep\s+(-\S+\s+)*-[a-zA-Z]*[qm]"),
    re.compile(r"\|\s*grep\b.*\s--max-count"),
    re.compile(r"\|\s*awk\b.*\bexit\s*\}"),
    re.compile(r"^'?\s*\"?\$1\"?\s*\|\s*awk\b.*\bexit\s*\}"),
]


class NoEarlyPipeReaderTest(unittest.TestCase):
    def test_no_reader_exits_early_on_a_pipe(self):
        found = []
        for name in SCRIPTS:
            with open(os.path.join(PROOF, name)) as f:
                for no, line in enumerate(f, 1):
                    if line.lstrip().startswith("#"):
                        continue
                    if any(p.search(line) for p in BAD):
                        found.append("%s:%d: %s" % (name, no, line.strip()))
        self.assertEqual(found, [])

    def test_has_line_reads_all_input_under_pipefail(self):
        script = (
            "set -euo pipefail\n"
            "has_line() { awk -v re=\"$1\" '$0 ~ re {found = 1} END {exit !found}'; }\n"
            "seq 1 200000 | has_line '^1$'\n"
            "if seq 1 200000 | has_line '^x$'; then exit 3; fi\n"
            "echo ok\n"
        )
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, "ok"))


if __name__ == "__main__":
    unittest.main()

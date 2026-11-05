"""Soak window sizing.

SOAK_TR_ENDS must not lower the ticket-end count below ends_for_soak.
ticket-renewal.sh sizes the last interval with the ticket life.
Gate 1 still requires TR_ENDS crossed ends.
"""

import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(HERE)
SCRIPTS = os.path.dirname(PROOF)
SOAK = os.path.join(PROOF, "coord-cert-soak.sh")
RENEW = os.path.join(PROOF, "ticket-renewal.sh")


def function_text(path, name):
    with open(path, encoding="utf-8") as handle:
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


def run_bash(script):
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


class SoakWindowTest(unittest.TestCase):
    def test_soak_tr_ends_cannot_lower_the_count(self):
        fn = function_text(SOAK, "choose_tr_ends")
        script = "set -euo pipefail\n" + fn + "\n" + r"""
choose_tr_ends 12 3 6
choose_tr_ends 12 3 ""
choose_tr_ends 4 3 9
choose_tr_ends 2 5 ""
choose_tr_ends 12 3 12
choose_tr_ends 1 1 1
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["12", "12", "9", "5", "12", "2"])
        with open(SOAK, encoding="utf-8") as handle:
            src = handle.read()
        self.assertIn(
            'TR_ENDS="$(choose_tr_ends "$ends_for_soak" "$ends_for_coord" "${SOAK_TR_ENDS:-}")"',
            src,
        )
        self.assertIn("ends_for_soak ${ends_for_soak}", src)
        self.assertIn("ends_for_coord ${ends_for_coord}", src)
        self.assertIn("soak_tr_ends ${SOAK_TR_ENDS:-unset}", src)
        self.assertIn("tr_ends ${TR_ENDS}", src)
        self.assertNotIn('TR_ENDS="${SOAK_TR_ENDS:-', src)

    def test_run_end_uses_the_ticket_life_on_the_last_interval(self):
        fn = function_text(RENEW, "ticket_run_end")
        script = "set -euo pipefail\n" + fn + "\n" + r"""
ticket_run_end 10000 1 600 900 60
ticket_run_end 10000 2 600 900 60
ticket_run_end 10000 6 600 900 60
ticket_run_end 1000 5 40 60 60
ticket_run_end 1000 0 40 60 60
"""
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        # TR_ENDS=1 and TR_ENDS=0: first end + skew + 5.
        # TR_ENDS=6, period 600, ttl 900: 10000 + 4*600 + 900 + 60 + 5.
        # TR_ENDS=5, period 40, ttl 60: 1000 + 3*40 + 60 + 60 + 5.
        self.assertEqual(result.stdout.splitlines(), ["10065", "10965", "13365", "1245", "1065"])
        with open(RENEW, encoding="utf-8") as handle:
            src = handle.read()
        call = src.index(
            'RUN_END="$(ticket_run_end "$max_e0" "$TR_ENDS" "$PERIOD" "$TR_SVID_TTL" "$SKEW")"'
        )
        ping = src.index("PING_SECS=$(( RUN_END - $(date +%s) + 3 ))")
        gate = src.index("(( crossed >= TR_ENDS ))")
        count = src.index("if (( e + SKEW < RUN_END )); then")
        self.assertLess(call, ping)
        self.assertLess(ping, count)
        self.assertLess(count, gate)
        self.assertNotIn("(TR_ENDS - 1) * PERIOD", src)
        # A last gap equal to the ticket life still counts. The +5 s keeps the strict test.
        max_e0, ends, period, ttl, skew = 10000, 6, 600, 900, 60
        run_end = max_e0 + (ends - 2) * period + ttl + skew + 5
        last = max_e0 + (ends - 2) * period + ttl
        self.assertLess(last + skew, run_end)
        nominal = max_e0 + (ends - 1) * period
        self.assertLess(nominal + skew, run_end)

    def test_gate_1_callers_keep_the_same_rule(self):
        mentions = []
        for dirpath, dirnames, filenames in os.walk(SCRIPTS):
            dirnames[:] = [name for name in dirnames if name != "fixtures"]
            for name in filenames:
                if not name.endswith((".sh", ".py", ".md", ".yml")):
                    continue
                if name.startswith("test_"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
                if "ticket-renewal.sh" in text:
                    mentions.append(os.path.relpath(path, SCRIPTS))
        self.assertEqual(
            sorted(mentions),
            ["proof/coord-cert-soak.sh", "proof/w25-42-step2-METHOD.md"],
        )
        with open(RENEW, encoding="utf-8") as handle:
            src = handle.read()
        self.assertEqual(src.count("(( crossed >= TR_ENDS ))"), 1)
        self.assertEqual(src.count("e + SKEW < RUN_END"), 1)
        self.assertIn('TR_ENDS="${TR_ENDS:-5}"', src)


if __name__ == "__main__":
    unittest.main()

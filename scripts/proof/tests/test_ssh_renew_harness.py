"""W25-40: the SSH renewal proof builds release and checks the shell gates.

Gate c uses a PTY shell. An exec command stops at 30 s.
The proof reads the SURVIVED output line. It does not read the typed SURV""IVED line.
The shell end time must be after renewal 1.
The login after renewal 2 must end within one renewal interval.
"""

import os
import re
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "ssh-renew.sh")


def source():
    with open(SCRIPT, encoding="utf-8") as handle:
        return handle.read()


def function_text(src, name):
    lines = src.splitlines()
    start = lines.index(name + "() {")
    out = []
    for line in lines[start:]:
        out.append(line)
        if line == "}":
            break
    else:
        raise AssertionError("no end for " + name)
    return "\n".join(out) + "\n"


class SshRenewHarnessTest(unittest.TestCase):
    def setUp(self):
        self.src = source()

    def test_the_proof_keeps_the_lock_shape_and_the_ttl_floor(self):
        src = self.src
        minimum = src.index("PROOF_MIN_FREE_GIB=15  # reason:")
        self.assertLess(minimum, src.index('proof_lock_take "ssh-renew" "orblx-ssh-renew"'))
        self.assertIn('proof_compose_clean "orblx-ssh-renew" || exit 1', src)
        self.assertRegex(src, r'(?m)^ttl="\$\{SSH_RENEW_TTL:-180\}"$')
        self.assertNotIn("target/debug/orblx", src)
        self.assertIn('bin="$root/target/release/orblx"', src)
        self.assertLess(src.index('bin="$root/target/release/orblx"'), src.index("cargo build --release"))

    def test_the_build_is_release_and_the_log_names_the_profile(self):
        src = self.src
        self.assertRegex(src, r'(?m)^rustc -V$')
        self.assertRegex(src, r'(?m)^echo "cargo profile=release"$')
        self.assertLess(src.index("rustc -V"), src.index('echo "cargo profile=release"'))
        self.assertLess(src.index('echo "cargo profile=release"'), src.index("cargo build --release"))
        builds = [line.strip() for line in src.splitlines() if line.strip().startswith("cargo build")]
        self.assertEqual(builds, ["cargo build --release -p orblx-cli --bin orblx --locked"])

    def test_gate_c_uses_a_pty_shell_and_reads_the_output_word(self):
        shell = function_text(self.src, "ssh_shell")
        self.assertIn("--shell", shell)
        self.assertIn("--peer-cert", shell)
        self.assertNotIn("--command", shell)
        self.assertIn('echo SURV""IVED at $(date +%%s)', shell)
        self.assertNotIn("password", shell.lower())
        gate = self.src.split("gate c: a shell opens", 1)[1].split("gate b: login after renewal 2", 1)[0]
        self.assertNotIn("--command", gate)
        self.assertIn("ssh_shell peer-session", gate)
        self.assertIn("(( shell_end > renewal1_at ))", gate)
        self.assertIn('echo "gate_c survived"', gate)

    def test_short_logins_stay_on_the_cert_command(self):
        login = function_text(self.src, "ssh_b")
        self.assertIn("--peer-cert", login)
        self.assertIn("--command", login)
        self.assertNotIn("--shell", login)
        self.assertNotIn("password", self.src.lower())
        self.assertIn("denied old_host_key_1", self.src)
        self.assertIn('[[ "$key1" != "$key0" ]]', self.src)
        self.assertIn('[[ "$key2" != "$key1" ]]', self.src)

    def test_the_session_default_spans_renewal_1_at_the_ttl_floor(self):
        self.assertRegex(self.src, r'(?m)^renew_interval=\$\(\(ttl \* 2 / 3\)\)$')
        self.assertIn('session_secs="${SSH_RENEW_SESSION_SECS:-$renew_interval}"', self.src)
        result = subprocess.run(
            ["bash", "-c", 'ttl=180; renew_interval=$((ttl * 2 / 3)); '
             'session_secs="${SSH_RENEW_SESSION_SECS:-$renew_interval}"; '
             'printf "%s %s\\n" "$session_secs" "$renew_interval"'],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "120 120")

    def test_after_2_must_land_within_one_renewal_interval(self):
        gate = self.src.split("gate b: login after renewal 2", 1)[1]
        self.assertIn("renewal_2_seen_at", gate)
        self.assertIn("(( after_2_at > renewal_2_seen_at + renew_interval ))", gate)
        self.assertIn("renewals_b $(renewals_b)", gate)
        self.assertIn('echo "login ${label} renewals_b $(renewals_b)', self.src)
        seen = self.src.index('echo "renewal_2_seen_at ${renewal_2_seen_at} renewals_b ${count}"')
        login = self.src.index("login after-2")
        check = self.src.index("(( after_2_at > renewal_2_seen_at + renew_interval ))")
        self.assertLess(seen, login)
        self.assertLess(login, check)

    def test_shell_end_at_reads_survived_and_skips_the_typed_line(self):
        fn = function_text(self.src, "shell_end_at")
        typed = 'sleep 120; echo SURV""IVED at $(date +%s); exit\r\n'
        output = "SURVIVED at 1700000123\r\n"
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(typed)
            handle.write(output)
            path = handle.name
        try:
            result = subprocess.run(
                ["bash", "-c", fn + 'shell_end_at "$1"', "bash", path],
                capture_output=True, text=True, check=False)
        finally:
            os.remove(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1700000123\n")

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(typed)
            path = handle.name
        try:
            result = subprocess.run(
                ["bash", "-c", fn + 'shell_end_at "$1"', "bash", path],
                capture_output=True, text=True, check=False)
        finally:
            os.remove(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "\n")

    def test_the_piped_line_keeps_the_quotes_for_the_remote_shell(self):
        fn = function_text(self.src, "ssh_shell")
        match = re.search(r"printf '([^']*)'", fn)
        self.assertIsNotNone(match)
        result = subprocess.run(
            ["bash", "-c", "session_secs=120; printf '" + match.group(1) + "' \"$session_secs\""],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'sleep 120; echo SURV""IVED at $(date +%s); exit\n')
        self.assertNotIn("SURVIVED", result.stdout)


if __name__ == "__main__":
    unittest.main()

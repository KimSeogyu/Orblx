"""W25-40: the SSH renewal proof builds release and checks the shell gates.

Gate c uses a PTY shell. An exec command stops at 30 s.
The shell prints keepalive every 10 s so the client receives a packet.
The proof reads the SURVIVED output line.
It does not read keepalive lines or the typed SURV""IVED line.
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


def orblx_ssh_commands(src):
    """Return each continued orblx ssh command as one string."""
    lines = src.splitlines()
    commands = []
    index = 0
    while index < len(lines):
        if "orblx ssh" not in lines[index]:
            index += 1
            continue
        parts = []
        while True:
            part = lines[index].strip()
            continued = part.endswith("\\")
            if continued:
                part = part[:-1].rstrip()
            parts.append(part)
            index += 1
            if not continued:
                break
        commands.append(" ".join(parts))
    return commands


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

    def test_the_image_build_uses_the_host_network_and_keeps_no_cache(self):
        builds = [
            line.strip()
            for line in self.src.splitlines()
            if line.strip().startswith("docker build")
        ]
        self.assertEqual(
            builds,
            ['docker build --network host --no-cache -q -t orblx-ssh-renew:local "$image_dir" >/dev/null'],
        )

    def test_node_a_enrolls_via_oidc_and_the_ssh_src_is_a_user_id(self):
        user = function_text(self.src, "enroll_user")
        token = function_text(self.src, "enroll_token")
        self.assertIn("--id-token-file", user)
        self.assertNotIn("--token-file", user)
        self.assertNotIn("--wait-approval", user)
        self.assertIn("owner user, no wait", user)
        self.assertIn("--token-file", token)
        self.assertNotIn("--id-token-file", token)
        self.assertIn("enroll_user a 172.28.19.11 alice", self.src)
        self.assertIn("enroll_token b 172.28.19.12", self.src)
        self.assertIn('wait_log coord "oidc issuer"', self.src)
        policy_path = os.path.join(os.path.dirname(HERE), "ssh-renew.hujson")
        with open(policy_path, encoding="utf-8") as handle:
            policy = handle.read()
        self.assertIn('"ownerUsers": ["oidc:alice"]', policy)
        acls, ssh = policy.split('"ssh"', 1)
        self.assertIn("spiffe://orblx.local/node/a", acls)
        self.assertNotIn("spiffe://orblx.local/node/a", ssh)
        self.assertIn('"src": ["spiffe://orblx.local/user/alice"]', ssh)
        self.assertIn('"dst": ["spiffe://orblx.local/node/b"]', ssh)
        compose_path = os.path.join(os.path.dirname(HERE), "compose.ssh-renew.yml")
        with open(compose_path, encoding="utf-8") as handle:
            compose = handle.read()
        self.assertIn("orblx-test-idp", compose)
        self.assertIn("https://idp:8443", compose)
        self.assertIn('"idp:172.28.19.9"', compose)

    def test_each_orblx_ssh_line_uses_state_and_not_identity_or_netmap(self):
        commands = orblx_ssh_commands(self.src)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertNotIn("--identity", command)
            self.assertNotIn("--netmap", command)
            self.assertIn("--state /var/lib/orblx", command)
        self.assertIn("--command", commands[0])
        self.assertIn("--shell", commands[1])
        self.assertIn("--peer-cert", commands[0])
        self.assertIn("--peer-cert", commands[1])

    def test_the_build_is_release_and_the_log_names_the_profile(self):
        src = self.src
        self.assertRegex(src, r'(?m)^rustc -V$')
        self.assertRegex(src, r'(?m)^echo "cargo profile=release"$')
        self.assertLess(src.index("rustc -V"), src.index('echo "cargo profile=release"'))
        self.assertLess(src.index('echo "cargo profile=release"'), src.index("cargo build --release"))
        builds = [line.strip() for line in src.splitlines() if line.strip().startswith("cargo build")]
        self.assertEqual(
            builds,
            ["cargo build --release -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked"],
        )

    def test_gate_c_uses_a_pty_shell_and_reads_the_output_word(self):
        shell = function_text(self.src, "ssh_shell")
        self.assertIn("--shell", shell)
        self.assertIn("--peer-cert", shell)
        self.assertNotIn("--command", shell)
        self.assertIn('echo SURV""IVED at $(date +%%s)', shell)
        self.assertIn("echo keepalive $(date +%%s)", shell)
        self.assertIn("sleep %s", shell)
        self.assertIn("keep_step=10", shell)
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

    def test_shell_end_at_reads_survived_and_skips_keepalive_and_the_typed_line(self):
        fn = function_text(self.src, "shell_end_at")
        typed = (
            'i=0; while [ "$i" -lt 12 ]; do echo keepalive $(date +%s); '
            'sleep 10; i=$((i+1)); done; echo SURV""IVED at $(date +%s); exit\r\n'
        )
        body = (
            typed
            + "keepalive 1700000001\r\n"
            + "keepalive SURVIVED at 1\r\n"
            + "SURVIVED at 1700000123\r\n"
        )
        path = self.write_text(body)
        try:
            result = self.run_shell_end(fn, path)
        finally:
            os.remove(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1700000123\n")

        path = self.write_text(typed + "keepalive 1700000001\n")
        try:
            result = self.run_shell_end(fn, path)
        finally:
            os.remove(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "\n")

    def test_the_piped_line_keeps_the_quotes_and_covers_the_session(self):
        fn = function_text(self.src, "ssh_shell")
        self.assertIn("keep_count=$(( (session_secs + keep_step - 1) / keep_step ))", fn)
        match = re.search(r"printf '([^']*)'", fn)
        self.assertIsNotNone(match)
        script = (
            "session_secs=120; keep_step=10; "
            "keep_count=$(( (session_secs + keep_step - 1) / keep_step )); "
            "printf '" + match.group(1) + "' \"$keep_count\" \"$keep_step\"; "
            "printf 'count %s step %s\\n' \"$keep_count\" \"$keep_step\""
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        line, count = result.stdout.splitlines()
        self.assertEqual(
            line,
            'i=0; while [ "$i" -lt 12 ]; do echo keepalive $(date +%s); '
            'sleep 10; i=$((i+1)); done; echo SURV""IVED at $(date +%s); exit')
        self.assertEqual(count, "count 12 step 10")
        self.assertNotIn("SURVIVED", line)
        self.assertGreaterEqual(int(count.split()[1]) * int(count.split()[3]), 120)

        odd = subprocess.run(
            ["bash", "-c",
             "session_secs=121; keep_step=10; "
             "keep_count=$(( (session_secs + keep_step - 1) / keep_step )); "
             "printf '%s\\n' \"$keep_count\""],
            capture_output=True, text=True, check=False)
        self.assertEqual(odd.stdout.strip(), "13")

    def write_text(self, text):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write(text)
        handle.close()
        return handle.name

    def run_shell_end(self, fn, path):
        return subprocess.run(
            ["bash", "-c", fn + 'shell_end_at "$1"', "bash", path],
            capture_output=True, text=True, check=False)


if __name__ == "__main__":
    unittest.main()

"""W24-E4b and W25-14: no shell script in the repo may end a pipe reader early.

Under set -o pipefail, a reader that exits before the end of its input (grep -q, grep -m,
head, awk with exit, sed with q) makes the writer get SIGPIPE (exit 141), and the pipe fails.
- In an assignment, the script stops (main perf-watch run 41070530507, run2).
- In "if WRITER | grep -q BAD; then fail", the condition is false, so a leak, hole punch
  or deny check passes when it must fail.
The fix is scripts/proof/pipe-lib.sh: read_all reads all of stdin first, and has_line is an awk
reader that reads all of stdin. A line inside a string that runs in a container sh (no pipefail)
has a "# pipe-ok:" comment on the line above.

The negative tests take the reader from the real script line, put the bad line first in a
large input (so that an early reader stops the writer), and check that the check finds it.
"""

import os
import re
import subprocess
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PIPE_LIB = os.path.join(REPO, "scripts", "proof", "pipe-lib.sh")
SKIP_DIRS = {".git", "target", "node_modules"}
READER = re.compile(r"(?<![|])\|(?![|])(\s*)(grep|head|awk|sed)\b")


def shell_files():
    out = []
    for top, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        out += [os.path.join(top, f) for f in files if f.endswith(".sh")]
    return sorted(out)


def early(cmd, rest):
    if cmd == "head":
        return True
    if cmd == "grep":
        for tok in rest.split():
            if not tok.startswith("-") or tok == "--":
                return False
            if tok.startswith("--"):
                if tok.startswith(("--max-count", "--quiet", "--silent")):
                    return True
            elif re.search("[qm]", tok[1:]):
                return True
        return False
    m = re.match(r"\s*((-\S+\s+(\S+\s+)?)*)'([^']*)'", rest)
    body = m.group(4) if m else rest
    if cmd == "awk":
        return re.search(r"\bexit\b", body) is not None
    return re.search(r"(^|[;}\s/])q\b", body) is not None  # sed


def allowed(lines, i):
    j = i - 1
    while j >= 0 and lines[j].rstrip().endswith("\\"):
        j -= 1
    return (j >= 0 and "pipe-ok:" in lines[j]) or (i > 0 and "pipe-ok:" in lines[i - 1])


def early_readers(path):
    found = []
    with open(path, errors="replace") as f:
        lines = f.read().split("\n")
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") or allowed(lines, i):
            continue
        for m in READER.finditer(line):
            if early(m.group(2), line[m.end():]):
                found.append("%s:%d: %s" % (os.path.relpath(path, REPO), i + 1, line.strip()))
                break
    return found


def bash(script, env=None):
    full = dict(os.environ, **(env or {}))
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=full)


def line_of(rel, needle):
    with open(os.path.join(REPO, rel)) as f:
        hits = [l for l in f if needle in l and not l.lstrip().startswith("#")]
    assert len(hits) == 1, (rel, needle, hits)
    return hits[0].strip()


def reader_of(line):
    """Return the reader command of a check line: the text after "| read_all " or "| "has_line."""
    m = re.search(r"\|\s*(read_all\s+.*|has_line\s+.*)$", line)
    assert m, line
    cmd = m.group(1)
    cmd = re.split(r";\s*then\b|\s\|\|\s|\s&&\s", cmd)[0]
    return cmd.rstrip(" \\")


# The checks that find a bad line and then fail the proof: "if WRITER | READER; then fail".
# Before W24-E4b / W25-14 each one could pass when it must fail. (file, text of the line, bad line)
SILENT_PASS_CHECKS = [
    ("scripts/proof/coord-enroll.sh", "grep -q 'ge1\\.'", '{"token":"ge1.fake-token"}', "leak"),
    ("scripts/proof/coord-enroll.sh", "nodes.json | read_all grep -q 'PRIVATE KEY'", "-----BEGIN PRIVATE KEY-----", "leak"),
    ("scripts/proof/coord-enroll.sh", "\"$up_out\" | read_all grep -q 'The netmap is not valid'", "The netmap is not valid.", "gate"),
    ("scripts/proof/coord-enroll.sh", "\"$ready_out\" | read_all grep -q 'The netmap is not valid'", "The netmap is not valid.", "gate"),
    ("scripts/proof/custom-oidc.sh", "dc logs 2>&1 | read_all grep -qF", "token eyJfake.sigpart end", "leak"),
    ("scripts/proof/custom-oidc.sh", "nodes.json | read_all grep -qF", "token eyJfake.sigpart end", "leak"),
    ("scripts/proof/custom-oidc.sh", "dc logs 2>&1 | read_all grep -q 'PRIVATE KEY'", "-----BEGIN PRIVATE KEY-----", "leak"),
    ("scripts/proof/nat.sh", "grep -q '^The hole punch reached'", "The hole punch reached 172.29.20.13:4000.", "hole punch"),
    ("scripts/proof/nat.sh", 'dc logs coord | read_all grep -q "PRIVATE KEY"', "-----BEGIN PRIVATE KEY-----", "leak"),
    ("scripts/proof/node-lock.sh", "netmap_peers \"$name\" | read_all grep -qw arogue", "peer arogue 100.64.0.9", "deny"),
    ("scripts/proof/policy.sh", "grep -q '5432'", '{"port_start":5432}', "deny"),
    ("scripts/proof/serve-funnel.sh", "PRIVATE KEY|BEGIN CERTIFICATE", "-----BEGIN CERTIFICATE-----", "leak"),
    ("scripts/proof/serve-hardening.sh", "PRIVATE KEY|BEGIN CERTIFICATE", "-----BEGIN PRIVATE KEY-----", "leak"),
    ("scripts/proof/split-dns.sh", "if dc exec -T c ip route show dev orblx0", "10.88.24.0/24 dev orblx0 scope link", "deny"),
    ("scripts/proof/split-dns.sh", "-e '10.88.24.20' -e '192.0.2.1'", "db.corp.lan 10.88.24.20", "deny"),
    ("scripts/proof/ssh.sh", "grep -q leaked", "leaked", "deny"),
    ("scripts/proof/subnet.sh", "\"$route_text\" | read_all grep -q '10.99.0.0/24'", "10.99.0.0/24 dev orblx0", "deny"),
    ("scripts/proof/subnet.sh", "grep -q '0.0.0.0/0'", "0.0.0.0/0 dev orblx0", "deny"),
    ("scripts/proof/subnet.sh", "\"$inet_path\" | read_all grep -q 'orblx0'", "1.1.1.1 dev orblx0 src 100.64.0.2", "deny"),
    ("scripts/proof/w18-names.sh", "grep -q 'DUP!'", "64 bytes from 100.64.0.2: icmp_seq=3 (DUP!)", "gate"),
    ("scripts/proof/nat-realism.sh", "has_line '^The hole punch reached'", "The hole punch reached 172.29.20.13:4000.", "hole punch"),
    ("scripts/proof/nat-realism.sh", 'docker logs "$name" 2>&1 | has_line "PRIVATE KEY"', "-----BEGIN PRIVATE KEY-----", "leak"),
    ("scripts/proof/nat-realism.sh", 'dc logs coord relay 2>&1 | has_line "PRIVATE KEY"', "-----BEGIN PRIVATE KEY-----", "leak"),
]

# Audit verify and deny count checks: "WRITER | read_all grep -q GOOD || fail" (or set -e).
# The bad output has no good line, so the reader must return 1. (file, text of the line, good line)
AUDIT_CHECKS = [
    ("scripts/proof/agent-gateway.sh", '"$api_verify" | read_all grep -qx ok', "ok"),
    ("scripts/proof/agent-gateway.sh", '"$db_verify" | read_all grep -qx ok', "ok"),
    ("scripts/proof/agent-gateway.sh", "gateway-audit-api.jsonl\" | read_all grep -qx ok", "ok"),
    ("scripts/proof/agent-gateway.sh", '"$new_verify" | read_all grep -qx ok', "ok"),
    ("scripts/proof/agent-gateway.sh", "\"$coord_audit\" | read_all grep -q '^verify ok '", "verify ok records 9 tip ab"),
    ("scripts/proof/agent-grant.sh", "\"$early_audit\" | read_all grep -q '^verify ok '", "verify ok records 9 tip ab"),
    ("scripts/proof/agent-grant.sh", "\"$coord_audit\" | read_all grep -q '^verify ok '", "verify ok records 9 tip ab"),
    ("scripts/proof/agent-python-sdk.sh", '"$api_verify" | read_all grep -qx ok', "ok"),
    ("scripts/proof/agent-python-sdk.sh", "\"$coord_audit\" | read_all grep -q '^verify ok '", "verify ok records 9 tip ab"),
    ("scripts/proof/config-audit.sh", "verify ok records 13 tip", "verify ok records 13 tip " + "a" * 64),
    ("scripts/proof/node-lock.sh", "\"$audit\" | read_all grep -q '^verify ok '", "verify ok records 9 tip ab"),
    ("scripts/proof/policy.sh", "grep -qx 'deny 1'", "deny 1"),
    ("scripts/proof/policy.sh", "\"$verify\" | read_all grep -qx 'ok'", "ok"),
    ("scripts/proof/split-dns.sh", "packet-audit.jsonl | read_all grep -qx ok", "ok"),
    ("scripts/proof/serve-funnel.sh", "echo \"$audit\" | read_all grep -qx 'ok'", "ok"),
    ("scripts/proof/ssh.sh", "echo \"$b_audit\" | read_all grep -q '^ok$'", "ok"),
    ("scripts/proof/ssh.sh", "echo \"$b_audit\" | read_all grep -Eq '^deny [1-9]'", "deny 2"),
    ("scripts/proof/ssh.sh", "echo \"$c_audit\" | read_all grep -Eq '^deny [1-9]'", "deny 1"),
]

GEN = r'{ printf "%s\n" "$BAD_LINE"; awk "BEGIN {for (i = 0; i < 300000; i++) print \"clean line\"}"; }'
ENV = {"sig_part": "eyJfake.sigpart"}


class NoEarlyPipeReaderTest(unittest.TestCase):
    def test_no_shell_script_has_an_early_pipe_reader(self):
        files = shell_files()
        self.assertGreater(len(files), 40)
        found = [hit for path in files for hit in early_readers(path)]
        self.assertEqual(found, [])

    def test_the_guard_finds_each_kind_of_early_reader(self):
        lines = [
            "x | grep -q a", "x | grep -qx -- a", "x | grep -Eq a", "x | grep -m1 a", "x | head -n 1",
            "x | awk '/a/ {print; exit}'", "x | sed -n '1p;q'", "x | grep --quiet a",
        ]
        for line in lines:
            m = READER.search(line)
            self.assertTrue(m and early(m.group(2), line[m.end():]), line)
        for line in ["x | grep -c a", "x | grep -v a", "x | awk '{print $1}'", "x || grep -q a f"]:
            m = READER.search(line)
            self.assertFalse(m and early(m.group(2), line[m.end():]), line)

    def test_read_all_keeps_the_bytes_and_the_exit_code(self):
        res = subprocess.run(["bash", "-c", '. "$0"; set -euo pipefail; printf "a\\n\\nb\\n" | read_all cat; '
                              'printf "" | read_all grep -q x || echo "rc $?"; '
                              'seq 1 300000 | read_all grep -qx 2 && echo found', PIPE_LIB],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout, "a\n\nb\nrc 1\nfound\n")

    def _run(self, reader, bad, old=False):
        prefix = "" if old else ". \"$0\"; "
        if old:
            reader = re.sub(r"^read_all\s+", "", reader)
            reader = re.sub(r"^has_line\s+", "grep -Eq ", reader)
        script = prefix + "set -euo pipefail; " + GEN + " | " + reader
        env = dict(ENV, BAD_LINE=bad)
        return subprocess.run(["bash", "-c", script, PIPE_LIB], capture_output=True, text=True,
                              env=dict(os.environ, **env)).returncode

    def test_each_silent_pass_check_fails_on_a_bad_line(self):
        for rel, needle, bad, kind in SILENT_PASS_CHECKS:
            with self.subTest(rel=rel, check=needle, kind=kind):
                reader = reader_of(line_of(rel, needle))
                # The bad line is found: the "if" is true and the proof fails.
                self.assertEqual(self._run(reader, bad), 0, reader)
                # Without the bad line the check passes.
                self.assertEqual(self._run(reader, "clean line"), 1, reader)
                # The old reader stops early: the writer gets SIGPIPE, so the old check missed it.
                self.assertEqual(self._run(reader, bad, old=True), 141, reader)

    def test_each_audit_and_deny_check_fails_on_bad_output(self):
        for rel, needle, good in AUDIT_CHECKS:
            with self.subTest(rel=rel, check=needle):
                reader = reader_of(line_of(rel, needle))
                self.assertEqual(self._run(reader, good), 0, reader)
                self.assertEqual(self._run(reader, "verify failed: The hash check failed at index 2"), 1, reader)


ROOT_PROOFS = ["coord-enroll.sh", "split-dns.sh", "svid-renew.sh", "w18-names.sh"]
PROOFS_WITH_OWN_LOCK = sorted(
    f for f in os.listdir(os.path.join(REPO, "scripts", "proof"))
    if f.endswith(".sh") and f not in {
        "proof-lock.sh", "pipe-lib.sh", "compose-clean.sh", "serve-lib.sh", "stage-image.sh", "entrypoint.sh", "nat-router.sh",
        # The rc.3 release sweep is a driver, not a proof. It builds before the lock (so no proof
        # waits for a build) and takes the lock for each proof it runs (test_release_sweep.py).
        "release-sweep.sh"}
)


class ProofHardeningTest(unittest.TestCase):
    def test_each_proof_takes_the_lock_before_its_first_docker_or_cargo_command(self):
        paths = [os.path.join(REPO, "scripts", "proof", f) for f in PROOFS_WITH_OWN_LOCK]
        paths.append(os.path.join(REPO, "examples", "policy-gitops", "proof", "proof.sh"))
        for path in paths:
            with self.subTest(proof=os.path.relpath(path, REPO)):
                with open(path) as f:
                    lines = f.read().split("\n")
                take = [i for i, l in enumerate(lines) if re.match(r"\s*proof_lock_take ", l)]
                self.assertTrue(take, "no proof_lock_take")
                self.assertEqual(lines[take[0]], lines[take[0]].lstrip(), "proof_lock_take is indented")
                in_function = False
                depth = 0
                for i, l in enumerate(lines[: take[0]]):
                    s = l.strip()
                    if re.match(r"^[a-z_][a-z0-9_]*\(\) \{", l):
                        in_function = not l.rstrip().endswith("}")
                        continue
                    if in_function:
                        in_function = l != "}"
                        continue
                    if s.startswith("#"):
                        continue
                    # The lock must not be inside an if, a loop, or a case.
                    # A line that ends with ":" is Python code in a string, not shell.
                    if s.endswith(":"):
                        continue
                    if re.match(r"(if|for|while|until|case)\b", s) and not re.search(r"\b(fi|done|esac)$", s):
                        depth += 1
                    elif re.match(r"(fi|done|esac)\b", s):
                        depth -= 1
                    self.assertIsNone(re.match(r"(docker|dc|cargo|compose|iptables\S*|ip|sudo|as_root)\b", s),
                                      "line %d runs before the lock: %s" % (i + 1, s))
                self.assertEqual(depth, 0, "proof_lock_take is inside an if, a loop, or a case")

    @unittest.skipIf(os.geteuid() == 0, "the test runs as root")
    def test_a_root_proof_without_root_stops_in_one_second(self):
        for name in ROOT_PROOFS:
            with self.subTest(proof=name):
                start = time.monotonic()
                res = subprocess.run([os.path.join(REPO, "scripts", "proof", name)],
                                     capture_output=True, text=True, timeout=10, cwd=REPO)
                took = time.monotonic() - start
                self.assertEqual(res.returncode, 1)
                self.assertIn("run as root: sudo -n ", res.stderr)
                self.assertEqual(res.stdout, "")
                self.assertLess(took, 1.0)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(subprocess.run(["sh", "-c", "command -v flock"], capture_output=True).returncode != 0,
                 "no flock on this host")
class ProofLockQueueTest(unittest.TestCase):
    """W25-14: two or more proofs that start at the same time run one after the other, in arrival order."""

    def test_waiters_take_the_lock_in_arrival_order_and_print_the_wait(self):
        import tempfile
        work = tempfile.mkdtemp()
        lock = os.path.join(work, "lock")
        order = os.path.join(work, "order")
        script = (
            '. "$0"; trap proof_lock_end EXIT; proof_lock_take "$1"; '
            'echo "start $1 $(date +%s%N)" >>"$2"; sleep "$3"; echo "end $1 $(date +%s%N)" >>"$2"'
        )
        lib = os.path.join(REPO, "scripts", "proof", "proof-lock.sh")
        env = dict(os.environ, ORBLX_PROOF_LOCK=lock, ORBLX_PROOF_LOCK_NOTE_SECS="1", ORBLX_PROOF_SAMPLE_SECS="1")
        # W25-35: the sampler uses a docker stand-in, which prints no names.
        from fake_docker import with_fake_docker
        env = with_fake_docker(env)
        procs = []
        heads = []
        for label, hold in [("holder", "3"), ("first", "1"), ("second", "1"), ("third", "1")]:
            proc = subprocess.Popen(["bash", "-c", script, lib, label, order, hold], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            # W25-19: start the next proof only after this one is in the queue. The holder is in
            # the queue when it has the lock. A waiter is in the queue when it prints its first
            # proof_context line, because the ticket is made before that line.
            mark = "proof_lock holder acquired" if label == "holder" else f"proof_context {label} phase queued"
            head = ""
            while mark not in head:
                line = proc.stdout.readline()
                self.assertTrue(line, f"{label} ended before {mark!r}: {head}")
                head += line
            procs.append(proc)
            heads.append(head)
        outs = [h + p.communicate(timeout=60)[0] for h, p in zip(heads, procs)]
        self.assertEqual([p.returncode for p in procs], [0, 0, 0, 0], outs)
        with open(order) as f:
            events = [l.split() for l in f.read().split("\n") if l]
        self.assertEqual([e[1] for e in events if e[0] == "start"], ["holder", "first", "second", "third"])
        # One proof at a time: each start comes after the end of the one before.
        self.assertEqual([e[0] for e in events], ["start", "end"] * 4)
        self.assertRegex(outs[3], r"proof_lock third waiting for lock, \d+ s, position \d+, .*holder: label=")
        self.assertGreaterEqual(len(re.findall(r"waiting for lock", outs[3])), 3)


class SteadyPingGateTest(unittest.TestCase):
    """W25-14: nat-realism.sh must fail a steady ping run with a high max RTT or with loss.

    The bad sample is from the W25-1b run2 log (w25a1b-branch-80a507f-run2-release-nat-realism.log,
    prc_sym steady): max 121.701 ms, and the old script printed proof_ok.
    """

    BAD = ("50 packets transmitted, 50 received, 0% packet loss, time 10087ms\n"
           "rtt min/avg/max/mdev = 0.214/2.979/121.701/16.961 ms\n")
    GOOD = ("50 packets transmitted, 50 received, 0% packet loss, time 10045ms\n"
            "rtt min/avg/max/mdev = 0.202/0.525/1.029/0.223 ms\n")
    LOSS = ("50 packets transmitted, 48 received, 4% packet loss, time 10045ms\n"
            "rtt min/avg/max/mdev = 0.202/0.525/1.029/0.223 ms\n")

    def gate(self, text, limit="100"):
        return subprocess.run(["bash", "-c", '. "$0"; set -euo pipefail; steady_ping_gate prc_sym 50 1 "$1"',
                               PIPE_LIB, limit], input=text, capture_output=True, text=True)

    def test_a_high_max_rtt_fails(self):
        res = self.gate(self.BAD)
        self.assertEqual(res.returncode, 1)
        self.assertIn("prc_sym steady lost 0/50 max_ms 121.701 limit_ms 100", res.stdout)
        self.assertIn("max ping RTT 121.701 ms is more than 100 ms", res.stderr)

    @staticmethod
    def sample(ms):
        return ("64 bytes from 100.64.0.2: icmp_seq=1 ttl=64 time=0.412 ms\n"
                "64 bytes from 100.64.0.2: icmp_seq=2 ttl=64 time=%s ms\n"
                "64 bytes from 100.64.0.2: icmp_seq=3 ttl=64 time=0.398 ms\n"
                "50 packets transmitted, 50 received, 0%% packet loss, time 10087ms\n"
                "rtt min/avg/max/mdev = 0.214/4.100/%s/1.000 ms\n" % (ms, ms))

    def nat_gate(self, text):
        return subprocess.run(["bash", "-c", '. "$0"; set -euo pipefail; steady_ping_gate prc_sym 50 1 200 100',
                               PIPE_LIB], input=text, capture_output=True, text=True)

    def test_a_201_ms_sample_fails_the_stall_limit(self):
        res = self.nat_gate(self.sample("201"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("max ping RTT 201 ms is more than 200 ms", res.stderr)
        self.assertIn("steady_warn prc_sym icmp_seq 2 ms 201 warn_ms 100 limit_ms 200 time ", res.stdout)

    def test_a_150_ms_sample_passes_with_a_steady_warn_line(self):
        res = self.nat_gate(self.sample("150"))
        self.assertEqual(res.returncode, 0, res.stderr)
        warn = [line for line in res.stdout.splitlines() if line.startswith("steady_warn ")]
        self.assertEqual(len(warn), 1, res.stdout)
        self.assertRegex(warn[0], r"^steady_warn prc_sym icmp_seq 2 ms 150 warn_ms 100 limit_ms 200 "
                                  r"time \d{4}-\d\d-\d\dT\S+ proof_context ")

    def test_no_steady_warn_line_at_or_below_100_ms(self):
        res = self.nat_gate(self.sample("100"))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("steady_warn", res.stdout)

    def test_a_normal_run_passes(self):
        res = self.gate(self.GOOD)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_loss_and_a_missing_summary_fail(self):
        self.assertEqual(self.gate(self.LOSS).returncode, 1)
        self.assertEqual(self.gate("").returncode, 1)
        self.assertEqual(self.gate("ping: unknown host\n").returncode, 1)

    def test_nat_realism_uses_the_gate_for_each_steady_run(self):
        with open(os.path.join(REPO, "scripts", "proof", "nat-realism.sh")) as f:
            text = f.read()
        body = text[text.index("steady_pings() {"):]
        body = body[: body.index("\n}\n")]
        self.assertIn('steady_ping_gate "$label" "$PINGS" "$MAX_LOSS" "$STEADY_MAX_MS" "$STEADY_WARN_MS" || exit 1', body)
        self.assertIn('STEADY_MAX_MS="${ORBLX_NATR_STEADY_MAX_MS:-200}"', text)
        self.assertIn("STEADY_WARN_MS=100", text)
        # proof_ok comes after the last steady ping run.
        self.assertGreater(text.rindex("proof_ok"), text.rindex("\nsteady_pings "))


class FullOutputAndSecretScanTest(unittest.TestCase):
    """W25-14 item 7: a proof step keeps its full output in the log, and the policy-sync leak scan fails."""

    def lib(self, script, *args, stdin=""):
        return subprocess.run(["bash", "-c", '. "$0"; set -euo pipefail; ' + script, PIPE_LIB, *args],
                              input=stdin, capture_output=True, text=True)

    def test_no_script_pipes_cargo_output_into_a_filter(self):
        bad = []
        for path in shell_files():
            with open(path, errors="replace") as f:
                for n, line in enumerate(f, 1):
                    if not line.lstrip().startswith("#") and re.search(r"\bcargo (test|build|run|clippy)\b[^#]*\|", line):
                        bad.append("%s:%d: %s" % (os.path.relpath(path, REPO), n, line.strip()))
        self.assertEqual(bad, [])

    def test_show_matching_prints_the_full_input_when_nothing_matches(self):
        res = self.lib("printf 'error: the cause\\ntest result: FAILED\\n' | show_matching -E '^test ok'")
        self.assertEqual(res.returncode, 1)
        self.assertIn("error: the cause", res.stderr)
        res = self.lib("printf 'a\\ntest ok 1\\n' | show_matching -E '^test ok'")
        self.assertEqual((res.returncode, res.stdout), (0, "test ok 1\n"))

    def scan(self, text):
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(text)
        return self.lib('secret_scan "$1"', f.name)

    def test_secret_scan_fails_on_a_key_a_token_or_an_empty_log(self):
        noise = "".join("router | line %d\n" % i for i in range(200000))
        res = self.scan(noise + "a | -----BEGIN PRIVATE KEY-----\n")
        self.assertEqual(res.returncode, 1)
        self.assertIn("secret_grep 'PRIVATE KEY' 1", res.stdout)
        self.assertEqual(self.scan("b | token ge1.fake\n" + noise).returncode, 1)
        self.assertEqual(self.scan("").returncode, 1)
        self.assertEqual(self.lib('secret_scan /nonexistent/all-logs.out').returncode, 1)
        res = self.scan(noise)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("secret_grep 'PRIVATE KEY' 0", res.stdout)

    def test_policy_sync_uses_the_secret_scan_and_fails_on_a_log_error(self):
        with open(os.path.join(REPO, "scripts", "proof", "policy-sync.sh")) as f:
            text = f.read()
        self.assertIn('secret_scan "$WORK/all-logs.out" || fail', text)
        self.assertIn('logs >"$WORK/all-logs.out" 2>&1 || fail', text)
        self.assertNotIn("grep -cF 'PRIVATE KEY'", text)


SIEM = os.path.join(REPO, "scripts", "proof", "siem-streaming.sh")


class SiemStreamingTest(unittest.TestCase):
    """W25-14 items 8 and 9: the siem-streaming leak checks fail closed, and gate 1 uses one clock."""

    def script(self):
        with open(SIEM) as f:
            return f.read()

    def arrivals(self, tmp, rows, start, limit=10000, lo=0, hi=3):
        import json
        src = self.script()
        a = src.index("cat > \"$WORK/arrivals.py\" <<'PY'\n")
        a = src.index("\n", a) + 1
        b = src.index("\nPY\n", a)
        prog = os.path.join(tmp, "arrivals.py")
        with open(prog, "w") as f:
            f.write(src[a:b] + "\n")
        os.makedirs(os.path.join(tmp, "recv", "s"), exist_ok=True)
        with open(os.path.join(tmp, "recv", "s", "arrivals.jsonl"), "w") as f:
            for seq, ms in rows:
                f.write(json.dumps({"seq": seq, "recv_ms": ms}) + "\n")
        with open(os.path.join(tmp, "chain.jsonl"), "w") as f:
            f.write("")
        res = subprocess.run(["python3", prog, os.path.join(tmp, "chain.jsonl"), os.path.join(tmp, "recv"),
                              str(start), str(lo), str(hi), str(limit), "s"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout

    def test_gate1_has_no_second_clock(self):
        src = self.script()
        self.assertNotIn("coord-ts.log\" \"$g", src)
        self.assertNotIn("latency_ms min", src)
        for g in ("g1", "g3", "g4"):
            self.assertIn('%s_start_ms="$(now_ms)"' % g, src)

    def test_gate1_passes_inside_the_limit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = self.arrivals(tmp, [(0, 1010.0), (1, 1020.0), (2, 1030.5)], 1000)
        self.assertIn("start_to_last_arrival_ms 30.5", out)
        self.assertTrue(out.endswith("arrivals ok\n"), out)

    def test_gate1_fails_over_the_limit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = self.arrivals(tmp, [(0, 1010.0), (1, 1020.0), (2, 11000.1)], 1000)
        self.assertTrue(out.endswith("arrivals fail\n"), out)

    def test_gate1_fails_when_a_record_arrives_before_the_start(self):
        # The old reader printed a negative latency (min -13.9 ms) and passed.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = self.arrivals(tmp, [(0, 986.1), (1, 1020.0), (2, 1030.0)], 1000)
        self.assertIn("start_to_first_arrival_ms -13.9", out)
        self.assertTrue(out.endswith("arrivals fail\n"), out)

    def test_gate1_fails_on_a_gap_duplicate_or_no_records(self):
        import tempfile
        for rows in ([(0, 1010.0), (2, 1030.0)], [(0, 1010.0), (1, 1020.0), (1, 1021.0), (2, 1030.0)], []):
            with tempfile.TemporaryDirectory() as tmp:
                out = self.arrivals(tmp, rows, 1000)
            self.assertTrue(out.endswith("arrivals fail\n"), (rows, out))

    def test_leak_checks_fail_closed(self):
        src = self.script()
        self.assertIn('. "$ROOT/scripts/proof/pipe-lib.sh"', src)
        self.assertIn('> "$WORK/logs.txt" 2>&1 || fail', src)
        self.assertIn('secret_scan "$WORK/logs.txt" || fail', src)
        self.assertNotIn("/var/lib/orblx | wc -l", src)
        self.assertNotIn("/recv | wc -l", src)
        self.assertRegex(src, r'hits_state=.*\|\| fail')
        self.assertRegex(src, r'hits_recv=.*\|\| fail')
        self.assertIn('[[ "$recv_files" -gt 0 ]] || fail', src)

    def test_container_scan_fails_when_grep_fails(self):
        # The old form "grep -rlF ... DIR | wc -l" printed 0 when DIR was missing.
        old = subprocess.run(["sh", "-c", "grep -rlF x /no/such/dir 2>/dev/null | wc -l"], capture_output=True, text=True)
        self.assertEqual((old.returncode, old.stdout.strip()), (0, "0"))
        new = subprocess.run(["sh", "-c", "set -e; test -d /no/such/dir; wc -l < /dev/null"], capture_output=True, text=True)
        self.assertNotEqual(new.returncode, 0)


# compose-clean.sh (#114) is a library. It removes containers and starts none.
COMPOSE_PROOF_LIBS = {"serve-lib.sh", "stage-image.sh", "pipe-lib.sh", "proof-lock.sh", "compose-clean.sh"}


class ComposeCleanupTest(unittest.TestCase):
    """W25-14b: a proof that starts compose containers removes them on each exit (port 443 leak)."""

    def test_each_compose_proof_has_a_down_in_its_exit_trap(self):
        proof_dir = os.path.join(REPO, "scripts", "proof")
        bad = []
        for name in sorted(os.listdir(proof_dir)):
            if not name.endswith(".sh") or name in COMPOSE_PROOF_LIBS:
                continue
            with open(os.path.join(proof_dir, name)) as f:
                src = f.read()
            if not re.search(r"docker compose|\bdc\(\)|\bcompose\(\)", src):
                continue
            trap = re.search(r"^\s*trap '([^']*)' EXIT", src, re.M)
            if not trap:
                bad.append("%s: no exit trap with cleanup" % name)
                continue
            funcs = re.findall(r"\b([a-z_]+)\b", trap.group(1))
            bodies = "".join(re.findall(r"^%s\(\) \{\n(.*?)^\}" % fn, src, re.M | re.S)[0]
                             for fn in funcs if re.search(r"^%s\(\) \{" % fn, src, re.M))
            if not re.search(r"\bdown\b", bodies):
                bad.append("%s: the exit trap does not run compose down" % name)
        self.assertEqual(bad, [])

    def test_coord_enroll_up_check_needs_a_real_tun_and_a_bad_netmap_fails(self):
        with open(os.path.join(REPO, "scripts", "proof", "coord-enroll.sh")) as f:
            src = f.read()
        with open(os.path.join(REPO, "scripts", "proof", "compose.coord.yml")) as f:
            compose = f.read()
        self.assertIn("/dev/net/tun:/dev/net/tun", compose)
        self.assertIn("NET_ADMIN", compose)
        for text in ("orblx up did not accept the netmap.", "orblx up rejected the coordinator netmap.",
                     "orblx up reported success without a TUN device.",
                     "orblx up changed the node state when the TUN device did not open.",
                     "orblx up did not reject the changed netmap.", 'grep -qx "The overlay IP is ${self_ip}."'):
            self.assertIn(text, src)
        self.assertNotIn("sleep", src[src.index("orblx up reads netmap.json"):])
        self.assertLess(src.index("trap 'cleanup; proof_lock_end' EXIT"), src.index('proof_lock_take "coord-enroll"'))
        # W25-14b: the free-space check runs before the lock and before any proof step.
        self.assertIn("COORD_ENROLL_MIN_FREE_GIB=12", src)
        self.assertLess(src.index("proof_infra_abort coord-enroll reason=disk_low"), src.index('proof_lock_take "coord-enroll"'))
        self.assertLess(src.index("proof_infra_abort coord-enroll reason=disk_low"), src.index("cargo build"))
        # Without "--profile nodes", "down -v" keeps the node volumes (and an old ticket.bin).
        self.assertIn("dc --profile nodes down -v --remove-orphans", src)
        self.assertNotRegex(src, r"(?m)^dc down -v")
        self.assertIn("orblx-coord-proof_orblx-node-a", src)
        # PO gate 2c: a stale ticket.bin with no netmap must make up fail.
        self.assertIn("orblx up did not stop on a stale ticket.bin with no netmap", src)
        self.assertIn("orblx up reported ready with a stale ticket.bin and no netmap.", src)
        # PO: wait_bundle has a hard deadline and a timeout on each read.
        body = src[src.index("wait_bundle() {"):src.index("echo \"=== [C] remove old proof volumes")]
        self.assertIn("WAIT_BUNDLE_SECS=90", src)
        self.assertIn("SECONDS < deadline", body)
        self.assertIn("timeout 10 ", body)
        self.assertIn("return 1", body)

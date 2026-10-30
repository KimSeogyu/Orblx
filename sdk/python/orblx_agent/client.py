"""Client for agent JIT grants and the orblx gateway.

Each method runs one `orblx agent` command with `subprocess` and reads the
`key value` lines that the command prints. The command never prints a key,
a ticket, or a use proof. The SDK also removes such text from its log and
from its errors, as a second guard.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

LOG = logging.getLogger("orblx_agent")

EXIT_DENIED = 3
MAX_GRANT_SECS = 300

# Text that must not go to a log: PEM blocks, base64 of the use proof
# magic "OBLXAGT1", enroll tokens, proof header values, and long runs of
# base64 text.
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]+-----.*?(?:-----END [A-Z ]+-----|$)", re.S), "[redacted]"),
    (re.compile(r"T0JMWEFHVDE[A-Za-z0-9+/=_-]*"), "[redacted]"),
    (re.compile(r"\bge1\.[A-Za-z0-9._-]+"), "[redacted]"),
    (re.compile(r"(?i)(orblx-agent-proof\s*[:=]\s*)\S+"), r"\1[redacted]"),
    (re.compile(r"[A-Za-z0-9+/_-]{120,}={0,2}"), "[redacted]"),
]


def redact(text: str) -> str:
    """Return the text with key, token, and proof material removed."""
    out = text
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _log_args(command: Sequence[str]) -> List[str]:
    """Return the command for the log: no path query and no body text."""
    out = list(command)
    for index in range(len(out) - 1):
        if out[index] == "--path":
            out[index + 1] = out[index + 1].split("?")[0]
        elif out[index] == "--body":
            out[index + 1] = f"[{len(out[index + 1].encode())} bytes]"
    return out


class OrblxError(RuntimeError):
    """An `orblx` command failed. The message has no secret material."""

    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(redact(message))
        self.code = code


class GrantPending(OrblxError):
    """The owner did not approve the grant before the wait ended."""


@dataclass(frozen=True)
class CoordTarget:
    """Where the coordinator is, and the node state of this host."""

    coord: str
    state: str = "/var/lib/orblx"
    bundle: Optional[str] = None
    coord_name: Optional[str] = None

    def flags(self) -> List[str]:
        bundle = self.bundle or str(Path(self.state) / "bundle.pem")
        out = ["--coord", self.coord, "--state", self.state, "--bundle", bundle]
        if self.coord_name:
            out += ["--coord-name", self.coord_name]
        return out


@dataclass(frozen=True)
class Grant:
    """An issued grant. `files` is the grant directory (mode 0700)."""

    grant_id: str
    agent: str
    node: str
    addr: str
    service: str
    port: int
    path: str
    approver: str
    not_before: int
    expires_ms: int
    files: str

    def expired(self, now_ms: Optional[int] = None) -> bool:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        return now >= self.expires_ms


@dataclass(frozen=True)
class Response:
    """One gateway reply.

    `body` is the first body line for a 200 reply. For a refusal,
    `reason` is the deny token, for example `path`, `expired`, or `replay`.
    """

    status: int
    reason: Optional[str]
    body: str
    at_ms: int
    done_ms: int

    @property
    def ok(self) -> bool:
        return self.status == 200


@dataclass
class AgentClient:
    """Request a grant, wait for the owner, and call the gateway."""

    target: CoordTarget
    agent: str
    orblx: str = "orblx"
    timeout: float = 30.0
    _env: Optional[Dict[str, str]] = field(default=None, repr=False)

    def _run(self, args: Sequence[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        command = [self.orblx, *args]
        LOG.debug("run %s", redact(" ".join(_log_args(command))))
        try:
            done = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env=self._env,
                check=False,
            )
        except FileNotFoundError as err:
            raise OrblxError(f"The orblx command was not found: {self.orblx}") from err
        except subprocess.TimeoutExpired as err:
            raise OrblxError("The orblx command did not finish in time.") from err
        LOG.debug("exit %s", done.returncode)
        return done

    @staticmethod
    def _fields(text: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in text.splitlines():
            key, _, value = line.partition(" ")
            if key and key not in out:
                out[key] = value.strip()
        return out

    @staticmethod
    def _fail(done: subprocess.CompletedProcess, what: str) -> OrblxError:
        detail = (done.stderr or done.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else "no output"
        return OrblxError(f"{what} failed (exit {done.returncode}): {tail}", done.returncode)

    def request_grant(
        self,
        node: str,
        service: str,
        port: int,
        ttl: int,
        path: Optional[str] = None,
    ) -> str:
        """Ask the coordinator for a grant. Return the grant id (pending)."""
        if not 0 < ttl <= MAX_GRANT_SECS:
            raise ValueError(f"ttl must be 1 to {MAX_GRANT_SECS} seconds")
        if not 0 < port < 65536:
            raise ValueError("port must be 1 to 65535")
        args = [
            "agent", "grant", "request",
            "--agent", self.agent,
            "--node", node,
            "--service", service,
            "--port", str(port),
            "--ttl", str(ttl),
        ]
        if path:
            args += ["--path", path]
        done = self._run(args + self.target.flags())
        if done.returncode != 0:
            raise self._fail(done, "The grant request")
        fields = self._fields(done.stdout)
        grant_id = fields.get("grant_id", "")
        if not re.fullmatch(r"[0-9a-f]{16}", grant_id):
            raise OrblxError("The grant request gave no valid grant id.")
        LOG.info("grant %s state %s", grant_id, fields.get("grant_state", "?"))
        return grant_id

    def wait_for_approval(self, grant_id: str, out: str, wait: float = 300.0, poll: float = 5.0) -> Grant:
        """Wait until a human owner approves the grant, then fetch it one time.

        The grant files go to `out`. The SDK does not read the key or the ticket.
        """
        limit = time.monotonic() + wait
        while True:
            left = max(1.0, min(poll, limit - time.monotonic()))
            done = self._run(
                ["agent", "grant", "fetch", "--id", grant_id, "--out", out,
                 "--wait", str(int(left))] + self.target.flags(),
                timeout=left + self.timeout,
            )
            fields = self._fields(done.stdout)
            if done.returncode == 0 and fields.get("grant_state") == "issued":
                grant = Grant(
                    grant_id=fields["grant_id"],
                    agent=fields.get("grant_agent", ""),
                    node=fields.get("grant_node", ""),
                    addr=fields.get("grant_addr", ""),
                    service=fields.get("grant_service", ""),
                    port=int(fields.get("grant_port", "0")),
                    path=fields.get("grant_path", "/"),
                    approver=fields.get("grant_approver", ""),
                    not_before=int(fields.get("grant_not_before", "0")),
                    expires_ms=int(fields.get("grant_expires_ms", "0")),
                    files=fields.get("grant_files", out),
                )
                LOG.info("grant %s issued approver %s expires_ms %s", grant.grant_id, grant.approver, grant.expires_ms)
                return grant
            if done.returncode == EXIT_DENIED and fields.get("grant_state") == "pending":
                if time.monotonic() >= limit:
                    raise GrantPending(f"The grant {grant_id} is not approved.", done.returncode)
                LOG.info("grant %s pending", grant_id)
                continue
            raise self._fail(done, "The grant fetch")

    def call(
        self,
        grant: Grant,
        path: str,
        method: str = "GET",
        body: str = "",
        to: Optional[str] = None,
        timeout: int = 5,
    ) -> Response:
        """Send one HTTP request through the orblx gateway with a new proof."""
        args = [
            "agent", "http",
            "--grant", grant.files,
            "--method", method,
            "--path", path,
            "--timeout", str(timeout),
        ]
        if body:
            args += ["--body", body]
        if to:
            args += ["--to", to]
        at_ms = int(time.time() * 1000)
        done = self._run(args, timeout=timeout + self.timeout)
        done_ms = int(time.time() * 1000)
        line = next((item for item in done.stdout.splitlines() if item.startswith("http attempt ")), "")
        if done.returncode not in (0, EXIT_DENIED) or not line:
            raise self._fail(done, "The gateway call")
        words = line.split(" ")
        status = int(words[4]) if len(words) > 4 and words[4].isdigit() else 0
        reason = None
        text = ""
        if status == 200:
            _, _, text = line.partition(" body ")
        elif "reason" in words:
            reason = words[words.index("reason") + 1]
        LOG.info("call %s %s status %s reason %s", method, path.split("?")[0], status, reason or "-")
        return Response(status=status, reason=reason, body=text, at_ms=at_ms, done_ms=done_ms)

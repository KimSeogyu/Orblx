# W22-4 Python agent SDK

`sdk/python/orblx_agent` lets a Python agent use agent JIT grants and the orblx gateway.
The agent asks for a grant, waits for a human owner to approve it, and calls the gateway.

The SDK runs the `orblx` command with `subprocess`. It adds no crypto and no handshake.
The Rust core signs and checks the grant, the ticket, and each request proof.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result.

## Why the SDK calls the orblx command

- The command is already on each node. The SDK needs no build step and no native module.
- PyO3 would need a Rust build for each Python version and platform.
- The key, the ticket, and the use proof stay inside the `orblx` process and the grant directory (mode 0700). The SDK reads only the `key value` lines that the command prints. These lines hold no secret.

## Install

The package has no dependencies. It needs Python 3.8 or later and the `orblx` command on `PATH`.

```sh
pip install ./sdk/python
```

## Use

```python
from orblx_agent import AgentClient, CoordTarget

client = AgentClient(CoordTarget(coord="100.64.0.1:443", state="/var/lib/orblx"), agent="sdkbot")
grant_id = client.request_grant("b", "api", 8080, ttl=60, path="/api")
grant = client.wait_for_approval(grant_id, "/var/lib/orblx/sdk-g1", wait=300)
reply = client.call(grant, "/api/items")
if reply.ok:
    print(reply.body)
else:
    print(reply.status, reply.reason)
```

| Method | Command | Result |
|---|---|---|
| `request_grant(node, service, port, ttl, path)` | `orblx agent grant request` | grant id. The grant is pending |
| `wait_for_approval(grant_id, out, wait, poll)` | `orblx agent grant fetch --wait` | `Grant` after the owner approves. `GrantPending` when the wait ends |
| `call(grant, path, method, body)` | `orblx agent http --grant` | `Response` with `status`, `reason` (deny token), `body` |

- Only a human owner approves a grant (`orblx admin grant-approve ID`). The SDK cannot approve.
- `call` sends a new proof and a new nonce for each request.
- A refusal gives `status` 403 and a `reason` such as `path`, `expired`, `revoked`, or `replay`. `call` does not raise for a refusal.
- `OrblxError` is raised when the command fails. The message goes through `redact`.

## Logs

The SDK logs to the `orblx_agent` logger. It logs the command line, the exit code, the grant id, the state, and the status of each call.
It does not log the query of a path or the body text. It logs the body size.
`redact()` removes PEM blocks, use proof text (`T0JMWEFHVDE...`), enroll tokens (`ge1.`), proof header values, and long base64 runs from each log line and each error, as a second guard.

## Tests

- `python3 -m unittest discover -s sdk/python/tests -v` runs the unit tests with a fake `orblx` command. CI runs them on Linux and macOS.
- The tests cover: request and approval wait, 200 in scope, 403 `path` out of scope, 403 `expired` after the end, the pending timeout, the TTL check, the redact function, and that errors and logs hold no key.

## Proof

Script: `scripts/proof/agent-python-sdk.sh`. It prints `proof_ok` at the end.

1. The script starts a coordinator, nodes a and b, an upstream on b, and `orblx gateway` for service `api`, port 8080.
2. It copies the SDK and `sdk/python/examples/example_agent.py` to node a and starts the example agent (agent `sdkbot`, path `/api`, TTL 20 s).
3. The agent requests the grant and waits. After 3 s the script checks that the agent has no grant yet. Then the owner approves.
4. The agent calls `GET /api/items` and `POST /api/items`, then `GET /admin`, then calls each 50 ms until a refusal.
5. The script checks the gateway chain, the coordinator chain, and greps all logs for the ticket, the key, and proof text.

### Result (2026-10-30 13:05 KST, log `w22-4-try2.log`)

| Check | Result |
|---|---|
| [C] Grant before the approval | pending. The agent waited |
| [C] After the approval | `GET /api/items` 200, `POST` 200 (body 9 bytes) |
| [C] Outside the scope (`/admin`) | 403 `path` |
| [C] After the end | 403 `expired`, 82 ms after the end (limit 1000 ms) |
| [C] Gateway chain | `ok`, 138 `agent-use`, deny `path` 1, deny `expired` 1 |
| [C] Coordinator chain | `verify ok`, with the owner `agent-approve` record |
| [C] Log grep (coordinator, nodes, gateway, upstream, agent output, SDK debug log) | ticket 0, key 0, `PRIVATE KEY` 0, `T0JMWEFHVDE` 0, `ge1.` 0, `orblx-agent-proof` 0, POST body text 0 |

The values of the run on main are in the PR report.

## Caveats

- Each call starts one `orblx` process (a few ms of overhead).
- `Response.body` holds the first line of the reply body only. The `orblx agent http` command reads one line.
- The SDK has no async API.
- The SDK is not on PyPI.
- No REAL run.

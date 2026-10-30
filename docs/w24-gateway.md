# W24-B gateway hardening

This change closes two known limits of the agent gateway ([W21 agent gateway](w21-agent-gateway.md), [W22-1 agent hardening](w22-agent-hardening.md)).
It adds no new crypto and no new handshake. It uses the existing use proof (`seal_use` and `open_use`, the SVID Ed25519 signature) and puts more bytes in its signed `extra` field.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result. The proof ran on one Linux box with Docker.

## Changes

| Item | Change | Mark |
|---|---|---|
| (a) Signed headers | The proof now binds each request header except the proof header, and the HTTP version. A changed, added, removed, or renamed header gets `403 ticket`. | [C] |
| (b) Nonce file | The gateway keeps the used nonces in a nonce file apart from the audit chain file. A restart with the audit chain file removed still refuses a replay with `403 replay`. | [C] |
| (c) W21-3, W22-1, W22-4 | The old proofs pass again with this change. | [C] |

## (a) Signed headers

### Signed bytes

The `extra` bytes are:

```text
orblx-gateway-v2
METHOD
TARGET
HTTP_VERSION
NONCE_HEX
SHA256_HEX(header block)
SHA256_HEX(body)
```

The header block has one `name:value\n` line for each request header, in the order of the request:

- The name is lowercase.
- The value has no spaces at the start or the end.
- The `orblx-agent-proof` header is not in the block. It holds the signature.
- All other headers are in the block: `host`, `connection`, `content-length`, `orblx-agent-nonce`, and each caller header.

The gateway makes the same block from the headers that it reads. A different block gives a different `extra`, and the proof check fails with `403 ticket`.
A header name with other letter case has the same meaning in HTTP, so it is the same block.

### Clients

- `orblx agent http --header NAME:VALUE` (more than one is permitted) adds a caller header. The client refuses `host`, `connection`, `content-length`, `transfer-encoding`, the two proof headers, `x-orblx-*` names, and values with control bytes.
- The Python SDK calls the `orblx` CLI, so it uses the same code. It needs no change.
- The `orblx-gateway-v1` label is not accepted. A v1 client gets `403 ticket`. The release is a release candidate, and all clients in this repository use v2.

## (b) Nonce file

- Flag: `orblx gateway --nonce-file FILE`. The default is `AUDIT.nonces` (for example `gateway-audit-api.jsonl.nonces`).
- Line format: `orblx-nonce-v1 TICKET_HASH_HEX NONCE_HEX STAMP_SECS`. The file holds no key, no ticket, and no proof. Mode 0600.
- The gateway appends the line and syncs the file before it forwards the request. If the write fails, the request gets `403 store` (fail closed).
- At start, the gateway reads the file and keeps the entries of the last two proof windows (120 s). It writes the kept entries to a new file (temp file, then rename).
- A line that is not valid stops the start (fail closed). A last line without a line end is a write that did not complete. Its request did not go on, so the gateway drops it.
- The gateway also reads the W22-1 `agent-use` records from the audit chain. The seen set is the union of the two.
- The start line now shows the file: `agent gateway service api ... nonces_loaded N nonce_file PATH`.
- The TCP guard has no request nonce and uses no nonce file.

## Proof

Script: `scripts/proof/agent-gateway.sh` (W21-3, W22-1 restart, and the W24-B checks).
The three agent proofs now take `PROOF_PROJECT` and `ORBLX_AGENT_IMAGE` for a parallel run. This run used `orblx-w24b-agent` and `orblx-w24b-agent:w24`.

Command (branch head `a4743ff9`):

```sh
sudo -n env PATH=... PROOF_PROJECT=orblx-w24b-agent ORBLX_AGENT_IMAGE=orblx-w24b-agent:w24 \
  ./scripts/proof/agent-gateway.sh > /workspace/orblx-w18-proof/w24b-a4743ff9-agent-gateway.log 2>&1
```

| Check | Result |
|---|---|
| [C] Signed caller header to the upstream | `200`, upstream saw `kind read` |
| [C] Changed header value (`x-kind: read` to `write`) | `403 ticket` |
| [C] Renamed header (`x-kind` to `x-kinx`) | `403 ticket` |
| [C] Changed `host` | `403 ticket` |
| [C] Nonce file mode | `600` |
| [C] Restart with the audit chain file removed | start line `nonces_loaded 142`, the audit chain file was removed and the new chain started empty |
| [C] Replay of the saved bytes after that restart | `403 replay`, 2235 ms after the first use. The new chain has 1 replay record and checks `ok` |
| [C] New request after that restart | `200` |
| [C] W21-3 checks (scope, other service, other port, replay, TTL) | pass. TTL deny 62 ms after the end (limit 1000 ms) |
| [C] W22-1 restart replay (audit chain kept) | `403 replay`, 2037 ms after the first use |
| [C] Request count (W21-3 part) | 146 requests sent, 146 records in the gateway chain |
| [C] Log grep | no key, ticket, use proof, or proof header in the logs |

Other proofs, same head:

| Proof | Log | Result |
|---|---|---|
| [C] W22-1 `agent-grant.sh` | `w24b-a4743ff9-agent-grant.log` | `proof_ok`. Coordinator expire 96 ms, TTL deny 144 ms, revoke deny 294 ms after done (limit 1000 ms) |
| [C] W22-4 `agent-python-sdk.sh` | `w24b-a4743ff9-agent-python-sdk.log` | `proof_ok`. SDK call `200`, out of scope `403 path`, deny 43 ms after the end |

Unit tests: `a_changed_header_is_refused`, `a_restart_without_the_audit_file_keeps_the_used_nonces`, `extra_binds_each_header_but_not_the_proof`, `caller_headers_are_checked`, and the `nonce_store` tests.

## Known limits

- A person with write access to the gateway host can remove the nonce file and the audit chain file. The gateway then accepts a replay inside the 60 s proof window. This is the same trust as for the audit chain.
- The body is bound by its SHA-256. The gateway reads at most 1 MiB and refuses `transfer-encoding`, as before.
- No REAL run.

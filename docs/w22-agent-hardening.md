# W22-1 agent hardening

This change closes gaps in the W21 agent grant ([W21 agent grant](w21-agent-grant.md)) and the agent gateway ([W21 agent gateway](w21-agent-gateway.md)).
It adds no new crypto and no new handshake.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result.

## Changes

| Item | Change | Mark |
|---|---|---|
| (a) Coordinator expiry | A coordinator tick each 500 ms writes the `agent-expire` record for each ended grant. No `orblx admin grants` call is necessary. | [C] |
| (b) Revoke scope | The `orblx admin` help, the revoke output, and the docs say that a revoke stops all grants for that agent name. | [C] |
| (c) TCP replay window | The W21 grant doc states the 60 s use proof replay window of the TCP guard as a known limit. | doc |
| (d) Gateway restart replay | The gateway keeps the used nonces across a restart. A proof that was used before the restart is refused with `403 replay` and audited. | [C] |
| (e) Gateway known limits | The W21 gateway doc lists the limits. | doc |

## (a) Coordinator expiry

- `expire_due` takes the grant lock, finds each issued grant with `now >= expires` and no expire record, and writes one `agent-expire` record.
- The detail is `expires SECS seen_ms MS`. `seen_ms` is the coordinator time of the record in Unix ms.
- The coordinator prints `coord agent grant ID expired expires SECS seen_ms MS`.
- `orblx admin grants` uses the same function. A grant gets one expire record only.

## (b) Revoke scope

A revoke puts the agent SPIFFE ID and the ticket nonce in the deny set. Thus:

- all grants for that agent name stop,
- the coordinator does not issue a later grant for the same agent name. The fetch fails.

Use a new agent name after a revoke. W22-2 adds a revoke for one grant.

## (d) Gateway restart replay

### Decision

The gateway stores the used nonces in its existing audit chain, and reads them at start.

- Each `agent-use` record detail now holds `nonce HEX stamp SECS`.
- At start, the gateway opens its chain. `ConfigLog::open` checks the full chain. A changed chain stops the start (fail closed).
- The gateway loads `(ticket_hash, nonce) -> stamp` from each `agent-use` record of the last 2 x 60 s.
- The gateway writes the use record before it forwards the request. Thus each forwarded request is in the chain before the upstream sees it.
- The start line prints `nonces_loaded N`.

### Why not a cutoff at the process start time

The proof stamp is the agent clock in whole seconds, with a 60 s window on each side.
A rule "refuse each proof made before the process start" is not sound:

- an agent clock that is behind lets an old proof through,
- an agent clock that is ahead, or a strict rule, refuses valid new requests for up to 60 s after each restart.

The chain is already written and checked. Thus the persisted set adds no new file, no new format, and no new crypto.

### Limits

- A restart with a different `--audit` file starts with an empty set.
- Each gateway process has its own set. Two gateways do not share it.
- `agent-use` records written before W22-1 have no nonce. The gateway skips them.

## Proof

Scripts: `scripts/proof/agent-grant.sh` and `scripts/proof/agent-gateway.sh`. Each script prints `proof_ok` at the end.

- `agent-grant.sh` does not call `orblx admin grants` after the end of grant 1 until the check is done. It waits for the coordinator expire line, prints `coord_expire_after_end_ms` (`seen_ms` minus the end time), and checks `owner audit` for the `agent-expire` record and `verify ok`. After the revoke, it requests, approves, and fetches grant 3 for the same agent name, and expects the fetch to fail.
- `agent-gateway.sh` gets grant 2 (TTL 120 s), sends one request with `--save-request FILE` (mode 0600), stops the api gateway, starts it again with the same audit file, and sends the saved bytes with `--send-file FILE`. It expects `403 replay`, a second replay record in the chain, and `200` for a new request with the same grant.

### Result (2026-10-30 12:37 KST, logs `w22-1-grant-try2.log` and `w22-1-gateway-try1.log`)

| Check | Result |
|---|---|
| [C] Coordinator expire record, no list call | `seen_ms` 203 ms after the end. The script saw the line 906 ms after the end (it polls `docker logs`). Coordinator chain `verify ok` |
| [C] Guard TTL deny | client deny 54 ms after the end |
| [C] Revoke deny | client deny 273 ms after `revoke_done` |
| [C] Later grant for the same agent name after a revoke | fetch refused |
| [C] Gateway restart replay | restart loaded 132 nonces. The saved bytes, sent 3179 ms after the first use, gave `403 replay`. The chain has the replay record and checks `ok` |
| [C] New request after the restart | 200 |
| [C] Request count | 142 requests sent, 142 records in the gateway chain |
| [C] Log grep | no key, ticket, use proof, or proof header in the logs |

The values of the run on main are in the PR report.

## Caveats

- The client line for `--send-file` prints the default path `/`. The saved bytes hold the real path.
- The TCP guard has no request nonce. The 60 s replay window stays (known limit).
- No REAL run.

# Agent JIT grant

An AI agent can get a short grant for exactly one service, one port, and a TTL of 300 s or less.
A guard on the receiver node admits a TCP connection only with a valid grant.
The design uses only parts that exist:

- The SVID issue path of the coordinator.
- Ed25519 signatures with the netmap key.
- The W19 SSH JIT ticket pattern (a signed ticket and a one-line use proof).
- The receiver `deny.json` and the coordinator deny op.
- The config audit chain from W20.

No new crypto or handshake design is in this change.

## Approval decision

Only a human owner approves an agent grant.
The owner uses the admin API: `orblx admin grant-approve ID`.
The policy `autoApprovers` do not apply to agent grants.
Reason: an agent can send requests in a loop, and an automatic approval removes the human check that the brief requires.
A later change can add an auto-approval rule. That change must have its own review.

## Flow

1. The agent runs `orblx agent grant request --agent NAME --node B --service S --port P --ttl T` on node a.
   The coordinator checks the node SVID, the TTL (1 to 300 s), the port (1 to 65535), and the policy.
   The grant state is `pending`. The chain gets an `agent-grant` record.
2. The owner runs `orblx admin grants` and `orblx admin grant-approve ID`.
   The chain gets an `agent-approve` record.
3. The agent runs `orblx agent grant fetch --id ID --out DIR`.
   The coordinator issues a short SVID `spiffe://orblx.local/agent/NAME` and a signed grant.
   The grant `expires` is the SVID end. The fetch works one time only.
   The chain gets an `agent-grant` record with `issued` and the ticket hash.
4. The agent runs `orblx agent connect --grant DIR --to IP:PORT --service S`.
   The first line is the use proof: base64 of the magic `OBLXAGT1`, the grant, and an Ed25519 signature over the destination.
5. The guard (`orblx agent guard --listen IP:PORT --service S --target 127.0.0.1:PORT`) checks:
   - the grant signature with `netmap.pub`,
   - the ticket signature with `ticket-verifier.pem`,
   - the service, the node, and the port,
   - the end time, with a strict millisecond check and no skew,
   - the deny list from the coordinator, polled each 200 ms.
   If the last good poll is older than 2 s, the guard refuses with `stale` (fail closed).
6. The owner runs `orblx admin grant-revoke ID`.
   The coordinator adds the ticket nonce of grant ID to `deny.json`. The chain gets an `agent-revoke` record.
   Since W22-2 a revoke stops grant ID only. Other grants for the same agent name stay valid ([W22 grant revoke](w22-grant-revoke.md)).

The guard writes `agent-grant`, `agent-use`, `agent-deny`, `agent-expire`, and `agent-revoke` records to its own chain file.
The coordinator writes `agent-expire` at the end time. A tick each 500 ms finds the ended grants. No admin call is necessary (W22-1).

## Deny reasons

| Case | Reason |
| --- | --- |
| No use proof line | `missing` |
| Proof for another service on the same guard | `ticket` (signature mismatch) |
| Proof for another port | `destination` |
| After the end time | `expired` |
| After a revoke | `revoked` |
| No good deny poll for 2 s | `stale` |

## Proof

| Part | Kind | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator, mock OIDC, policy `scripts/proof/agent.hujson` |
| `owner` container | [C] | Owner SVID. Runs `orblx admin` |
| `a` container | [C] | Agent node. TUN `up --coord` |
| `b` container | [C] | Receiver node. TUN. Guards `web` on 8080 and `db` on 5432 |

Run this command on the REAL Linux host:

```sh
./scripts/proof/agent-grant.sh
```

The script prints `proof_ok` at the end.
Set `PROOF_KEEP=1` to keep the stack.

### Result (2026-10-30 11:21 KST, log `w21-2-try6.log`)

| Check | Result |
| --- | --- |
| [C] TTL 301 | Refused |
| [C] Fetch before approve | `pending` |
| [C] Second fetch | Refused |
| [C] Connect to web 8080 | `connect ok`, HTTP 200 |
| [C] Port 5432, service db | `destination` |
| [C] Port 5432, service web | `ticket` |
| [C] Port 8080, service db | `ticket` |
| [C] No grant | `orblx-deny missing` |
| [C] TTL end 11:21:56.000 KST | Guard deny at +91 ms. Client deny reply at +120 ms. Last ok at -121 ms |
| [C] Revoke | Guard deny 150 ms after `revoke_done`. Client deny reply 168 ms after `revoke_done`, 377 ms after `revoke_start` |
| [C] Web guard chain | `ok`, 137 records: grant 2, use 129, deny 4, expire 1, revoke 1 |
| [C] Db guard chain | `ok`, 2 records: deny 2 |
| [C] Coordinator chain | `verify ok`, 14 records, with agent-grant, agent-approve, agent-expire, agent-revoke |
| [C] Logs | 0 matches for ticket hex, key PEM, `PRIVATE KEY`, `T0JMWEFHVDE`, `ge1.` |

The limit is 1000 ms. All measured times are below the limit.

## Caveats

- Known limit: the TCP guard has no request nonce. A copy of a use proof can be sent again to the same guard within the 60 s proof window, until the grant ends or a revoke. The HTTP gateway (W21-3) has a nonce and a replay check. See [W22 agent hardening](w22-agent-hardening.md).
- A grant has many uses in its TTL. The guard records each use.
- A clock difference between the coordinator and the receiver moves the end time by the same value.
- The guard refuses all connections when the deny poll is older than 2 s.
- The chain holds a hash of the ticket (a fingerprint), not the ticket.
- The coordinator tick can write `agent-expire` up to 500 ms after the end, plus the time of one chain write.
- `up --coord` does not refresh the netmap. The proof runs `coord netmap` before `up`.
- Since W22-2 a revoke denies the ticket nonce of one grant. To stop all grants for an agent, revoke each grant ID.
- Each guard process writes its own chain file.

## Renewal (W25-30)

A grant is single-use. A running `connect` or `http` loop reads the grant directory again before each attempt.
When the agent fetches a newer approved grant with the same scope into the same directory, the loop uses it without a restart.
The loop never takes a next grant with another scope, or a next grant that `deny.json` in the node state revokes.
See `docs/w25-30-agent-grant-renewal.md`.

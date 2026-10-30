# W22-2 revoke for one grant

`orblx admin grant-revoke ID` now stops grant ID only.
Other grants for the same agent name stay valid, and the coordinator can issue new grants for that name.
The change adds no new crypto and no new handshake. It uses the W19 ticket nonce deny entry.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result.

## Change

| Before (W21-2, W22-1) | After (W22-2) |
|---|---|
| The revoke puts the agent SPIFFE ID and the ticket nonce in `deny.json`. | The revoke puts the ticket nonce of grant ID in `deny.json`. The agent SPIFFE ID does not go in. |
| All grants for the agent name stop. | Grant ID stops. |
| The coordinator does not issue a later grant for that name. | The coordinator issues later grants for that name. |

- Each issued grant has its own random 16-byte ticket nonce. Thus a nonce entry matches one grant.
- The guard and the gateway check the nonce in each deny poll (each 200 ms) and in each ticket check. The guard code did not change.
- The coordinator `agent-revoke` record detail is `agent URI scope grant deny_version N`.
- The `grant-revoke` output prints `revoke_scope this grant only`.
- To stop all grants for an agent, revoke each grant ID. `orblx admin grants` lists them.

## Proof

Script: `scripts/proof/agent-grant.sh`. It prints `proof_ok` at the end.

1. Grant 2 and grant 3 are for the same agent name `bot`, service `web`, port 8080. Both give 200.
2. A loop connects with grant 2 each 50 ms. The owner revokes grant 2.
3. The script measures the first deny after `revoke_done`. The limit is 1000 ms.
4. Grant 3 gives 200 after the revoke. Grant 2 stays refused with `revoked`. The guard log has no revoke line for grant 3.
5. A new grant 4 for `bot` is issued and gives 200.
6. `deny.json` on the coordinator does not hold the agent URI.
7. The guard chain and the coordinator chain check `ok`. Both have the `agent-revoke` record.

### Result (2026-10-30 12:57 KST, log `w22-2-try2.log`)

| Check | Result |
|---|---|
| [C] Grant 2 deny after the revoke | client deny 136 ms after `revoke_done` (332 ms after `revoke_start`). Guard deny 106 ms after `revoke_done` |
| [C] Grant 3, same agent, after the revoke | 200 (400 ms after `revoke_done`) |
| [C] Grant 2 after the revoke | `revoked` |
| [C] New grant 4, same agent | 200 |
| [C] `deny.json` | no agent URI |
| [C] Guard chain | `ok`: grant 4, use 138, deny 5, expire 1, revoke 1 |
| [C] Coordinator chain | `verify ok`, 20 records. The revoke record has `scope grant` |

The values of the run on main are in the PR report.

## Caveats

- The agent SVID of a revoked grant stays valid until its end (5 minutes or less). The guard refuses it because the ticket nonce is denied. The SVID alone does not give access.
- A stop for all grants of an agent needs one revoke for each grant.
- The deny set grows by one nonce for each revoke. This change adds no pruning.
- No REAL run.

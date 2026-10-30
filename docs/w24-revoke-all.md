# W24-D revoke all access of one principal

`orblx admin revoke-all PRINCIPAL` removes all access of one principal with one command.
The command denies the SVID of the principal, revokes all agent grants of the principal, and denies the nonces of the issued grants.
SSH and file send on the other nodes then refuse the principal.
The coordinator writes exactly one audit record for the command.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result.

## Command

```text
orblx admin revoke-all PRINCIPAL --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
```

PRINCIPAL is a node name (for example `a`) or a SPIFFE URI of kind `node`, `user`, or `agent` in the mesh domain.

| Rule | Result |
|---|---|
| The node name is not enrolled. | The coordinator refuses the request. |
| The URI is a coordinator URI or has a different trust domain. | The coordinator refuses the request. |
| The URI is the URI of the caller. | The coordinator refuses the request. The caller cannot revoke its own SVID. |
| The caller is not an owner. | The coordinator refuses the request (same rule as the other admin operations). |

The command prints these lines. It prints no ticket, key, or token.

```text
revoked_all spiffe://orblx.local/node/a
revoke_scope all
svid_denied yes
revoked_grant GRANT_ID        (one line for each grant)
grants_revoked N
grant_nonces_denied M
deny_version V
revoke_start_ms MS
revoke_done_ms MS
```

## What the coordinator does

The admin operation is `admin-revoke-all`. The coordinator does these steps under the grant lock:

1. It finds the grants of the principal that are not revoked. A node principal owns the grants that it requested.
   An agent principal owns the grants for its agent name. A user principal owns no grants.
2. It collects the ticket nonces of the issued grants.
3. It adds the principal URI and the nonces to the deny list in one step. The deny version increases by 1.
4. It marks the grants revoked and saves the grants file. The deny list changes first, so no issued ticket stays valid after its grant is revoked.
5. It writes one config audit record: action `revoke`, actor = the owner, target = the principal URI,
   detail `principal URI scope all svid denied grants N nonces M deny_version V`, and the digests before and after.

The command denies only the nonces of the grants. It does not deny the agent name.
Thus a grant of a different principal for the same agent name stays valid.

The change adds no new crypto design. It uses the deny list, the grant nonces, and the config audit chain that are already in orblx.

## How each surface refuses the principal

| Surface | Check | Delay after the deny list changes |
|---|---|---|
| Agent grants | The agent guard gets the deny list every 200 ms (`--poll-ms 200`). A denied nonce gives `connect denied reason revoked`. | Up to one guard poll. |
| SVID at the coordinator | The coordinator checks the deny list for the mTLS peer of each request (netmap, renew, grants). | None. |
| SSH | The SSH server on the node reads `deny.json` in the node state for each login. A denied leaf gives `The SSH session was refused.` and an audit record `deny` with reason `revoked`. | Up to one node deny refresh. |
| File send | The file receiver reads `deny.json` for each connection. A denied sender gets `deny identity` and an audit record `file-deny`. | Up to one node deny refresh. |

## Change outside the revoke files

`orblx up` (crates/orblx-cli/src/up.rs) gets the coordinator deny list every **500 ms**. Before this change, the interval was 10 s.
With 10 s, SSH and file send cannot refuse the principal in 1 s or less.
The node writes `deny.json` only when the text changes. It writes a temporary file and renames it, so a reader never sees a part of the file.
Each refresh is one small mTLS request to the coordinator. This change does not measure the cost of this request at large node counts.

## Limits

- The datapath of the node reloads `deny.json` every 10 s. This change does not change that interval.
  Thus raw overlay traffic from the principal to a port without its own check can continue for up to 10 s.
  The proof does not measure this.
- An SSH session that is already open closes at the next recheck of the session (the `checkPeriod` of the SSH rule).
  The proof does not measure this. The proof measures new logins.
- The principal keeps its certificate files until the certificate expires. The coordinator and the peers refuse the certificate because of the deny list.
- A deny list entry stays until the coordinator removes it. This change adds no undo command.

## Proof [C]

Script: `scripts/proof/revoke-all.sh`. Compose project `orblx-w24d-revoke-all`. Policy: `scripts/proof/revoke-all.hujson`.
Probe helper: `scripts/proof/revoke-probe.py`. The script prints `proof_ok` at the end.

The proof has a coordinator, an owner node, and nodes a, b, and c. Node b runs the agent guard (TCP 8080), SSH, and the file receiver.
Node a is the principal that the owner revokes. Node c is the other principal.

1. The owner issues grants a1 and a2 to node a and grant c1 to node c. All grants are for the same agent name `bot`. Grant a3 for node a stays pending.
2. The script shows that each surface works for a and c before the revoke.
3. Probes on node a run each surface again and again (every 50 ms) until the first refusal.
   Probes on node c run each surface for 16 s (every 100 ms). Each run of c must succeed.
4. The owner runs `orblx admin revoke-all a`.
5. For each surface, the script measures the time from `revoke_done_ms` to the end of the first refused run on node a.
   The end of the first refused run is an upper limit. The run also includes the process start and the connection setup.
   The limit is 1000 ms. The first refusal must not come before `revoke_start_ms`.
6. The script checks the reason of each refusal, the grant states, the deny list, the audit chains, and the logs for secrets.

### Results [C]

Log: `/workspace/orblx-w18-proof/w24d-revoke-all-branch.log` (branch `w24-revoke-all`, 2026-10-30 KST).

| Surface of node a | Refusal | Time to refusal after `revoke_done_ms` |
|---|---|---|
| Grant a1 | `connect denied reason revoked` | 607 ms |
| Grant a2 | `connect denied reason revoked` | 397 ms |
| SVID (coordinator netmap) | `The coordinator request failed.` | 261 ms |
| SSH login to b | `The SSH session was refused.` | 258 ms |
| File send to b | `reply deny identity` | 509 ms |

| Check | Result |
|---|---|
| Output of `revoke-all a` | `grants_revoked 3` (a1, a2, a3), `grant_nonces_denied 2`, `deny_version 1` |
| Pending grant a3 | The fetch fails. State `revoked`. |
| Node c during and after the revoke | 0 failures on all 4 surfaces. Grant c1 stays `issued`. SSH and file send of c work after the revoke. |
| Coordinator deny list | `revoked_uris ["spiffe://orblx.local/node/a"]`, 2 nonces |
| Coordinator audit chain | 18 records before, 19 after: exactly 1 new record. `revoke_all_records 1`. `verify ok`. |
| Chains on node b | Guard chain, file chain, and SSH chain verify `ok`. SSH chain has 1 `deny` with reason `revoked`. File chain has 1 `file-deny` with `reason identity` for node a. |
| Secret check | No enroll token, no a1 or a2 ticket, and no `PRIVATE KEY` in the logs. |

Summary line of the proof:

```text
summary principal spiffe://orblx.local/node/a grant-a1=607 grant-a2=397 svid=261 ssh=258 file=509 limit_ms 1000 other_principal_failures 0 coord_new_records 1 revoke_all_records 1 coord_verify ok
```

## Run the proof

```sh
ORBLX_PROOF_NET_HOOK=/path/to/fix-container-egress.sh ./scripts/proof/revoke-all.sh
```

The script uses `sudo -n` for Docker when the user is not root. `ORBLX_PROOF_NET_HOOK` is optional. It runs after the coordinator starts.
`PROOF_KEEP=1` keeps the containers for debug.

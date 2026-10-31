# W25-32: OIDC step-up per SSH policy rule (design)

Status: draft design. No product code. This item is a follow-up. It is not an rc.3 blocker.

Depends on: W25-31 SSH user certificates (#127, stacked on #119).
Do the work in this document only after #127 merges.

Decisions (2026-10-31 KST):

- The PO ruled on Q1 to Q11. Section 12 has the rulings.
- Crypto answered Q4: NO. `ssh_step_up` is not a new token format. W25-32 continues.
- Crypto set 8 required conditions. Section 13 has the conditions and the code check.
- Product code waits until #127 merges.

## 1. Goal

An operator can mark one SSH policy rule as "step-up".
A login that matches that rule needs a recent OIDC login by the node owner.
A rule without the mark works as before.

The design adds no new signing and no new token format.
It uses only these existing parts:

- The OIDC ID token verifier of W17 (Google) and W20 (custom issuer).
- The node mTLS session to the coordinator.
- The signed netmap.
- The W25-31 single-use nonce pattern.
- The W25-31 node check order.

## 2. Terms

| Term | Meaning |
| --- | --- |
| Owner | The `oidc:SUBJECT` that owns the client node (W25-15). |
| Client node | The node where the user runs `orblx ssh`. |
| Destination | The node that runs the orblx SSH server. |
| Step-up | One fresh OIDC login by the owner, verified by the coordinator. |
| Step-up record | The coordinator state after one accepted step-up. |

## 3. Policy syntax

### 3.1 Do not reuse `checkPeriod`

`checkPeriod` already has a meaning.
It is the interval of the in-session recheck in `orblx-ssh` (`server.rs`, `recheck()`).
The recheck examines the policy and the revoke list. It does not ask the user to log in.
Thus this design adds a new field. It does not change `checkPeriod`.

### 3.2 New field `stepUp`

```hujson
"ssh": [
  {
    "src":   ["group:ops"],
    "dst":   ["tag:prod"],
    "users": ["root"],
    "checkPeriod": "5m",
    "stepUp": "12h"
  }
]
```

Rules for `stepUp`:

1. The field is optional. When the field is absent, the rule has no step-up.
2. The value has the same syntax as `checkPeriod`: `Ns`, `Nm`, or `Nh`. The parser adds `Nh`. There is no leading zero.
3. The range is 1 min to 24 h. The feature is off by default: a rule without `stepUp` has no step-up. A value out of the range does not compile. Section 10 lists one planned test for each edge.
4. The value is the maximum age of a step-up. A step-up older than the value does not satisfy the rule.
5. A rule with `stepUp` must have only human sources (users, groups, `autogroup:member`). A source that can be an agent SVID is a compile error. An agent cannot do an interactive login.
6. `SshRuleFile` keeps `deny_unknown_fields`. A node or coordinator before W25-32 refuses a policy with `stepUp`. This fails closed.

### 3.3 More than one matching rule

The compiled `SshGrant` gets `step_up: Option<u64>` (seconds).
A new function `ssh_step_up(src, dst, user)` returns the value for one login:

- `None`: no matching rule. The login is refused (as today).
- `Some(None)`: matching rules exist, and no matching rule has `stepUp`.
- `Some(Some(age))`: one or more matching rules have `stepUp`. `age` is the smallest value.

This is the strict choice. One rule that asks for a step-up is sufficient.
`ssh_recording_required` uses the same "any rule" logic.
PO ruling Q3: accepted (section 12).

### 3.4 `sshTests`

An `sshTests` assertion can add `"stepUp": "12h"` or `"stepUp": null`.
The policy compile fails when the computed value is different.

## 4. Flow

### 4.1 Login flow

1. The user runs `orblx ssh USER@DEST` on the client node.
2. The CLI sends `ssh-step-up-status {dst, user}` to the coordinator over node mTLS.
3. The coordinator computes `ssh_step_up(owner, dst, user)`. It replies with one of:
   - `not-needed`.
   - `live, expires_at`.
   - `needed, age`.
4. If the reply is `needed`, the CLI does steps 5 to 9. Otherwise, it goes to step 10.
5. The CLI asks the coordinator for a nonce (`ssh-step-up-nonce`). The nonce is single use. It is bound to this mTLS connection. It expires after 120 s. This is the W25-31 nonce pattern.
6. The CLI runs the existing W17/W20 browser login with this nonce. Section 6 gives the freshness parameters.
7. The CLI sends `ssh-step-up {id_token}` on the same mTLS connection.
8. The coordinator runs the checks in section 5.
9. The coordinator stores the step-up record and writes one audit record (code 40). Then it pushes new netmaps to the destinations in scope. It replies with `expires_at` only after the push is sent.
10. The CLI does the W25-31 cert request and the SSH login as before.

The CLI does not keep or print the ID token.
The CLI drops the token after step 7.

### 4.2 Where the check runs

There are two checks:

| Place | Check | Why |
| --- | --- | --- |
| Coordinator, `ssh-step-up` | Verifies the ID token and makes the record. | Only the coordinator has the IdP config and the JWKS. |
| Destination, SSH auth | Requires a live record for this login. | The W25-31 cert does not name a destination. A cert issued for a rule without step-up can reach a rule with step-up. Thus the destination must also check. |

The destination check is a new step in the W25-31 order. It comes after step 5 (principal and policy rule):

> 5a. Get `ssh_step_up(principal, this node, login user)`. If the value is `Some(Some(age))`, the verified netmap must have an entry with `owner` equal to the cert principal AND `node` equal to the key ID node, and `expires_at > now`. No match, no entry, or an expired entry: refuse with `step-up-required`.

Step 5a is a gate after the W25-31 cert check (steps 1 to 5). It is never an authenticator. An entry without a valid cert gives no access.

The destination does not see an ID token.
The destination trusts only the signed netmap.
The W25-31 rule "refuse when the netmap is older than 60 s" also applies.

### 4.3 Netmap entry

The netmap for one destination gets a new list `ssh_step_up`:

```json
"ssh_step_up": [
  { "owner": "oidc:SUBJECT", "node": "spiffe://orblx.local/node/CLIENT-NODE", "expires_at": 1793000000 }
]
```

- `owner` is the stable user ID: the enrolled OIDC `sub` of the node owner (W25-15), in the W25-31 principal form `oidc:SUBJECT`.
- `node` is the node SVID URI of the client node. It is the same value as the `node=` part of the W25-31 cert key ID (`ssh_key_id_node`).
- The list is a `Vec` in a fixed sort order (owner, node). It is not a map. The entry type has `deny_unknown_fields`.

- The coordinator computes `expires_at` for each destination: `verified_at + age`. `age` is the smallest `stepUp` of the rules that match this destination.
- A destination gets only entries for logins that can reach it. Other nodes do not see the entry.
- The list is inside the existing netmap signature. It is a new JSON field. It is not a new signed format. Crypto answered Q4: NO (section 12, section 13).
- The list has no ID token, no email, and no nonce.

## 5. Coordinator checks for `ssh-step-up`

The coordinator accepts a step-up only when all checks pass.
Each check has a reason name for the audit record.

| # | Check | Reason on fail |
| --- | --- | --- |
| 1 | The OIDC mode is Google or Issuer. `TokenOnly` refuses. `Mock` is for CI only. | `oidc-off` |
| 2 | The existing verifier (`owner_from_oidc`) accepts the token: signature, `kid` in JWKS, `iss`, `aud`/`azp`, `exp`, 60 s skew. | `token` |
| 3 | The token `nonce` is the nonce from step 5. It is unused, not expired, and from the same mTLS connection. | `nonce` |
| 4 | The token `sub` is the owner of the client node. | `subject` |
| 5 | Freshness (section 6). | `stale` |
| 6 | The client node is not revoked. The owner is approved (W25-15). | `revoked` |

The coordinator burns the nonce at check 3, also when a later check fails.

## 6. Freshness (PO ruling Q2)

A valid ID token does not prove a new authentication.
The IdP can issue a token from an old browser session.

- The `ssh-step-up-nonce` reply tells the CLI to send `max_age=0` (or `prompt=login`) in the authorize URL. The nonce book records this with the nonce.
- If the token has `auth_time`, the coordinator uses `auth_time`. It requires `now - auth_time <= 120 s`.
- If the token has no `auth_time`, the coordinator accepts `iat` with `now - iat <= 120 s` only when both are true:
  - The nonce record shows that the request sent `max_age=0` or `prompt=login`.
  - The single-use nonce matches.
- The existing 60 s `MAX_SKEW` applies on top of the 120 s, once. There is no other grace. A time more than `MAX_SKEW` in the future is refused.
- The step-up starts at `auth_time`, or at `iat` if there is no `auth_time`. It does not start at the coordinator receive time. `expires_at = start + age`.
- The audit record shows `auth_time: absent` when the token has no `auth_time`.

Limit: the coordinator does not see the browser request. It trusts the client node CLI (root on a node of the owner) to send the parameter that the nonce reply gave. G8 shows what real Google returns.

## 7. Cache and expiry

The coordinator keeps the step-up records in memory, with the key (owner, client node).
A record holds `verified_at` and the IdP issuer. It holds no token.

| Event | Effect |
| --- | --- |
| A new step-up for the same key | Replaces the record. |
| `now > verified_at + 24 h` (the maximum `stepUp`) | The coordinator deletes the record. |
| The client node is revoked or removed (W25 code 37) | The coordinator deletes the record. |
| The owner is rejected or revoked (W25-15) | The coordinator deletes all records of the owner. |
| A policy change | The coordinator computes `expires_at` again from the new rules and pushes netmaps. |
| A coordinator restart | All records are lost. The users must do the step-up again. This fails closed. PO accepted Q6. |
| An SVID renewal or a cert renewal | No effect. A renewal does not extend a step-up. |

The step-up also caps the W25-31 cert.
When a step-up is live, the coordinator sets `valid_before = min(now + 15 min, node SVID not_after, step_up.expires_at)`.
This uses the existing cert field. It is not a new cert field.

### 7.1 Open sessions (PO accepted Q5)

An expiry does not stop an open session.
A W25-31 cert expiry also does not stop an open session.
The `checkPeriod` recheck continues to examine the policy and the revoke list.
A revoke still stops the session.

## 8. Audit

Code: **40** (provisional), name `ssh-step-up`.
On main (1459cc2), the codes go up to 36, and 38. `RESERVED_CODES` is `[37]` for #106. #127 uses 39. No open PR uses 40.

The code is set when this branch takes main after #127 merges. #93 is already on main (1459cc2). The branch merges main in. It does not rebase.
The existing `ConfigAction::ALL` and `RESERVED_CODES` test shows that each code is unique. W25-32 does not reuse a reserved code.

The coordinator writes one record for each `ssh-step-up` decision, accept or refuse, in the config audit chain.

| Field | Value |
| --- | --- |
| `decision` | `accept` or `refuse` |
| `reason` | A reason from section 5, or none |
| `owner` | `oidc:SUBJECT` |
| `node` | The client node name |
| `issuer` | The IdP issuer URL |
| `auth_time` | Unix seconds, or `absent` |
| `iat` | Unix seconds |
| `expires_at` | The maximum `expires_at` that was written to a netmap, or none |

The record never has the ID token, the nonce, the authorization code, an email, or the client secret.

The destination writes one `ssh` deny record with the new `DenyReason::StepUpRequired` (`step-up-required`) for each login that step 5a refuses.
The status and nonce requests do not write audit records.

## 9. Failure modes

| Failure | Result |
| --- | --- |
| The IdP or the JWKS is not available | The step-up is refused (`token`). Logins to rules without `stepUp` continue. |
| The user logs in with a different account | Refused (`subject`). |
| The user takes more than 120 s in the browser | The nonce expires. Refused (`nonce`). The user tries again. |
| A replayed token or nonce | Refused (`nonce`). |
| The token comes from an old browser session | Refused (`stale`) when `auth_time` or `iat` is older than 120 s. |
| The netmap of the destination does not have the entry yet | The login is refused (`step-up-required`). Gate G3 measures this delay. |
| The netmap of the destination is older than 60 s | The W25-31 rule refuses the login. |
| A clock difference between the coordinator and the destination | `expires_at` moves by the difference. The W25-31 60 s skew limit applies. |
| A node before W25-32 | It refuses a policy with `stepUp` (`deny_unknown_fields`). It does not accept a login without a check. |
| A headless client node with no browser | No step-up is possible. Device code is out of scope (Q7). |
| A coordinator restart | Records are lost. The users do the step-up again. |

## 10. Proof gates

All gates use the `orblx-test-idp` issuer (W20 Issuer mode) or `ORBLX_OIDC_MODE=mock`.
The box proofs do not use Google, and they do not use port 8787.
Each run takes the FIFO lock for that run only and runs `proof_compose_clean`.
There are no fixed sleeps, no retries, and no exclusions.

| Gate | Pass condition |
| --- | --- |
| G1 policy | Unit tests: `stepUp` parse (good and bad values, range, `Nh`), agent source refused, smallest value wins, "any rule" logic, the `sshTests` assertion. |
| G2 deny | Without a step-up, a login to a `stepUp` rule is refused with `step-up-required`, and 1 deny record is written. A login to a rule without `stepUp` on the same destination is accepted. |
| G3 accept | 10 serial runs. Each run: 2 s or less from the coordinator accepting the ID token to the destination accepting the login, over the netmap push path. Report the max. All 10 runs must pass. |
| G4 expiry | With `"stepUp": "1m"`: a login before `expires_at` is accepted. A login after `expires_at` is refused. The test controls the clock or waits on the expiry event. It does not use a fixed sleep. |
| G5 negative | A token for a different subject, a reused nonce, a nonce from a different connection, a tampered signature (`tamper_signature`), a token with no `auth_time` and `iat` older than 120 s + `MAX_SKEW`, and a token with no `auth_time` for a nonce whose request did not send `max_age=0` or `prompt=login`. Each is refused with its reason and 1 audit record. |
| G5b netmap integrity | Change one field of one `ssh_step_up` entry in a signed netmap. `verify_signed_netmap` fails. A netmap with a lower or equal sequence is refused (C7). |
| G5c binding | A cert with the right principal but a different key ID node is refused. A cert with the right node but a different principal is refused. An entry with no valid cert gives no access. |
| G1b range edges | `stepUp` compiles for `60s`, `1m`, `1440m`, `24h`. It does not compile for `59s`, `0m`, `1441m`, `25h`, `86401s`, `01h`, and an empty string. No `stepUp` means off. |
| G6 revoke | Revoke the client node, then revoke a user. In each case, the same netmap delta that adds the cert serials to `ssh_revoked` removes the `ssh_step_up` entry. A new login is refused. The open session stops by the existing revoke path. |
| G7 secrets | The config audit chain verifies. A scan of all proof logs and audit files finds no ID token (no `eyJ` JWT prefix), no nonce, and no client secret. |
| G8 Google (manual) | One step-up with real Google on an operator laptop. Report if the token has `auth_time` with `max_age=0`. The row does not become shipped until a G8 run log on the merge commit exists on the box. |

G1 to G7 run in CI with the test IdP (`orblx-test-idp`) and the mock IdP.
Port 8787 is off limits. The proofs do not read `orblx_oauth.env`.

### 10.1 Release note

Add this line: "SSH step-up needs a browser on the client node." 

## 11. Rejected alternatives

| Alternative | Why rejected |
| --- | --- |
| Reuse `checkPeriod` | It already means the in-session recheck interval. |
| Send the ID token to the destination | The token audience is the coordinator. The destination can replay it. The destination needs the JWKS. |
| Put the step-up time in an SSH cert extension or `key_id` | This adds a field to a signed format. That is a STOP for the PO and Crypto. |
| A new signed step-up token | New token format. STOP. |
| Store the records on disk | Not necessary for safety. A loss fails closed. PO accepted Q6. |

## 12. PO rulings (2026-10-31 KST)

| Q | Ruling |
| --- | --- |
| Q1 Proof IdP | G1 to G7 use the test IdP and the mock IdP in CI. G8 (real Google) can be manual. The G8 row does not become shipped until a G8 run log on the merge commit exists on the box. Port 8787 is off limits. `orblx_oauth.env` is not read. |
| Q2 Freshness | Use `auth_time` if present. Else accept `iat` within 120 s only when the request sent `max_age=0` or `prompt=login` and the single-use nonce matches. The 60 s `MAX_SKEW` applies on top, with no other grace. A planned negative test uses `iat` older than 120 s (G5). See section 6. |
| Q3 Rule merge | Accepted as written (strict: any matching rule with `stepUp`). |
| Q4 Netmap field | Crypto: NO, not a new token format. W25-32 continues with the conditions in section 13. |
| Q5 Open sessions | Accepted as written (an expiry does not stop an open session). |
| Q6 Restart | Accepted as written (a restart deletes all records; fails closed). |
| Q7 Headless | Device code is out of scope. Release note: "SSH step-up needs a browser on the client node." |
| Q8 Latency | G3: 2 s or less on each of 10 serial runs, from the coordinator accepting the ID token to the destination accepting the login, over the netmap push path. Report the max. |
| Q9 Scope | Accepted as written: (owner, client node). |
| Q10 Audit code | Code 40 is provisional. It is set when the branch takes main after #127 (#93 is already on main). The `ALL` and `RESERVED_CODES` test shows uniqueness. No reserved code is reused. |
| Q11 Range | 1 min to 24 h. Off by default. A value out of the range does not compile. One planned test for each edge (G1b). |

## 13. Crypto conditions (required)

| # | Condition | Design and status |
| --- | --- | --- |
| C1 | The existing netmap signature covers `ssh_step_up`. | Code check done (main 1459cc2 and #127 1317d58). `sign_netmap` and `verify_signed_netmap` (`crates/orblx-coord/src/netmap.rs`) sign and verify `canonical_payload(&Netmap)`, that is `serde_json::to_vec` of the whole `Netmap` struct. A new field of `Netmap` is in the signed bytes. #127 adds `ssh_user_ca` and `ssh_revoked` the same way. `Netmap` has `deny_unknown_fields`. The verifier serializes the parsed struct again, so an unknown or changed field makes the verify fail. Result: covered. No STOP. Planned test G5b. |
| C2 | The destination reads `ssh_step_up` only from the verified netmap. | The SSH server reads the list from `netmap.json`, as #127 does for `ssh_user_ca` (`fresh_netmap`). The node writes that file only after `verify_signed_netmap` passes. The server never reads the list from the client, the session, or a request. |
| C3 | The entry binds owner and client node. | `owner` = the stable user ID `oidc:SUBJECT`. `node` = the node SVID URI. Step 5a matches the cert principal to `owner` AND the key ID node to `node`. No match, no entry, or an expired entry: deny. Planned test G5c. |
| C4 | A gate, not an authenticator. | Step 5a runs only after the W25-31 cert check passes. |
| C5 | Coordinator token checks. | The existing verifier (`iss`, `aud`, `exp`, `nonce` = the W25-31 single-use nonce) plus `auth_time` freshness (section 6). `sub` must equal the enrolled OIDC `sub` of the owner. The raw ID token is never logged, stored, or forwarded. |
| C6 | Cert life. | `valid_before = min(now + 15 min, node SVID not_after, step_up.expires_at)`. |
| C7 | Netmap age and order. | A netmap older than 60 s refuses a new SSH login (#127 `NETMAP_MAX_AGE_SECS`). The skew on `expires_at` is 60 s or less. GAP: today `Netmap.version` is the document schema version. It must be 1. There is no increasing netmap counter. W25-32 must add a signed, increasing `seq: u64` to `Netmap`. The coordinator keeps the counter on disk, so a restart does not reset it. The node refuses a `seq` that is lower than or equal to the last accepted `seq`. This is a new field inside the existing signature, as in C1. See open question Q12. |
| C8 | Revoke. | A node or user revoke removes the entry in the same netmap delta that adds the serials to `ssh_revoked`. Planned test G6. |

## 14. Open questions

- **Q12 (Crypto, PO):** C7 needs an increasing netmap version, and the code has none today. Is a new signed `seq: u64` field in `Netmap`, persisted by the coordinator, acceptable under the Q4 answer? Is it in W25-32, or in a separate item before W25-32?

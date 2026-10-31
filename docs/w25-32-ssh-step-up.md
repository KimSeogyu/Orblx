# W25-32: OIDC step-up per SSH policy rule (design)

Status: draft design. No product code. This item is a follow-up. It is not an rc.3 blocker.

Depends on: W25-31 SSH user certificates (#127, stacked on #119).
Do the work in this document only after #127 merges.

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
3. The range is 1 min to 24 h. A value out of range is a policy compile error.
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
See question Q3.

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

> 5a. Get `ssh_step_up(principal, this node, login user)`. If the value is `Some(Some(age))`, the netmap must have a step-up entry for (principal, client node) with `expires_at > now`. Else, refuse with `step-up-required`.

The destination does not see an ID token.
The destination trusts only the signed netmap.
The W25-31 rule "refuse when the netmap is older than 60 s" also applies.

### 4.3 Netmap entry

The netmap for one destination gets a new list `ssh_step_up`:

```json
"ssh_step_up": [
  { "owner": "oidc:SUBJECT", "node": "CLIENT-NODE", "expires_at": 1793000000 }
]
```

- The coordinator computes `expires_at` for each destination: `verified_at + age`. `age` is the smallest `stepUp` of the rules that match this destination.
- A destination gets only entries for logins that can reach it. Other nodes do not see the entry.
- The list is inside the existing netmap signature. It is a new JSON field. It is not a new signed format. See question Q4.
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

## 6. Freshness

A valid ID token does not prove a new authentication.
The IdP can issue a token from an old browser session.

- The CLI sends `max_age=0` in the authorize URL. The CLI keeps `prompt=select_account`.
- If the token has `auth_time`, the coordinator requires `now - auth_time <= 120 s`.
- If the token has no `auth_time`, the coordinator requires `now - iat <= 120 s`. The audit record shows `auth_time: absent`.

The Google behaviour for `max_age` and `auth_time` is not measured in this repo. See question Q2.

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
| A coordinator restart | All records are lost. The users must do the step-up again. This fails closed. See question Q6. |
| An SVID renewal or a cert renewal | No effect. A renewal does not extend a step-up. |

The step-up also caps the W25-31 cert.
When a step-up is live, the coordinator sets `valid_before = min(now + 15 min, SVID not_after, step-up expiry)`.
This uses the existing cert field. It is not a new cert field.

### 7.1 Open sessions

The proposal: an expiry does not stop an open session.
A W25-31 cert expiry also does not stop an open session.
The `checkPeriod` recheck continues to examine the policy and the revoke list.
A revoke still stops the session.
See question Q5.

## 8. Audit

New code: **40**, name `ssh-step-up`.
On main, the codes go up to 36, and 38. #106 uses 37. #127 uses 39. No open PR uses 40.

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
| A headless client node with no browser | No step-up is possible. See question Q7. |
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
| G3 accept | After a step-up, the login is accepted. 20 of 20 runs. Report the median, p95, and max time from the step-up reply to the SSH accept. The PO sets the limit (Q8). |
| G4 expiry | With `"stepUp": "1m"`: a login before `expires_at` is accepted. A login after `expires_at` is refused. The test controls the clock or waits on the expiry event. It does not use a fixed sleep. |
| G5 negative | A token for a different subject, a reused nonce, a nonce from a different connection, a stale `iat`, and a tampered signature (`tamper_signature`). Each is refused with its reason and 1 audit record. |
| G6 revoke | Revoke the client node. The record is deleted. A new login is refused. The open session stops by the existing revoke path. |
| G7 secrets | The config audit chain verifies. A scan of all proof logs and audit files finds no ID token (no `eyJ` JWT prefix), no nonce, and no client secret. |
| G8 Google (manual, report only) | One step-up with real Google on an operator laptop. Report if the token has `auth_time` with `max_age=0`. This gate is not on the box (port 8787). |

## 11. Rejected alternatives

| Alternative | Why rejected |
| --- | --- |
| Reuse `checkPeriod` | It already means the in-session recheck interval. |
| Send the ID token to the destination | The token audience is the coordinator. The destination can replay it. The destination needs the JWKS. |
| Put the step-up time in an SSH cert extension or `key_id` | This adds a field to a signed format. That is a STOP for the PO and Crypto. |
| A new signed step-up token | New token format. STOP. |
| Store the records on disk | Not necessary for safety. A loss fails closed. See Q6. |

## 12. Open questions for the PO

- **Q1 Proof IdP.** The Google redirect is fixed to `127.0.0.1:8787` and `localhost:8787`. The box proofs must not use port 8787. Are the box gates (G1 to G7) with `orblx-test-idp` and mock sufficient? Is G8 a manual laptop check only, or do we register a new redirect?
- **Q2 Freshness.** Does Google return `auth_time` and force a new login for `max_age=0`? If not, is the `iat` fallback (120 s) acceptable? Is 120 s the correct limit?
- **Q3 Rule merge.** If one matching rule has `stepUp` and a different matching rule does not, the design asks for a step-up (strict). Is this correct?
- **Q4 Netmap field.** The design adds `ssh_step_up` inside the existing signed netmap. Crypto must confirm that a new JSON field in the netmap is not a new token format. If Crypto says it is, W25-32 stops.
- **Q5 Open sessions.** Does a step-up expiry stop an open session? The design says no.
- **Q6 Restart.** Is it acceptable that a coordinator restart deletes all step-up records?
- **Q7 Headless clients.** Do we need a device-code flow for a client node with no browser? The design has none.
- **Q8 Latency limit.** What is the G3 limit from step-up to login accept?
- **Q9 Scope.** The record key is (owner, client node). Do we need a smaller scope, for example (owner, client node, rule)?
- **Q10 Audit code.** Is code 40 `ssh-step-up` confirmed? No open PR uses 40 now.
- **Q11 Range.** Is 1 min to 24 h correct for `stepUp`?

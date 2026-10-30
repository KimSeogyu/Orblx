# W25-15 User approval

Gap matrix row 32 (PARITY). A new human user who signs in with OIDC waits until an owner approves the user.
A pending user gets no SVID and no node enroll.

Marks: **[C]** = shown in the container proof (`scripts/proof/user-approval.sh`). **REAL** = shown on a real host (Linux host, Docker engine, `cargo test`).
The unit tests are REAL. The network results are [C].

## Behavior

| Case | Result |
|---|---|
| New OIDC user (`oidc:SUBJECT`), first enroll | The coordinator adds the user as `pending` and refuses the enroll: `The user waits for owner approval.` No node, no SVID, no IP. |
| Pending user, enroll again | Refused with the same text. The pending record does not change. |
| `orblx admin user-approve oidc:SUBJECT` | The user is `approved`. 1 audit record `user-approve` (code 36). The next enroll gets an SVID. |
| `orblx admin user-reject oidc:SUBJECT` | The user is `rejected`. 1 audit record `user-reject` (code 37). Each later enroll is refused: `The owner rejected this user.` |
| Token enroll (`--token-file`) | No user check. A token node is a node of the owner, so it never waits. |
| User in policy `userApproval.ownerUsers` | Approved at the first enroll with 1 record (detail `policy owner user`). `user-reject` refuses an owner user. |
| User whose verified email is in `userApproval.autoApproveDomains` | Approved at the first enroll with 1 record (detail `policy auto-approve domain D`). The list is empty by default, so auto-approve is OFF by default. A rejected user stays rejected. |
| Store from before W25-15 | At the first open, each `oidc:` owner of a node in the store becomes `approved`. The coordinator prints `user migration approved N`. When the audit chain opens, the coordinator writes 1 `user-approve` record for each migrated user, with the detail `store migration`. The users need no action. |

An owner can approve a user before the first sign-in. `user-reject` refuses an approved user: expire or revoke the user nodes instead.
Each approve or reject needs the config audit chain (`coord serve`). If the record write fails, the user state does not change.
A user change does not change the datapath or the handshake. A node of an approved user is a new peer, and W25-6 (#92) applies a new peer with no restart.

## Policy

```hujson
"userApproval": {
  "ownerUsers": ["oidc:olivia"],          // never pending, cannot be rejected
  "autoApproveDomains": ["example.test"], // optional; empty by default (OFF)
},
```

- At most 64 owner users and 64 domains. No duplicates. An owner user is `oidc:SUBJECT` with the W25-1 subject rules.
- A domain must be a DNS name. The match is exact on the part after `@`, and the ID token must have `email_verified: true`.

## Store

The users are in the same store file as the nodes (`nodes.json`, key `users`). There is no second identity store.
Each user record has the user, the state (`pending`, `approved`, `rejected`), the email (for the domain match only), and two times.
Limits: 4096 users, 256 pending users. The coordinator refuses a new pending user above the limit.

## CLI

```bash
orblx admin users --coord ADDR ...            # user SUBJECT STATE nodes N; users N; users_pending N
orblx admin user-approve oidc:SUBJECT --coord ADDR ...
orblx admin user-reject oidc:SUBJECT --coord ADDR ...
orblx coord enroll --id-token-file FILE --wait-approval SECS ...
```

`--wait-approval SECS` (1 to 3600) tries the enroll again each 250 ms while the user is pending.
It prints `enroll pending: ...` one time, then `approval_wait_ms N` when the enroll passes.
An API token needs the `nodes:write` scope for `user-approve` and `user-reject`.

## Proof

PROOF_RESULTS_PLACEHOLDER

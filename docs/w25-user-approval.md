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
| `orblx admin user-approve oidc:SUBJECT` | The user is `approved`. 1 audit record `user-approve` (code 35). The next enroll gets an SVID. |
| `orblx admin user-reject oidc:SUBJECT` | The user is `rejected`. 1 audit record `user-reject` (code 36). Each later enroll is refused: `The owner rejected this user.` |
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

REAL: measured in a Docker proof on this box. [C]: a claim that the proof or a unit test checks, or that comes from a design rule, with no measured number.

`scripts/proof/user-approval.sh` (compose `scripts/proof/compose.user-approval.yml`, test OIDC issuer, no real OAuth secret).
Every node enrolls through `orblx coord enroll` with an enroll token or an ID token. The coordinator issues each ticket. There are no lab tickets.
Final run: run 8 on `cd2600e` (branch merged with main `690558d`, #114), log `/workspace/orblx-w18-proof/w25o-user-approval-8.log`, result `proof_ok`.
After `cd2600e`, the branch changes only the main merge of #111 (`scripts/proof/proof-lock.sh` and its tests, no crate) and this doc.
The proof took the FIFO proof lock (`proof-lock.sh`) at 08:22:15 KST, then `proof_compose_clean orblx-w25o-users clean`. `contended_samples 0`, `max_other_orblx_containers 0`.

| Gate | Result | Mark |
|---|---|---|
| 1. A new OIDC user is pending | `oidc:nina` enroll refused 2 times. No state dir, no node, `users_pending 1`. nina-pc sent 65536 B TCP and 65536 B UDP to `100.64.0.2:7070`; the srv sink got 0 B. | REAL |
| 2. List, approve, reject | `orblx admin users` shows `users_pending 1`. Reject `oidc:rex`: records 9 to 10 (+1). Later enrolls are refused. Approve `oidc:nina`: SVID 725 ms after the coordinator approve log line. First HTTP 200 nina-pc to srv:8080 at 1594 ms (limit 2000 ms). From the start of the admin CLI (includes `docker run` of the CLI): 2214 ms. After approve, the srv sink got 131072 B from nina. | REAL |
| 2. Audit | 1 record for each action. In the run: `user-approve` 4 (mia migration, olivia owner user, nina, ivy auto), `user-reject` 1. `verify ok records 16`. | REAL |
| 3. Migration | An old coordinator (pre-change binary) enrolls `oidc:mia`. The store has no `users` key. The new coordinator prints `user migration approved 1` and writes 1 `user-approve` record with detail `store migration`. mia enrolls a second node with no action. | REAL; old binary [C] |
| 4. Owner never pending | A token enroll does not use the user list. Owner user `oidc:olivia` enrolls with no approval (1 record `policy owner user`). A reject of olivia is refused. | REAL |
| 4. Auto-approve OFF by default | Default policy: nina and rex wait. With `autoApproveDomains ["example.test"]`: `oidc:ivy` is approved (1 record). Rejected rex stays rejected. | REAL; default OFF also [C] unit test |
| 5. No secrets in logs | `secret_grep tokens 0 id_tokens 0 'PRIVATE KEY' 0`. | REAL |
| 5. W23-4 nat-realism | c1 on `cd2600e`, release, project `orblx-w25o-natr`, FIFO lock, `proof_compose_clean orblx-w25o-natr clean`, `proof_ok`, exit 0. Steady ping max ms (lost 0/50 each, limit 200): prc_prc 1.097, prc_sym 8.349, sym_sym 1.673, renew_direct 1.009, renew_relay 1.419. `contended_samples 0`, other orblx containers 0. Log `w25o-c1-release-nat-realism.log`. | REAL |

The reach time includes the 250 ms `--wait-approval` retry, the 250 ms netmap read of each node, and the start of `orblx up` in nina-pc. It changes between runs: 948, 1934, 980, and 1594 ms (runs 3, 5, 6, 8). All are below the 2000 ms limit.
The admin-CLI figure includes the `docker run` start of the CLI container: in run 8 the coordinator logged the approve 620 ms after the CLI start (`coord_approve_after_cmd_start_ms 620`). It is not a gate number.
Runs before #114 (runs 3 to 6) do not count for rc.3. They are listed for history only.

nat-realism runs before #114 (history only, all `proof_ok`): r1, r2, r3 on `41db806` and m1 on `a9f9cd1`. In r2, one ping in `renew_relay` was 46.766 ms (lost 0/50, avg 1.943 ms, other orblx containers 0). All other steady maxima were below 5 ms.

# Admin roles

Candidate (a), human admin roles. Gap matrix row 36. Eng Lead confirmed the row.

Candidate (a) is the first candidate in the check order. It is not on main.
Main has owner SVIDs, user approval (row 32), enroll tokens (row 33), and scoped API tokens (row 35).
It does not store a role for each user, and it does not map each admin operation to a role list.
Row 34 is pre-auth keys (open PR 158). This change does not touch those files.
Candidates (b) and (c) stay open. (b) is device posture checks in grants. (c) is SCIM-style user deprovision.
Issue 159 (tag route auto-approvers) is reserved and is not part of this change.

Marks: **REAL** means `cargo test` on this host. **[C]** means the container proof. This environment has no Docker run, so the [C] gates are not measured.

## Behavior

| Case | Result |
| --- | --- |
| New OIDC user | Role `member`. A member cannot call the admin API. The sentence is `The caller is not an owner.` |
| Policy owner SVID | Role `owner` for every admin operation. This is the same caller as before. |
| Node of an OIDC user | The call uses the role of that user. |
| `orblx admin role-set USER ROLE` | One `role-set` record (code 39). Only an owner can call it. |
| Last user with role `owner` | The coordinator refuses a change to another role. The role does not change. No `role-set` record. |
| User in `userApproval.ownerUsers` | Role `owner` at approve time. A later `role-set` cannot move that user off `owner`. |
| Role refusal | One `role-deny` record (code 40). The operation does not run. A refused role change also writes one `role-deny`. The reason is `bad-role`, `unknown-user`, `same-role`, `owner-user`, or `last-owner`. |
| API token | At each call the rights are the token scopes crossed with the creator's current role. A scope that contains one operation outside the creator role is refused at create time. |
| `admin-role-set` with a token | No token scope. One `token-deny` record, reason `scope`. |

Roles: `owner`, `admin`, `network-admin`, `it-admin`, `auditor`, `member`.

| Operation | owner | admin | network-admin | it-admin | auditor | member |
| --- | --- | --- | --- | --- | --- | --- |
| Read nodes, users, roles, routes, grants, node lock | yes | yes | yes | yes | yes | no |
| Read policy | yes | yes | yes | no | yes | no |
| Read audit | yes | yes | no | no | yes | no |
| Approve, revoke, expire a node | yes | yes | yes | yes | no | no |
| Approve or reject a user | yes | yes | no | yes | no | no |
| Grant approve or revoke, node lock write, policy write | yes | yes | yes | no | no | no |
| Create a token | yes | yes | yes | yes | no | no |
| List tokens | yes | yes | no | no | no | no |
| Revoke a token | yes | yes | own token | own token | no | no |
| Change a role | yes | no | no | no | no | no |

An auditor is read-only. The read set includes the audit log.
A member can call no admin operation.
A token stores `created_role` and, for an OIDC creator, `created_user`.
`created_role` is the role at create time. A later call does not use it to grant rights.
At each call the scope must match and the creator's current role must allow the operation.
The coordinator reads that role from the current policy and the current user store.
A policy owner SVID is `owner` while it stays in `owners`.
An enrolled node uses the approved role of its OIDC user.
A removed user, a rejected user, a pending user, or a creator that is not found grants no rights.
A demotion takes effect on the next call. The token file does not change.

Migration: a token file from before this change has no `created_role` and no `created_user`.
The file default for `created_role` is `owner`. That default does not grant rights.
If the creator SVID is not a current policy owner and not an approved user of an enrolled node, the token has no rights.
The call writes one `role-deny`. Replace or revoke those tokens after you move a SVID out of `owners`.
The coordinator keeps only the token digest. Logs and audit records show the token id, not the token text.

A role change needs the config audit chain. When the record write fails, the role does not change.

## CLI

```bash
orblx admin users --coord ADDR ...
orblx admin roles --coord ADDR ...
orblx admin role-set USER ROLE --coord ADDR ...
orblx admin token-create --scope SCOPE --ttl 10m --coord ADDR ...
```

`users` prints `user SUBJECT STATE role ROLE nodes N`.
`roles` prints `role SUBJECT STATE ROLE`, then `roles N` and `owners N`.
`role-set` prints `role_set`, `role`, and `role_from`.

## Tests

| Test | Mark | What it shows |
| --- | --- | --- |
| `roles::tests::the_role_table_covers_each_admin_operation` | REAL | The role table and the admin operation list are the same set. An auditor has only the read operations. A member has none. Scope fit matches the table. |
| `roles::tests::the_last_owner_cannot_be_demoted_and_each_change_has_one_record` | REAL | Two owners. One demotion. The last owner stays `owner`. One `role-set` record for each change. The failed call writes one `role-deny` with reason `last-owner`. |
| `roles::tests::each_refused_role_change_writes_one_role_deny` | REAL | Same role, unknown user, bad role text, owner user, and last owner each write one `role-deny` and do not change the role. Five records in total. |
| `roles::tests::an_owner_user_stays_an_owner` | REAL | An owner user is `owner` at approve time and cannot move to `admin`. |
| `roles::tests::a_member_deny_has_one_record_and_the_old_sentence` | REAL | One `role-deny` per call. The sentence is `The caller is not an owner.` |
| `roles::tests::an_auditor_can_read_the_audit_log_and_cannot_write` | REAL | Audit read and node read pass. Approve and role-set each write one `role-deny`. |
| `roles::tests::a_token_cannot_exceed_the_creator_role_and_a_demotion_has_one_deny` | REAL | `it-admin` cannot create a `policy:write` token. A `nodes:write` token works, then the user moves to `member`. The next call is `role-deny` once and not `token-deny`. The audit text has no token secret. |
| `roles::tests::a_demoted_admin_token_follows_the_current_role` | REAL | An admin token has `nodes:read` and `nodes:write`. As `auditor`, `admin-nodes` still works and `admin-approve` is one `role-deny`. A member can call no admin operation, so after `member` the same read is one `role-deny`. Back as `admin`, `admin-approve` works and `admin-policy-set` stays a scope refusal. A rejected user and a removed user grant no rights. |
| `server::tests::a_removed_policy_owner_token_gets_403_and_one_role_deny` | REAL | An owner SVID creates a `nodes:read` token. After the policy drops that SVID, the token gets status 403 and one `role-deny`. It does not write `token-deny`. |
| `server::tests::a_legacy_token_without_a_live_creator_gets_403` | REAL | An old token file has no `created_role` and no live creator. The call gets status 403 and one `role-deny`. The stored default `owner` grants nothing. |
| `roles::tests::a_former_owner_node_uses_the_approved_user_role` | REAL | A policy owner node leaves `owners`. Its user is rejected and the stored role is still `admin`. The token gets one `role-deny` and not the stored role. |
| `admin::tests::role_set_parses_the_user_and_the_role` | REAL | The CLI accepts a known role and refuses an unknown role. |

## Proof

Script: `scripts/proof/admin-roles.sh`.
Compose: `scripts/proof/compose.admin-roles.yml`.
Policy: `scripts/proof/admin-roles.hujson`.
The script takes the proof lock (`scripts/proof/proof-lock.sh`).
The issuer is `orblx-test-idp`. The script does not read a real OAuth secret.
This environment did not run Docker. Do not treat the [C] rows as measured results.

| Gate | Mark | What the script checks |
| --- | --- | --- |
| 1. Member | [C] | `oidc:mem` calls `admin nodes` and gets `The caller is not an owner.` One `role-deny` for target `nodes`. |
| 2. Role list | [C] | `role-set` for ada, ned, ita, and aud. `admin roles` shows those roles. One `role-set` record for each change. |
| 3. Auditor | [C] | `admin audit` and `admin nodes` pass. `admin approve` fails with `role auditor`. One `role-deny`. The node stays pending. |
| 4. IT admin and network admin | [C] | IT admin approves a pending node. IT admin `policy-set` fails and the policy sha256 stays the same. Network admin `policy-set` of a new comment passes. Network admin cannot create a `nodes:write` token. IT admin cannot create a `policy:write` token. |
| 5. Token cap | [C] | IT admin creates a `nodes:write` token. The token approves one node. After `role-set` to `member`, the same token gets status 403 and `The caller is not an owner.` One new `role-deny`. No new `token-deny` for that token. |
| 5b. Current role | [C] | Admin `ada` creates a token with `nodes:read` and `nodes:write`. As `auditor`, node read returns status 200 and approve returns status 403 with one `role-deny`. As `member`, node read returns status 403 with one `role-deny`. Back as `admin`, approve returns status 200. `policy-set` stays status 403 for scope. One `token-deny`. No `role-deny` for `policy-set`. |
| 6. Owner user | [C] | `role-set` of `oidc:olivia` to `admin` fails. The sentence has `owner user`. Her role stays `owner`. `ada` can move to `owner` and back to `admin` (one extra `role-set` each way, 6 records in total). `ada` cannot call `role-set`. One `role-deny` for target `role-set`. The last-owner refusal is the REAL unit test, because `olivia` is already an owner user. |
| 7. Secrets | [C] | The state files, the coordinator log, and the proof log contain no `orblx-at1.` text, no `PRIVATE KEY`, and no ID token. |
| 8. Chain | [C] | `admin audit --verify` prints `verify ok`. |

## Open questions

- Eng Lead confirmed row 36. A network admin has no `nodes:write`. An admin may revoke a token that an owner created.
- Candidates (b) and (c) are still open.

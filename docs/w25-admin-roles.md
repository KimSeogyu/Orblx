# Admin roles

Candidate (a), human admin roles. Proposed gap matrix row 36. Eng Lead confirms the row.

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
| Role refusal | One `role-deny` record (code 40). The operation does not run. |
| API token | The token cannot do more than the stored creator role and the live creator role. A scope that contains one operation outside the creator role is refused at create time. |
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
A token stores `created_role` and, for an OIDC creator, `created_user`.
At each call the scope must match and both roles must allow the operation.
A policy owner SVID does not bind `created_user`. That token follows the stored role.
Old token files have no `created_role`. The coordinator treats them as `owner`, because only an owner could create a token before this change.
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
| `roles::tests::the_last_owner_cannot_be_demoted_and_each_change_has_one_record` | REAL | Two owners. One demotion. The last owner stays `owner`. One `role-set` record for each change. The failed call adds no record. |
| `roles::tests::an_owner_user_stays_an_owner` | REAL | An owner user is `owner` at approve time and cannot move to `admin`. |
| `roles::tests::a_member_deny_has_one_record_and_the_old_sentence` | REAL | One `role-deny` per call. The sentence is `The caller is not an owner.` |
| `roles::tests::an_auditor_can_read_the_audit_log_and_cannot_write` | REAL | Audit read and node read pass. Approve and role-set each write one `role-deny`. |
| `roles::tests::a_token_cannot_exceed_the_creator_role_and_a_demotion_has_one_deny` | REAL | `it-admin` cannot create a `policy:write` token. A `nodes:write` token works, then the user moves to `member`. The next call is `role-deny` once and not `token-deny`. The audit text has no token secret. |
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
| 6. Owner user | [C] | `role-set` of `oidc:olivia` to `admin` fails. The sentence has `owner user`. Her role stays `owner`. `ada` can move to `owner` and back to `admin` (one extra `role-set` each way, 3 records in total). `ada` cannot call `role-set`. One `role-deny` for target `role-set`. The last-owner refusal is the REAL unit test, because `olivia` is already an owner user. |
| 7. Secrets | [C] | The state files, the coordinator log, and the proof log contain no `orblx-at1.` text, no `PRIVATE KEY`, and no ID token. |
| 8. Chain | [C] | `admin audit --verify` prints `verify ok`. |

## Open questions

- Eng Lead confirms proposed row 36. Rows 32, 33, and 35 are already on main. Row 34 is open PR 158.
- A network admin cannot hold `nodes:write`, because that scope also approves users. A later split of the scope can give the network admin a node-only token.
- An admin can revoke a token that an owner created. A network admin can revoke only a token that they created.
- Candidates (b) and (c) are still open.

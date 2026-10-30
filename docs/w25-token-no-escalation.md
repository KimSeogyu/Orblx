# W25-3b Scoped API tokens cannot escalate

W25-3 added scoped API tokens (`docs/w25-api-tokens.md`). It had a known gap: a `policy:write` token
could set a policy with new owners. An owner can make tokens, so `policy:write` had the same power as an owner.
This change closes the gap. No scoped API token can give itself or another token more power than its scope.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the owner node, node `a`, the client host, and the Docker network are [C].

The change adds no new crypto design. It does not change the owner mTLS path (W19).

## 1. Rule

| What can change it | Owner SVID (mTLS) | API token |
| --- | --- | --- |
| Policy owners (`owners`) | yes | no (`403`, reason `owners`), for all scopes |
| Other policy text | yes | `policy:write` only |
| Node lock signers (`admin-lock-init`, `admin-lock-update`, `admin-lock-sign`) | yes | `lock:write` only |
| Token rules (`admin-token-create`, `admin-token-list`, `admin-token-revoke`) | yes | no (`403`, reason `scope`) |

- The policy has no node lock or token fields. The policy parser refuses unknown fields
  (`deny_unknown_fields`), so a policy text cannot change the node lock signers or the token rules.
- The owner check compares the owner set of the new text with the owner set of the loaded policy.
  The order of the list does not matter. An added, removed, or changed owner is a change.
- A text that is not a valid policy is not an owner change. It gets `400` from `policy_set`, as before.

## 2. Call path

- `apitoken::check` takes one more rule. The rule runs only after the token, the expiry, the revoke, and the scope checks pass.
  When the rule refuses, the call gets `403` and the coordinator writes 1 `token-deny` record
  (`op policy-set scope policy:write reason owners status 403`). It writes no `token-use` record.
- `admin-policy-set` takes the policy write lock (`admin::policy_write_lock`) before the check.
  The token path keeps the lock through the owner check and the file write. So an owner change by the owner SVID between the
  check and the write cannot be lost. `admin::policy_set` takes a `PolicyWrite` value, so a caller cannot write the policy
  without the lock.
- The owner SVID path takes the same lock and then calls `policy_set`. It has no owner check. It did not change in any other way.

## 3. Tests

| Test | Label | What it shows |
| --- | --- | --- |
| `server::tests::a_token_cannot_escalate_past_its_scope` | REAL | A `policy:write` token and a token with all 9 scopes: add, remove, and change of the owners each get `403`. The policy file digest does not change. `owner` stays an owner and `a` stays not an owner. 3 `token-deny` records with reason `owners` for each token. A policy-set that keeps the owners gets `200`. The token operations get `403` and the token store digest does not change. A `policy:write` token gets `403` for the 3 lock write operations and the lock store digest does not change. The owner SVID path changes the owners. The chain check is ok. |
| Same test with the owner rule turned off | REAL | The test fails (`server.rs` assertion on `403`). This shows that the test checks the rule. |

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and
`cargo test --workspace --locked` pass on the branch (REAL).

## 4. Proof

Script: `scripts/proof/token-no-escalation.sh` (compose `scripts/proof/compose.api-tokens.yml`, project `orblx-w25e-escalation`).
The `client` host [C] has no SVID. It has only the trust bundle and the token files.
The script never prints a token or a key. It keeps each command output in a variable or a file before it checks it.
It does not pipe into `head` or `grep -q` under `pipefail`. It prints `proof_ok`.

Branch log: `/workspace/orblx-w18-proof/w25-e-token-no-escalation-branch-e754eb4.log` (commit `e754eb4b`).

| Gate | Label | Result (branch) |
| --- | --- | --- |
| 1. Token policy-set that adds, removes, or changes the owners | [C] | `policy:write` token: add `403`, remove `403`, change `403`. All-scope token: add `403`, remove `403`, change `403`. Reply: `An API token cannot change the policy owners. Only an owner SVID can do this.` Policy SHA-256 before and after: `88634284…` (same). `owner` still an owner. Node `a` still gets `The caller is not an owner.` |
| 2. Token policy-set that keeps the owners | [C] | `200` (policy SHA-256 changes to `7b988ae4…`, the new text is on the coordinator). The first policy again: `200`. |
| 3. Node lock signers and token rules | [C] | The owner set up node lock with 1 key and signed `a`. The `policy:write` token: `lock-init` (with a second key), `lock-update`, `lock-sign`, `token-create`, `token-list`, `token-revoke`: `403` each (6 of 6). Lock store digest and `lock show` output: same before and after (`coord_lock on version 0 keys 1`). Token store digest and `token-list` output: same before and after. |
| 4. Owner SVID changes the owners | [C] | `admin policy-set` with owners `owner` and `a`: ok. The mTLS reply has no status field. `ok` is the `200` of this path. Then node `a` can run `admin nodes`. The restore to owner `owner`: ok, and `a` is refused again. |
| 5. Audit | [C] | `policy:write` token: `token-deny` reason `owners` 3, reason `scope` 6, total 9 for 9 refusals. `token-use` 2 for the 2 allowed calls. All-scope token: `token-deny` 3 for 3 refusals, `token-use` 0. `verify ok records 25`. `audit verify-config` ok, records 25. |
| 7. No token text | [C] | 0 hits in the coordinator state files, 0 in 72 container log lines, 0 in the audit records, 0 in the proof log. Control: the same check finds 2 of 2 token files. |

## 5. W25-3 proof and W23-4 gates (gate 6)

| Proof | Log | Result (branch, [C]) |
| --- | --- | --- |
| `scripts/proof/api-tokens.sh` (project `orblx-w25e-tokens`) | `/workspace/orblx-w18-proof/w25-e-api-tokens-branch-e754eb4.log` | `proof_ok`. `nodes:read` token: 3 of 20 operations `200`, 17 `403`. `policy:write` token: `policy-set` `200` (same owners), `nodes` `403`, `grant-approve` `403`. Expiry to `401`: 125 ms. Revoke to `401`: 275 ms. Limit 1000 ms. `verify ok records 73`. 0 token hits in state files, 157 log lines, audit records, and the proof log. |
| `scripts/proof/nat-realism.sh` (`ORBLX_NATR_PROFILE=release`, prefix `orblx-w25e-natr-`, `172.29.165.0/24`, `10.165.2x.0/24`) | `/workspace/orblx-w18-proof/w25-e-nat-realism-branch-e754eb4.log` | `proof_ok`. Plain 0.050 ms, direct 0.447 ms, `rtt limit_ms 5 ok`. prc relay 0.619 ms (limit direct + 1 ms = 1.447 ms), 0/50 lost, `relay_gate ok`. sym relay 0.589 ms, 0/50 lost, `relay_gate ok`. |

TCP bulk throughput (5 s, measured, not a gate): plain 33316.77, prc direct 983.53, prc relay 1028.92,
sym relay 728.94 Mbit/s. Other workers used the same host during the run.

After the merge, the proofs run again on `main`. Logs: `/workspace/orblx-w18-proof/w25-e-*-main-*.log`.

## 6. Shared files

These files are shared with other tracks. The diff in each is small.

- `crates/orblx-coord/src/state.rs`: a new `policy_owners()` accessor (7 lines).
- `crates/orblx-coord/src/admin.rs`: the policy write lock, `policy_keeps_owners`, and a `PolicyWrite` argument for `policy_set`.
- `crates/orblx-coord/src/server.rs`: the owner rule in the token path and the lock for `admin-policy-set`.
- `.github/workflows/ci.yml`: 1 line. `bash -n` for `api-tokens.sh` and `token-no-escalation.sh`.
- `docs/w25-api-tokens.md`: 2 lines about `policy:write`.

## 7. Caveats

- A person with write access to the policy file on the coordinator host can still change the owners. That is not a token.
- A `lock:write` token can change the node lock signers. That is its scope. Give it only to a client that you trust with node lock.
- A `policy:write` token can still change the rest of the policy (ACLs, routes, SSH rules, `nodeApproval`). That is its scope.

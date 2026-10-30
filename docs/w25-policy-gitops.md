# W25-9 Policy GitOps

An owner keeps the mesh policy in Git. A pull request runs the policy tests.
The merge applies the policy with a scoped `policy:write` API token (W25-3).
This closes gap matrix row 24.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the owner node, the `ci` host, and the Docker network are [C].

Out of scope: a hosted GitHub App, Terraform, and GitLab.
The change does not touch the datapath, `node.rs`, `up.rs`, or the owner mTLS path. The apply needs no owner SVID.

## 1. Commands

| Command | What it does | Exit |
| --- | --- | --- |
| `orblx policy diff --file F --coord ADDR --token-file T [--sha-out S]` | Reads the live policy (`admin-policy`, scope `policy:read`). Prints `live_sha256`, `file_sha256`, and the changed lines (`-` live, `+` file). `--sha-out` writes the live sha256 to a file. | 0 the same, 1 they differ, 2 error |
| `orblx policy apply --file F --coord ADDR --token-file T --expect-sha SHA` | Runs the tests in the file first. A failed test sends nothing. Then sends `admin-policy-set` with the expected live sha256 (scope `policy:write`). Prints `status N` and `policy_set SHA changed true\|false`. | 0 applied or no change, 1 refused or error |

- `--expect-sha-file FILE` reads the sha from a file (for example the `--sha-out` file).
- `--expect-sha none` means that no live policy file is present.
- `diff` also works with an owner SVID (no `--token-file`). `apply` needs a token. The expected sha256 goes only in the token call.
- Both commands take `--coord-name`, `--bundle`, and `--state`, as `orblx admin` does.
- The commands do not print the token. They read it from the file.

## 2. Coordinator change (small, admin API only)

`admin-policy-set` takes one new optional request field, `expect_sha256`. This is the only coordinator change.

- With `expect_sha256`, the coordinator writes only when the live policy file has that sha256. Otherwise it returns
  `CoordError::Conflict`. The token path sends status `409` and the text
  "The live policy changed. Its sha256 is not the expected sha256." It writes nothing.
- When the new text has the same sha256 as the live file, the coordinator does not write the file and does not reload the policy.
  It returns `"changed": false`. So there is no new `policy-replace` record. A write returns `"changed": true`.
- The check runs under the policy write lock (W25-3b), after the owner rule. A text that changes the owners still gets `403`.
- The token check writes 1 `token-use` record for each allowed call, also for a `409` or a no-change call (W25-3 rule).
- A request without the field works as before. Old clients do not send the field (`skip_serializing_if`).

## 3. Example workflow

Directory: `examples/policy-gitops/`.

| File | Use |
| --- | --- |
| `github-workflow.yml` | GitHub Actions example. Pull request: `steps.sh test`, then `steps.sh plan` when the read token is set. Push to `main`: `steps.sh apply`. It does not run in this repository. |
| `steps.sh` | The steps. `test` runs `orblx policy test`. `plan` runs the tests and the diff. `apply` runs the tests, the diff, and the apply with the sha that the diff saw. |
| `policy.hujson` | An example policy with one test. |
| `proof/proof.sh`, `proof/compose.yml` | The local [C] proof. The `ci` container runs the same `steps.sh`. |

Secrets: `ORBLX_POLICY_READ_TOKEN` (`policy:read`) and `ORBLX_POLICY_WRITE_TOKEN` (`policy:write`).
The workflow writes each token to a mode 0600 file in `RUNNER_TEMP` and removes the file at the end of the step.
It does not echo a token. A pull request from a fork gets no secrets, so it runs only `policy test`.
The apply job uses `concurrency` with `cancel-in-progress: false`, so two merges do not apply at the same time.

A stale apply: the live policy changed after the diff. The apply gets `409` and writes nothing.
Run the plan again, review the new diff, and merge again. To apply only the reviewed diff, set `ORBLX_EXPECT_SHA`
to the sha that the reviewed plan printed. Then a change after the review gets `409`.

## 4. Tests (REAL)

| Test | What it shows |
| --- | --- |
| `server::tests::policy_set_with_an_expected_sha_refuses_a_stale_write` | A wrong expected sha gets `409`, the file digest and the `policy-replace` count do not change. The live sha gets `200` and `changed true` (1 new `policy-replace`). The same text again gets `200`, `changed false`, and no new record. The sha from before the write now gets `409`. |
| Same test with the expected sha check turned off | The test fails (`server.rs` assertion on `409`). This shows that the test checks the rule. |
| `policy_gitops::tests::*` (5 tests) | The flag rules of `diff` and `apply` (a token and an expected sha are necessary for `apply`), the line diff, and the sha256 hex. |

`cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` pass on the branch (REAL).

## 5. Proof ([C])

Script: `examples/policy-gitops/proof/proof.sh` (compose project `orblx-w25i-gitops-proof`, image `orblx-w25i-gitops:local`).
The `ci` host has no SVID (0 files in `/var/lib/orblx`). It has the trust bundle and two token files (mode 600):
`read` (`policy:read`) and `write` (`policy:write`). The script prints `proof_ok`.

Branch log: `/workspace/orblx-w18-proof/w25i-gitops-branch.log`.

| Gate | Label | Result (branch) |
| --- | --- | --- |
| 1. diff exit codes | [C] | The same file: exit 0, `policy same`. A changed file: exit 1, `policy differs removed 1 added 1`. |
| 2. A failed test applies nothing | [C] | `steps.sh test` exit 1. `steps.sh apply` exit 1 before the diff. `token-use` records 2 -> 2, `policy-replace` 0 -> 0, the live sha256 did not change. |
| 3. Apply with `policy:write` | [C] | Exit 0, status 200, `changed true`. Live sha256 `f65212eb…c0ac` = file sha256. A new diff exits 0. |
| 4. The same file again | [C] | Exit 0, status 200, `changed false`. The policy file mtime and inode did not change. `policy-replace` 1 -> 1, all `policy-*` records 2 -> 2. |
| 5. Owner change | [C] | Exit 1, status 403. The live sha256 did not change. `policy-replace` 1 -> 1. 1 `token-deny` record with reason `owners`. |
| 6. Stale apply | [C] | The plan saw `f65212eb…c0ac`. The owner (mTLS) then set `bd472f90…178b`. The apply with the seen sha: exit 1, status 409. The live sha256 stays `bd472f90…178b`. `policy-replace` 2 -> 2. After a new diff, the apply gets 200. |
| 7. No token text | [C] | Control: the check finds 2 of 2 planted tokens and 2 of 2 token files. Hits: step output 0 (120 lines), `GITHUB_OUTPUT` 0, container logs 0 (67 lines), audit records 0 (20 records), coordinator state files 0, proof log 0. |

The audit chain check (`orblx audit verify-config`) prints `ok` with 20 records.

KILL check: the apply needs no owner mTLS and no datapath change. The `ci` host has no SVID.

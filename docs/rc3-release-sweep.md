# rc.3 release sweep

This change adds the release sweep for rc.3 condition 4.
It changes scripts and docs only. It does not change datapath code, crypto, or the wire format.

Marks: **[C]** = shown in the container proof. **REAL** = shown on the real host (the Linux box). Every node, router, coordinator and relay in the proofs is a [C] container.

## Why

The exit-node proof over the TCP Relay broke in #45, before rc.2. No gate found it, because each proof ran only on its own PR. Condition 4 of rc.3: on the rc.3 candidate commit, every proof that backs a "shipped" row of the Tailscale gap matrix must run serially under the proof lock and print `proof_ok`.

## The sweep

```bash
scripts/proof/release-sweep.sh COMMIT
```

1. The script resolves `COMMIT` (after `git fetch origin`) and makes a detached worktree of it (`/workspace/orblx-rc3-sweep-<sha>`).
2. It builds the release binary there with the `~/.cargo/bin` toolchain (the build log has the `rustc --version` line). It also builds the debug binaries that the older proofs use, so that no proof compiles while it holds the lock.
3. It runs each proof of the list below, one at a time, from that worktree. A wrapper takes the W25-5 box proof lock (`proof-lock.sh`) before the proof starts and releases it after the proof ends. Since W25-14 every proof takes the lock itself; it sees that its parent (the wrapper) holds it and does not wait again.
4. The log of each proof is `/workspace/orblx-w18-proof/rc3-sweep-<sha>-<proof>.log`. The table is `/workspace/orblx-w18-proof/rc3-sweep-<sha>.md`. The table has 4 columns: proof, gap row, log path, result.
5. The log of a proof is the full stdout and stderr of the proof, with no filter and no cut. The sweep adds only the lock lines (`proof_lock`, `proof_context`, `proof_contention`) and its own `release_sweep:` notes. A step that a proof script filters itself is filtered in the log too; the sweep does not change the proof scripts. Since W25-14d (#101) no proof pipes `cargo` output into a filter, and the excerpt steps use `show_matching`, which prints the full step output when no line matches. The sweep takes a `show_matching: no line matches` or `secret_scan:` line as an error line.
6. After each proof, the script removes the images that the proof built (without `-f`, so an image that a running container uses stays). At the end, it removes the worktree and its target.

Result rules:

| Result | Rule |
|---|---|
| `proof_ok` | The proof exit code is 0 and the log has a line `proof_ok` (`docker-image.sh` adds fields after it; `w18-linux-daemon.sh` prints `W18 proof passed`). |
| `FAIL (exit N): LINE` | Any other case. `LINE` is the first log line that matches `error`, `FAIL`, `failed`, `panicked`, `: line N:`, `command not found`, `No such file`, `timed out`, `Traceback`, `show_matching: no line matches` or `secret_scan:`. When no line matches, it is the last log line. |
| `FAIL (exit 0, no proof_ok line)` | The proof skipped itself (for example, it was not root). A skip is not a pass. |
| `FAIL (exit 0, no pass line RE)` | A proof with its own pass line (`sym-throughput`: `^sym_gate ok: `) ended with exit 0 but without that line. |
| `FAIL (exit 124, timeout ...)` | The proof ran longer than `ORBLX_SWEEP_TIMEOUT` (default 3600 s, the lock wait does not count). |

A failed proof does not stop the sweep. The exit code is 1 when a proof failed, 2 when the setup or the build failed, and 0 when every proof gave `proof_ok`.

The script sends no proof output through a pipe. The output goes to the log file, and the checks read the whole file (the `has_line` helper of #94, and awk with no early exit). So no reader can end early and cause SIGPIPE (exit 141) under `set -o pipefail`. `scripts/proof/tests/test_no_early_pipe_reader.py` also checks `release-sweep.sh` now.

| Env | Default | Meaning |
|---|---|---|
| `ORBLX_SWEEP_OUT` | `/workspace/orblx-w18-proof` | Log and table directory. |
| `ORBLX_SWEEP_WT` | `/workspace/orblx-rc3-sweep-<sha>` | Worktree path. |
| `ORBLX_SWEEP_ONLY` | every proof | Space list of proof names. |
| `ORBLX_SWEEP_TIMEOUT` | 3600 | Seconds for each proof, without the wait for the lock. |
| `ORBLX_SWEEP_KEEP` | 0 | 1 keeps the worktree, the target and the images. |
| `ORBLX_SWEEP_FETCH` | 1 | 0 does not run `git fetch`. |
| `ORBLX_SWEEP_PROGRESS` | none | A file. The script adds one line for each step. |
| `ORBLX_SWEEP_LOCK_MODE` | `proof` | `proof`: take the lock for each proof, so other proofs can run between two sweep proofs. `sweep`: take the lock once and hold it for all the proofs. |
| `ORBLX_SWEEP_LIST`, `ORBLX_SWEEP_TEST_ROOT` | none | Test only (`tests/test_release_sweep.py`). |

The script runs git as the caller. It runs the build and the proofs with `sudo -n` when the caller is not root, so it never asks for a password.

## Shipped rows and their proofs

Source: the Page "Orblx vs Tailscale 기능 격차 매트릭스 + Wave 계획" (the gap matrix is not in this repository). It has 26 shipped rows (row 17 shipped with W25-6). The proof of each row comes from the `docs/wNN-*.md` file that the row names as its evidence.

| Row | Feature | Evidence doc | Proof in the sweep |
|---|---|---|---|
| 1 | P2P mesh datapath | `w18-linux-daemon.md` | `w18-linux-daemon` |
| 9 | Subnet routers | `w18-subnet.md` | `subnet` |
| 10 | Split tunneling / accept-routes | `w18-subnet.md` | `subnet` |
| 11 | Exit nodes | `w19-exit-node.md` | `exit-node` |
| 16 | MagicDNS | `w18-names.md` | `w18-names` |
| 17 | Split DNS (Linux only) | `w25-6-policy-sync.md` | `policy-sync` |
| 19 | ACL policy file | `w18-policy.md`, `w24-port-acl.md` | `policy`, `datapath-acl` |
| 21 | ACL tests | `w18-policy.md` | `policy` |
| 24 | GitOps for ACLs | `w25-policy-gitops.md` | `policy-gitops` (`examples/policy-gitops/proof/proof.sh`) |
| 28 | Node key expiry / auth period | `gyeol-identity/src/clock.rs` (code constants) | **none: gap** (no proof script) |
| 29 | Key / SVID rotation UX | `w18-svid-renew.md`, `w20-nat-followup.md` | `svid-renew`, `nat-realism` |
| 30 | Revocation / device removal | `w19-admin-cli.md`, `w24-revoke-all.md`, `w25-revoke-followup.md` | `admin`, `revoke-all`, `revoke-followup` |
| 31 | Device approval | `w19-admin-cli.md` | `admin` |
| 33 | Auth keys (headless enroll) | `w18-coord-enroll.md` | `coord-enroll` |
| 35 | OAuth clients / API tokens | `w25-api-tokens.md`, `w25-token-no-escalation.md` | `api-tokens`, `token-no-escalation` |
| 38 | Node sharing | `w25-node-sharing.md` | `node-share` |
| 40 | Tailscale SSH | `w19-ssh.md`, `w23-ssh-pty-recording.md` | `ssh` |
| 41 | SSH session recording | `w22-ssh-recording.md`, `w23-ssh-pty-recording.md` | `ssh` |
| 45 | Taildrop | `w23-file-send.md` | `file-send` |
| 49 | Configuration audit logs | `w20-config-audit.md` | `config-audit` |
| 52 | Webhooks | `w25-audit-webhooks.md` | `audit-webhooks` |
| 53 | status / netcheck / ping / metrics | `w19-admin-cli.md` | `admin` |
| 54 | Linux client | `w18-linux-daemon.md`, `w23-release.md` | `w18-linux-daemon`; **gap** for the rc.2 real install (`release-real.sh` installs a published GitHub release, not a commit) |
| 58 | Docker image | `w25-docker-image.md` | `docker-image` |
| 61 | CLI UX (login/up/down/set) | `w18-linux-daemon.md`, `w18-coord-enroll.md`, `w19-exit-node.md` | `w18-linux-daemon`, `coord-enroll`, `exit-node` |
| 62 | Admin CLI / console | `w19-admin-cli.md` | `admin` |

Gate with no shipped row:

| Gate | Evidence doc | Proof in the sweep |
|---|---|---|
| W23-4 sym relay throughput: the sym_sym relay median of at least 5 runs with a 30 s bulk is at or above 1113 Mbit/s (W25-12, #104) | `w25-sym-throughput.md` | `sym-throughput` |

The gap matrix rows near it (4 Relay, 8 Throughput / latency) are `partial`, not shipped, so the table column says `W23-4 sym gate (no shipped row)`.

Gaps (a shipped row, or part of one, with no proof script that the sweep can run on a commit):

- Row 28: the evidence is the TTL constants in `clock.rs` (unit tests only). No proof script.
- Row 54, rc.2 install part: `scripts/proof/release-real.sh` checks a published release tag from github.com. It does not test a commit, so it is not in the sweep. Run it after the rc.3 tag.

The sweep has 23 proofs: 22 for the shipped rows and `sym-throughput`. The proof list is the `PROOFS` variable in the script. When a shipped row changes, change the list and this table together.

## Proof settings

- `nat-realism`: `ORBLX_NATR_PROFILE=release`, own names `orblx-rc3sw-natr`.
- `revoke-followup`: `ORBLX_PROOF_PROFILE=release` (its default).
- `api-tokens`, `token-no-escalation`, `audit-webhooks`, `policy-gitops`: the release binary (`TOKENS_BIN`, `ESC_BIN`, `HOOKS_BIN`, `GITOPS_BIN`) and own `orblx-rc3sw-*` project and image names.
- `policy-sync`: `ORBLX_SYNC_PROFILE=release` (its default) and own names `orblx-rc3sw-sync`. Linux only (gap matrix row 17).
- `sym-throughput`: own names `orblx-rc3sw-symt` (the `ORBLX_NATR_*` variables pass to the five release `nat-realism.sh` runs of `serial-rtt.sh`). It passes only with the line `sym_gate ok: ...` and exit 0; a `proof_ok` of one run is not enough. `serial-rtt.sh` writes each run to `target/sym-throughput/runN.log`; the sweep adds each run log, whole, to the end of the sweep log (`=== release_sweep: step log ... (full) ===`).
- `docker-image`: own `orblx-rc3sw-*` names. It builds `docker/Dockerfile` (release build in the image).
- The other proofs have no binary setting. They use the debug binary of the same commit (the sweep builds it before the first proof) and their fixed names.
- Each proof gets `PROOF_LOG` set to its log, so the secret checks also read the log.

## Dry run on main

This dry run is for early detection only. **It does not count for rc.3.** The real sweep runs later on a commit that has the W25-14 merge.

Commit: `cd6c8eea` (main at the start of the dry run, before W25-6, W25-14 and the FIFO lock). Started 00:29:53 KST, lock mode `proof`. The build took about 1 min. The other proofs of the box ran at the same time, so most of each proof time below is the wait for the lock. The live table is `/workspace/orblx-w18-proof/rc3-sweep-cd6c8eea.md`. `policy-sync` and `sym-throughput` are not in this commit.

State at the merge of this PR (18 of 21 proofs done; `config-audit`, `audit-webhooks` and `docker-image` still ran):

| proof | gap row | result |
|---|---|---|
| w18-linux-daemon | 1, 54, 61 | `proof_ok` |
| coord-enroll | 33, 61 | FAIL (exit 1): The TUN device did not open. The TUN device needs CAP_NET_ADMIN on Linux. ... No such file or directory (os error 2) |
| subnet | 9, 10 | `proof_ok` |
| exit-node | 11, 61 | FAIL (exit 1): mkdir ... No space left on device (box disk full) |
| w18-names | 16 | FAIL (exit 1): proof-lock.sh: line 165: echo: write error: No space left on device (box disk full) |
| policy | 19, 21 | FAIL (exit 1): same (box disk full) |
| datapath-acl | 19 | FAIL (exit 1): Error response from daemon: write /orblx: no space left on device (box disk full) |
| policy-gitops | 24 | FAIL (exit 100): apt: Error writing to file ... No space left on device (box disk full) |
| svid-renew | 29 | FAIL (exit 1): cp: error copying ... No space left on device (box disk full) |
| nat-realism | 29 | FAIL (exit 1): no error line; last line `=== REAL cargo test signed hello and birthday bounds ===` (the proof filters the cargo test output; it ran while the disk was full) |
| admin | 30, 31, 53, 62 | `proof_ok` |
| revoke-all | 30 | `proof_ok` |
| revoke-followup | 30 | `proof_ok` |
| api-tokens | 35 | `proof_ok` |
| token-no-escalation | 35 | `proof_ok` |
| node-share | 38 | `proof_ok` |
| ssh | 40, 41 | `proof_ok` |
| file-send | 45 | `proof_ok` |

- The box disk reached 100% at about 01:32 KST (the targets and images of other workers). The seven `No space left on device` failures are of the box, not of the product. They need a run again.
- `coord-enroll` is the one product failure so far: `orblx up` does not open the TUN device in its container.
- The `proof_ok` logs show no skipped check. Some setup steps (for example `=== [C] start coordinator ===`) print nothing, because the proof sends their output to `/dev/null`.

## Limits

- The dry run started before W25-14c (#99). Then `flock` did not serve waiters in order: other workers ran `nat-realism.sh` in loops, and the sweep waited up to about 24 minutes for one proof. #99 makes the lock first come, first served, so a sweep proof now waits at most for the queue in front of it. `ORBLX_SWEEP_LOCK_MODE=sweep` still makes the sweep wait once and then hold the lock until it ends.
- The lock only orders the proofs that take it. A proof that does not take the lock (from another branch or another agent) can run at the same time. Proofs with fixed container names or subnets (for example `subnet.sh`, `exit-node.sh`) can then collide with the same proof of another worktree.
- The `proof_context` and `proof_contention` lines count every other running orblx container. For the proofs with fixed names, this count includes the containers of the proof itself.
- The proofs with no binary setting use a debug binary, not the release binary.
- The "first error line" is a text match. A proof that prints an expected error before its real failure gives the expected line. The exit code and the log path are in the row.
- The real sweep is Linux only (`flock`, `timeout`, Docker). On a host with no `timeout` (macOS CI), a proof runs with no time limit; with no `flock`, it runs without the lock. The unit test runs on both.

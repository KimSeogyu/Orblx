# W25-17 proof sweep runner (rc.3 condition 4)

`scripts/proof/release-sweep.sh` runs, in one command, every proof that backs a shipped row of
the Tailscale gap matrix on one commit. The proofs run one at a time under the W25-5 box proof
lock. The exit code is not 0 when a proof fails or when a shipped row has no proof. This is rc.3
condition 4, and later the nightly run on main (the nightly schedule is not in this change).

The rc.3 sweep counts only on a commit that has the W25-14, the W25-14b (coord-enroll fix) and the W25-6b merges.

## Commands

```bash
scripts/proof/release-sweep.sh --plan COMMIT   # list every row and its proof, and a time estimate
scripts/proof/release-sweep.sh COMMIT          # run the sweep
```

`--plan` does not build and does not run a proof. It checks that each proof script is in
`COMMIT`, prints every row with its proofs, and prints a time estimate. The estimate of a proof
is its run time under the lock (from the lock `acquired` line to the `released` line, or the
sweep marks) in its newest passing log in `ORBLX_SWEEP_OUT`. A proof with no such log is listed
as "no measure", and the total is the sum of the measured proofs only, plus the build and the
lock waits. The plan exits 1 when a row has no proof or a script is missing.

The run:

1. It resolves `COMMIT` (after `git fetch origin`). Then it checks the free disk space on the
   file system of the worktree and of `ORBLX_SWEEP_OUT`. With less than 30 GB free
   (`ORBLX_SWEEP_MIN_FREE_GB`), it stops with exit 2 and the message `disk FAIL: only N GB free
   at DIR; ...`, and no proof runs. A run that failed from a full disk never counts. Then it makes
   a detached worktree (`/workspace/orblx-rc3-sweep-<sha>`).
2. It builds the release binary there with the `~/.cargo/bin` toolchain (the build log has the
   `rustc --version` line), and the debug binaries that the older proofs use, so no proof
   compiles while it holds the lock.
3. It runs each proof of the manifest once, from that worktree. A wrapper takes the box proof
   lock before the proof starts and releases it after the proof ends. Since W25-14 each proof
   takes the lock itself; it sees that its parent holds it and does not wait again. The
   timeout (`ORBLX_SWEEP_TIMEOUT`) counts only the proof, not the lock wait.
4. It writes the summary `/workspace/orblx-w18-proof/rc3-sweep-<sha>.md` after each proof.
5. After each proof it removes the images of that proof (without `-f`). At the end it removes
   the worktree and its target.

There is no retry, no skip and no "run until it passes": each proof runs once. A failed proof
does not stop the sweep. `ORBLX_SWEEP_ONLY` runs some proofs only; such a run never counts
(exit 3 at best, and the summary says "Partial run").

| Exit | Meaning |
|---|---|
| 0 | Every row passed: each of its proofs gave its pass line. |
| 1 | A proof failed, or a shipped row has no proof. The summary line `Failed rows: ...` names the rows. |
| 2 | Setup, manifest or build error. |
| 3 | `ORBLX_SWEEP_ONLY` run with no failure. It does not count. |

## Manifest

`scripts/proof/sweep-manifest.txt` maps the shipped rows (by the row number of the gap matrix)
to their proofs, and holds the settings of each proof:

- `row|NUMBER|FEATURE|PROOFS`: one line for each shipped row. `PROOFS` is a list of proof
  names, or `-`. A row with `-` is `FAIL: no proof for this shipped row`, and the sweep exits 1.
- `gate|NAME|TEXT|PROOFS`: a gate with no shipped row of its own (W23-4 sym gate).
- `proof|NAME|SCRIPT|ENV|IMAGES[|PASS ERE[|STEP LOGS]]`: the script, its env (`@BIN@` is the
  release binary), its images, the pass line (default `proof_ok`), and the logs that the proof
  writes to its own files.

The script stops with exit 2 when a row names an unknown proof or a proof backs no row. The
sweep reads the manifest of `COMMIT`; when the commit has none (an older commit), it reads the
manifest of the checkout of the script, and the summary says so.

Source of the rows: the Page "Orblx vs Tailscale 기능 격차 매트릭스 + Wave 계획" (not in this
repository) and the PO list of 2026-10-31: rows 17, 24, 38, 51 and 52 are shipped, plus the
earlier rows. The proof of each row comes from the evidence doc that the row names.

| Row | Feature | Evidence doc | Proofs |
|---|---|---|---|
| 1 | P2P mesh datapath | `w18-linux-daemon.md` | `w18-linux-daemon` |
| 9 | Subnet routers | `w18-subnet.md` | `subnet` |
| 10 | Split tunneling / accept-routes | `w18-subnet.md` | `subnet` |
| 11 | Exit nodes | `w19-exit-node.md` | `exit-node` |
| 16 | MagicDNS | `w18-names.md` | `w18-names` |
| 17 | Split DNS / policy sync (Linux only) | `w24-split-dns.md`, `w25-6-policy-sync.md` | `split-dns`, `policy-sync` |
| 19 | ACL policy file | `w18-policy.md`, `w24-port-acl.md` | `policy`, `datapath-acl` |
| 21 | ACL tests | `w18-policy.md` | `policy` |
| 24 | GitOps for ACLs | `w25-policy-gitops.md` | `policy-gitops` (`examples/policy-gitops/proof/proof.sh`) |
| 28 | Node key expiry / auth period | `crates/orblx-identity/src/clock.rs` (code constants) | **none: the sweep fails on this row** |
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
| 51 | Log streaming (SIEM) | `w25-siem-streaming.md` | `siem-streaming` |
| 52 | Webhooks | `w25-audit-webhooks.md` | `audit-webhooks` |
| 53 | status / netcheck / ping / metrics | `w19-admin-cli.md` | `admin` |
| 54 | Linux client | `w18-linux-daemon.md`, `w23-release.md` | `w18-linux-daemon` (the rc.2 real install part is `release-real.sh`, which tests a published release, not a commit) |
| 58 | Docker image | `w25-docker-image.md` | `docker-image` |
| 61 | CLI UX (login/up/down/set) | `w18-linux-daemon.md`, `w18-coord-enroll.md`, `w19-exit-node.md` | `w18-linux-daemon`, `coord-enroll`, `exit-node` |
| 62 | Admin CLI / console | `w19-admin-cli.md` | `admin` |
| W23-4 gate | sym relay throughput: sym_sym median of at least 5 runs of 30 s at or above 1113 Mbit/s (#104) | `w25-sym-throughput.md` | `sym-throughput` |

27 shipped rows, one gate, 25 proofs. Row 28 has no proof script (its evidence is the TTL
constants in `clock.rs` and their unit tests), so every sweep fails on row 28 until a proof for
it is in the manifest. The sweep does not hide this row.

## Release checklist (rc.3)

1. The rc.3 sweep runs on a commit that has the W25-14, W25-14b and W25-6b merges, with at least
   30 GB free disk. It exits 0. A run that failed from a full disk never counts.
2. Row 54 (Linux client) counts for rc.3 on the commit build proof (`up`, `down`, `status` and
   systemd), not on a published artifact. Coverage today: the sweep proof `w18-linux-daemon`
   runs `orblx up` in [C] containers and checks `orblx status`. W25-54: it also runs the
   unit `scripts/orblxd.service` under systemd as PID 1 in [C] `node-s`: start, stop, restart,
   and `orblx down` (see `docs/w18-linux-daemon.md`). `scripts/proof/release.sh` (not in the manifest)
   builds the release tarball at the commit, installs it in a clean [C] container with `--service`, and checks
   that the installer writes `/etc/systemd/system/orblxd.service`. The `down` and systemd start
   parts are in `w18-linux-daemon` since W25-54.
3. After the rc.3 artifact is published, run `scripts/proof/release-real.sh` again on the
   published rc.3 artifact. Nobody announces rc.3 before that run passes.
4. The real sweep records the run times of the proofs that have no measure in the plan today:
   `coord-enroll`, `exit-node`, `datapath-acl`, `policy-gitops`, `svid-renew`, `docker-image` and
   `sym-throughput`.

## Results and logs

| Result | Rule |
|---|---|
| `proof_ok` | The proof exit code is 0 and the log has its pass line: a `proof_ok` line (`docker-image.sh` adds fields after it; `w18-linux-daemon.sh` prints `W18 proof passed`), or the pass line of the manifest (`sym-throughput`: `^sym_gate ok: `). |
| `FAIL (exit N): LINE` | Any other case. `LINE` is the first log line that matches `error`, `FAIL`, `failed`, `panicked`, `: line N:`, `command not found`, `No such file`, `timed out`, `Traceback`, `show_matching: no line matches` or `secret_scan:`. When no line matches, it is the last log line. |
| `FAIL (exit 0, no proof_ok line)` | The proof skipped itself (for example, it was not root). A skip is not a pass. |
| `FAIL (exit 0, no pass line RE)` | A proof with its own pass line ended with exit 0 but without that line. |
| `FAIL (exit 124, timeout ...)` | The proof ran longer than `ORBLX_SWEEP_TIMEOUT`. |
| `FAIL: no proof for this shipped row` | The manifest row has `-`. |

The summary has one line for each row and proof: row, feature, proof, result, log path, time
(`T s (run R s, lock wait W s)`) and the `proof_contention` line of the proof (samples,
contended samples, the most other orblx containers, the most load). Then `Failed rows: ...`,
and the proof count and the total time.

The log of a proof (`/workspace/orblx-w18-proof/rc3-sweep-<sha>-<proof>.log`) is the full
stdout and stderr of the proof, with no filter and no cut. The sweep adds only its own lines
(`proof_lock`, `proof_context`, `proof_contention`, `release_sweep:`). When a proof writes step
output to files of its own (`sym-throughput`: `target/sym-throughput/runN.log` of
`serial-rtt.sh`), the sweep adds each file, whole, after the proof output
(`=== release_sweep: step log ... (full) ===`). The sweep does not change the proof scripts
(W25-14 owns them); since W25-14d (#101) no proof pipes `cargo` output into a filter.

### steady_warn rate (report only)

`nat-realism.sh` prints a `steady_warn` line when a steady ping sample is over 100 ms. It is
report only. The sweep counts the nat-realism runs that have at least one `steady_warn` line: the
log of the `nat-realism` proof is one run, and each step log of a proof with step logs is one
run (the five or more release `nat-realism.sh` runs of `sym-throughput`). The summary always has
the line `steady_warn: W of N nat-realism runs have a steady_warn line (P%). Report only.` When
more than 1% of the runs have one, it adds:

```
steady_warn_rate over 1%: root-cause item (W of N nat-realism runs, P%). This does not fail the sweep.
```

This line does not change the exit code. Note: with about six nat-realism runs in one sweep, one
run with a `steady_warn` line is over 1%. On main (4bcc3b0) `nat-realism.sh` does not print
`steady_warn` yet, so the count is 0 until the proof prints it.

The script sends no proof output through a pipe. The checks read the whole file (the
`has_line` helper of #94, and awk with no early exit), so no reader can end early and cause
SIGPIPE (exit 141) under `set -o pipefail`.

| Env | Default | Meaning |
|---|---|---|
| `ORBLX_SWEEP_OUT` | `/workspace/orblx-w18-proof` | Log and summary directory. |
| `ORBLX_SWEEP_WT` | `/workspace/orblx-rc3-sweep-<sha>` | Worktree path. |
| `ORBLX_SWEEP_MANIFEST` | the manifest of `COMMIT` | Manifest file. |
| `ORBLX_SWEEP_ONLY` | every proof | Space list of proof names. A partial run, exit 3 at best. |
| `ORBLX_SWEEP_TIMEOUT` | 3600 | Seconds for each proof, without the lock wait. |
| `ORBLX_SWEEP_KEEP` | 0 | 1 keeps the worktree, the target and the images. |
| `ORBLX_SWEEP_FETCH` | 1 | 0 does not run `git fetch`. |
| `ORBLX_SWEEP_PROGRESS` | none | A file. The script adds one line for each step. |
| `ORBLX_SWEEP_LOCK_MODE` | `proof` | `proof`: take the lock for each proof. `sweep`: take the lock once and hold it for all the proofs. |
| `ORBLX_SWEEP_MIN_FREE_GB` | 30 | Free GB that the run needs before it starts. |
| `ORBLX_SWEEP_TEST_ROOT` | none | Test only (`tests/test_release_sweep.py`). |

The script runs git as the caller. It runs the build and the proofs with `sudo -n` when the
caller is not root, so it never asks for a password.

## Proof settings

- `nat-realism`: `ORBLX_NATR_PROFILE=release`, own names `orblx-rc3sw-natr`.
- `revoke-followup`: `ORBLX_PROOF_PROFILE=release` (its default).
- `api-tokens`, `token-no-escalation`, `audit-webhooks`, `policy-gitops`, `siem-streaming`: the
  release binary (`TOKENS_BIN`, `ESC_BIN`, `HOOKS_BIN`, `GITOPS_BIN`, `SIEM_BIN`) and own
  `orblx-rc3sw-*` project and image names.
- `split-dns`, `policy-sync`: own `orblx-rc3sw-*` project and image names; `policy-sync` uses
  `ORBLX_SYNC_PROFILE=release` (its default). Linux only.
- `sym-throughput`: own names `orblx-rc3sw-symt` (the `ORBLX_NATR_*` variables pass to the five
  release `nat-realism.sh` runs of `serial-rtt.sh`). Its pass line is `sym_gate ok: ...`; a
  `proof_ok` of one run is not enough.
- `docker-image`: own `orblx-rc3sw-*` names. It builds `docker/Dockerfile`.
- The other proofs have no binary setting. They use the debug binary of the same commit (the
  sweep builds it before the first proof) and their fixed names.
- Each proof gets `PROOF_LOG` set to its log, so the secret checks also read the log.

## Tests

`scripts/proof/tests/test_release_sweep.py` (no git, no build, no Docker):

- every proof runs once, a failure does not stop the sweep, and `Failed rows:` names the rows;
- negative test: one proof made to fail makes the sweep exit 1 and names its row;
- a shipped row with no proof fails the sweep; a bad manifest is exit 2;
- a skip (exit 0, no `proof_ok`) is a FAIL; a partial run is exit 3;
- the log keeps the full proof output (100000 lines, stderr, a last line with no newline) and
  the step logs, whole;
- the lock is taken (lock mode `proof` and `sweep`);
- `--plan` lists every row and proof and prints the estimate;
- less free disk than `ORBLX_SWEEP_MIN_FREE_GB` stops the run with exit 2 before any proof;
- a `steady_warn` rate over 1% prints the root-cause line and does not fail the sweep;
- the real manifest has every shipped row, and each proof it names is defined.

`scripts/proof/tests/test_no_early_pipe_reader.py` checks the script for early pipe readers.

## Plan on main

`scripts/proof/release-sweep.sh --plan 92c698e7` (main on 2026-10-31 04:25 KST, with the
manifest of this change):

| proof | rows | estimate s (proof run, no lock wait) | source log |
|---|---|---|---|
| w18-linux-daemon | 1, 54, 61 | 37 | rc3-sweep-cd6c8eea-w18-linux-daemon.log |
| coord-enroll | 33, 61 | no measure | - |
| subnet | 9, 10 | 20 | rc3-sweep-cd6c8eea-subnet.log |
| exit-node | 11, 61 | no measure | - |
| w18-names | 16 | 28 | w25n-main-8996f4e8-w18-names.log |
| split-dns | 17 | 66 | w25n-main-8996f4e8-split-dns.log |
| policy-sync | 17 | 196 | w256-w256b-eb57e2b4-policy-sync-run1.log |
| policy | 19, 21 | 49 | w25n-main-a5a38013-policy.log |
| datapath-acl | 19 | no measure | - |
| policy-gitops | 24 | no measure | - |
| svid-renew | 29 | no measure | - |
| nat-realism | 29 | 323 | w25o-r1-release-nat-realism.log |
| admin | 30, 31, 53, 62 | 63 | rc3-sweep-cd6c8eea-admin.log |
| revoke-all | 30 | 64 | rc3-sweep-cd6c8eea-revoke-all.log |
| revoke-followup | 30 | 274 | rc3-sweep-cd6c8eea-revoke-followup.log |
| api-tokens | 35 | 35 | rc3-sweep-cd6c8eea-api-tokens.log |
| token-no-escalation | 35 | 32 | rc3-sweep-cd6c8eea-token-no-escalation.log |
| node-share | 38 | 89 | rc3-sweep-cd6c8eea-node-share.log |
| ssh | 40, 41 | 34 | rc3-sweep-cd6c8eea-ssh.log |
| file-send | 45 | 86 | rc3-sweep-cd6c8eea-file-send.log |
| config-audit | 49 | 32 | w25n-main-8996f4e8-config-audit.log |
| siem-streaming | 51 | no measure | - |
| audit-webhooks | 52 | no measure | - |
| docker-image | 58 | no measure | - |
| sym-throughput | W23-4 | no measure | - |

Rows: 28. Proofs: 25.
Estimate: 1428 s (23 min) for the 16 proofs with a measure (the run time under the lock, from the newest passing log in /workspace/orblx-w18-proof), plus the build and the lock waits. No measure: coord-enroll exit-node datapath-acl policy-gitops svid-renew siem-streaming audit-webhooks docker-image sym-throughput.
Plan FAIL: rows 28.

The plan fails on row 28 (no proof). The real rc.3 sweep runs later, on a commit with the
W25-14, W25-14b (coord-enroll fix) and W25-6b merges, when the PO says so.

## Proof dry run on main (pass 1)

This run used the first version of the script (one line for each proof, no manifest). It is for early detection only. **It does not count for rc.3.** The real sweep runs later on a commit that has the W25-14, W25-14b (coord-enroll fix) and W25-6b merges.

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

- The dry run started before W25-14c (#99). Then `flock` did not serve waiters in order: other workers ran `nat-realism.sh` in loops, and the sweep waited about 50 minutes for one proof (`ssh`). #99 makes the lock first come, first served, so a sweep proof now waits at most for the queue in front of it. `ORBLX_SWEEP_LOCK_MODE=sweep` still makes the sweep wait once and then hold the lock until it ends.
- The lock only orders the proofs that take it. A proof that does not take the lock (from another branch or another agent) can run at the same time. Proofs with fixed container names or subnets (for example `subnet.sh`, `exit-node.sh`) can then collide with the same proof of another worktree.
- The `proof_context` and `proof_contention` lines count every other running orblx container. For the proofs with fixed names, this count includes the containers of the proof itself.
- The proofs with no binary setting use a debug binary, not the release binary.
- The "first error line" is a text match. A proof that prints an expected error before its real failure gives the expected line. The exit code and the log path are in the row.
- The sweep is Linux only (`flock`, `timeout`, Docker). On a host with no `timeout` (macOS CI), a proof runs with no time limit; with no `flock`, it runs without the lock. The unit test runs on both.

## Rows that the rc.3 sweep skips (W25-27)

`docs/matrix-rows.txt` is the one source of row status. A partial row may have a 4th field, and
the only accepted value is `not in rc.3 sweep: no coordinator SSH certs`. A proof is skipped only
when every row that names it has this mark; the summary shows `skipped (<mark>)` and the plan
shows `skipped: <mark>`. Without the mark the proof runs. Rows 40 (Tailscale SSH) and 41 (SSH
session recording) have the mark, so the `ssh` proof does not run in the rc.3 sweep: it makes lab
tickets, and the lab-ticket guard fails it. The sweep exits 2 when row 40 or row 41 claims
shipped in the rows file or the manifest, when a 4th field is not the mark, and when a shipped
row has the mark. The release notes draft (`docs/rc3-release-notes.md`) says so for users.

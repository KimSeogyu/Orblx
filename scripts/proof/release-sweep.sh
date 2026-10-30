#!/usr/bin/env bash
# rc.3 release sweep (rc.3 condition 4).
# On one commit, the script runs every proof that backs a "shipped" row of the
# Tailscale gap matrix. It runs the proofs one at a time. Each proof runs under the
# W25-5 box proof lock (proof-lock.sh), so no other proof that uses the lock runs at
# the same time.
#
# Usage: scripts/proof/release-sweep.sh COMMIT
#
# Steps:
#   1. Resolve COMMIT. Make a detached worktree of it (ORBLX_SWEEP_WT).
#   2. Build the release binary there (and the debug binaries that the proofs use).
#   3. Run each proof from that worktree, with the lock. The log of each proof is
#      $ORBLX_SWEEP_OUT/rc3-sweep-<sha>-<proof>.log.
#   4. Write a markdown table: proof, gap row, log path, result. The result is
#      proof_ok, or FAIL with the exit code and the first error line of the log.
#   5. Remove the images of each proof and, at the end, the worktree and its target.
# A failed proof does not stop the sweep. The exit code is 1 when a proof failed,
# 2 when the setup or the build failed, and 0 when every proof printed proof_ok.
#
# The proofs need root and Docker. The script runs git as the caller and runs the build
# and the proofs with sudo -n (no password prompt) unless the caller is root.
# The toolchain is $CARGO_HOME/bin (default ~/.cargo/bin), not the system rustc.
#
# This script does not use head, grep -q, grep -m or awk with exit at all: under
# set -o pipefail, a reader that ends early gives the writer SIGPIPE (exit 141).
# Proof output goes to a file. The checks read the file.
# The log of a proof is its full stdout and stderr, not filtered and not cut: the sweep adds
# only its own lock lines (proof_lock, proof_context, proof_contention) around it.
#
# Env:
#   ORBLX_SWEEP_OUT       Log and table directory (default /workspace/orblx-w18-proof).
#   ORBLX_SWEEP_WT        Worktree path (default /workspace/orblx-rc3-sweep-<sha>).
#   ORBLX_SWEEP_ONLY      Space list of proof names. Default: every proof.
#   ORBLX_SWEEP_TIMEOUT   Seconds for each proof, without the lock wait (default 3600).
#                         Then the proof is FAIL.
#   ORBLX_SWEEP_KEEP      1 keeps the worktree, the target and the images.
#   ORBLX_SWEEP_FETCH     0 does not run git fetch before COMMIT is resolved.
#   ORBLX_SWEEP_PROGRESS  A file. The script adds one line for each step.
#   ORBLX_SWEEP_LOCK_MODE proof (default): take the lock for each proof, so other proofs can
#                         run between two sweep proofs. sweep: take the lock once for all the
#                         proofs. flock is not first-come-first-served, so on a busy box the
#                         proof mode can wait long for each proof.
#   ORBLX_SWEEP_LIST      Test only: the proof list (the format of PROOFS below).
#   ORBLX_SWEEP_TEST_ROOT Test only: use this directory as the checkout. No git, no build,
#                         no sudo, no image removal.
# The script prints no token and no key. It prints the table at the end.

set -euo pipefail

usage() {
  echo "usage: $0 COMMIT" >&2
  exit 2
}
[[ $# -eq 1 && -n "$1" ]] || usage

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SELF_DIR/../.." && pwd)"
LOCK_LIB="$SELF_DIR/proof-lock.sh"
OUT="${ORBLX_SWEEP_OUT:-/workspace/orblx-w18-proof}"
TIMEOUT="${ORBLX_SWEEP_TIMEOUT:-3600}"
ONLY="${ORBLX_SWEEP_ONLY:-}"
KEEP="${ORBLX_SWEEP_KEEP:-0}"
TEST_ROOT="${ORBLX_SWEEP_TEST_ROOT:-}"
PROGRESS="${ORBLX_SWEEP_PROGRESS:-}"
TOOL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
TOOL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
TOOL_PATH="$TOOL_CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# A line equal to proof_ok (docker-image adds fields after it). w18-linux-daemon.sh
# prints "W18 proof passed" in place of proof_ok.
OK_RE='^(proof_ok( .*)?|W18 proof passed)$'
ERR_RE='(error|Error|ERROR|FAIL|panicked|[Ff]ailed|: line [0-9]+:|command not found|No such file|[Tt]imed out|Traceback)'
LOCK_LINE_RE='^proof_(lock|context|contention) '

# One proof for each line: name|script|gap rows|env|images.
# env: space-separated NAME=VALUE words ("-" for none). @BIN@ is the release orblx binary.
# images: the image tags that the proof builds. The sweep removes them after the proof.
# The map comes from the docs/wNN-*.md files of each shipped row (docs/rc3-release-sweep.md).
PROOFS='w18-linux-daemon|scripts/proof/w18-linux-daemon.sh|1, 54, 61|-|orblx-w18:local
coord-enroll|scripts/proof/coord-enroll.sh|33, 61|-|orblx-coord:w18
subnet|scripts/proof/subnet.sh|9, 10|-|orblx-subnet:local
exit-node|scripts/proof/exit-node.sh|11, 61|-|orblx-exit:local
w18-names|scripts/proof/w18-names.sh|16|-|orblx-w18:local
policy|scripts/proof/policy.sh|19, 21|-|orblx-coord:w18
datapath-acl|scripts/proof/datapath-acl.sh|19|-|orblx-w24acl:w24
policy-gitops|examples/policy-gitops/proof/proof.sh|24|GITOPS_BIN=@BIN@ GITOPS_PROJECT=orblx-rc3sw-gitops GITOPS_IMAGE=orblx-rc3sw-gitops:local|orblx-rc3sw-gitops:local
svid-renew|scripts/proof/svid-renew.sh|29|-|orblx-svid:local
nat-realism|scripts/proof/nat-realism.sh|29|ORBLX_NATR_PROFILE=release ORBLX_NATR_PREFIX=orblx-rc3sw-natr- ORBLX_NATR_PROJECT=orblx-rc3sw-natr ORBLX_NATR_IMAGE=orblx-rc3sw-natr:local|orblx-rc3sw-natr:local
admin|scripts/proof/admin.sh|30, 31, 53, 62|-|orblx-admin:w19
revoke-all|scripts/proof/revoke-all.sh|30|-|orblx-w24d-revoke:w24
revoke-followup|scripts/proof/revoke-followup.sh|30|ORBLX_PROOF_PROFILE=release|orblx-w25a-revoke:w25
api-tokens|scripts/proof/api-tokens.sh|35|TOKENS_BIN=@BIN@ TOKENS_PROJECT=orblx-rc3sw-tokens TOKENS_IMAGE=orblx-rc3sw-tokens:local|orblx-rc3sw-tokens:local
token-no-escalation|scripts/proof/token-no-escalation.sh|35|ESC_BIN=@BIN@ ESC_PROJECT=orblx-rc3sw-escalation ESC_IMAGE=orblx-rc3sw-escalation:local|orblx-rc3sw-escalation:local
node-share|scripts/proof/node-share.sh|38|-|orblx-w25a-share:w25
ssh|scripts/proof/ssh.sh|40, 41|-|orblx-ssh:local
file-send|scripts/proof/file-send.sh|45|-|orblx-w23a-file:w23
config-audit|scripts/proof/config-audit.sh|49|-|orblx-audit:w20
audit-webhooks|scripts/proof/audit-webhooks.sh|52|HOOKS_BIN=@BIN@ HOOKS_PROJECT=orblx-rc3sw-webhooks HOOKS_IMAGE=orblx-rc3sw-webhooks:local|orblx-rc3sw-webhooks:local
docker-image|scripts/proof/docker-image.sh|58|ORBLX_DIMG_PREFIX=orblx-rc3sw-dimg ORBLX_DIMG_IMAGE=orblx-rc3sw-image:local|orblx-rc3sw-image:local
policy-sync|scripts/proof/policy-sync.sh|17|ORBLX_SYNC_PROFILE=release PROOF_PROJECT=orblx-rc3sw-sync ORBLX_SYNC_IMAGE=orblx-rc3sw-sync:local|orblx-rc3sw-sync:local'
PROOFS="${ORBLX_SWEEP_LIST:-$PROOFS}"

now() { date '+%Y-%m-%dT%H:%M:%S%z'; }

note() {
  echo "release_sweep $*"
  if [[ -n "$PROGRESS" ]]; then
    echo "$(now) release_sweep $*" >>"$PROGRESS"
  fi
}

as_root() {
  if [[ -n "$TEST_ROOT" || "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# Run a command with the ~/.cargo toolchain. sudo drops the environment, so pass it with env.
tool_env() {
  local pass=()
  if [[ -n "${ORBLX_PROOF_LOCK:-}" ]]; then
    pass+=("ORBLX_PROOF_LOCK=$ORBLX_PROOF_LOCK")
  fi
  if [[ -n "${ORBLX_PROOF_LOCK_HELD:-}" ]]; then
    pass+=("ORBLX_PROOF_LOCK_HELD=$ORBLX_PROOF_LOCK_HELD")
  fi
  as_root env ${pass[@]+"${pass[@]}"} PATH="$TOOL_PATH" CARGO_HOME="$TOOL_CARGO_HOME" RUSTUP_HOME="$TOOL_RUSTUP_HOME" "$@"
}

# Exit 0 when a line of stdin matches the ERE $1. It reads all of stdin (the #94 helper),
# so it is safe on a pipe under set -o pipefail. The sweep gives it files with <.
has_line() {
  awk -v re="$1" '$0 ~ re {found = 1} END {exit !found}'
}

# The first error line of a log, else its last line. Not the lock lines of the sweep.
# awk reads the whole file and has no early exit.
first_error() {
  local log="$1" line
  line="$(awk -v re="$ERR_RE" -v skip="$LOCK_LINE_RE" '!done && $0 ~ re && $0 !~ skip {print; done = 1}' "$log")"
  if [[ -z "$line" ]]; then
    line="$(awk -v skip="$LOCK_LINE_RE" 'NF && $0 !~ skip {l = $0} END {print l}' "$log")"
    if [[ -n "$line" ]]; then
      line="(no error line; last line) $line"
    fi
  fi
  [[ -n "$line" ]] || line="(empty log)"
  line="${line//|/\\|}"
  line="${line//$'\r'/}"
  printf '%s\n' "${line:0:240}"
}

mkdir -p "$OUT"

# 1. Resolve the commit and make the worktree.
if [[ -n "$TEST_ROOT" ]]; then
  ROOT="$TEST_ROOT"
  SHA="$1"
  SHORT="$1"
else
  if [[ "${ORBLX_SWEEP_FETCH:-1}" != 0 ]]; then
    git -C "$REPO" fetch -q origin || note "git fetch failed, the local refs are used"
  fi
  SHA="$(git -C "$REPO" rev-parse --verify "$1^{commit}")" || { echo "release_sweep: unknown commit $1" >&2; exit 2; }
  SHORT="${SHA:0:8}"
  ROOT="${ORBLX_SWEEP_WT:-/workspace/orblx-rc3-sweep-$SHORT}"
  if [[ -d "$ROOT" ]]; then
    have="$(git -C "$ROOT" rev-parse HEAD)"
    if [[ "$have" != "$SHA" ]]; then
      echo "release_sweep: $ROOT is at $have, not $SHA" >&2
      exit 2
    fi
  else
    git -C "$REPO" worktree add -q --detach "$ROOT" "$SHA"
  fi
fi

TABLE="$OUT/rc3-sweep-$SHORT.md"
BIN="$ROOT/target/release/orblx"
SWEEP_START="$(date +%s)"
note "commit $SHA worktree $ROOT start $(now)"

cleanup_worktree() {
  [[ -z "$TEST_ROOT" && "$KEEP" != 1 ]] || return 0
  note "remove worktree $ROOT and its target"
  as_root rm -rf "$ROOT/target" || true
  git -C "$REPO" worktree remove --force "$ROOT" || true
}

# 2. Build.
if [[ -z "$TEST_ROOT" ]]; then
  build_log="$OUT/rc3-sweep-$SHORT-build.log"
  note "build release and debug, log $build_log"
  if ! tool_env bash -c '
      set -euo pipefail
      cd "$1"
      command -v rustc
      rustc --version
      cargo --version
      cargo build --release --locked -p orblx-cli --bin orblx
      cargo build --release --locked -p orblx-coord --example deny_poll
      cargo build --locked -p orblx-cli --bin orblx
      cargo build --locked -p orblx-test-idp --bin orblx-test-idp
    ' release-sweep-build "$ROOT" >"$build_log" 2>&1 </dev/null; then
    note "build FAIL: $(first_error "$build_log")"
    {
      echo "| proof | gap row | log path | result |"
      echo "|---|---|---|---|"
      echo "| build | - | $build_log | FAIL: $(first_error "$build_log") |"
    } >"$TABLE"
    cleanup_worktree
    exit 2
  fi
  note "build ok: $(awk '!done && /^rustc / {print; done = 1}' "$build_log")"
fi

# 3. Run the proofs.
specs=()
while IFS= read -r line; do
  [[ -n "$line" && "$line" != \#* ]] || continue
  specs+=("$line")
done <<<"$PROOFS"

if [[ -n "$ONLY" ]]; then
  for want in $ONLY; do
    found=0
    for line in "${specs[@]}"; do
      if [[ "${line%%|*}" == "$want" ]]; then
        found=1
      fi
    done
    if [[ "$found" != 1 ]]; then
      echo "release_sweep: unknown proof $want" >&2
      exit 2
    fi
  done
fi

ROWS_FILE="$(mktemp)"
LOCK_MODE="${ORBLX_SWEEP_LOCK_MODE:-proof}"
case "$LOCK_MODE" in
  proof)
    trap 'rm -f "$ROWS_FILE"' EXIT
    ;;
  sweep)
    # One hold for all the proofs. The wrapper of each proof sees ORBLX_PROOF_LOCK_HELD.
    # shellcheck source=proof-lock.sh
    . "$LOCK_LIB"
    trap 'proof_lock_end; rm -f "$ROWS_FILE"' EXIT
    note "lock mode sweep: wait for the lock"
    proof_lock_take "rc3-sweep:$SHORT" orblx-rc3sw-
    note "lock mode sweep: lock taken $(now)"
    ;;
  *)
    echo "release_sweep: ORBLX_SWEEP_LOCK_MODE must be proof or sweep" >&2
    exit 2
    ;;
esac
failed=0
ran=0
for line in "${specs[@]}"; do
  IFS='|' read -r name path rows envs images <<<"$line"
  if [[ -n "$ONLY" && " $ONLY " != *" $name "* ]]; then
    continue
  fi
  ran=$((ran + 1))
  log="$OUT/rc3-sweep-$SHORT-$name.log"
  : >"$log"
  env_words=()
  if [[ "$envs" != "-" && -n "$envs" ]]; then
    read -r -a env_words <<<"${envs//@BIN@/$BIN}"
  fi
  note "proof $name start $(now) log $log"
  started="$(date +%s)"
  rc=0
  if [[ ! -f "$ROOT/$path" ]]; then
    echo "release_sweep: No such file $path at $SHA" >>"$log"
    rc=127
  else
    # The wrapper takes the lock, runs the proof, and releases the lock in its EXIT trap.
    # ORBLX_PROOF_LOCK_HELD is the wrapper pid, so a proof that takes the lock itself
    # (nat-realism.sh) sees that its parent holds it.
    # The timeout counts only the proof, not the wait for the lock.
    tool_env PROOF_LOG="$log" ${env_words[@]+"${env_words[@]}"} \
      bash -c '
        . "$1" || exit 98
        trap proof_lock_end EXIT
        proof_lock_take "$2" orblx-rc3sw-
        cd "$3"
        timeout -k 60 "$5" bash "$4"
      ' release-sweep-proof "$LOCK_LIB" "rc3-sweep:$name" "$ROOT" "$ROOT/$path" "$TIMEOUT" \
      >>"$log" 2>&1 </dev/null || rc=$?
  fi
  secs=$(( $(date +%s) - started ))
  if [[ "$rc" -eq 0 ]] && has_line "$OK_RE" <"$log"; then
    result="proof_ok"
  else
    failed=$((failed + 1))
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
      result="FAIL (exit $rc, timeout ${TIMEOUT} s): $(first_error "$log")"
    elif [[ "$rc" -eq 0 ]]; then
      result="FAIL (exit 0, no proof_ok line): $(first_error "$log")"
    else
      result="FAIL (exit $rc): $(first_error "$log")"
    fi
  fi
  echo "| $name | $rows | $log | $result |" >>"$ROWS_FILE"
  note "proof $name end $(now) secs $secs result $result"
  if [[ -z "$TEST_ROOT" && "$KEEP" != 1 && -n "$images" ]]; then
    for image in $images; do
      # No -f: an image that a running container uses stays.
      as_root docker image rm "$image" >/dev/null 2>&1 || true
    done
  fi
  {
    echo "# rc.3 release sweep $SHORT"
    echo
    echo "Commit \`$SHA\`. Started $(date -d "@$SWEEP_START" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo "$SWEEP_START")."
    echo
    echo "| proof | gap row | log path | result |"
    echo "|---|---|---|---|"
    cat "$ROWS_FILE"
  } >"$TABLE"
done

cleanup_worktree
total=$(( $(date +%s) - SWEEP_START ))
{
  echo
  echo "Proofs: $ran. Failed: $failed. Total time: ${total} s ($((total / 60)) min $((total % 60)) s). Ended $(date '+%Y-%m-%d %H:%M:%S %Z')."
} >>"$TABLE"
note "end $(now) proofs $ran failed $failed total_secs $total table $TABLE"
cat "$TABLE"
if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
exit 0

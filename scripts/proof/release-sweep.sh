#!/usr/bin/env bash
# W25-17 proof sweep runner (rc.3 condition 4).
# On one commit, the script runs every proof that backs a shipped row of the Tailscale gap
# matrix. The map is scripts/proof/sweep-manifest.txt (row number -> proofs). The proofs run
# one at a time, each under the W25-5 box proof lock (proof-lock.sh).
#
# Usage: scripts/proof/release-sweep.sh COMMIT          run the sweep
#        scripts/proof/release-sweep.sh --plan COMMIT   list every row and its proof, check the
#                                                       scripts at COMMIT, print a time estimate
#
# Run steps:
#   1. Resolve COMMIT. Make a detached worktree of it (ORBLX_SWEEP_WT).
#   2. Build the release binary there (and the debug binaries that the proofs use).
#   3. Run each proof of the manifest once, with the lock. The log of each proof is
#      $ORBLX_SWEEP_OUT/rc3-sweep-<sha>-<proof>.log: the full stdout and stderr of the proof,
#      not filtered and not cut. The sweep adds only its own lines (proof_lock, proof_context,
#      proof_contention, release_sweep:) and the step logs of the manifest, whole.
#   4. Write the summary $ORBLX_SWEEP_OUT/rc3-sweep-<sha>.md: one line for each row and proof
#      with the row, the result, the log path, the time and the proof_contention line.
#   5. Remove the images of each proof and, at the end, the worktree and its target.
# There is no retry and no skip: each proof runs once, and a failed proof does not stop the
# sweep. A shipped row with no proof is a FAIL.
# Exit: 0 every row passed; 1 a proof failed or a row has no proof (the summary names the
# rows); 2 setup, manifest or build error; 3 ORBLX_SWEEP_ONLY run with no failure (a partial
# run never counts).
#
# The proofs need root and Docker. The script runs git as the caller and runs the build and
# the proofs with sudo -n (no password prompt) unless the caller is root.
# The toolchain is $CARGO_HOME/bin (default ~/.cargo/bin), not the system rustc.
# The script does not use head, grep -q, grep -m or awk with exit: under set -o pipefail, a
# reader that ends early gives the writer SIGPIPE (exit 141). The checks read whole files.
#
# Env:
#   ORBLX_SWEEP_OUT       Log and summary directory (default /workspace/orblx-w18-proof).
#   ORBLX_SWEEP_WT        Worktree path (default /workspace/orblx-rc3-sweep-<sha>).
#   ORBLX_SWEEP_MANIFEST  Manifest file. Default: the manifest of COMMIT, else of this checkout.
#   ORBLX_SWEEP_ONLY      Space list of proof names (a partial run, exit 3 at best).
#   ORBLX_SWEEP_TIMEOUT   Seconds for each proof, without the lock wait (default 3600).
#   ORBLX_SWEEP_KEEP      1 keeps the worktree, the target and the images.
#   ORBLX_SWEEP_FETCH     0 does not run git fetch before COMMIT is resolved.
#   ORBLX_SWEEP_PROGRESS  A file. The script adds one line for each step.
#   ORBLX_SWEEP_LOCK_MODE proof (default): take the lock for each proof. sweep: take it once
#                         for all the proofs.
#   ORBLX_SWEEP_TEST_ROOT Test only: use this directory as the checkout. No git, no build,
#                         no sudo, no image removal.
# The script prints no token and no key.

set -euo pipefail

usage() {
  echo "usage: $0 [--plan] COMMIT" >&2
  exit 2
}
PLAN=0
if [[ "${1:-}" == "--plan" ]]; then
  PLAN=1
  shift
fi
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
MANIFEST_REL="scripts/proof/sweep-manifest.txt"
TOOL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
TOOL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
TOOL_PATH="$TOOL_CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# A line equal to proof_ok (docker-image adds fields after it). w18-linux-daemon.sh
# prints "W18 proof passed" in place of proof_ok.
OK_RE='^(proof_ok( .*)?|W18 proof passed)$'
ERR_RE='(error|Error|ERROR|FAIL|panicked|[Ff]ailed|: line [0-9]+:|command not found|No such file|[Tt]imed out|Traceback|show_matching: no line matches|secret_scan: )'
SKIP_RE='^(proof_(lock|context|contention) |release_sweep: proof run (start|end) epoch )'

now() { date '+%Y-%m-%dT%H:%M:%S%z'; }

note() {
  echo "release_sweep $*"
  if [[ -n "$PROGRESS" ]]; then
    echo "$(now) release_sweep $*" >>"$PROGRESS"
  fi
}

die() {
  echo "release_sweep: $*" >&2
  exit 2
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

# Exit 0 when a line of stdin matches the ERE $1. It reads all of stdin (the #94 helper).
has_line() {
  awk -v re="$1" '$0 ~ re {found = 1} END {exit !found}'
}

cell() {
  local s="$1"
  s="${s//|/\\|}"
  s="${s//$'\r'/}"
  printf '%s\n' "${s:0:240}"
}

# The first error line of a log, else its last line. Not the lines of the sweep itself.
first_error() {
  local log="$1" line
  line="$(awk -v re="$ERR_RE" -v skip="$SKIP_RE" '!done && $0 ~ re && $0 !~ skip {print; done = 1}' "$log")"
  if [[ -z "$line" ]]; then
    line="$(awk -v skip="$SKIP_RE" 'NF && $0 !~ skip {l = $0} END {print l}' "$log")"
    if [[ -n "$line" ]]; then
      line="(no error line; last line) $line"
    fi
  fi
  [[ -n "$line" ]] || line="(empty log)"
  cell "$line"
}

# Seconds from a lock time stamp (2026-10-31T04:10:09.794+0900). Empty when date cannot read it.
stamp_secs() {
  local t="$1"
  t="${t%.*}${t#*.???}"
  date -d "$t" +%s 2>/dev/null || true
}

# "RUN WAIT" seconds of the proof in a sweep log. Each is empty when the log has no mark.
# The sweep marks (epoch) come first; an older log has only the lock lines.
log_times() {
  local log="$1" name="$2" s e a r w
  s="$(awk '/^release_sweep: proof run start epoch / {v = $NF} END {print v}' "$log")"
  e="$(awk '/^release_sweep: proof run end epoch / {v = $NF} END {print v}' "$log")"
  w="$(awk -v l="proof_lock rc3-sweep:$name acquired at" 'index($0, l) == 1 {v = $(NF - 3)} END {print v}' "$log")"
  if [[ -n "$s" && -n "$e" ]]; then
    printf '%s %s\n' "$((e - s))" "${w:+$((w / 1000))}"
    return
  fi
  a="$(awk -v l="proof_lock rc3-sweep:$name acquired at" 'index($0, l) == 1 {v = $5} END {print v}' "$log")"
  r="$(awk -v l="proof_lock rc3-sweep:$name released at" 'index($0, l) == 1 {v = $5} END {print v}' "$log")"
  if [[ -z "$a" || -z "$r" ]]; then
    # A proof log of another run (not of the sweep): its first lock take and its last release.
    a="$(awk '!done && /^proof_lock [^ ]+ acquired at / {v = $5; done = 1} END {print v}' "$log")"
    r="$(awk '/^proof_lock [^ ]+ released at / {v = $5} END {print v}' "$log")"
  fi
  if [[ -n "$a" && -n "$r" ]]; then
    a="$(stamp_secs "$a")"
    r="$(stamp_secs "$r")"
    if [[ -n "$a" && -n "$r" ]]; then
      printf '%s %s\n' "$((r - a))" "${w:+$((w / 1000))}"
      return
    fi
  fi
  printf ' \n'
}

contention_of() {
  local log="$1" name="$2" c
  c="$(awk -v l="proof_contention rc3-sweep:$name " 'index($0, l) == 1 {v = substr($0, length(l) + 1)} END {print v}' "$log")"
  cell "${c:--}"
}

mkdir -p "$OUT"

# 1. Resolve the commit.
if [[ -n "$TEST_ROOT" ]]; then
  ROOT="$TEST_ROOT"
  SHA="$1"
  SHORT="$1"
else
  if [[ "${ORBLX_SWEEP_FETCH:-1}" != 0 ]]; then
    git -C "$REPO" fetch -q origin || note "git fetch failed, the local refs are used"
  fi
  SHA="$(git -C "$REPO" rev-parse --verify "$1^{commit}")" || die "unknown commit $1"
  SHORT="${SHA:0:8}"
  ROOT="${ORBLX_SWEEP_WT:-/workspace/orblx-rc3-sweep-$SHORT}"
fi

# script_at PATH: exit 0 when PATH is a file at the commit.
script_at() {
  if [[ -n "$TEST_ROOT" || "$PLAN" != 1 ]]; then
    [[ -f "$ROOT/$1" ]]
  else
    git -C "$REPO" cat-file -e "$SHA:$1" 2>/dev/null
  fi
}

# 2. Read the manifest.
MANIFEST_TMP="$(mktemp)"
trap 'rm -f "$MANIFEST_TMP"' EXIT
if [[ -n "${ORBLX_SWEEP_MANIFEST:-}" ]]; then
  cp "$ORBLX_SWEEP_MANIFEST" "$MANIFEST_TMP" || die "cannot read $ORBLX_SWEEP_MANIFEST"
  MANIFEST_SRC="$ORBLX_SWEEP_MANIFEST"
elif [[ -n "$TEST_ROOT" && -f "$ROOT/$MANIFEST_REL" ]]; then
  cp "$ROOT/$MANIFEST_REL" "$MANIFEST_TMP"
  MANIFEST_SRC="$ROOT/$MANIFEST_REL"
elif [[ -z "$TEST_ROOT" ]] && git -C "$REPO" show "$SHA:$MANIFEST_REL" >"$MANIFEST_TMP" 2>/dev/null; then
  MANIFEST_SRC="$MANIFEST_REL at $SHORT"
else
  cp "$SELF_DIR/sweep-manifest.txt" "$MANIFEST_TMP" || die "no manifest"
  MANIFEST_SRC="$SELF_DIR/sweep-manifest.txt (the commit has no manifest)"
fi

R_ID=(); R_KIND=(); R_FEAT=(); R_PROOFS=()
P_NAME=(); P_PATH=(); P_ENV=(); P_IMAGES=(); P_OK=(); P_STEPS=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" && "$line" != \#* ]] || continue
  IFS='|' read -r kind f1 f2 f3 f4 f5 f6 <<<"$line"
  case "$kind" in
    row|gate)
      [[ -n "$f1" && -n "$f3" ]] || die "manifest: bad line: $line"
      R_KIND+=("$kind"); R_ID+=("$f1"); R_FEAT+=("$f2"); R_PROOFS+=("$f3")
      ;;
    proof)
      [[ -n "$f1" && -n "$f2" ]] || die "manifest: bad line: $line"
      P_NAME+=("$f1"); P_PATH+=("$f2"); P_ENV+=("${f3:--}"); P_IMAGES+=("${f4:--}")
      P_OK+=("${f5:-$OK_RE}"); P_STEPS+=("${f6:-}")
      ;;
    *) die "manifest: bad line: $line" ;;
  esac
done <"$MANIFEST_TMP"
[[ "${#R_ID[@]}" -gt 0 && "${#P_NAME[@]}" -gt 0 ]] || die "manifest: no rows or no proofs"

proof_index() {
  local i
  for i in "${!P_NAME[@]}"; do
    if [[ "${P_NAME[$i]}" == "$1" ]]; then
      echo "$i"
      return 0
    fi
  done
  return 1
}

# Every proof that a row names exists, and every proof backs a row or a gate.
P_USED=()
for i in "${!P_NAME[@]}"; do P_USED+=(0); done
for r in "${!R_ID[@]}"; do
  [[ "${R_PROOFS[$r]}" == "-" ]] && continue
  for p in ${R_PROOFS[$r]}; do
    i="$(proof_index "$p")" || die "manifest: ${R_KIND[$r]} ${R_ID[$r]} names an unknown proof $p"
    P_USED[$i]=1
  done
done
for i in "${!P_NAME[@]}"; do
  [[ "${P_USED[$i]}" == 1 ]] || die "manifest: proof ${P_NAME[$i]} backs no row and no gate"
done
for want in $ONLY; do
  proof_index "$want" >/dev/null || die "unknown proof $want"
done

rows_of() {
  local p="$1" r out=""
  for r in "${!R_ID[@]}"; do
    if [[ " ${R_PROOFS[$r]} " == *" $p "* ]]; then
      out="${out:+$out, }${R_ID[$r]}"
    fi
  done
  echo "$out"
}

# 3. Plan: list every row and its proof, and the time estimate. No build, no proof run.
if [[ "$PLAN" == 1 ]]; then
  PLAN_FILE="$OUT/rc3-sweep-$SHORT-plan.md"
  bad=0
  bad_rows=""
  total_est=0
  measured=0
  unmeasured=""
  {
    echo "# Proof sweep plan $SHORT"
    echo
    echo "Commit \`$SHA\`. Manifest: $MANIFEST_SRC."
    echo
    echo "| row | feature | proof | script at commit |"
    echo "|---|---|---|---|"
    for r in "${!R_ID[@]}"; do
      if [[ "${R_PROOFS[$r]}" == "-" ]]; then
        echo "| ${R_ID[$r]} | $(cell "${R_FEAT[$r]}") | - | FAIL: no proof for this shipped row |"
        bad=1
        bad_rows="${bad_rows:+$bad_rows, }${R_ID[$r]}"
        continue
      fi
      for p in ${R_PROOFS[$r]}; do
        i="$(proof_index "$p")"
        if script_at "${P_PATH[$i]}"; then
          have="${P_PATH[$i]}"
        else
          have="FAIL: no ${P_PATH[$i]}"
          bad=1
          bad_rows="${bad_rows:+$bad_rows, }${R_ID[$r]}"
        fi
        echo "| ${R_ID[$r]} | $(cell "${R_FEAT[$r]}") | $p | $have |"
      done
    done
    echo
    echo "| proof | rows | estimate s (proof run, no lock wait) | source log |"
    echo "|---|---|---|---|"
    for i in "${!P_NAME[@]}"; do
      p="${P_NAME[$i]}"
      est=""
      src="-"
      # The newest earlier sweep log of this proof with a pass line and a measured run, else
      # the newest other proof log in OUT (NAME.log or NAME-runN.log) with both.
      for f in $(ls -t "$OUT"/rc3-sweep-*-"$p".log 2>/dev/null || true) \
               $(ls -t "$OUT"/*-"$p".log "$OUT"/*-"$p"-run*.log 2>/dev/null || true); do
        [[ -f "$f" ]] || continue
        has_line "${P_OK[$i]}" <"$f" || continue
        read -r run _ <<<"$(log_times "$f" "$p")" || true
        if [[ -n "${run:-}" ]]; then
          est="$run"
          src="$f"
          break
        fi
      done
      if [[ -n "$est" ]]; then
        total_est=$((total_est + est))
        measured=$((measured + 1))
      else
        est="no measure"
        unmeasured="${unmeasured:+$unmeasured }$p"
      fi
      echo "| $p | $(rows_of "$p") | $est | $src |"
    done
    echo
    echo "Rows: ${#R_ID[@]}. Proofs: ${#P_NAME[@]}."
    echo "Estimate: ${total_est} s ($((total_est / 60)) min) for the ${measured} proofs with a measure (the run time under the lock, from the newest passing log in $OUT), plus the build and the lock waits.${unmeasured:+ No measure: $unmeasured.}"
    if [[ "$bad" == 1 ]]; then
      echo "Plan FAIL: rows $bad_rows."
    fi
  } >"$PLAN_FILE"
  cat "$PLAN_FILE"
  exit "$bad"
fi

# 4. The worktree and the build.
if [[ -z "$TEST_ROOT" ]]; then
  if [[ -d "$ROOT" ]]; then
    have="$(git -C "$ROOT" rev-parse HEAD)"
    [[ "$have" == "$SHA" ]] || die "$ROOT is at $have, not $SHA"
  else
    git -C "$REPO" worktree add -q --detach "$ROOT" "$SHA"
  fi
fi

TABLE="$OUT/rc3-sweep-$SHORT.md"
BIN="$ROOT/target/release/orblx"
SWEEP_START="$(date +%s)"
note "commit $SHA worktree $ROOT manifest $MANIFEST_SRC start $(now)"

cleanup_worktree() {
  [[ -z "$TEST_ROOT" && "$KEEP" != 1 ]] || return 0
  note "remove worktree $ROOT and its target"
  as_root rm -rf "$ROOT/target" || true
  git -C "$REPO" worktree remove --force "$ROOT" || true
}

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
      echo "| row | feature | proof | result | log | time | proof_contention |"
      echo "|---|---|---|---|---|---|---|"
      echo "| - | build | - | FAIL: $(first_error "$build_log") | $build_log | - | - |"
    } >"$TABLE"
    cleanup_worktree
    exit 2
  fi
  note "build ok: $(awk '!done && /^rustc / {print; done = 1}' "$build_log")"
fi

# 5. Run each proof once.
P_RESULT=(); P_LOG=(); P_TIME=(); P_CONT=()
for i in "${!P_NAME[@]}"; do
  P_RESULT+=("pending"); P_LOG+=("-"); P_TIME+=("-"); P_CONT+=("-")
done

write_table() {
  local r p i failed_rows="" res
  {
    echo "# Proof sweep $SHORT"
    echo
    echo "Commit \`$SHA\`. Manifest: $MANIFEST_SRC. Started $(date -d "@$SWEEP_START" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo "$SWEEP_START")."
    echo
    echo "| row | feature | proof | result | log | time | proof_contention |"
    echo "|---|---|---|---|---|---|---|"
    for r in "${!R_ID[@]}"; do
      if [[ "${R_PROOFS[$r]}" == "-" ]]; then
        echo "| ${R_ID[$r]} | $(cell "${R_FEAT[$r]}") | - | FAIL: no proof for this shipped row | - | - | - |"
        failed_rows="${failed_rows:+$failed_rows, }${R_ID[$r]}"
        continue
      fi
      res=ok
      for p in ${R_PROOFS[$r]}; do
        i="$(proof_index "$p")"
        echo "| ${R_ID[$r]} | $(cell "${R_FEAT[$r]}") | $p | ${P_RESULT[$i]} | ${P_LOG[$i]} | ${P_TIME[$i]} | ${P_CONT[$i]} |"
        [[ "${P_RESULT[$i]}" == FAIL* ]] && res=fail
      done
      if [[ "$res" == fail ]]; then
        failed_rows="${failed_rows:+$failed_rows, }${R_ID[$r]}"
      fi
    done
    echo
    echo "Failed rows: ${failed_rows:-none}."
  } >"$TABLE"
  FAILED_ROWS="$failed_rows"
}

LOCK_MODE="${ORBLX_SWEEP_LOCK_MODE:-proof}"
case "$LOCK_MODE" in
  proof) ;;
  sweep)
    # One hold for all the proofs. The wrapper of each proof sees ORBLX_PROOF_LOCK_HELD.
    # shellcheck source=proof-lock.sh
    . "$LOCK_LIB"
    trap 'proof_lock_end; rm -f "$MANIFEST_TMP"' EXIT
    note "lock mode sweep: wait for the lock"
    proof_lock_take "rc3-sweep:$SHORT" orblx-rc3sw-
    note "lock mode sweep: lock taken $(now)"
    ;;
  *) die "ORBLX_SWEEP_LOCK_MODE must be proof or sweep" ;;
esac

FAILED_ROWS=""
failed=0
ran=0
not_run=0
write_table
for i in "${!P_NAME[@]}"; do
  name="${P_NAME[$i]}"
  path="${P_PATH[$i]}"
  if [[ -n "$ONLY" && " $ONLY " != *" $name "* ]]; then
    P_RESULT[$i]="not run (ORBLX_SWEEP_ONLY)"
    not_run=$((not_run + 1))
    continue
  fi
  ran=$((ran + 1))
  log="$OUT/rc3-sweep-$SHORT-$name.log"
  : >"$log"
  env_words=()
  if [[ "${P_ENV[$i]}" != "-" ]]; then
    read -r -a env_words <<<"${P_ENV[$i]//@BIN@/$BIN}"
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
    # (every proof since W25-14) sees that its parent holds it.
    # The timeout counts only the proof, not the wait for the lock.
    tool_env PROOF_LOG="$log" ${env_words[@]+"${env_words[@]}"} \
      bash -c '
        . "$1" || exit 98
        trap "echo \"release_sweep: proof run end epoch \$(date +%s)\"; proof_lock_end" EXIT
        proof_lock_take "$2" orblx-rc3sw-
        echo "release_sweep: proof run start epoch $(date +%s)"
        cd "$3"
        if command -v timeout >/dev/null 2>&1; then
          timeout -k 60 "$5" bash "$4"
        else
          echo "release_sweep: no timeout command on this host, the proof runs with no time limit"
          bash "$4"
        fi
      ' release-sweep-proof "$LOCK_LIB" "rc3-sweep:$name" "$ROOT" "$ROOT/$path" "$TIMEOUT" \
      >>"$log" 2>&1 </dev/null || rc=$?
  fi
  secs=$(( $(date +%s) - started ))
  if [[ -n "${P_STEPS[$i]}" ]]; then
    # The full output of the steps that the proof wrote to its own files (root owned).
    tool_env bash -c '
      cd "$1" || exit 0
      shopt -s nullglob
      for f in $2; do
        echo "=== release_sweep: step log $f (full) ==="
        cat "$f"
      done
    ' release-sweep-step-logs "$ROOT" "${P_STEPS[$i]}" >>"$log" 2>&1 </dev/null || true
  fi
  ok_re="${P_OK[$i]}"
  if [[ "$rc" -eq 0 ]] && has_line "$ok_re" <"$log"; then
    result="proof_ok"
  else
    failed=$((failed + 1))
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
      result="FAIL (exit $rc, timeout ${TIMEOUT} s): $(first_error "$log")"
    elif [[ "$rc" -eq 0 && "$ok_re" == "$OK_RE" ]]; then
      result="FAIL (exit 0, no proof_ok line): $(first_error "$log")"
    elif [[ "$rc" -eq 0 ]]; then
      result="FAIL (exit 0, no pass line ${ok_re}): $(first_error "$log")"
    else
      result="FAIL (exit $rc): $(first_error "$log")"
    fi
  fi
  read -r run wait <<<"$(log_times "$log" "$name")" || true
  P_RESULT[$i]="$result"
  P_LOG[$i]="$log"
  P_TIME[$i]="${secs} s (run ${run:-?} s, lock wait ${wait:-?} s)"
  P_CONT[$i]="$(contention_of "$log" "$name")"
  note "proof $name rows $(rows_of "$name") end $(now) secs $secs result $result"
  if [[ -z "$TEST_ROOT" && "$KEEP" != 1 && "${P_IMAGES[$i]}" != "-" ]]; then
    for image in ${P_IMAGES[$i]}; do
      # No -f: an image that a running container uses stays.
      as_root docker image rm "$image" >/dev/null 2>&1 || true
    done
  fi
  write_table
done

cleanup_worktree
write_table
total=$(( $(date +%s) - SWEEP_START ))
{
  echo "Proofs run: $ran. Failed proofs: $failed. Not run: $not_run. Total time: ${total} s ($((total / 60)) min $((total % 60)) s). Ended $(date '+%Y-%m-%d %H:%M:%S %Z')."
  if [[ "$not_run" -gt 0 ]]; then
    echo "Partial run (ORBLX_SWEEP_ONLY): it does not count."
  fi
} >>"$TABLE"
note "end $(now) proofs $ran failed $failed not_run $not_run failed_rows ${FAILED_ROWS:-none} total_secs $total table $TABLE"
cat "$TABLE"
if [[ -n "$FAILED_ROWS" ]]; then
  exit 1
fi
if [[ "$not_run" -gt 0 ]]; then
  exit 3
fi
exit 0

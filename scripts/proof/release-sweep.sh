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
# There is no retry, and no skip except the rows-file mark below: each proof runs once, and a
# failed proof does not stop the sweep. A shipped row with no proof is a FAIL.
# W25-27: the row status has ONE source, docs/matrix-rows.txt (ID|STATUS|FEATURE, copied
# from the gap matrix Page). The "row" lines of the manifest must be exactly the shipped rows
# of that file, and each "partial" line must name a partial row of it. Any difference stops
# the sweep (exit 2) before a proof runs, in --plan and in a run, and names the rows.
# A partial row may carry a 4th field, the skip mark (exactly SKIP_MARK below). A proof whose
# rows all carry the mark does not run: the summary shows it as skipped with the mark. Any
# other 4th field, or the mark on a shipped row, is exit 2. The SSH rows (40 and 41) can not
# be shipped for rc.3: a shipped claim for them in either file is exit 2 (PO, 2026-10-31).
# A proof_ok row counts only when its contention probe reports unknown_samples 0 (see
# contention_verdict); else the row is INVALID. --contention-check LOG NAME checks one log.
# Exit: 0 every row passed; 1 a proof failed, a row has no proof, a row is INVALID, or a row
# is ABORT (proof_infra_abort; the row stays open) (the summary names the rows); 2 setup, manifest or build error; 3 ORBLX_SWEEP_ONLY run with no failure (a partial
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
#   ORBLX_SWEEP_ROWS      Rows file. Default: docs/matrix-rows.txt of COMMIT (of the test
#                         root with ORBLX_SWEEP_TEST_ROOT). No rows file is a setup error.
#   ORBLX_SWEEP_ONLY      Space list of proof names (a partial run, exit 3 at best).
#   ORBLX_SWEEP_TIMEOUT   Seconds for each proof, without the lock wait (default 3600).
#   ORBLX_SWEEP_KEEP      1 keeps the worktree, the target and the images.
#   ORBLX_SWEEP_FETCH     0 does not run git fetch before COMMIT is resolved.
#   ORBLX_SWEEP_PROGRESS  A file. The script adds one line for each step.
#   ORBLX_SWEEP_LOCK_MODE proof (default): take the lock for each proof. sweep: take it once
#                         for all the proofs.
#   ORBLX_SWEEP_MIN_FREE_GB Free disk space (GB) that the run needs before it starts (default
#                         30), on the file system of the worktree and of ORBLX_SWEEP_OUT.
#   ORBLX_SWEEP_WORK      Work dir for the old-binary builds and their cache (default
#                         /workspace/orblx-rc3-sweep-work).
#   OLD_ORBLX             When set, the proofs that pin an old binary use it, and the sweep
#                         builds none.
# Old binaries (W25-27): a proof ENV word may hold @OLD:<full commit SHA>@. The sweep builds
# orblx (debug) at that commit in a temp git worktree with its own target dir, caches the
# binary at $ORBLX_SWEEP_WORK/old-orblx/<sha>/orblx, deletes the worktree and the target, and
# puts the cached path in the word. A proof whose script needs OLD_ORBLX ("OLD_ORBLX:?") must
# have an OLD_ORBLX=@OLD:<sha>@ word. No pin, a pin that is not 40 hex digits, or (with git)
# a pin that is not an ancestor of COMMIT is exit 2, in --plan and in a run.
#   ORBLX_SWEEP_TEST_ROOT Test only: use this directory as the checkout. No git, no build,
#                         no sudo, no image removal.
# The script prints no token and no key.

set -euo pipefail

usage() {
  echo "usage: $0 [--plan] COMMIT" >&2
  echo "       $0 --contention-check LOG PROOF_NAME" >&2
  exit 2
}
PLAN=0
CHECK_LOG=""
if [[ "${1:-}" == "--contention-check" ]]; then
  [[ $# -eq 3 && -f "$2" && -n "$3" ]] || usage
  CHECK_LOG="$2"
  CHECK_NAME="$3"
  set -- check
fi
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
WORK="${ORBLX_SWEEP_WORK:-/workspace/orblx-rc3-sweep-work}"
OLD_ENV="${OLD_ORBLX:-}"
PROGRESS="${ORBLX_SWEEP_PROGRESS:-}"
MANIFEST_REL="scripts/proof/sweep-manifest.txt"
ROWS_REL="docs/matrix-rows.txt"
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

# W25-27 (PO rule 2026-10-31): a proof row counts only when its contention probe reports
# unknown_samples 0. contention_verdict LOG NAME prints "ok" (exit 0) or the reason (exit 1):
# the log must have the sweep wrapper line "proof_contention rc3-sweep:NAME ... unknown_samples
# N ...", and every proof_contention line in the log (the wrapper's and the proof's own) must
# have unknown_samples 0. The wrapper line must also have samples 1 or more (Eng Lead,
# 2026-10-31 14:49 KST): samples 0 is no contention evidence. The proof's own lines may have
# samples 0. The probe itself is in proof-lock.sh.
contention_verdict() {
  local log="$1" name="$2"
  awk -v want="rc3-sweep:$name" '
    index($0, "proof_contention ") == 1 {
      label = $2; u = ""; n = ""
      for (k = 3; k < NF; k++) {
        if ($k == "unknown_samples") u = $(k + 1)
        if ($k == "samples") n = $(k + 1)
      }
      if (u !~ /^[0-9]+$/) { bad = bad ? bad : "proof_contention " label " has no unknown_samples field"; next }
      if (label == want) {
        seen = 1
        if (n !~ /^[0-9]+$/ && !bad) bad = "proof_contention " label " has no samples field"
        else if (n + 0 == 0 && !bad) bad = "samples 0 in proof_contention " label " (no contention evidence)"
      }
      if (u + 0 > 0 && !bad) bad = "unknown_samples " u " in proof_contention " label
    }
    END {
      if (!seen && !bad) bad = "no proof_contention " want " line with unknown_samples"
      if (bad) { print bad; exit 1 }
      print "ok"
    }
  ' "$log"
}

if [[ -n "$CHECK_LOG" ]]; then
  if v="$(contention_verdict "$CHECK_LOG" "$CHECK_NAME")"; then
    echo "contention_check $CHECK_NAME ok: unknown_samples 0 ($CHECK_LOG)"
    exit 0
  fi
  echo "contention_check $CHECK_NAME INVALID: $v ($CHECK_LOG)"
  exit 1
fi

# W25-27 (PO rule 2026-10-31 18:55 KST): a proof can stop with an infrastructure abort. It
# prints "proof_infra_abort PROOF reason=REASON ..." before its own lock and before any build,
# and exits with an abort code (3 now; a distinct code, 4, may come with the proof-lock.sh
# check; ORBLX_SWEEP_ABORT_CODES, default "3 4"). The result is ABORT: not PASS, not FAIL, not
# INVALID. The row stays open until a clean run passes.
# abort_verdict LOG RC prints the reason (exit 0) when the run is an ABORT. It prints why not
# (exit 1) when the log has a proof_infra_abort line but the run is not an ABORT, and prints
# nothing (exit 2) when the log has no proof_infra_abort line.
# Taking the proof lock is not a proof step, but the abort line must come before the proof's
# own proof_lock or proof_context lines and before any cargo "Compiling" line: else a proof
# step can have started, and the run is a FAIL.
ABORT_CODES="${ORBLX_SWEEP_ABORT_CODES:-3 4}"
abort_verdict() {
  local log="$1" rc="$2" name="$3" out code ok=0
  out="$(awk -v mine="rc3-sweep:$name" '
    /^proof_infra_abort / && !line { line = $0; next }
    !line && ($1 == "proof_lock" || $1 == "proof_context") && $2 != mine { step = 1 }
    !line && /^ *Compiling / { step = 1 }
    END {
      if (!line) exit 2
      r = ""
      if (match(line, / reason=[^ .]*/)) r = substr(line, RSTART + 8, RLENGTH - 8)
      if (step) { print "proof_infra_abort after the proof took its lock or started a build"; exit 1 }
      if (r != "disk_low" && r != "disk_unknown") { print "proof_infra_abort with reason \"" r "\" (only disk_low and disk_unknown)"; exit 1 }
      print r
    }' "$log")" || {
    code=$?
    [[ "$code" -eq 2 ]] && return 2
    echo "$out"
    return 1
  }
  for code in $ABORT_CODES; do
    [[ "$rc" == "$code" ]] && ok=1
  done
  if [[ "$ok" -ne 1 ]]; then
    echo "proof_infra_abort but exit $rc (abort codes: $ABORT_CODES)"
    return 1
  fi
  echo "$out"
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
ROWS_TMP="$(mktemp)"
trap 'rm -f "$MANIFEST_TMP" "$ROWS_TMP"' EXIT
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
    row|gate|partial)
      [[ -n "$f1" && -n "$f3" ]] || die "manifest: bad line: $line"
      if [[ "$kind" == partial && "$f3" == "-" ]]; then
        die "manifest: partial row $f1 has no proof (a partial row with no proof is not a sweep row)"
      fi
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

# W25-27: the row status source. Read it, then compare it with the manifest rows.
if [[ -n "${ORBLX_SWEEP_ROWS:-}" ]]; then
  cp "$ORBLX_SWEEP_ROWS" "$ROWS_TMP" || die "cannot read $ORBLX_SWEEP_ROWS"
  ROWS_SRC="$ORBLX_SWEEP_ROWS"
elif [[ -n "$TEST_ROOT" ]]; then
  cp "$ROOT/$ROWS_REL" "$ROWS_TMP" 2>/dev/null || die "rows: no $ROWS_REL in the test root"
  ROWS_SRC="$ROOT/$ROWS_REL"
else
  git -C "$REPO" show "$SHA:$ROWS_REL" >"$ROWS_TMP" 2>/dev/null || die "rows: no $ROWS_REL at $SHORT"
  ROWS_SRC="$ROWS_REL at $SHORT"
fi
# Row ids are numbers, so plain (sparse) arrays keyed by the id work in bash 3.2 (macOS).
ROW_STATUS=()
ROW_NOTE=()
SKIP_MARK='not in rc.3 sweep: no coordinator SSH certs'
SSH_ROWS="40 41"
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" && "$line" != \#* ]] || continue
  IFS='|' read -r rid rstatus _ rnote <<<"$line"
  [[ "$rid" =~ ^[0-9]+$ ]] || die "rows: bad line: $line"
  case "$rstatus" in shipped|partial|missing) ;; *) die "rows: bad status in line: $line" ;; esac
  [[ -z "${ROW_STATUS[$rid]:-}" ]] || die "rows: row $rid is listed twice"
  if [[ -n "$rnote" && "$rnote" != "$SKIP_MARK" ]]; then
    die "rows: row $rid has an unknown 4th field '$rnote' (the only one is '$SKIP_MARK')"
  fi
  if [[ -n "$rnote" && "$rstatus" != partial ]]; then
    die "rows: row $rid is $rstatus and has the skip mark; only a partial row can be skipped"
  fi
  ROW_STATUS[$rid]="$rstatus"
  ROW_NOTE[$rid]="$rnote"
done <"$ROWS_TMP"
[[ "${#ROW_STATUS[@]}" -gt 0 ]] || die "rows: $ROWS_SRC has no rows"
for id in $SSH_ROWS; do
  if [[ "${ROW_STATUS[$id]:-}" == shipped ]]; then
    die "rows: row $id (SSH) claims shipped in $ROWS_SRC; the SSH rows stay partial for rc.3 (no coordinator SSH certs)"
  fi
done
for r in "${!R_ID[@]}"; do
  if [[ "${R_KIND[$r]}" == row && " $SSH_ROWS " == *" ${R_ID[$r]} "* ]]; then
    die "manifest: row ${R_ID[$r]} (SSH) claims shipped ($MANIFEST_SRC); the SSH rows stay partial for rc.3 (no coordinator SSH certs)"
  fi
done
mismatch=""
MAN_ROW=()
for r in "${!R_ID[@]}"; do
  kind="${R_KIND[$r]}"
  [[ "$kind" == gate ]] && continue
  id="${R_ID[$r]}"
  if [[ ! "$id" =~ ^[0-9]+$ ]]; then
    mismatch="${mismatch}${mismatch:+; }row $id: a manifest $kind id must be a number"
    continue
  fi
  [[ -z "${MAN_ROW[$id]:-}" ]] || mismatch="${mismatch}${mismatch:+; }row $id is in the manifest twice"
  MAN_ROW[$id]="$kind"
  want=shipped
  [[ "$kind" == partial ]] && want=partial
  have="${ROW_STATUS[$id]:-not in the rows file}"
  if [[ "$have" != "$want" ]]; then
    mismatch="${mismatch}${mismatch:+; }row $id: manifest $kind, rows file $have"
  fi
done
for id in $(printf '%s\n' "${!ROW_STATUS[@]}" | sort -n); do
  if [[ "${ROW_STATUS[$id]}" == shipped && -z "${MAN_ROW[$id]:-}" ]]; then
    mismatch="${mismatch}${mismatch:+; }row $id: rows file shipped, no manifest row line"
  fi
done
if [[ -n "$mismatch" ]]; then
  die "rows mismatch between the manifest ($MANIFEST_SRC) and the rows file ($ROWS_SRC): $mismatch"
fi
note "rows: the manifest matches $ROWS_SRC"

# Report only (PO, W25-17): nat-realism prints a steady_warn line for a steady ping sample over
# 100 ms. A run is the nat-realism proof log, or one step log section of a proof with step logs
# (the nat-realism runs of sym-throughput). Print "RUNS WARNED" for one proof log.
STEADY_RE='(^|[^[:alnum:]_])steady_warn([^[:alnum:]_]|$)'
steady_warn_runs() {
  local log="$1" name="$2" steps="$3"
  [[ "$name" == nat-realism || -n "$steps" ]] || { echo "0 0"; return 0; }
  awk -v re="$STEADY_RE" -v sections="${steps:+1}" '
    index($0, "=== release_sweep: step log ") == 1 { runs++; cur = runs; next }
    index($0, "release_sweep: ") == 1 { next }
    $0 ~ re { if (sections == "") hit[0] = 1; else if (cur) hit[cur] = 1 }
    END {
      if (sections == "") { print 1, (0 in hit) ? 1 : 0; exit }
      n = 0; for (k in hit) n++
      print runs + 0, n
    }' "$log"
}

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

# W25-27: a proof is skipped only when every row that names it has the skip mark in the rows
# file. A proof that also backs a row without the mark (or a gate) runs.
P_SKIP=()
for i in "${!P_NAME[@]}"; do
  skip=1
  for r in "${!R_ID[@]}"; do
    [[ " ${R_PROOFS[$r]} " == *" ${P_NAME[$i]} "* ]] || continue
    if [[ "${R_KIND[$r]}" == gate || "${ROW_NOTE[${R_ID[$r]}]:-}" != "$SKIP_MARK" ]]; then
      skip=0
    fi
  done
  P_SKIP+=("$skip")
  if [[ "$skip" == 1 ]]; then
    note "skip: proof ${P_NAME[$i]} (rows $(for r in "${!R_ID[@]}"; do [[ " ${R_PROOFS[$r]} " == *" ${P_NAME[$i]} "* ]] && printf '%s ' "${R_ID[$r]}"; done)): $SKIP_MARK"
  fi
done
for want in $ONLY; do
  proof_index "$want" >/dev/null || die "unknown proof $want"
done

# A partial row shows its status next to its number.
row_label() {
  if [[ "${R_KIND[$1]}" == partial ]]; then
    echo "${R_ID[$1]} (partial)"
  else
    echo "${R_ID[$1]}"
  fi
}

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
# W25-27: old-binary pins. P_PIN[i] is the pinned SHA of proof i, or "-".
script_text() {
  if [[ -n "$TEST_ROOT" ]]; then
    cat "$ROOT/$1" 2>/dev/null
  else
    git -C "$REPO" show "$SHA:$1" 2>/dev/null
  fi
}
P_PIN=()
OLD_PINS=""
for i in "${!P_NAME[@]}"; do
  pin="-"
  envs="${P_ENV[$i]}"
  if [[ "$envs" == *"@OLD:"* ]]; then
    [[ "$envs" =~ OLD_ORBLX=@OLD:([^@ ]*)@ ]] ||
      die "manifest: proof ${P_NAME[$i]}: an @OLD:...@ pin must be the value of OLD_ORBLX (OLD_ORBLX=@OLD:<full sha>@)"
    pin="${BASH_REMATCH[1]}"
    [[ "$pin" =~ ^[0-9a-f]{40}$ ]] ||
      die "manifest: proof ${P_NAME[$i]}: bad old-binary pin '$pin' (a full 40-hex commit SHA)"
    if [[ -z "$TEST_ROOT" ]]; then
      git -C "$REPO" cat-file -e "$pin^{commit}" 2>/dev/null ||
        die "manifest: proof ${P_NAME[$i]}: old-binary pin $pin is not a commit here"
      git -C "$REPO" merge-base --is-ancestor "$pin" "$SHA" ||
        die "manifest: proof ${P_NAME[$i]}: old-binary pin $pin is not an ancestor of $SHORT"
    fi
    [[ " $OLD_PINS " == *" $pin "* ]] || OLD_PINS="${OLD_PINS:+$OLD_PINS }$pin"
  fi
  if [[ "$pin" == "-" ]] && script_text "${P_PATH[$i]}" | has_line 'OLD_ORBLX:[?]'; then
    die "manifest: proof ${P_NAME[$i]} needs OLD_ORBLX (its script requires it), and its manifest line has no OLD_ORBLX=@OLD:<full sha>@ pin"
  fi
  P_PIN+=("$pin")
done
old_bin_of() { echo "$WORK/old-orblx/$1/orblx"; }
# The label of an old build comes from git (rev-parse and the tag name), never from
# "orblx --version": a dev build can print a release version.
old_label_of() {
  local sha tag
  sha="$(git -C "$REPO" rev-parse --verify -q "$1^{commit}" 2>/dev/null)" || sha="$1"
  tag="$(git -C "$REPO" tag --points-at "$sha" 2>/dev/null)" || tag=""
  tag="${tag%%$'\n'*}"
  echo "commit $sha tag ${tag:-none}"
}
old_step_of() {
  if [[ -n "$OLD_ENV" ]]; then
    echo "OLD_ORBLX from the environment: $OLD_ENV (no build)"
  elif [[ -x "$(old_bin_of "$1")" ]]; then
    echo "old binary cached: $(old_bin_of "$1") ($(old_label_of "$1"))"
  else
    echo "build old orblx (debug) at $1 in a temp worktree, cache $(old_bin_of "$1")"
  fi
}

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
        if [[ "${P_SKIP[$i]}" == 1 ]]; then
          have="skipped: $SKIP_MARK"
        elif script_at "${P_PATH[$i]}"; then
          have="${P_PATH[$i]}"
        else
          have="FAIL: no ${P_PATH[$i]}"
          bad=1
          bad_rows="${bad_rows:+$bad_rows, }${R_ID[$r]}"
        fi
        echo "| $(row_label "$r") | $(cell "${R_FEAT[$r]}") | $p | $have |"
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
    if [[ -n "$OLD_PINS" ]]; then
      echo
      echo "| proof | old-binary step |"
      echo "|---|---|"
      for i in "${!P_NAME[@]}"; do
        [[ "${P_PIN[$i]}" != "-" ]] || continue
        echo "| ${P_NAME[$i]} | $(old_step_of "${P_PIN[$i]}") |"
      done
    fi
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

# Free disk space. A proof that fails from a full disk is a box failure, and such a run never
# counts. So the run does not start with less than ORBLX_SWEEP_MIN_FREE_GB free.
MIN_FREE_GB="${ORBLX_SWEEP_MIN_FREE_GB:-30}"
[[ "$MIN_FREE_GB" =~ ^[0-9]+$ ]] || die "ORBLX_SWEEP_MIN_FREE_GB must be a whole number of GB"
free_gb_of() {
  local dir="$1" text
  while [[ ! -d "$dir" ]]; do dir="$(dirname "$dir")"; done
  text="$(df -Pk "$dir")" || return 1
  awk 'NR == 2 {kb = $4} END {if (kb == "") exit 1; printf "%d\n", kb / 1048576}' <<<"$text"
}
for disk_dir in "$ROOT" "$OUT"; do
  free_gb="$(free_gb_of "$disk_dir")" || die "cannot read the free disk space of $disk_dir"
  note "disk: $free_gb GB free at $disk_dir, the run needs $MIN_FREE_GB GB"
  if [[ "$free_gb" -lt "$MIN_FREE_GB" ]]; then
    die "disk FAIL: only $free_gb GB free at $disk_dir; the sweep needs at least $MIN_FREE_GB GB free before it starts. A run that fails from a full disk never counts. Nothing ran."
  fi
done

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

# W25-27: the old binaries of the pins of the proofs that run.
if [[ -n "$OLD_ENV" ]]; then
  [[ -x "$OLD_ENV" ]] || die "OLD_ORBLX=$OLD_ENV is not an executable file"
  note "old binary: OLD_ORBLX from the environment: $OLD_ENV (no build)"
fi
for pin in $OLD_PINS; do
  [[ -z "$OLD_ENV" && -z "$TEST_ROOT" ]] || break
  need=0
  for i in "${!P_NAME[@]}"; do
    [[ "${P_PIN[$i]}" == "$pin" && "${P_SKIP[$i]}" != 1 ]] || continue
    [[ -z "$ONLY" || " $ONLY " == *" ${P_NAME[$i]} "* ]] || continue
    need=1
  done
  [[ "$need" == 1 ]] || continue
  old_bin="$(old_bin_of "$pin")"
  if [[ -x "$old_bin" ]]; then
    note "old binary cached: $old_bin ($(old_label_of "$pin"))"
    continue
  fi
  old_wt="$WORK/old-${pin:0:12}-wt"
  old_target="$WORK/old-${pin:0:12}-target"
  old_log="$OUT/rc3-sweep-$SHORT-old-${pin:0:12}-build.log"
  note "build old orblx at $pin ($(old_label_of "$pin")), worktree $old_wt, target $old_target, log $old_log"
  mkdir -p "$WORK"
  as_root rm -rf "$old_target"
  git -C "$REPO" worktree remove --force "$old_wt" 2>/dev/null || true
  rc=0
  git -C "$REPO" worktree add -q --detach "$old_wt" "$pin" >"$old_log" 2>&1 || rc=$?
  if [[ "$rc" == 0 ]]; then
    tool_env CARGO_TARGET_DIR="$old_target" bash -c '
        set -euo pipefail
        cd "$1"
        echo "old_build $4"
        git rev-parse HEAD
        rustc --version
        cargo build --locked -p orblx-cli --bin orblx
        mkdir -p "$(dirname "$3")"
        cp "$2/debug/orblx" "$3.tmp"
        mv -f "$3.tmp" "$3"
      ' release-sweep-old-build "$old_wt" "$old_target" "$old_bin" "$(old_label_of "$pin")" >>"$old_log" 2>&1 </dev/null || rc=$?
  fi
  as_root rm -rf "$old_target" || true
  git -C "$REPO" worktree remove --force "$old_wt" >/dev/null 2>&1 || true
  if [[ "$rc" != 0 || ! -x "$old_bin" ]]; then
    note "old build FAIL: $(first_error "$old_log")"
    {
      echo "| row | feature | proof | result | log | time | proof_contention |"
      echo "|---|---|---|---|---|---|---|"
      echo "| - | old orblx $pin | - | FAIL: $(first_error "$old_log") | $old_log | - | - |"
    } >"$TABLE"
    cleanup_worktree
    exit 2
  fi
  note "old binary ok: $old_bin ($(old_label_of "$pin"), worktree and target removed)"
done

# 5. Run each proof once.
P_RESULT=(); P_LOG=(); P_TIME=(); P_CONT=(); P_ABORT=()
for i in "${!P_NAME[@]}"; do
  P_RESULT+=("pending"); P_LOG+=("-"); P_TIME+=("-"); P_CONT+=("-")
done

write_table() {
  local r p i failed_rows="" invalid_rows="" aborted_rows="" res why
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
      why=""
      for p in ${R_PROOFS[$r]}; do
        i="$(proof_index "$p")"
        echo "| $(row_label "$r") | $(cell "${R_FEAT[$r]}") | $p | ${P_RESULT[$i]} | ${P_LOG[$i]} | ${P_TIME[$i]} | ${P_CONT[$i]} |"
        [[ "${P_RESULT[$i]}" == FAIL* ]] && res=fail
        [[ "$res" != fail && "${P_RESULT[$i]}" == INVALID* ]] && res=invalid
        if [[ "${P_RESULT[$i]}" == ABORT* ]]; then
          [[ "$res" == ok ]] && res=abort
          why="${why:+$why, }$p: ${P_ABORT[$i]:-}"
        fi
      done
      if [[ "$res" == fail ]]; then
        failed_rows="${failed_rows:+$failed_rows, }${R_ID[$r]}"
      elif [[ "$res" == invalid ]]; then
        invalid_rows="${invalid_rows:+$invalid_rows, }${R_ID[$r]}"
      elif [[ "$res" == abort ]]; then
        aborted_rows="${aborted_rows:+$aborted_rows, }${R_ID[$r]} ($why)"
      fi
    done
    echo
    echo "Failed rows: ${failed_rows:-none}."
    echo "Invalid rows (the contention probe did not report unknown_samples 0; they do not count): ${invalid_rows:-none}."
    echo "Aborted rows (proof_infra_abort before any proof step; the row stays open until a clean run passes): ${aborted_rows:-none}."
  } >"$TABLE"
  FAILED_ROWS="$failed_rows"
  INVALID_ROWS="$invalid_rows"
  ABORTED_ROWS="$aborted_rows"
}

LOCK_MODE="${ORBLX_SWEEP_LOCK_MODE:-proof}"
case "$LOCK_MODE" in
  proof) ;;
  sweep)
    # One hold for all the proofs. The wrapper of each proof sees ORBLX_PROOF_LOCK_HELD.
    # shellcheck source=proof-lock.sh
    . "$LOCK_LIB"
    trap 'proof_lock_end; rm -f "$MANIFEST_TMP" "$ROWS_TMP"' EXIT
    note "lock mode sweep: wait for the lock"
    proof_lock_take "rc3-sweep:$SHORT" orblx-rc3sw-
    note "lock mode sweep: lock taken $(now)"
    ;;
  *) die "ORBLX_SWEEP_LOCK_MODE must be proof or sweep" ;;
esac

FAILED_ROWS=""
INVALID_ROWS=""
ABORTED_ROWS=""
STEADY_RUNS=0
STEADY_WARNED=0
failed=0
invalid=0
aborted=0
ran=0
not_run=0
skipped=0
write_table
for i in "${!P_NAME[@]}"; do
  name="${P_NAME[$i]}"
  path="${P_PATH[$i]}"
  if [[ "${P_SKIP[$i]}" == 1 ]]; then
    P_RESULT[$i]="skipped ($SKIP_MARK)"
    skipped=$((skipped + 1))
    note "proof $name skipped: $SKIP_MARK"
    continue
  fi
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
    words="${P_ENV[$i]//@BIN@/$BIN}"
    if [[ "${P_PIN[$i]}" != "-" ]]; then
      if [[ -n "$OLD_ENV" ]]; then
        words="${words//@OLD:${P_PIN[$i]}@/$OLD_ENV}"
      else
        words="${words//@OLD:${P_PIN[$i]}@/$(old_bin_of "${P_PIN[$i]}")}"
      fi
    fi
    read -r -a env_words <<<"$words"
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
  # W25-35 (proof-lock.sh): when unknown_samples is more than 0, proof_lock_end prints a
  # "proof_contention_invalid LABEL ..." line and exits 3. A proof that gave its pass line and
  # then stopped only for that reason is INVALID (its contention is not known), not FAIL.
  probe_exit=0
  if [[ "$rc" -eq 3 ]] && has_line '^proof_contention_invalid ' <"$log"; then
    probe_exit=1
  fi
  abort_rc=0
  abort_why="$(abort_verdict "$log" "$rc" "$name")" || abort_rc=$?
  P_ABORT[$i]=""
  if [[ "$abort_rc" -eq 0 ]]; then
    result="ABORT (infrastructure, reason=$abort_why, exit $rc): $(awk '/^proof_infra_abort / {print; exit}' "$log")"
    P_ABORT[$i]="$abort_why"
    aborted=$((aborted + 1))
  elif [[ "$abort_rc" -eq 1 ]]; then
    failed=$((failed + 1))
    result="FAIL (exit $rc): $abort_why"
  elif [[ "$rc" -eq 0 || "$probe_exit" -eq 1 ]] && has_line "$ok_re" <"$log" \
    && ! verdict="$(contention_verdict "$log" "$name")"; then
    result="INVALID: proof_ok but $verdict"
    invalid=$((invalid + 1))
  elif [[ "$rc" -eq 0 ]] && has_line "$ok_re" <"$log"; then
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
  read -r s_runs s_warned <<<"$(steady_warn_runs "$log" "$name" "${P_STEPS[$i]}")" || true
  STEADY_RUNS=$((STEADY_RUNS + ${s_runs:-0}))
  STEADY_WARNED=$((STEADY_WARNED + ${s_warned:-0}))
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
  echo "Proofs run: $ran. Failed proofs: $failed. Invalid proofs: $invalid. Aborted proofs: $aborted. Not run: $not_run. Skipped (rows file mark): $skipped. Total time: ${total} s ($((total / 60)) min $((total % 60)) s). Ended $(date '+%Y-%m-%d %H:%M:%S %Z')."
  if [[ "$not_run" -gt 0 ]]; then
    echo "Partial run (ORBLX_SWEEP_ONLY): it does not count."
  fi
  if [[ "$STEADY_RUNS" -gt 0 ]]; then
    STEADY_PCT="$(awk -v w="$STEADY_WARNED" -v n="$STEADY_RUNS" 'BEGIN {printf "%.1f", 100 * w / n}')"
    echo "steady_warn: $STEADY_WARNED of $STEADY_RUNS nat-realism runs have a steady_warn line (${STEADY_PCT}%). Report only."
    if [[ $((STEADY_WARNED * 100)) -gt "$STEADY_RUNS" ]]; then
      echo "steady_warn_rate over 1%: root-cause item ($STEADY_WARNED of $STEADY_RUNS nat-realism runs, ${STEADY_PCT}%). This does not fail the sweep."
    fi
  else
    echo "steady_warn: no nat-realism run in this sweep."
  fi
} >>"$TABLE"
note "end $(now) proofs $ran failed $failed invalid $invalid invalid_rows ${INVALID_ROWS:-none} aborted $aborted aborted_rows ${ABORTED_ROWS:-none} not_run $not_run failed_rows ${FAILED_ROWS:-none} total_secs $total table $TABLE"
cat "$TABLE"
if [[ -n "$FAILED_ROWS" || -n "$INVALID_ROWS" || -n "$ABORTED_ROWS" ]]; then
  exit 1
fi
if [[ "$not_run" -gt 0 ]]; then
  exit 3
fi
exit 0

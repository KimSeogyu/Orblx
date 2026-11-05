#!/usr/bin/env bash
# Run test_proof_lock.ProofLockTest.test_two_proofs_run_one_after_the_other N times.
# Usage: scripts/loop-proof-lock-test.sh [N] [LOG_DIR]
# N defaults to 50. LOG_DIR defaults to /workspace/orblx-w18-proof/.
# The loop always runs N iterations. It does not stop early. A run with no
# output counts as a failure (it is not a pass).
# Disk: compile the two Python modules once into LOG_DIR/build and reuse that
# for every run. One short line per run. A failure also writes a short excerpt.
# Each run uses its own TMPDIR, which is removed after the run, along with any
# containers that appeared during that run.
set -euo pipefail

N="${1:-50}"
LOG_DIR="${2:-/workspace/orblx-w18-proof/}"

if ! [[ "$N" =~ ^[1-9][0-9]*$ ]]; then
  echo "loop-proof-lock-test: N must be a positive integer, got ${N}" >&2
  exit 2
fi

# Measured peak of build + logs + one run's TMPDIR: 2248 KiB (Python 3.12,
# pyc cache of this test and the stdlib modules it imports, reused for every
# later run). 3072 KiB is the free space the script needs before it starts.
MIN_FREE_KIB=3072

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$ROOT/scripts/proof/tests"
BUILD_DIR="$LOG_DIR/build"
FAIL_DIR="$LOG_DIR/failures"
LOG_FILE="$LOG_DIR/loop.log"

free_kib() {
  df -Pk "$1" | awk 'NR == 2 { print $4 }'
}

mkdir -p "$LOG_DIR"
free="$(free_kib "$LOG_DIR")"
if ! [[ "$free" =~ ^[0-9]+$ ]]; then
  echo "loop-proof-lock-test: cannot read free space for ${LOG_DIR}. Stop." >&2
  exit 1
fi
if (( free < MIN_FREE_KIB )); then
  echo "loop-proof-lock-test: free space on ${LOG_DIR} is ${free} KiB, need at least ${MIN_FREE_KIB} KiB for the build directory, the logs, and one run. Stop." >&2
  exit 1
fi

mkdir -p "$BUILD_DIR/pyc" "$FAIL_DIR"
if [[ ! -f "$BUILD_DIR/stamp" ]]; then
  PYTHONPYCACHEPREFIX="$BUILD_DIR/pyc" python3 -m compileall -q \
    "$TEST_DIR/test_proof_lock.py" \
    "$TEST_DIR/fake_docker.py"
  printf '%s\n' "test_proof_lock.ProofLockTest.test_two_proofs_run_one_after_the_other" >"$BUILD_DIR/stamp"
fi

container_ids() {
  if ! command -v docker >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
    return 0
  fi
  timeout 5 docker ps -aq 2>/dev/null || true
}

disk_kib() {
  # $1 is an optional extra directory (the live TMPDIR). Build and logs only
  # when no extra path is given.
  du -sk "$@" 2>/dev/null | awk '{ s += $1 } END { print s + 0 }'
}

peak_extra=0
note_disk() {
  local used="$1"
  if (( used > peak_extra )); then
    peak_extra=$used
  fi
}

# Build dir is reused. Count it from the start.
note_disk "$(disk_kib "$BUILD_DIR")"

failures=0
: >"$LOG_FILE"

for ((i = 1; i <= N; i++)); do
  run_tmp="$(mktemp -d "$LOG_DIR/tmp.XXXXXX")"
  run_out="$run_tmp/out.txt"
  before="$(container_ids | sort -u || true)"
  start_s=$(date +%s)
  set +e
  (
    cd "$TEST_DIR"
    PYTHONPYCACHEPREFIX="$BUILD_DIR/pyc" \
      TMPDIR="$run_tmp" \
      python3 -m unittest test_proof_lock.ProofLockTest.test_two_proofs_run_one_after_the_other
  ) >"$run_out" 2>&1
  rc=$?
  set -e
  end_s=$(date +%s)
  elapsed=$((end_s - start_s))
  # Temp files are still on disk here. That is the peak for this run.
  note_disk "$(disk_kib "$BUILD_DIR" "$LOG_FILE" "$FAIL_DIR" "$run_tmp")"
  bytes=$(wc -c <"$run_out" | tr -d ' ')
  if [[ "$rc" -eq 0 && "$bytes" -gt 0 ]]; then
    result=pass
    printf 'run=%s result=pass seconds=%s\n' "$i" "$elapsed" >>"$LOG_FILE"
  else
    result=fail
    failures=$((failures + 1))
    excerpt="$FAIL_DIR/run-${i}.txt"
    if [[ "$bytes" -eq 0 ]]; then
      printf 'no output, exit %s\n' "$rc" >"$excerpt"
    else
      # Failure-only excerpt. Cap it so one bad run cannot fill the disk.
      # No pipe: a pipe into head fails the early-reader check.
      python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); t="\n".join(p.read_text(errors="replace").splitlines()[-40:])+"\n"; pathlib.Path(sys.argv[2]).write_text(t[:8192])' "$run_out" "$excerpt"
    fi
    printf 'run=%s result=fail seconds=%s excerpt=%s\n' "$i" "$elapsed" "$excerpt" >>"$LOG_FILE"
  fi
  after="$(container_ids | sort -u || true)"
  if [[ -n "$after" ]]; then
    new_ids="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") || true)"
    if [[ -n "$new_ids" ]]; then
      # shellcheck disable=SC2086
      timeout 15 docker rm -f $new_ids >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$run_tmp"
  note_disk "$(disk_kib "$BUILD_DIR" "$LOG_FILE" "$FAIL_DIR")"
done

printf 'peak_extra_kib=%s\n' "$peak_extra" >>"$LOG_FILE"
printf 'min_free_kib=%s\n' "$MIN_FREE_KIB" >>"$LOG_FILE"
printf 'runs=%s failures=%s\n' "$N" "$failures" >>"$LOG_FILE"
cat "$LOG_FILE"
if (( failures > 0 )); then
  exit 1
fi

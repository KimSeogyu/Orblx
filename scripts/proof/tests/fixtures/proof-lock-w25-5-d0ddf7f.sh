# shellcheck shell=bash
# W25-5 box proof lock.
# Source this file. Then call: proof_lock_take LABEL [OWN_NAME_PREFIX ...]
# Every proof that runs the RTT or throughput gates takes one lock for the whole host,
# so that these proofs run one at a time. The lock waits. It does not fail.
# While it waits, it prints the holder every ORBLX_PROOF_LOCK_NOTE_SECS seconds (default 30).
# At the start and at the end, it prints a proof_context line: the host load average and the
# number of other running orblx containers. A sampler counts them every ORBLX_PROOF_SAMPLE_SECS
# seconds (default 2) during the run, and the end line gives the maximum.
# When docker ps fails, the count is "unknown" (unknown_samples in the end line).
# Env:
#   ORBLX_PROOF_LOCK       lock file. Default /workspace/.orblx-proof.lock when /workspace is
#                          a writable directory, else ${TMPDIR:-/tmp}/orblx-proof.lock.
#   ORBLX_PROOF_LOCK_HELD  the holder sets it to its pid. A child proof (perf-watch.sh runs
#                          nat-realism.sh) then does not take the lock again. The child checks
#                          that this pid is the pid in the holder file and that it runs.
# The lock uses flock(1). Without flock (macOS), the proof runs without the lock and says so.
# The script must call proof_lock_end in its EXIT trap.

PROOF_LOCK_FD=9
PROOF_LOCK_OWNER=0
PROOF_LOCK_LABEL=""
PROOF_LOCK_OWN=()
PROOF_LOCK_SAMPLER=""
PROOF_LOCK_SAMPLES=""

proof_lock_file() {
  if [[ -n "${ORBLX_PROOF_LOCK:-}" ]]; then
    printf '%s\n' "$ORBLX_PROOF_LOCK"
  elif [[ -d /workspace && -w /workspace ]]; then
    printf '%s\n' /workspace/.orblx-proof.lock
  else
    printf '%s\n' "${TMPDIR:-/tmp}/orblx-proof.lock"
  fi
}

proof_lock_now() {
  date '+%Y-%m-%dT%H:%M:%S.%3N%z'
}

proof_lock_ms() {
  date +%s%3N
}

# Print the running orblx container names that do not belong to this proof.
# Return 2 when docker ps fails (then the count is not known).
proof_lock_others() {
  local names name own mine
  names="$(docker ps --format '{{.Names}}' 2>/dev/null)" || return 2
  while IFS= read -r name; do
    [[ "$name" == orblx-* ]] || continue
    mine=0
    for own in "${PROOF_LOCK_OWN[@]}"; do
      if [[ -n "$own" && "$name" == "$own"* ]]; then
        mine=1
      fi
    done
    if [[ "$mine" == "0" ]]; then
      printf '%s\n' "$name"
    fi
  done <<<"$names"
  return 0
}

proof_lock_load() {
  cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || uptime | sed 's/.*load averages*: *//; s/,//g'
}

# proof_context PHASE: one line with the time, the load average and the other orblx containers.
proof_context() {
  local phase="$1" others count groups
  if ! others="$(proof_lock_others)"; then
    count=unknown
    groups="-"
  elif [[ -z "$others" ]]; then
    count=0
    groups="-"
  else
    count="$(printf '%s\n' "$others" | wc -l | tr -d ' ')"
    # Group the names by their first two words, for example orblx-w25a.
    groups="$(printf '%s\n' "$others" | cut -d- -f1-2 | sort | uniq -c | awk '{printf "%s%s:%s", sep, $2, $1; sep=","}')"
  fi
  echo "proof_context ${PROOF_LOCK_LABEL} phase ${phase} time $(proof_lock_now) load $(proof_lock_load | tr ' ' '/') other_orblx_containers ${count} groups ${groups}"
}

proof_lock_holder() {
  local file="$1"
  local pid
  if [[ -s "${file}.holder" ]]; then
    tr '\n' ' ' <"${file}.holder"
    # The record can be stale for a moment: a killed holder leaves it, and
    # the new holder writes it just after flock returns.
    pid="$(sed -n 's/^pid=//p' "${file}.holder" 2>/dev/null)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null && [[ ! -d "/proc/$pid" ]]; then
      printf '(stale record, pid not running)'
    fi
  else
    printf 'unknown'
  fi
}

# True when ORBLX_PROOF_LOCK_HELD names a running process that the holder file names.
proof_lock_parent_holds() {
  local file="$1" pid="${ORBLX_PROOF_LOCK_HELD:-}"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  grep -qx "pid=${pid}" "${file}.holder" 2>/dev/null || return 1
  kill -0 "$pid" 2>/dev/null
}

proof_lock_sample_loop() {
  local parent="$1" out="$2" interval="$3" others count
  while kill -0 "$parent" 2>/dev/null; do
    if ! others="$(proof_lock_others)"; then count=-1; elif [[ -z "$others" ]]; then count=0; else count="$(printf '%s\n' "$others" | wc -l | tr -d ' ')"; fi
    echo "$(proof_lock_ms) ${count} $(proof_lock_load | cut -d' ' -f1)" >>"$out"
    sleep "$interval"
  done
}

proof_lock_take() {
  PROOF_LOCK_LABEL="$1"
  shift
  PROOF_LOCK_OWN=("$@")
  local file waited_from note
  file="$(proof_lock_file)"
  note="${ORBLX_PROOF_LOCK_NOTE_SECS:-30}"
  proof_context queued
  if proof_lock_parent_holds "$file"; then
    echo "proof_lock ${PROOF_LOCK_LABEL} held by the parent proof, file ${file}"
  elif ! command -v flock >/dev/null 2>&1; then
    echo "proof_lock ${PROOF_LOCK_LABEL} no flock on this host, the proof runs without the lock"
  else
    # The lock file must be writable by every user that runs a proof.
    if [[ ! -e "$file" ]]; then
      (umask 000 && : >>"$file")
    fi
    eval "exec ${PROOF_LOCK_FD}>>\"\$file\""
    waited_from="$(proof_lock_ms)"
    if ! flock -n "$PROOF_LOCK_FD"; then
      echo "proof_lock ${PROOF_LOCK_LABEL} waiting at $(proof_lock_now), file ${file}, holder: $(proof_lock_holder "$file")"
      until flock -w "$note" "$PROOF_LOCK_FD"; do
        echo "proof_lock ${PROOF_LOCK_LABEL} still waiting at $(proof_lock_now), holder: $(proof_lock_holder "$file")"
      done
    fi
    PROOF_LOCK_OWNER=1
    export ORBLX_PROOF_LOCK_HELD="$$"
    {
      echo "label=${PROOF_LOCK_LABEL}"
      echo "pid=$$"
      echo "user=$(id -un)"
      echo "cwd=$(pwd)"
      echo "since=$(proof_lock_now)"
    } >"${file}.holder.$$" 2>/dev/null || true
    chmod 0666 "${file}.holder.$$" 2>/dev/null || true
    # A waiter must never read a half-written holder file.
    mv -f "${file}.holder.$$" "${file}.holder" 2>/dev/null || true
    echo "proof_lock ${PROOF_LOCK_LABEL} acquired at $(proof_lock_now) after $(( $(proof_lock_ms) - waited_from )) ms, file ${file}"
  fi
  proof_context start
  PROOF_LOCK_SAMPLES="$(mktemp)"
  # The sampler is not a job of the proof shell: a proof that calls "wait" with no argument
  # must not wait for it. The sampler also closes the lock fd, so it cannot keep the lock.
  # It stops by itself when the proof shell ends.
  local pid_file
  pid_file="$(mktemp)"
  eval "( proof_lock_sample_loop $$ \"\$PROOF_LOCK_SAMPLES\" \"\${ORBLX_PROOF_SAMPLE_SECS:-2}\" </dev/null >/dev/null 2>&1 & echo \$! >\"\$pid_file\" ) ${PROOF_LOCK_FD}>&-"
  PROOF_LOCK_SAMPLER="$(cat "$pid_file")"
  rm -f "$pid_file"
}

# Call in the EXIT trap. It prints the end context and the sampler maximum, then releases the lock.
proof_lock_end() {
  [[ -n "$PROOF_LOCK_LABEL" ]] || return 0
  if [[ -n "$PROOF_LOCK_SAMPLER" ]]; then
    kill "$PROOF_LOCK_SAMPLER" 2>/dev/null || true
    PROOF_LOCK_SAMPLER=""
  fi
  proof_context end
  if [[ -n "$PROOF_LOCK_SAMPLES" && -f "$PROOF_LOCK_SAMPLES" ]]; then
    awk -v label="$PROOF_LOCK_LABEL" '
      { n++; if ($2 < 0) unknown++; if ($2 > 0) busy++; if ($2 > maxc) maxc = $2; if ($3 > maxl) maxl = $3 }
      END { printf "proof_contention %s samples %d contended_samples %d unknown_samples %d max_other_orblx_containers %d max_load1 %s\n", label, n, busy + 0, unknown + 0, maxc + 0, (n ? maxl : "-") }
    ' "$PROOF_LOCK_SAMPLES"
    rm -f "$PROOF_LOCK_SAMPLES"
    PROOF_LOCK_SAMPLES=""
  fi
  if [[ "$PROOF_LOCK_OWNER" == "1" ]]; then
    flock -u "$PROOF_LOCK_FD" 2>/dev/null || true
    eval "exec ${PROOF_LOCK_FD}>&-"
    PROOF_LOCK_OWNER=0
    echo "proof_lock ${PROOF_LOCK_LABEL} released at $(proof_lock_now)"
  fi
  PROOF_LOCK_LABEL=""
}

# shellcheck shell=bash
# W25-5 box proof lock.
# Source this file. Then call: proof_lock_take LABEL [OWN_COMPOSE_PROJECT ...]
# Every proof that runs the RTT or throughput gates takes one lock for the whole host,
# so that these proofs run one at a time. The lock waits. It does not fail.
# W25-14: the waiters take the lock in arrival order (a ticket queue next to the lock file).
# While it waits, it prints the wait time in s, the queue position, and the holder at once and
# then every ORBLX_PROOF_LOCK_NOTE_SECS seconds (default 30).
# At the start and at the end, it prints a proof_context line: the host load average and the
# number of other running orblx containers. A sampler counts them every ORBLX_PROOF_SAMPLE_SECS
# seconds (default 2) during the run, and the end line gives the maximum.
# When docker ps fails, the count is "unknown" (unknown_samples in the end line).
# W25-35: the proof user often cannot use the docker socket (the proofs use "sudo -n docker").
# Thus, when "docker ps" fails and the user is not root, the count uses "sudo -n docker ps".
# When unknown_samples is more than 0, the contention of the run is not known:
# proof_lock_end prints "proof_contention_invalid LABEL unknown_samples N samples M" after the
# proof_contention line, releases the lock, and stops the script with exit status 3.
# Env:
#   ORBLX_PROOF_LOCK       lock file. Default /workspace/.orblx-proof.lock when /workspace is
#                          a writable directory, else ${TMPDIR:-/tmp}/orblx-proof.lock.
#   ORBLX_PROOF_LOCK_HELD  the holder sets it to its pid. A child proof (perf-watch.sh runs
#                          nat-realism.sh) then does not take the lock again. The child checks
#                          that this pid is the pid in the holder file and that it runs.
# The lock uses flock(1). Without flock (macOS), the proof runs without the lock and says so.
# The script must call proof_lock_end in its EXIT trap.
# proof_lock_end prints "proof_lock LABEL released at TIME pid=PID". When SIGKILL
# skips the trap, the next proof_lock_take prints the same form with
# reason=killed_holder_cleared_by_next for the dead holder pid (W25-46).
# W25-19: a proof from an old checkout takes the lock file with a plain flock. While a FIFO
# proof runs or waits first in the queue, a keeper process holds that flock, so the old
# proof cannot pass the queue. The FIFO proofs take turns on a second lock, "${file}.fifo".
# A proof that runs under a plain flock of the lock file (for example "flock FILE proof.sh")
# stops at once with a message: it must use proof_lock_take.

# W25-27: the lab-ticket guard (ticket-guard.sh) comes with the lock.
# shellcheck source=scripts/proof/ticket-guard.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ticket-guard.sh"

PROOF_LOCK_FD=9
PROOF_LOCK_OWNER=0
PROOF_LOCK_LABEL=""
PROOF_LOCK_OWN=()
PROOF_LOCK_OWN_FILE=""
PROOF_LOCK_SAMPLER=""
PROOF_LOCK_SAMPLES=""
PROOF_LOCK_TICKET=""
# The keeper runs this file, so it needs the full path.
PROOF_LOCK_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
# The ticket line that tells the keeper that a waiter uses the W25-19 protocol.
PROOF_LOCK_PROTO="proto=fifo-keeper"

proof_lock_file() {
  if [[ -n "${ORBLX_PROOF_LOCK:-}" ]]; then
    printf '%s\n' "$ORBLX_PROOF_LOCK"
  elif [[ -d /workspace && -w /workspace ]]; then
    printf '%s\n' /workspace/.orblx-proof.lock
  else
    printf '%s\n' "${TMPDIR:-/tmp}/orblx-proof.lock"
  fi
}

# GNU date prints nine digits for %N. BSD date (macOS) prints the letter N.
# The check runs once. Linux then uses the same date commands as before.
PROOF_DATE_NS=""
proof_date_has_ns() {
  if [[ -z "$PROOF_DATE_NS" ]]; then
    if [[ "$(date +%N 2>/dev/null || true)" =~ ^[0-9]{9}$ ]]; then
      PROOF_DATE_NS=1
    else
      PROOF_DATE_NS=0
    fi
  fi
  [[ "$PROOF_DATE_NS" == "1" ]]
}

# One clock helper for GNU date and BSD date.
# ms: milliseconds since the epoch (GNU: date +%s%3N).
# ns: seconds plus nine nanosecond digits (GNU: date +%s%N).
# now: local time with milliseconds (GNU: date +%Y-%m-%dT%H:%M:%S.%3N%z).
proof_date_ns() {
  if proof_date_has_ns; then
    case "$1" in
      ms) date +%s%3N ;;
      ns) date +%s%N ;;
      now) date '+%Y-%m-%dT%H:%M:%S.%3N%z' ;;
      *) return 1 ;;
    esac
    return
  fi
  case "$1" in
    ms) python3 -c 'import time; print(int(time.time() * 1000))' ;;
    ns) python3 -c 'import time
t = time.time()
sec = int(t)
ns = int((t - sec) * 1000000000)
if ns < 0:
    ns = 0
if ns > 999999999:
    ns = 999999999
print("%d%09d" % (sec, ns))' ;;
    now) python3 -c 'import time
t = time.time()
ms = int(t * 1000) % 1000
local = time.localtime(t)
print(time.strftime("%Y-%m-%dT%H:%M:%S", local) + ".%03d" % ms + time.strftime("%z", local))' ;;
    *) return 1 ;;
  esac
}

proof_lock_now() {
  proof_date_ns now
}

proof_lock_ms() {
  proof_date_ns ms
}

# W25-46: a container belongs to this proof when its compose project label
# (com.docker.compose.project) is exactly one of the OWN_COMPOSE_PROJECT words of
# proof_lock_take. A name prefix is never used: a prefix can match a foreign container
# (orblx-ssh is a prefix of orblx-ssh-renew). A proof that starts a container with
# "docker run" gives it the label "com.docker.compose.project=<own project>".
# The proof that holds the lock also owns the projects of its child proofs (a child under
# ORBLX_PROOF_LOCK_HELD writes its projects to ORBLX_PROOF_OWN_FILE).
# Print one "NAME<TAB>PROJECT" line for each running container.
# Return 2 when docker ps fails (then the count is not known).
PROOF_LOCK_PS_FORMAT='{{.Names}}	{{.Label "com.docker.compose.project"}}'
proof_lock_docker_names() {
  docker ps --format "$PROOF_LOCK_PS_FORMAT" 2>/dev/null && return 0
  [[ "$(id -u)" != "0" ]] || return 2
  sudo -n docker ps --format "$PROOF_LOCK_PS_FORMAT" 2>/dev/null || return 2
}

# Print the own projects: the words of proof_lock_take, and (for the holder) the child projects.
proof_lock_own_projects() {
  local own
  # Bash 3.2 (macOS /bin/bash) treats "${array[@]}" as unset when the array is
  # empty and the script uses set -u. A proof script uses set -u.
  if [[ ${#PROOF_LOCK_OWN[@]} -gt 0 ]]; then
    for own in "${PROOF_LOCK_OWN[@]}"; do
      [[ -n "$own" ]] && printf '%s\n' "$own"
    done
  fi
  if [[ "$PROOF_LOCK_OWNER" == "1" && -n "$PROOF_LOCK_OWN_FILE" && -f "$PROOF_LOCK_OWN_FILE" ]]; then
    cat "$PROOF_LOCK_OWN_FILE" 2>/dev/null
  fi
  return 0
}

# Print the running orblx container names that do not belong to this proof.
proof_lock_others() {
  local names name project own mine owns
  names="$(proof_lock_docker_names)" || return 2
  owns="$(proof_lock_own_projects)"
  while IFS=$'\t' read -r name project; do
    [[ "$name" == orblx-* ]] || continue
    mine=0
    if [[ -n "$project" ]]; then
      while IFS= read -r own; do
        if [[ -n "$own" && "$project" == "$own" ]]; then
          mine=1
        fi
      done <<<"$owns"
    fi
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


# W25-46: when a killed holder left the holder file, the next taker prints its release
# line with the dead pid. SIGKILL skips the EXIT trap, so proof_lock_end never runs.
proof_lock_note_killed_holder() {
  local file="$1" prev_pid prev_label
  [[ -s "${file}.holder" ]] || return 0
  prev_pid="$(sed -n 's/^pid=//p' "${file}.holder" 2>/dev/null)"
  prev_label="$(sed -n 's/^label=//p' "${file}.holder" 2>/dev/null)"
  [[ "$prev_pid" =~ ^[0-9]+$ ]] || return 0
  # A live process still owns the record until it releases; do not clear it.
  if kill -0 "$prev_pid" 2>/dev/null; then
    return 0
  fi
  echo "proof_lock ${prev_label:-unknown} released at $(proof_lock_now) pid=${prev_pid} reason=killed_holder_cleared_by_next"
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

# W25-14: first come, first served. Each waiter writes a ticket file in "${file}.queue".
# Only the waiter with the oldest live ticket tries the lock. A ticket is live while its pid runs.
# While it waits, the waiter prints "waiting for lock, N s, position P, holder X"
# every NOTE seconds.
# W25-19: the ticket is made before the first proof_context line, so the arrival time is the
# time of the proof_lock_take call (docker ps in proof_context can take a long time).
proof_lock_queue_first() {
  local dir="$1" t pid
  for t in $(ls "$dir" 2>/dev/null | LC_ALL=C sort); do
    pid="${t##*-}"
    if [[ -d "/proc/${pid}" ]] || kill -0 "$pid" 2>/dev/null; then
      printf '%s\n' "$t"
      return 0
    fi
    rm -f "${dir}/${t}" 2>/dev/null || true
  done
  return 1
}

proof_lock_queue_position() {
  local dir="$1" t pid n=0
  for t in $(ls "$dir" 2>/dev/null | LC_ALL=C sort); do
    pid="${t##*-}"
    if [[ -d "/proc/${pid}" ]] || kill -0 "$pid" 2>/dev/null; then
      n=$((n + 1))
    fi
    if [[ "$t" == "$PROOF_LOCK_TICKET" ]]; then
      break
    fi
  done
  printf '%s\n' "$n"
}

# proof_lock_queue_join LOCK_FILE: write this proof's ticket into the queue.
proof_lock_queue_join() {
  local file="$1" dir
  dir="${file}.queue"
  if [[ ! -d "$dir" ]]; then
    (umask 000 && mkdir -p "$dir") 2>/dev/null || true
    chmod 1777 "$dir" 2>/dev/null || true
  fi
  PROOF_LOCK_TICKET="$(proof_date_ns ns)-$$"
  printf 'label=%s\n%s\n' "$PROOF_LOCK_LABEL" "$PROOF_LOCK_PROTO" >"${dir}/${PROOF_LOCK_TICKET}" 2>/dev/null || PROOF_LOCK_TICKET=""
}

# True when the oldest live ticket is from a W25-19 waiter. A W25-14 waiter (an older
# checkout) takes the lock file itself, so the keeper must free it for that waiter.
proof_lock_fifo_first_waits() {
  local dir="$1" first
  first="$(proof_lock_queue_first "$dir")" || return 1
  grep -qx "$PROOF_LOCK_PROTO" "${dir}/${first}" 2>/dev/null
}

# The inode of the lock file, for the lock lines in /proc/PID/fdinfo.
proof_lock_inode() {
  stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1" 2>/dev/null
}

# True when process $1 holds a flock on inode $2. It reads /proc/PID/fdinfo, because
# /proc/locks does not list a lock after the flock(1) process that took it ends.
# When the fdinfo of the process cannot be read (another user), a live process counts.
proof_lock_pid_holds() {
  local pid="$1" ino="$2" state
  [[ -n "$ino" && -d "/proc/${pid}" ]] || return 1
  state="$(sed -n 's/^State:[[:space:]]*\(.\).*/\1/p' "/proc/${pid}/status" 2>/dev/null)"
  [[ "$state" != "Z" ]] || return 1
  if ! ls "/proc/${pid}/fdinfo" >/dev/null 2>&1; then
    return 0
  fi
  grep -qs "^lock:.*FLOCK.*WRITE.*:${ino} " "/proc/${pid}/fdinfo/"* 2>/dev/null
}

# True when the keeper holds the lock file now.
proof_lock_keeper_holds() {
  local file="$1" pid
  pid="$(sed -n 's/^pid=//p' "${file}.keeper" 2>/dev/null)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  if [[ -d /proc/self/fdinfo ]]; then
    proof_lock_pid_holds "$pid" "$(proof_lock_inode "$file")"
  else
    kill -0 "$pid" 2>/dev/null
  fi
}

# Start a keeper. It is not a job of the proof shell, it is in its own session (a timeout
# that stops the process group of the proof does not stop it), and it closes the proof fds.
proof_lock_keeper_start() {
  local file="$1"
  if command -v setsid >/dev/null 2>&1; then
    eval "( setsid bash -c '. \"\$1\"; proof_lock_keeper \"\$2\"' orblx-proof-lock-keeper \"\$PROOF_LOCK_LIB\" \"\$file\" </dev/null >/dev/null 2>&1 & ) ${PROOF_LOCK_FD}>&-"
  else
    eval "( bash -c '. \"\$1\"; proof_lock_keeper \"\$2\"' orblx-proof-lock-keeper \"\$PROOF_LOCK_LIB\" \"\$file\" </dev/null >/dev/null 2>&1 & ) ${PROOF_LOCK_FD}>&-"
  fi
}

# The keeper holds the lock file (the flock that old checkouts use) while a FIFO proof runs
# or while the oldest live ticket is from a FIFO waiter. Only one keeper runs.
# It stops when "${file}.fifo" is free and the oldest live ticket is not from a FIFO waiter
# (or no ticket is left). It checks this under the fifo lock, so no FIFO proof can start
# while it stops. The holder also stops it with TERM in proof_lock_end.
proof_lock_keeper() {
  local file="$1" dir="${1}.queue" lib_keeper="${1}.keeper"
  exec 7>>"${file}.keeper.lock" || exit 0
  flock -n 7 || exit 0
  exec 8>>"$file" || exit 0
  flock 8 || exit 0
  exec 6>>"${file}.fifo" || exit 0
  trap 'rm -f "$lib_keeper"; exit 0' TERM
  printf 'pid=%s\nsince=%s\n' "$$" "$(proof_lock_now)" >"${lib_keeper}.$$" 2>/dev/null || exit 0
  chmod 0666 "${lib_keeper}.$$" 2>/dev/null || true
  mv -f "${lib_keeper}.$$" "$lib_keeper" || exit 0
  while :; do
    # The sleep must not keep the lock fds open after the keeper ends.
    sleep 0.2 6>&- 7>&- 8>&- &
    wait $! || true
    if flock -n 6; then
      if ! proof_lock_fifo_first_waits "$dir"; then
        rm -f "$lib_keeper"
        exit 0
      fi
      flock -u 6
    fi
  done
}

# Stop the keeper and wait until it frees the lock file (at most 3 s). Call it with the fifo lock.
proof_lock_keeper_stop() {
  local file="$1" pid ino i
  pid="$(sed -n 's/^pid=//p' "${file}.keeper" 2>/dev/null)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  kill -TERM "$pid" 2>/dev/null || return 0
  ino="$(proof_lock_inode "$file")"
  for ((i = 0; i < 60; i++)); do
    proof_lock_pid_holds "$pid" "$ino" || return 0
    sleep 0.05
  done
}

# W25-19: print "PID COMMAND" when this shell or a parent process holds a flock on the lock
# file. Then the proof runs under a plain flock and not in the FIFO queue.
proof_lock_plain_parent() {
  local file="$1" ino pid cmd
  [[ -d /proc/self/fdinfo && -e "$file" ]] || return 1
  ino="$(proof_lock_inode "$file")"
  pid="$$"
  while [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )); do
    # One grep per process, not one per fd: an ancestor such as a CI runner can have
    # hundreds of fds, and one grep per fd made the check take 0.7 s or more.
    if grep -qs "^lock:.*FLOCK.*WRITE.*:${ino} " "/proc/${pid}/fdinfo/"* 2>/dev/null; then
      cmd="$(tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null)"
      printf '%s %s\n' "$pid" "${cmd% }"
      return 0
    fi
    pid="$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/${pid}/status" 2>/dev/null)"
  done
  return 1
}

proof_lock_queue_wait() {
  local file="$1" note="$2" from="$3" dir first next_note have_fifo=0 next_keeper=0 now
  dir="${file}.queue"
  if [[ -z "${PROOF_LOCK_TICKET:-}" ]]; then
    proof_lock_queue_join "$file"
  fi
  next_note=0
  while :; do
    if [[ "$have_fifo" == "0" ]]; then
      first="$(proof_lock_queue_first "$dir" || true)"
      if [[ -z "$PROOF_LOCK_TICKET" || "$first" == "$PROOF_LOCK_TICKET" ]] && flock -w 1 "$PROOF_LOCK_FD"; then
        have_fifo=1
      elif [[ -z "$PROOF_LOCK_TICKET" || "$first" != "$PROOF_LOCK_TICKET" ]]; then
        sleep 1
      fi
    fi
    if [[ "$have_fifo" == "1" ]]; then
      # The turn is ours. The lock file must be held by the keeper before the proof starts.
      if proof_lock_keeper_holds "$file"; then
        break
      fi
      now="$(proof_lock_ms)"
      if (( now >= next_keeper )); then
        proof_lock_keeper_start "$file"
        next_keeper=$(( now + 1000 ))
      fi
      sleep 0.1
    fi
    local waited=$(( ($(proof_lock_ms) - from) / 1000 ))
    if (( waited >= next_note )); then
      echo "proof_lock ${PROOF_LOCK_LABEL} waiting for lock, ${waited} s, position $(proof_lock_queue_position "$dir"), at $(proof_lock_now), file ${file}, holder: $(proof_lock_holder "$file")"
      next_note=$(( waited + note ))
    fi
  done
  proof_lock_queue_leave
}

proof_lock_queue_leave() {
  if [[ -n "$PROOF_LOCK_TICKET" ]]; then
    rm -f "$(proof_lock_file).queue/${PROOF_LOCK_TICKET}" 2>/dev/null || true
    PROOF_LOCK_TICKET=""
  fi
}

# W25-14b: free disk space before the lock and before any build (proof_disk_check).
# A build or an image step that stops on a full disk is a FAIL, so a proof does not start
# with low free space. Each proof script sets PROOF_MIN_FREE_GIB in the script, with its reason.
# PROOF_DISK_FLOOR_GIB is the lowest value that a script can set. The reason: the PO rule of
# 2026-10-31 (15 GiB free before builds). The measure under it: the biggest build output seen on
# this box (11 GiB, a worktree target/ at 16:42 KST 2026-10-31), plus the biggest proof image
# (0.55 GiB), plus the image stage copy (0.25 GiB), is 11.8 GiB.
# The sweep (#119) parses "proof_infra_abort PROOF reason=disk_low|disk_unknown". The line comes
# before any proof_lock line and before any build.
# Below the minimum, or when the free space is not known, the function prints
#   proof_infra_abort LABEL reason=... dir=DIR. No proof step ran.
# and stops the script with exit status 4 (PROOF_INFRA_ABORT_EXIT). Status 3 stays
# proof_contention_invalid. An infra abort is not a PASS, a FAIL, or an INVALID run.
PROOF_DISK_FLOOR_GIB=15
PROOF_INFRA_ABORT_EXIT=4
PROOF_DISK_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

proof_free_gib_at() {
  local kib
  kib="$(df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $4 }')" || return 1
  [[ "$kib" =~ ^[0-9]+$ ]] || return 1
  echo $((kib / 1048576))
}

proof_infra_abort() {
  echo "proof_infra_abort $1 $2. No proof step ran." >&2
  exit "$PROOF_INFRA_ABORT_EXIT"
}

# Report the free space when the lock is acquired. This is a reported value only: the run does
# not stop after the lock on free space. The one check is proof_disk_check before the lock.
proof_disk_report() {
  local dir free
  for dir in "$PROOF_DISK_REPO" /var/lib/docker; do
    [[ -d "$dir" ]] || continue
    free="$(proof_free_gib_at "$dir")" || free=unknown
    echo "proof_context $1 phase disk_at_lock free_gib=$free dir=$dir"
  done
}

proof_disk_check() {
  local label="$1" min="${PROOF_MIN_FREE_GIB:-}" dir free
  if ! [[ "$min" =~ ^[0-9]+$ ]]; then
    proof_infra_abort "$label" "reason=min_unset dir=none"
  fi
  if (( min < PROOF_DISK_FLOOR_GIB )); then
    proof_infra_abort "$label" "reason=min_below_floor min_gib=$min floor_gib=$PROOF_DISK_FLOOR_GIB dir=none"
  fi
  for dir in "$PROOF_DISK_REPO" /var/lib/docker; do
    [[ -d "$dir" ]] || continue
    if ! free="$(proof_free_gib_at "$dir")"; then
      proof_infra_abort "$label" "reason=disk_unknown dir=$dir"
    fi
    if (( free < min )); then
      proof_infra_abort "$label" "reason=disk_low free_gib=$free min_gib=$min dir=$dir"
    fi
  done
}

# W25-40 (PO rule 2026-10-31 23:14 KST): no foreign orblx container at lock acquire.
# After the lock is taken, and before the proof's first step (build, compose up), the proof
# stops when an orblx container that does not belong to this run exists (proof_lock_others: a
# name that starts with "orblx-" and with no own compose project label). It prints
#   proof_infra_abort LABEL reason=foreign_containers names=A,B,C. No proof step ran.
# or, when docker ps fails,
#   proof_infra_abort LABEL reason=containers_unknown names=none. No proof step ran.
# releases the lock, and exits with status 5 (PROOF_FOREIGN_ABORT_EXIT). It never stops or
# removes the other containers. The check runs only when this proof took the lock itself (not
# under a parent proof that holds it, and not on a host with no flock).
PROOF_FOREIGN_ABORT_EXIT=5

proof_foreign_check() {
  local label="$1" others names
  if ! others="$(proof_lock_others)"; then
    echo "proof_infra_abort ${label} reason=containers_unknown names=none. No proof step ran." >&2
    proof_lock_end
    exit "$PROOF_FOREIGN_ABORT_EXIT"
  fi
  others="$(printf '%s\n' "$others" | sed '/^$/d' | sort -u)"
  [[ -n "$others" ]] || return 0
  names="$(printf '%s\n' "$others" | paste -sd, -)"
  echo "proof_infra_abort ${label} reason=foreign_containers names=${names}. No proof step ran." >&2
  proof_lock_end
  exit "$PROOF_FOREIGN_ABORT_EXIT"
}

proof_lock_take() {
  # The disk check runs before the lock, also when the script ran it before its build.
  proof_disk_check "$1"
  # W25-27: a manifest proof that makes lab tickets fails before it waits for the lock.
  proof_lab_ticket_static_guard "$0" || exit 1
  PROOF_LOCK_LABEL="$1"
  shift
  PROOF_LOCK_OWN=("$@")
  # W25-46: the words are exact compose project names. A word that ends in "-" is an old
  # name prefix: stop, so that no proof counts its own containers as other containers.
  local own_word
  # Same bash 3.2 rule as proof_lock_own_projects: do not expand an empty array.
  if [[ ${#PROOF_LOCK_OWN[@]} -gt 0 ]]; then
    for own_word in "${PROOF_LOCK_OWN[@]}"; do
      if [[ -z "$own_word" || "$own_word" == *- || ! "$own_word" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
        echo "proof_lock ${PROOF_LOCK_LABEL} FAIL: \"${own_word}\" is not a compose project name. Give the exact compose project names, not a name prefix (W25-46)." >&2
        PROOF_LOCK_LABEL=""
        exit 1
      fi
    done
  fi
  local file waited_from note plain mode=lock
  file="$(proof_lock_file)"
  note="${ORBLX_PROOF_LOCK_NOTE_SECS:-30}"
  if proof_lock_parent_holds "$file"; then
    mode=parent
  elif ! command -v flock >/dev/null 2>&1; then
    mode=none
  elif plain="$(proof_lock_plain_parent "$file")"; then
    echo "proof_lock ${PROOF_LOCK_LABEL} FAIL: process ${plain} holds ${file} with a plain flock, not with the FIFO queue. Do not wrap a proof in flock. Use proof_lock_take from scripts/proof/proof-lock.sh (W25-19)." >&2
    PROOF_LOCK_LABEL=""
    exit 1
  else
    # The lock files must be writable by every user that runs a proof.
    if [[ ! -e "$file" ]]; then
      (umask 000 && : >>"$file")
    fi
    local extra
    for extra in "${file}.fifo" "${file}.keeper.lock"; do
      if [[ ! -e "$extra" ]]; then
        (umask 000 && : >>"$extra")
      fi
    done
    proof_lock_queue_join "$file"
  fi
  proof_context queued
  if [[ "$mode" == "parent" ]]; then
    echo "proof_lock ${PROOF_LOCK_LABEL} held by the parent proof, file ${file}"
    if [[ -n "${ORBLX_PROOF_OWN_FILE:-}" && -f "$ORBLX_PROOF_OWN_FILE" && ${#PROOF_LOCK_OWN[@]} -gt 0 ]]; then
      printf '%s\n' "${PROOF_LOCK_OWN[@]}" >>"$ORBLX_PROOF_OWN_FILE" 2>/dev/null || true
    fi
  elif [[ "$mode" == "none" ]]; then
    echo "proof_lock ${PROOF_LOCK_LABEL} no flock on this host, the proof runs without the lock"
  else
    eval "exec ${PROOF_LOCK_FD}>>\"\${file}.fifo\""
    # The wait time counts from here, as in W25-14 (after the queued proof_context line).
    waited_from="$(proof_lock_ms)"
    proof_lock_queue_wait "$file" "$note" "$waited_from"
    PROOF_LOCK_OWNER=1
    export ORBLX_PROOF_LOCK_HELD="$$"
    PROOF_LOCK_OWN_FILE="$(mktemp)"
    chmod 0666 "$PROOF_LOCK_OWN_FILE" 2>/dev/null || true
    export ORBLX_PROOF_OWN_FILE="$PROOF_LOCK_OWN_FILE"
    # W25-46: log a release for a killed previous holder before we replace the record.
    proof_lock_note_killed_holder "$file"
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
    proof_disk_report "$PROOF_LOCK_LABEL"
    proof_foreign_check "$PROOF_LOCK_LABEL"
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
  proof_lock_queue_leave
  if [[ -n "$PROOF_LOCK_SAMPLER" ]]; then
    kill "$PROOF_LOCK_SAMPLER" 2>/dev/null || true
    PROOF_LOCK_SAMPLER=""
  fi
  proof_context end
  local invalid=""
  if [[ -n "$PROOF_LOCK_SAMPLES" && -f "$PROOF_LOCK_SAMPLES" ]]; then
    awk -v label="$PROOF_LOCK_LABEL" '
      { n++; if ($2 < 0) unknown++; if ($2 > 0) busy++; if ($2 > maxc) maxc = $2; if ($3 > maxl) maxl = $3 }
      END {
        printf "proof_contention %s samples %d contended_samples %d unknown_samples %d max_other_orblx_containers %d max_load1 %s\n", label, n, busy + 0, unknown + 0, maxc + 0, (n ? maxl : "-")
        if (unknown > 0) printf "proof_contention_invalid %s unknown_samples %d samples %d\n", label, unknown, n
      }
    ' "$PROOF_LOCK_SAMPLES"
    # W25-35: fail closed when the sampler could not count the other containers.
    if awk '$2 < 0 {bad = 1} END {exit !bad}' "$PROOF_LOCK_SAMPLES"; then
      invalid=1
    fi
    rm -f "$PROOF_LOCK_SAMPLES"
    PROOF_LOCK_SAMPLES=""
  fi
  if [[ "$PROOF_LOCK_OWNER" == "1" ]]; then
    # W25-19: when no FIFO waiter is next, stop the keeper before the fifo lock is free, so
    # the lock file is free when this function returns.
    if ! proof_lock_fifo_first_waits "$(proof_lock_file).queue"; then
      proof_lock_keeper_stop "$(proof_lock_file)"
    fi
    flock -u "$PROOF_LOCK_FD" 2>/dev/null || true
    eval "exec ${PROOF_LOCK_FD}>&-"
    PROOF_LOCK_OWNER=0
    rm -f "$PROOF_LOCK_OWN_FILE"
    PROOF_LOCK_OWN_FILE=""
    echo "proof_lock ${PROOF_LOCK_LABEL} released at $(proof_lock_now) pid=$$"
  fi
  PROOF_LOCK_LABEL=""
  if [[ -n "$invalid" ]]; then
    echo "proof_lock FAIL: the sampler could not count the other orblx containers, so the run is not valid (W25-35)." >&2
    exit 3
  fi
}

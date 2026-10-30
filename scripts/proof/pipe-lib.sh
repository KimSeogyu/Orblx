# shellcheck shell=bash
# W25-14 pipe helpers for bash scripts with set -o pipefail.
#
# A pipe reader that exits before the end of its input (grep -q, grep -m, head, awk with exit,
# sed with q) makes the writer get SIGPIPE (exit 141). With set -o pipefail the pipe then fails:
# an assignment stops the script (W24-E4b, W25-3), and an "if" check gets false. A false "if"
# can make a leak, hole punch, deny or audit check pass when it must fail.
#
# read_all CMD [ARG ...]: read all of stdin, then run CMD with the same bytes on stdin.
#   The writer always sees the end of the pipe, so it cannot get SIGPIPE.
#   The exit code is the exit code of CMD (grep: 0 match, 1 no match, 2 error).
#   Use it for every early reader on a pipe:  ... | read_all grep -q PATTERN
# has_line ERE: exit 0 when a line of stdin matches the ERE. It reads all of stdin.
# PROOF_LIB_DIR: the directory of this file (scripts/proof). Use it to source proof-lock.sh.
# require_root: stop at once with exit 1 when the script does not run as root.

PROOF_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

read_all() {
  local input
  # The x keeps the trailing newlines. Then remove one newline, because <<< adds one.
  input="$(cat; printf x)"
  input="${input%x}"
  if [[ -z "$input" ]]; then
    "$@" </dev/null
  else
    "$@" <<<"${input%$'\n'}"
  fi
}

has_line() {
  awk -v re="$1" '$0 ~ re {found = 1} END {exit !found}'
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root: sudo -n $0 $*" >&2
    exit 1
  fi
}

# W25-14: the steady ping gate. Read the last 2 lines of a ping run on stdin.
# Arguments: label, pings sent, most lost pings, most max RTT in ms.
# Print "<label> steady lost L/N max_ms M limit_ms X". Return 1 when the loss or the
# max RTT is more than the limit, or when the summary is missing.
steady_ping_gate() {
  local label="$1" pings="$2" max_loss="$3" max_ms="$4" warn_ms="${5:-}" input received max seq ms context
  input="$(cat)"
  # W25-14: each reply above WARN_MS prints a report-only steady_warn line. It does not fail.
  if [[ -n "$warn_ms" ]]; then
    while read -r seq ms; do
      context="proof_context none"
      if declare -F proof_context >/dev/null; then
        context="$(proof_context steady_warn)"
      fi
      echo "steady_warn ${label} icmp_seq ${seq} ms ${ms} warn_ms ${warn_ms} limit_ms ${max_ms} time $(date '+%Y-%m-%dT%H:%M:%S.%3N%z') ${context}"
    done < <(printf '%s\n' "$input" | awk -v w="$warn_ms" '
      /icmp_seq=/ && / time=/ {
        s = $0; sub(/.*icmp_seq=/, "", s); sub(/ .*/, "", s)
        t = $0; sub(/.* time=/, "", t); sub(/ .*/, "", t)
        if (t + 0 > w + 0) print s, t
      }')
  fi
  received="$(printf '%s\n' "$input" | awk '/packets transmitted/ {v = $4} END {print v}')"
  max="$(printf '%s\n' "$input" | awk -F'/' '/^rtt / {v = $6} END {print v}')"
  if [[ -z "$received" || ( "$received" != "0" && -z "$max" ) ]]; then
    echo "${label} has no ping summary." >&2
    return 1
  fi
  echo "${label} steady lost $((pings - received))/${pings} max_ms ${max:-none} limit_ms ${max_ms}"
  if (( pings - received > max_loss )); then
    echo "${label} lost too many pings on a stable path." >&2
    return 1
  fi
  if ! awk -v m="$max" -v l="$max_ms" 'BEGIN {exit !(m + 0 <= l + 0)}'; then
    echo "${label} max ping RTT ${max} ms is more than ${max_ms} ms on a stable path." >&2
    return 1
  fi
}

# W25-14: show_matching GREP_ARGS... prints the matching lines of stdin, like grep.
# When no line matches, it prints the full input to stderr, so the log keeps the cause,
# and returns 1 (as grep does).
show_matching() {
  local input
  input="$(cat; printf x)"
  input="${input%x}"
  if printf '%s' "$input" | grep "$@"; then
    return 0
  fi
  echo "show_matching: no line matches: $*. The full output follows." >&2
  printf '%s' "$input" >&2
  return 1
}

# W25-14: secret_scan FILE fails when FILE is missing or empty, or when it holds PEM key
# text or an enroll token (ge1.). It prints "secret_grep <pattern> <count>" for each pattern.
secret_scan() {
  local file="$1" pattern hits bad=0
  if [[ ! -s "$file" ]]; then
    echo "secret_scan: ${file} is missing or empty. The scan cannot pass." >&2
    return 1
  fi
  for pattern in 'PRIVATE KEY' 'ge1\.'; do
    hits="$(awk -v re="$pattern" '$0 ~ re {n++} END {print n + 0}' "$file")" || return 1
    echo "secret_grep '${pattern}' ${hits}"
    if [[ "$hits" -ne 0 ]]; then
      bad=1
    fi
  done
  return "$bad"
}

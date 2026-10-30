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

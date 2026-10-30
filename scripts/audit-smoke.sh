#!/usr/bin/env bash
# Export one session deny and one successful session.
# Check the hash chain.
# The check does not use the data path.

set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/proof/pipe-lib.sh"

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
chain="$dir/chain.jsonl"

demo=$(cargo run -q -p orblx-cli -- audit demo --out "$chain")
printf '%s\n' "$demo"
verify=$(cargo run -q -p orblx-cli -- audit verify --file "$chain")
printf '%s\n' "$verify"

need_line() {
  local text=$1
  local pattern=$2
  if ! printf '%s\n' "$text" | read_all grep -Eq "$pattern"; then
    echo "The audit output does not match ${pattern}."
    exit 1
  fi
}

need_line "$demo" '^start 1$'
need_line "$demo" '^end 1$'
need_line "$demo" '^deny 1$'
need_line "$demo" '^records 3$'
need_line "$verify" '^ok$'
need_line "$verify" '^start 1$'
need_line "$verify" '^end 1$'
need_line "$verify" '^deny 1$'
need_line "$verify" '^records 3$'

demo_tip=$(printf '%s\n' "$demo" | awk '/^tip / { print $2 }')
verify_tip=$(printf '%s\n' "$verify" | awk '/^tip / { print $2 }')
if [ "$demo_tip" != "$verify_tip" ]; then
  echo "The tip hash from verify differs from the demo tip."
  exit 1
fi

echo "The session audit chain check passed."

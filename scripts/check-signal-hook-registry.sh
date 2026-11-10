#!/usr/bin/env bash
# Fail when Cargo.lock lists more than one signal-hook-registry version.
# Usage: scripts/check-signal-hook-registry.sh [LOCK] [lock-only]
# With no arguments the script also runs `cargo tree --duplicates`.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
lock="${1:-Cargo.lock}"
mode="${2:-full}"

versions="$(
  awk '
    $0 == "name = \"signal-hook-registry\"" { want = 1; next }
    want && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      want = 0
    }
  ' "$lock" | sort -u
)"
count="$(printf '%s\n' "$versions" | grep -c . || true)"
if [[ "$count" -ne 1 ]]; then
  echo "signal-hook-registry version count is ${count}: ${versions}" >&2
  exit 1
fi
echo "signal-hook-registry version ${versions}"

if [[ "$mode" == "lock-only" ]]; then
  exit 0
fi

dups="$(cargo tree --duplicates -i signal-hook-registry || true)"
if [[ -n "$dups" ]]; then
  echo "cargo tree reports more than one signal-hook-registry." >&2
  printf '%s\n' "$dups" >&2
  exit 1
fi

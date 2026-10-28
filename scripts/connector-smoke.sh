#!/usr/bin/env bash
# Run the Orblx connector userspace proof.
# The proof fetches two HTTPS apps through the QUIC mesh.
# The proof does not open a TUN device.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

out=$(cargo run -q -p gyeol-cli -- connector smoke)
printf '%s\n' "$out"

need_line() {
  local pattern=$1
  if ! printf '%s\n' "$out" | grep -Eq "$pattern"; then
    echo "The smoke output does not match ${pattern}."
    exit 1
  fi
}

need_line 'app-a\.orblx\.test status 200 body app-a overlay 10\.8\.0\.10 mesh_to [1-9][0-9]* mesh_from [1-9][0-9]*'
need_line 'app-b\.orblx\.test status 200 body app-b overlay 10\.8\.0\.11 mesh_to [1-9][0-9]* mesh_from [1-9][0-9]*'
echo "The userspace connector proof passed."

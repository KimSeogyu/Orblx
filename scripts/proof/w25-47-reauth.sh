#!/usr/bin/env bash
# W25-47 release proof for DoD a, b, and f.
# Eng Lead runs this on a host. Do not call scripts/proof/proof-lock.sh.
# The run needs CAP_SYS_TIME or root. It steps CLOCK_REALTIME with date -u -s.
# A real pause may use virsh suspend and virsh resume. Do not use docker pause.
# Repeat a and b 10 times on the merge commit. This script runs f, then one a/b pass
# when ORBLX_W25_47_NODE=1.
set -euo pipefail

if [[ "${ORBLX_PROOF_LOCK:-}" == "1" ]]; then
  echo "Do not run this proof from proof-lock.sh."
  exit 2
fi

if ! capsh --print 2>/dev/null | grep -q cap_sys_time && [[ "$(id -u)" != "0" ]]; then
  echo "The W25-47 release proof needs CAP_SYS_TIME or root. Eng Lead runs it."
  exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="${ORBLX_BIN:-$root/target/debug/orblx}"
if [[ ! -x "$bin" ]]; then
  echo "Build orblx first. The proof looks for $bin."
  exit 1
fi

saved=$(date -u +%Y-%m-%dT%H:%M:%S)
restore_clock() {
  date -u -s "$saved" >/dev/null || true
}
trap restore_clock EXIT

work=$(mktemp -d)
coord_dir="$work/coord"
mkdir -p "$coord_dir"
log="$work/coord.log"

export ORBLX_OIDC_MODE=mock
"$bin" coord serve --state "$coord_dir" --name coord --listen 127.0.0.1:9443 >"$log" 2>&1 &
coord_pid=$!
sleep 2
if ! kill -0 "$coord_pid" 2>/dev/null; then
  echo "The coordinator did not stay up."
  cat "$log"
  exit 1
fi

echo "DoD f: step the coordinator clock past its leaf end plus 60 s."
date -u -s "+20 min" >/dev/null
sleep 3
if ! grep -q "coord svid renewed" "$log"; then
  echo "DoD f failed. The coordinator log has no coord svid renewed line."
  kill "$coord_pid" || true
  exit 1
fi
echo "DoD f passed."
restore_clock

if [[ "${ORBLX_W25_47_NODE:-}" != "1" ]]; then
  kill "$coord_pid" || true
  wait "$coord_pid" || true
  echo "DoD a and b stay for Eng Lead. Set ORBLX_W25_47_NODE=1 after a node is up."
  echo "Step the node clock 20 min. orblx status must show state needs-reauth."
  echo "The status line must be: reauth orblx login --name NAME"
  echo "One owner login, or one in-scope pre-auth enroll, keeps the name and the overlay address."
  echo "Peers must pass traffic within 60 s. Repeat that pair 10 times."
  exit 0
fi

echo "DoD a and b need the node state directory in ORBLX_W25_47_STATE."
if [[ -z "${ORBLX_W25_47_STATE:-}" ]]; then
  echo "Set ORBLX_W25_47_STATE to the node state directory."
  kill "$coord_pid" || true
  exit 1
fi
date -u -s "+20 min" >/dev/null
sleep 3
status=$("$bin" status --state "$ORBLX_W25_47_STATE" || true)
printf '%s\n' "$status"
if ! printf '%s\n' "$status" | grep -q "state needs-reauth"; then
  echo "DoD a failed."
  kill "$coord_pid" || true
  exit 1
fi
if ! printf '%s\n' "$status" | grep -q "reauth orblx login --name"; then
  echo "DoD a failed. The login command is missing."
  kill "$coord_pid" || true
  exit 1
fi
echo "DoD a passed. Eng Lead runs the owner command for DoD b and checks peer traffic within 60 s."
kill "$coord_pid" || true
wait "$coord_pid" || true
exit 0

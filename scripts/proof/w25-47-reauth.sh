#!/usr/bin/env bash
# W25-47 release proof for DoD f, then one DoD a pass.
# Eng Lead runs this on the final pull request head.
# The script sources proof-lock.sh and takes the lock. It reads no manifest.
# Do not start proof-lock.sh as its own command.
#
# Privileges: CAP_SYS_TIME or root. Stop NTP before the run.
# This script does not stop NTP. The trap sets the clock back.
#
# Build, then point ORBLX_BIN at that binary. The default is target/debug/orblx.
#   cargo build --release --bin orblx
#
# DoD f. The script creates the coordinator directory with mktemp.
#   ORBLX_BIN=target/release/orblx scripts/proof/w25-47-reauth.sh
# PASS line: DoD f passed.
#
# DoD a in the same process, after f. The node directory must already exist.
#   ORBLX_W25_47_NODE=1 ORBLX_W25_47_STATE=/var/lib/orblx ORBLX_BIN=target/release/orblx scripts/proof/w25-47-reauth.sh
# PASS lines: DoD f passed.
#             DoD a passed.
# DoD b is not a script result. After PASS DoD a, status prints the owner command.
# Eng Lead runs that command and checks that peers pass traffic within 60 s.
# Repeat the node command 10 times on the same head.
#
# One iteration ends after ORBLX_W25_47_TIMEOUT seconds (default 180) with exit 124.
# A failed check exits 1. A missing privilege exits 2. The proof lock uses status 3, 4, or 5.
# A pass exits 0.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).

if ! capsh --print 2>/dev/null | read_all grep -q cap_sys_time && [[ "$(id -u)" != "0" ]]; then
  echo "The W25-47 release proof needs CAP_SYS_TIME or root. Eng Lead runs it."
  exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="${ORBLX_BIN:-$root/target/debug/orblx}"
if [[ ! -x "$bin" ]]; then
  echo "Build orblx first. The proof looks for $bin."
  exit 1
fi

proof_lock_take "w25-47-reauth"

saved=$(date -u +%Y-%m-%dT%H:%M:%S)
coord_pid=
watchdog_pid=
cleaned=0
cleanup() {
  if [[ "$cleaned" == 1 ]]; then
    return
  fi
  cleaned=1
  if [[ -n "$watchdog_pid" ]]; then
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  if [[ -n "$coord_pid" ]]; then
    kill "$coord_pid" 2>/dev/null || true
    wait "$coord_pid" 2>/dev/null || true
  fi
  date -u -s "$saved" >/dev/null || true
  proof_lock_end
}
trap cleanup EXIT INT TERM HUP
on_alarm() {
  echo "The iteration timed out after ${limit} s." >&2
  exit 124
}
trap on_alarm USR1

# One iteration. The alarm fires after this many seconds.
limit="${ORBLX_W25_47_TIMEOUT:-180}"
(
  sleep "$limit"
  kill -USR1 $$ 2>/dev/null || true
) &
watchdog_pid=$!

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
if ! read_all grep -q "coord svid renewed" <"$log"; then
  echo "DoD f failed. The coordinator log has no coord svid renewed line."
  exit 1
fi
echo "DoD f passed."
date -u -s "$saved" >/dev/null

if [[ "${ORBLX_W25_47_NODE:-}" != "1" ]]; then
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
  exit 1
fi
date -u -s "+20 min" >/dev/null
sleep 3
status=$("$bin" status --state "$ORBLX_W25_47_STATE" || true)
printf '%s\n' "$status"
if ! printf '%s\n' "$status" | read_all grep -q "state needs-reauth"; then
  echo "DoD a failed."
  exit 1
fi
if ! printf '%s\n' "$status" | read_all grep -q "reauth orblx login --name"; then
  echo "DoD a failed. The login command is missing."
  exit 1
fi
echo "DoD a passed."
echo "DoD b is the owner command in the status text. This script does not run it."
echo "Eng Lead checks that peers pass traffic within 60 s."
exit 0

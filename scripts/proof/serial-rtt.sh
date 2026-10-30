#!/usr/bin/env bash
# W25-5: run the release nat-realism proof ORBLX_SERIAL_RUNS times (default 10), one after the other,
# under one hold of the box proof lock (proof-lock.sh). Then print one table row per run:
# the max ping, the median ping and the lost pings of the W23-4 gate paths, and the contention.
# The host is REAL. Every node, router, coordinator and relay is a [C] container.
# Env: ORBLX_SERIAL_OUT (default target/serial-rtt) gets runN.log, runN.exit and serial-rtt.md.
#      The ORBLX_NATR_* variables of nat-realism.sh pass through.
#      ORBLX_SERIAL_SPIKE_MS (default 20) is the max ping limit.
# The script stops after a run with a ping above the limit while no other orblx container ran
# (contention is then not the cause; see docs/w25-proof-lock.md). It exits 1 when a run fails
# the limit, loses a gate ping, or does not print proof_ok.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
RUNS="${ORBLX_SERIAL_RUNS:-10}"
OUT="${ORBLX_SERIAL_OUT:-$ROOT/target/serial-rtt}"
NATR_PREFIX="${ORBLX_NATR_PREFIX:-orblx-natr-}"
PROJECT="${ORBLX_NATR_PROJECT:-orblx-natr-proof}"

# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "serial-rtt:${PROJECT}" "$NATR_PREFIX" "${PROJECT}-"

mkdir -p "$OUT"
rm -f "$OUT"/run*.log "$OUT"/run*.exit "$OUT"/serial-rtt.md

status=0
for i in $(seq 1 "$RUNS"); do
  echo "=== serial run ${i}/${RUNS} start $(proof_lock_now) ==="
  ORBLX_NATR_PROFILE=release ./scripts/proof/nat-realism.sh >"$OUT/run${i}.log" 2>&1
  code=$?
  echo "$code" >"$OUT/run${i}.exit"
  echo "=== serial run ${i}/${RUNS} end $(proof_lock_now) exit ${code} ==="
  python3 "$ROOT/scripts/proof/serial-rtt-table.py" "$OUT" --upto "$i" | tail -1
  python3 "$ROOT/scripts/proof/serial-rtt-table.py" "$OUT" --upto "$i" --kill-check
  case $? in
    0) ;;
    3)
      echo "serial_rtt stop: run ${i} had a ping above the limit with no other orblx container running"
      status=1
      break
      ;;
    *) status=1 ;;
  esac
done

python3 "$ROOT/scripts/proof/serial-rtt-table.py" "$OUT" | tee "$OUT/serial-rtt.md"
python3 "$ROOT/scripts/proof/serial-rtt-table.py" "$OUT" --gate || status=1
proof_lock_end
exit "$status"

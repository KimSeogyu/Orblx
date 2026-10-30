#!/usr/bin/env bash
# W25-12: the W23-4 sym relay throughput check with long samples.
# Runs serial-rtt.sh with ORBLX_SERIAL_RUNS (default 5) release nat-realism runs and a TCP bulk of
# ORBLX_BULK_SECS (default 30) seconds on every path, under one hold of the box proof lock.
# Then serial-rtt-table.py --sym-gate: at least 5 runs with a 30 s bulk, and their sym_sym relay
# median at or above the W22 floor (1113 Mbit/s). See docs/w25-sym-throughput.md.
# The host is REAL. Every node, router, coordinator and relay is a [C] container.
# Env: ORBLX_SERIAL_OUT (default target/sym-throughput). Other variables pass to serial-rtt.sh.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export ORBLX_SERIAL_RUNS="${ORBLX_SERIAL_RUNS:-5}"
export ORBLX_BULK_SECS="${ORBLX_BULK_SECS:-30}"
export ORBLX_SERIAL_OUT="${ORBLX_SERIAL_OUT:-$ROOT/target/sym-throughput}"

# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "sym-throughput:${ORBLX_NATR_PROJECT:-orblx-natr-proof}" "${ORBLX_NATR_PREFIX:-orblx-natr-}" "${ORBLX_NATR_PROJECT:-orblx-natr-proof}-"

"$ROOT/scripts/proof/serial-rtt.sh"
status=$?
python3 "$ROOT/scripts/proof/serial-rtt-table.py" "$ORBLX_SERIAL_OUT" --sym-gate || status=1
proof_lock_end
exit "$status"

#!/usr/bin/env bash
# W24 perf watch.
# Run the release nat-realism proof ORBLX_PERF_RUNS times (default 3) and summarize
# the RTT gate, the ping RTT, the slowest pings and the TCP bulk throughput of each path.
# The host is REAL. Every node, router, coordinator and relay is a [C] container.
# Output (ORBLX_PERF_OUT, default target/perf-watch):
#   runN.log, runN.exit, perf-watch.json, perf-watch.md
# The script runs every run, then fails when a run did not print proof_ok
# or when a CI gate of perf-summary.py did not pass in a run (W24-E2):
# relay ping median <= direct ping median + 1 ms, 0 lost, TCP >= 200 Mbit/s on each path (W24-E4),
# and at most 3 of 50 pings above 10 ms on each path.
# The avg is not a CI gate: one runner stall of 40 to 250 ms moves the avg of 50 pings by 1 to 5 ms.
# So the CI sets the nat-realism avg limits to 1000 ms (the ping timeout, -W 1). Then the avg
# checks cannot stop a run, and every path is measured. The avg gate stays in the summary as a report.
# The box merge gate does not change: nat-realism.sh without these env vars keeps 1 ms and 5 ms.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
RUNS="${ORBLX_PERF_RUNS:-3}"
OUT="${ORBLX_PERF_OUT:-$ROOT/target/perf-watch}"

# W25-5: hold the box proof lock for all runs. nat-realism.sh sees ORBLX_PROOF_LOCK_HELD
# and does not take it again.
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take perf-watch orblx-natr- orblx-natr-proof-

mkdir -p "$OUT"
echo "cpu_model $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || true)"
echo "throughput_floor_mbit ${ORBLX_PERF_MIN_MBIT:-200}"
rm -f "$OUT"/run*.log "$OUT"/run*.exit "$OUT"/perf-watch.json "$OUT"/perf-watch.md

for i in $(seq 1 "$RUNS"); do
  echo "=== perf watch run ${i}/${RUNS} ==="
  start="$(date +%s)"
  ORBLX_NATR_PROFILE=release ORBLX_RELAY_SLACK_MS=1000 ORBLX_RTT_LIMIT_MS=1000 \
    ./scripts/proof/nat-realism.sh >"$OUT/run${i}.log" 2>&1
  code=$?
  echo "$code" >"$OUT/run${i}.exit"
  echo "run ${i} exit ${code} seconds $(($(date +%s) - start))"
  grep -E '^(rtt plain_avg_ms|direct_ping|relay_ping|relay_rtt|throughput|proof_ok)' "$OUT/run${i}.log" | sort -u
  if [[ "$code" != "0" ]]; then
    echo "--- run ${i} log tail ---"
    tail -40 "$OUT/run${i}.log"
  fi
done

python3 "$ROOT/scripts/proof/perf-summary.py" "$OUT"
status=$?
if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$OUT/perf-watch.md" ]]; then
  cat "$OUT/perf-watch.md" >>"$GITHUB_STEP_SUMMARY"
fi
proof_lock_end
exit "$status"

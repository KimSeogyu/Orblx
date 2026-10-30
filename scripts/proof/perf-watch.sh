#!/usr/bin/env bash
# W24 perf watch.
# Run the release nat-realism proof ORBLX_PERF_RUNS times (default 3) and summarize
# the RTT gate, the ping RTT, the slowest pings and the TCP bulk throughput of each path.
# The host is REAL. Every node, router, coordinator and relay is a [C] container.
# Output (ORBLX_PERF_OUT, default target/perf-watch):
#   runN.log, runN.exit, perf-watch.json, perf-watch.md
# The script runs every run, then fails when a run did not print proof_ok
# or when the RTT gate (relay avg <= direct avg + 1 ms, 0/50 lost) did not pass.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
RUNS="${ORBLX_PERF_RUNS:-3}"
OUT="${ORBLX_PERF_OUT:-$ROOT/target/perf-watch}"

mkdir -p "$OUT"
rm -f "$OUT"/run*.log "$OUT"/run*.exit "$OUT"/perf-watch.json "$OUT"/perf-watch.md

for i in $(seq 1 "$RUNS"); do
  echo "=== perf watch run ${i}/${RUNS} ==="
  start="$(date +%s)"
  ORBLX_NATR_PROFILE=release ./scripts/proof/nat-realism.sh >"$OUT/run${i}.log" 2>&1
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
exit "$status"

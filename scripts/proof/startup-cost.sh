#!/usr/bin/env bash
# W25-21: the start-up cost of a node from the enroll call to the listener start.
# The script takes the box proof lock (proof-lock.sh), builds the orblx-coord lib test binary,
# and runs the ignored test startup_cost_runs one time. That test starts
# ORBLX_STARTUP_RUNS nodes (default 10) one after the other, each with a fresh in-process
# coordinator on 127.0.0.1, and prints one "startup_cost run N startup_ms ..." line per run,
# the median, p95 and max of each phase, and a summary line. ORBLX_TRACE_COORD=1 adds one
# "orblx coord_call close_wait_ms" line per coordinator call (no request or response data).
# Gate: the enroll-to-listener median is 1000 ms or less. The script prints proof_ok on a pass.
# The host, the coordinator and the node code are REAL. There are no containers and no TUN
# (the node uses the in-memory interface of the tests).
# Env: ORBLX_STARTUP_OUT (default target/startup-cost) gets run.log (the full test output).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
RUNS="${ORBLX_STARTUP_RUNS:-10}"
OUT="${ORBLX_STARTUP_OUT:-$ROOT/target/startup-cost}"
mkdir -p "$OUT"
build_json="$OUT/build.json"
log="$OUT/run.log"
rm -f "$build_json" "$log"

# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
PROOF_MIN_FREE_GIB=12  # reason: the floor (PROOF_DISK_FLOOR_GIB): one build output and one proof image. No bigger measure for this proof.
trap proof_lock_end EXIT
proof_lock_take "startup-cost" "orblx-startup-cost-"

if ! cargo test -p orblx-coord --lib --no-run --message-format=json >"$build_json"; then
  echo "The build of the orblx-coord test binary failed."
  exit 1
fi
bin="$(python3 - "$build_json" <<'PY'
import json, sys
found = ""
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        item = json.loads(line)
    except ValueError:
        continue
    target = item.get("target") or {}
    if item.get("reason") == "compiler-artifact" and item.get("executable") \
            and target.get("name") == "orblx_coord" and "lib" in target.get("kind", []):
        found = item["executable"]
print(found)
PY
)"
if [[ -z "$bin" || ! -x "$bin" ]]; then
  echo "The orblx-coord test binary is missing."
  exit 1
fi

echo "startup-cost start $(date '+%Y-%m-%dT%H:%M:%S%z') runs ${RUNS} binary ${bin}"
ORBLX_STARTUP_RUNS="$RUNS" ORBLX_TRACE_COORD=1 \
  "$bin" renew_test::startup_cost_runs --exact --ignored --nocapture --test-threads 1 >"$log" 2>&1
status=$?
cat "$log"
proof_lock_end
trap - EXIT
echo "startup-cost end $(date '+%Y-%m-%dT%H:%M:%S%z') exit ${status} log ${log}"
if [[ "$status" -ne 0 ]]; then
  echo "The start-up cost gate failed (see the test output above)."
  exit 1
fi
echo "proof_ok"

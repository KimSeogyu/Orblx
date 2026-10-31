#!/usr/bin/env bash
# W25-33: coordinator leaf soak at the default lives (rc.3 required row).
# The script runs scripts/proof/ticket-renewal.sh (PR #124) with the node leaf life
# MAX_USER_TTL (the default) and with enough ticket ends to run SOAK_S seconds or more from the
# coordinator start. The coordinator leaf life is MAX_USER_TTL. The proof does not change it.
# While ticket-renewal.sh runs, this script follows the coordinator log (docker logs -f, read
# only) into a file of its own.
# Gates:
#  1. ticket-renewal.sh passes (proof_ok): proof_compose_clean, 0 refusals ("leaf check
#     failed", "capability ticket check rejected", "The end time has passed"), 0 lost peers,
#     per-end gap lines, no restart, 0 contended samples.
#  2. The coordinator crosses SOAK_COORD_ENDS or more ends of its own leaf. An end is a
#     "coord svid expiry" or "coord svid renewed, new expiry" value E with E + MAX_SKEW before
#     the run end (run_end_unix of ticket-renewal.sh: the end of the pings and status samples).
#  3. 0 "coord handshake failed" lines and 0 "coord svid renewal failed" lines.
#  4. The run is SOAK_S seconds or more from the coordinator start to the run end.
# Each gate value prints, also when the proof fails.
# The script does not print tokens, keys, tickets, or bundles. It reads only coordinator
# lines that it selects by name.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
TR_SCRIPT="scripts/proof/ticket-renewal.sh"
CLOCK="crates/orblx-identity/src/clock.rs"
SOAK_S="${SOAK_S:-7200}"
SOAK_COORD_ENDS="${SOAK_COORD_ENDS:-3}"
export TR_PROJECT="${SOAK_PROJECT:-orblx-ccsoak}"
export TR_IMAGE="${SOAK_IMAGE:-orblx-ccsoak:local}"
export TR_NET="${SOAK_NET:-172.28.49}"
export TR_REVOKE="${SOAK_REVOKE:-0}"
export TR_BIN="${SOAK_BIN:-${TR_BIN:-}}"
WORK="$(mktemp -d /tmp/orblx-ccsoak.XXXXXX)"
COORD_LOG="$WORK/coord.log"
FOLLOW_PID=""
TR_PID=""

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

cleanup() {
  [[ -n "$FOLLOW_PID" ]] && kill "$FOLLOW_PID" >/dev/null 2>&1 || true
  [[ -n "$TR_PID" ]] && kill "$TR_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
if [[ ! -f "$TR_SCRIPT" ]]; then
  echo "FAIL: ${TR_SCRIPT} is missing. This proof needs PR #124 (W25-26)." >&2
  rm -rf "$WORK"
  exit 2
fi

# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
# The soak holds the lock. ticket-renewal.sh sees ORBLX_PROOF_LOCK_HELD and runs under it.
proof_lock_take "coord-cert-soak" "$TR_PROJECT"

clock_secs() {
  local name="$1" expr
  expr="$(sed -n "s/^pub const ${name}: Duration = Duration::from_secs(\([0-9 *]*\));\$/\1/p" "$CLOCK")"
  [[ -n "$expr" ]] || fail "${name} is not in ${CLOCK}."
  echo $(( expr ))
}

SKEW="$(clock_secs MAX_SKEW)"
TTL="$(clock_secs MAX_USER_TTL)"
export TR_SVID_TTL="$TTL"
PERIOD=$(( TTL - TTL / 3 ))
# ticket-renewal.sh ends the run at: first ticket end + (TR_ENDS - 1) * PERIOD + SKEW + 5 s.
# The first ticket end is about TTL s after the coordinator start.
ends_for_soak=$(( (SOAK_S - TTL - SKEW - 5 + PERIOD - 1) / PERIOD + 1 ))
# The coordinator leaf ends at TTL, then each PERIOD s, so its end K + MAX_SKEW comes at about
# TTL + (K - 1) * PERIOD + SKEW. The first ticket end comes after the first coordinator leaf end
# (the nodes enroll after the coordinator start), so TR_ENDS = K is enough for K ends.
ends_for_coord=$(( SOAK_COORD_ENDS ))
TR_ENDS="${SOAK_TR_ENDS:-$(( ends_for_soak > ends_for_coord ? ends_for_soak : ends_for_coord ))}"
(( TR_ENDS >= 2 )) || TR_ENDS=2
export TR_ENDS
echo "=== [C] coord-cert-soak constants ==="
echo "max_skew_s ${SKEW} max_user_ttl_s ${TTL} node_svid_ttl_s ${TR_SVID_TTL} coord_svid_ttl_s ${TTL}"
echo "soak_s ${SOAK_S} soak_coord_ends ${SOAK_COORD_ENDS} tr_ends ${TR_ENDS} project ${TR_PROJECT}"

coord_container() {
  docker ps -q --filter "label=com.docker.compose.project=${TR_PROJECT}" \
    --filter "label=com.docker.compose.service=coord" 2>/dev/null || true
}

echo "=== [C] run ${TR_SCRIPT} ==="
bash "$TR_SCRIPT" > "$WORK/tr.log" 2>&1 &
TR_PID="$!"
# proof_compose_clean in ticket-renewal.sh removes an old stack. Follow only a coordinator
# container that starts after the proof says "start coordinator".
followed=""
while kill -0 "$TR_PID" >/dev/null 2>&1; do
  if [[ -z "$followed" ]] && read_all grep -q "start coordinator" < "$WORK/tr.log"; then
    id="$(coord_container)"
    if [[ -n "$id" ]]; then
      docker logs -f -t "$id" > "$COORD_LOG" 2>&1 &
      FOLLOW_PID="$!"
      followed="$id"
      echo "coord_log_follow container ${id:0:12}"
    fi
  fi
  sleep 2
done
tr_status=0
wait "$TR_PID" || tr_status=$?
TR_PID=""
if [[ -n "$FOLLOW_PID" ]]; then
  kill "$FOLLOW_PID" >/dev/null 2>&1 || true
  wait "$FOLLOW_PID" 2>/dev/null || true
  FOLLOW_PID=""
fi
sed 's/^/tr | /' "$WORK/tr.log"
echo "tr_exit ${tr_status}"

echo "=== gates ==="
RUN_END="$(awk '/^renew_period_s .* run_end_unix [0-9]+ / && !f {for (i = 1; i < NF; i++) if ($i == "run_end_unix") print $(i + 1); f = 1}' "$WORK/tr.log")"
[[ -n "$RUN_END" ]] || fail "ticket-renewal.sh printed no run_end_unix."
[[ -s "$COORD_LOG" ]] || fail "No coordinator log. The proof did not start the coordinator."
coord_start_utc="$(awk '/ coord listen / && !f {print $1; f = 1}' "$COORD_LOG")"
[[ -n "$coord_start_utc" ]] || fail "The coordinator log has no 'coord listen' line."
coord_start="$(date -d "$coord_start_utc" +%s)"
soak_run_s=$(( RUN_END - coord_start ))
ends="$(awk -v e="$RUN_END" -v s="$SKEW" '
  / coord svid expiry [0-9]+$/ || / coord svid renewed, new expiry [0-9]+$/ {
    v = $NF; if (!(v in seen)) { seen[v] = 1; if (v + s < e + 0) n++ }
  }
  END {print n + 0}' "$COORD_LOG")"
renewals="$(awk '/ coord svid renewed, new expiry / {n++} END {print n + 0}' "$COORD_LOG")"
handshake_fail="$(awk '/ coord handshake failed$/ {n++} END {print n + 0}' "$COORD_LOG")"
renew_fail="$(awk '/ coord svid renewal failed/ {n++} END {print n + 0}' "$COORD_LOG")"
echo "coord_start_utc ${coord_start_utc} run_end_unix ${RUN_END} soak_run_s ${soak_run_s}"
echo "coord_svid_ends_crossed ${ends} coord_svid_renewals ${renewals} coord_handshake_failed ${handshake_fail} coord_svid_renewal_failed ${renew_fail}"
(( tr_status == 0 )) || fail "ticket-renewal.sh failed (exit ${tr_status})."
read_all grep -qx "proof_ok" < "$WORK/tr.log" || fail "ticket-renewal.sh has no proof_ok line."
(( handshake_fail == 0 )) || fail "${handshake_fail} coord handshake failed lines."
(( renew_fail == 0 )) || fail "${renew_fail} coord svid renewal failed lines."
(( ends >= SOAK_COORD_ENDS )) || fail "The run crossed ${ends} coordinator leaf ends, not ${SOAK_COORD_ENDS}."
(( soak_run_s >= SOAK_S )) || fail "The run is ${soak_run_s} s from the coordinator start, not ${SOAK_S} s."
echo "proof_ok coord-cert-soak"

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
#     When the log has no "coord svid expiry" line and no "coord svid renewed, new expiry" line,
#     gate 2 prints N/A and does not fail.
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
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before the lock).
trap 'cleanup; proof_lock_end' EXIT
# The soak holds the lock. ticket-renewal.sh sees ORBLX_PROOF_LOCK_HELD and runs under it.
proof_lock_take "coord-cert-soak" "$TR_PROJECT"

clock_secs() {
  local name="$1" expr
  expr="$(sed -n "s/^pub const ${name}: Duration = Duration::from_secs(\([0-9 *]*\));\$/\1/p" "$CLOCK")"
  [[ -n "$expr" ]] || fail "${name} is not in ${CLOCK}."
  echo $(( expr ))
}

# choose_tr_ends ENDS_FOR_SOAK ENDS_FOR_COORD SOAK_TR_ENDS
# SOAK_TR_ENDS is empty when the variable is unset.
# The result is the largest of the three numbers.
# An empty SOAK_TR_ENDS does not enter the comparison.
# SOAK_TR_ENDS must not lower the result below ENDS_FOR_SOAK.
# The result is at least 2.
choose_tr_ends() {
  local ends_for_soak="$1" ends_for_coord="$2" soak_tr_ends="$3" floor tr
  if (( ends_for_soak > ends_for_coord )); then
    floor="$ends_for_soak"
  else
    floor="$ends_for_coord"
  fi
  if [[ -n "$soak_tr_ends" ]]; then
    if (( soak_tr_ends > floor )); then
      tr="$soak_tr_ends"
    else
      tr="$floor"
    fi
  else
    tr="$floor"
  fi
  if (( tr < 2 )); then
    tr=2
  fi
  echo "$tr"
}

SKEW="$(clock_secs MAX_SKEW)"
TTL="$(clock_secs MAX_USER_TTL)"
export TR_SVID_TTL="$TTL"
PERIOD=$(( TTL - TTL / 3 ))
# The first ticket end is about TTL s after the coordinator start.
# ends_for_soak is the smallest count whose period window covers SOAK_S:
# TTL + (count - 1) * PERIOD + MAX_SKEW + 5 >= SOAK_S.
# ticket-renewal.sh uses the ticket life on the last interval.
# That run is longer than this period window, so this count still covers SOAK_S.
ends_for_soak=$(( (SOAK_S - TTL - SKEW - 5 + PERIOD - 1) / PERIOD + 1 ))
# The coordinator leaf ends at TTL, then each PERIOD s, so its end K + MAX_SKEW comes at about
# TTL + (K - 1) * PERIOD + SKEW. The first ticket end comes after the first coordinator leaf end
# (the nodes enroll after the coordinator start), so TR_ENDS = K is enough for K ends.
ends_for_coord=$(( SOAK_COORD_ENDS ))
TR_ENDS="$(choose_tr_ends "$ends_for_soak" "$ends_for_coord" "${SOAK_TR_ENDS:-}")"
export TR_ENDS
echo "=== [C] coord-cert-soak constants ==="
echo "max_skew_s ${SKEW} max_user_ttl_s ${TTL} node_svid_ttl_s ${TR_SVID_TTL} coord_svid_ttl_s ${TTL}"
echo "soak_s ${SOAK_S} soak_coord_ends ${SOAK_COORD_ENDS} ends_for_soak ${ends_for_soak} ends_for_coord ${ends_for_coord} soak_tr_ends ${SOAK_TR_ENDS:-unset} tr_ends ${TR_ENDS} project ${TR_PROJECT}"

# Ask 127.0.0.11 for a name. An answer means the embedded DNS server is up.
# No answer does not fail the run. The stack uses fixed addresses and hosts entries.
preflight_docker_dns() {
  local id="$1"
  if docker exec "$id" python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
q = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 5]) + b"coord" + bytes([0, 0, 1, 0, 1])
try:
    s.sendto(q, ("127.0.0.11", 53))
    s.recv(512)
except Exception:
    sys.exit(1)
' >/dev/null 2>&1; then
    echo "preflight docker_dns ok"
  else
    echo "preflight docker_dns unavailable (not needed: fixed IPs and hosts entries)"
  fi
}

# Each soak service name must resolve inside this container.
preflight_service_names() {
  local id="$1" role="$2" name ip line found first row
  local names=(coord owner a b c)
  local ips=("${TR_NET}.10" "${TR_NET}.20" "${TR_NET}.11" "${TR_NET}.12" "${TR_NET}.13")
  local i
  for i in "${!names[@]}"; do
    name="${names[$i]}"
    ip="${ips[$i]}"
    line="$(timeout 25 docker exec "$id" getent hosts "$name" 2>/dev/null || true)"
    found=0
    while IFS= read -r row || [[ -n "$row" ]]; do
      first="${row%%[[:space:]]*}"
      if [[ -n "$first" && "$first" == "$ip" ]]; then
        found=1
      fi
    done <<< "$line"
    if [[ "$found" -eq 0 ]]; then
      fail "The service name ${name} does not resolve to ${ip} inside the ${role} container."
    fi
  done
}

# The long-running service container. An enroll one-shot uses entrypoint sh.
service_container() {
  local svc="$1" id ep
  for id in $(docker ps -q --filter "label=com.docker.compose.project=${TR_PROJECT}" \
      --filter "label=com.docker.compose.service=${svc}" 2>/dev/null || true); do
    ep="$(docker inspect -f '{{index .Config.Entrypoint 0}}' "$id" 2>/dev/null || true)"
    if [[ "$ep" == /usr/local/bin/orblx-entrypoint ]]; then
      printf '%s\n' "$id"
      return 0
    fi
  done
}

echo "=== [C] run ${TR_SCRIPT} ==="
: > "$WORK/tr.log"
bash "$TR_SCRIPT" > "$WORK/tr.log" 2>&1 &
TR_PID="$!"
# proof_compose_clean in ticket-renewal.sh removes an old stack. Follow only a coordinator
# container that starts after the proof says "start coordinator".
followed=""
declare -A NAME_CHECKED=()
while kill -0 "$TR_PID" >/dev/null 2>&1; do
  if [[ -z "$followed" ]] && read_all grep -q "start coordinator" < "$WORK/tr.log"; then
    id="$(service_container coord)"
    if [[ -n "$id" ]]; then
      preflight_docker_dns "$id"
      preflight_service_names "$id" coord
      NAME_CHECKED[coord]=1
      docker logs -f -t "$id" > "$COORD_LOG" 2>&1 &
      FOLLOW_PID="$!"
      followed="$id"
      echo "coord_log_follow container ${id:0:12}"
    fi
  fi
  # owner, a, b, and c dial with the name coord. Check each one after it starts.
  if read_all grep -q "start owner, a, b, c" < "$WORK/tr.log"; then
    for role in owner a b c; do
      [[ -n "${NAME_CHECKED[$role]:-}" ]] && continue
      id="$(service_container "$role")"
      [[ -z "$id" ]] && continue
      preflight_service_names "$id" "$role"
      NAME_CHECKED[$role]=1
    done
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

# coord_cert_gate2_check LOG ENDS NEED
# N/A when LOG has no coordinator leaf line. Otherwise ENDS must reach NEED.
coord_cert_gate2_check() {
  local log="$1" ends="$2" need="$3" expiry_lines renewed_lines
  expiry_lines="$(awk 'index($0, "coord svid expiry") { n++ } END { print n + 0 }' "$log")"
  renewed_lines="$(awk 'index($0, "coord svid renewed, new expiry") { n++ } END { print n + 0 }' "$log")"
  if (( expiry_lines == 0 && renewed_lines == 0 )); then
    echo "gate2 N/A reason=main_lacks_coord_svid_expiry_lines"
    return 0
  fi
  (( ends >= need )) || fail "The run crossed ${ends} coordinator leaf ends, not ${need}."
}

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
# The product line is "coord handshake failed: <error> remote <address>".
# The phrase stays. The error and the address follow it. Count that line.
handshake_fail="$(awk '/ coord handshake failed/ {n++} END {print n + 0}' "$COORD_LOG")"
renew_fail="$(awk '/ coord svid renewal failed/ {n++} END {print n + 0}' "$COORD_LOG")"
echo "coord_start_utc ${coord_start_utc} run_end_unix ${RUN_END} soak_run_s ${soak_run_s}"
echo "coord_svid_ends_crossed ${ends} coord_svid_renewals ${renewals} coord_handshake_failed ${handshake_fail} coord_svid_renewal_failed ${renew_fail}"
(( tr_status == 0 )) || fail "ticket-renewal.sh failed (exit ${tr_status})."
read_all grep -qx "proof_ok" < "$WORK/tr.log" || fail "ticket-renewal.sh has no proof_ok line."
(( handshake_fail == 0 )) || fail "${handshake_fail} coord handshake failed lines."
(( renew_fail == 0 )) || fail "${renew_fail} coord svid renewal failed lines."
coord_cert_gate2_check "$COORD_LOG" "$ends" "$SOAK_COORD_ENDS"
(( soak_run_s >= SOAK_S )) || fail "The run is ${soak_run_s} s from the coordinator start, not ${SOAK_S} s."
echo "proof_ok coord-cert-soak"

#!/usr/bin/env bash
# W25-26: ticket renewal proof with real coordinator tickets (no lab tickets).
# Nodes owner, a, b, c run `orblx up --coord`. The coordinator issues the leaf and the
# capability ticket with the life ORBLX_SVID_TTL (TR_SVID_TTL). Each node pings each other
# node every TR_PING_I s on the overlay.
# Gates:
#  1. Each node crosses TR_ENDS or more ticket ends + MAX_SKEW in a row.
#  2. 0 refusals ("capability ticket check rejected", "leaf check failed", "The end time has passed").
#  3. 0 lost peers: each status sample shows all 3 peers with path direct.
#  4. The largest gap between two replies of a pair is TR_GAP_MS or less.
#  5. No restart: same container start time, restart count 0, same orblxd pid.
#  6. A new handshake (a to b) after the ticket ends passes.
#  7. (TR_REVOKE=1) A revoked node gets no new ticket, and its peers stop it in TR_REVOKE_MS.
# The proof reads MAX_SKEW and MAX_USER_TTL from clock.rs.
# The waits are a schedule. The proof does not retry a check. A failed check stops the proof.
# The script does not print tokens, keys, tickets, or bundles.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ticket-renewal.yml"
CLOCK="crates/orblx-identity/src/clock.rs"
export TR_PROJECT="${TR_PROJECT:-orblx-w25t-tr}"
export TR_IMAGE="${TR_IMAGE:-orblx-w25t-tr:local}"
export TR_NET="${TR_NET:-172.28.48}"
export TR_SVID_TTL="${TR_SVID_TTL:-60}"
TR_ENDS="${TR_ENDS:-5}"
TR_GAP_MS="${TR_GAP_MS:-200}"
TR_PING_I="${TR_PING_I:-0.05}"
TR_REVOKE="${TR_REVOKE:-1}"
TR_REVOKE_MS="${TR_REVOKE_MS:-1000}"
TR_BIN="${TR_BIN:-}"
COORD="${TR_NET}.10:443"
NODES=(owner a b c)
declare -A NODE_IP=([owner]="${TR_NET}.20" [a]="${TR_NET}.11" [b]="${TR_NET}.12" [c]="${TR_NET}.13")
WORK="$(mktemp -d /tmp/orblx-tr.XXXXXX)"
export TR_POLICY="$WORK/policy.hujson"
PING_PIDS=()
REFUSAL='capability ticket check rejected|leaf check failed|The end time has passed'

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  local pid
  for pid in "${PING_PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs, last 80 lines per service (the proof failed) ----"
    dc logs -t --tail 80 2>&1 | sed 's/[A-Za-z0-9_-]\{40,\}/<redacted>/g' || true
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ticket-renewal" "$TR_PROJECT"

# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${TR_PROJECT}" || exit 1

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

clock_secs() {
  local name="$1" expr
  expr="$(sed -n "s/^pub const ${name}: Duration = Duration::from_secs(\([0-9 *]*\));\$/\1/p" "$CLOCK")"
  [[ -n "$expr" ]] || fail "${name} is not in ${CLOCK}."
  echo $(( expr ))
}

now_s() {
  date +%s.%N
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir bin="$TR_BIN"
  if [[ -z "$bin" ]]; then
    cargo build -p orblx-cli --bin orblx --locked
    bin="$ROOT/target/debug/orblx"
  fi
  [[ -x "$bin" ]] || fail "The orblx binary ${bin} is missing."
  echo "orblx_bin_sha256 $(sha256sum "$bin" | awk '{print $1}')"
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t "$TR_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

wait_log() {
  local service="$1" needle="$2" limit="$3" since="${4:-}" i
  for ((i = 0; i < limit * 2; i++)); do
    if dc logs ${since:+--since "$since"} "$service" 2>&1 | read_all grep -q -- "$needle"; then
      return 0
    fi
    sleep 0.5
  done
  fail "The ${service} log has no line '${needle}' after ${limit} s."
}

status_of() {
  dc exec -T "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

direct_peers() {
  status_of "$1" | read_all awk '$1 == "peer" && $6 == "direct" {n++} END {print n + 0}'
}

overlay_of() {
  status_of owner | read_all awk -v p="$1" '$1 == "overlay_ip" && p == "owner" {print $2; exit} $1 == "peer" && $2 == p {print $4; exit}'
}

ticket_sha() {
  dc exec -T "$1" sha256sum /var/lib/orblx/ticket.bin | awk '{print substr($1, 1, 16)}'
}

started_of() {
  docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$(dc ps -q "$1")"
}

pid_of() {
  dc exec -T "$1" cat /var/lib/orblx/orblxd.pid 2>/dev/null | tr -d '\n' || true
}

# Print the first refusal line with its time, and fail.
check_refusals() {
  local hits first
  hits="$(dc logs -t "${NODES[@]}" 2>&1 | read_all grep -cE -- "$REFUSAL" || true)"
  if [[ "${hits:-0}" -ne 0 ]]; then
    first="$(dc logs -t "${NODES[@]}" 2>&1 | read_all grep -E -- "$REFUSAL" | sort -k3,3 | sed -n 1p)"
    echo "refusals ${hits}"
    echo "first_refusal ${first}"
    report_first_refusal "$first"
    fail "A peer refused a node that renews."
  fi
}

report_first_refusal() {
  local line="$1" ts at
  ts="$(printf '%s\n' "$line" | awk '{print $3}')"
  at="$(date -d "$ts" +%s.%N 2>/dev/null || echo "")"
  [[ -n "$at" ]] || return 0
  echo "first_refusal_after_first_enroll_s $(awk -v a="$at" -v e="$FIRST_ENROLL" 'BEGIN {printf "%.1f", a - e}')"
  echo "first_refusal_after_first_ticket_end_s $(awk -v a="$at" -v e="$FIRST_END" 'BEGIN {printf "%.1f", a - e}')"
}

echo "=== [C] constants from ${CLOCK} ==="
SKEW="$(clock_secs MAX_SKEW)"
MAX_USER="$(clock_secs MAX_USER_TTL)"
echo "max_skew_s ${SKEW}"
echo "max_user_ttl_s ${MAX_USER}"
echo "svid_ttl_s ${TR_SVID_TTL} ticket_ends ${TR_ENDS} gap_limit_ms ${TR_GAP_MS} ping_interval_s ${TR_PING_I}"
if (( TR_SVID_TTL < 30 || TR_SVID_TTL > MAX_USER )); then
  fail "TR_SVID_TTL must be from 30 to ${MAX_USER} seconds."
fi
# The node renews at two thirds of the life, so a new ticket comes each PERIOD seconds.
PERIOD=$(( TR_SVID_TTL - TR_SVID_TTL / 3 ))

cp "$ROOT/scripts/proof/ticket-renewal.hujson" "$TR_POLICY"
chmod 644 "$TR_POLICY"

echo "=== [C] remove old proof stack ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward

echo "=== [C] build image ${TR_IMAGE} ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
for ((i = 0; i < 60; i++)); do
  dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem && break
  sleep 0.5
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "The coordinator did not write the trust bundle."

FIRST_ENROLL=""
declare -A ENROLL_SHA
for name in "${NODES[@]}"; do
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 \
    --out "/var/lib/orblx/tokens/${name}" >/dev/null
  echo "=== [C] enroll ${name} ==="
  [[ -n "$FIRST_ENROLL" ]] || FIRST_ENROLL="$(now_s)"
  dc run --rm --no-deps --entrypoint sh "$name" -c \
    "rm -rf /var/lib/orblx/* && orblx coord enroll --name ${name} --coord ${COORD} --coord-name coord --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint ${NODE_IP[$name]}:443" \
    | read_all grep -E '^(enrolled|name|overlay_ip|svid) ' || fail "The enroll of ${name} failed."
done
FIRST_END="$(awk -v e="$FIRST_ENROLL" -v t="$TR_SVID_TTL" 'BEGIN {printf "%.3f", e + t}')"

echo "=== [C] start owner, a, b, c ==="
dc up -d "${NODES[@]}"
for name in "${NODES[@]}"; do
  wait_log "$name" "The TUN device" 30
done
for name in "${NODES[@]}"; do
  for ((i = 0; i < 60; i++)); do
    [[ "$(direct_peers "$name")" -eq 3 ]] && break
    sleep 0.5
  done
  [[ "$(direct_peers "$name")" -eq 3 ]] || fail "The node ${name} has no direct path to 3 peers after 30 s."
  ENROLL_SHA[$name]="$(ticket_sha "$name")"
done

declare -A OVERLAY START0 PID0 E0
for name in "${NODES[@]}"; do
  OVERLAY[$name]="$(overlay_of "$name")"
  [[ -n "${OVERLAY[$name]}" ]] || fail "No overlay IP for ${name}."
  START0[$name]="$(started_of "$name")"
  PID0[$name]="$(pid_of "$name")"
  E0[$name]="$(status_of "$name" | read_all awk '$1 == "svid_expiry" && !f {print $2; f = 1}')"
  [[ -n "${E0[$name]}" ]] || fail "No svid_expiry for ${name}."
  echo "node ${name} overlay ${OVERLAY[$name]} pid ${PID0[$name]} svid_expiry ${E0[$name]}"
done

# The run ends TR_ENDS ticket ends + MAX_SKEW + 5 s after the latest first ticket end.
max_e0=0
for name in "${NODES[@]}"; do
  if (( E0[$name] > max_e0 )); then
    max_e0="${E0[$name]}"
  fi
done
RUN_END=$(( max_e0 + (TR_ENDS - 1) * PERIOD + SKEW + 5 ))
PING_SECS=$(( RUN_END - $(date +%s) + 3 ))
echo "renew_period_s ${PERIOD} run_end_unix ${RUN_END} ping_s ${PING_SECS}"

echo "=== [C] ping each pair every ${TR_PING_I} s for ${PING_SECS} s ==="
for src in "${NODES[@]}"; do
  for dst in "${NODES[@]}"; do
    [[ "$src" == "$dst" ]] && continue
    dc exec -T "$src" ping -D -n -i "$TR_PING_I" -w "$PING_SECS" "${OVERLAY[$dst]}" \
      > "$WORK/ping-${src}-${dst}.txt" 2>&1 &
    PING_PIDS+=("$!")
  done
done

echo "=== [C] sample the status of each node every 2 s ==="
lost=0
samples=0
declare -A EXPIRIES
tick=0
while (( $(date +%s) < RUN_END )); do
  for name in "${NODES[@]}"; do
    st="$(status_of "$name")"
    e="$(printf '%s\n' "$st" | awk '$1 == "svid_expiry" && !f {print $2; f = 1}')"
    [[ -z "$e" ]] || EXPIRIES[$name]="$(printf '%s\n%s\n' "${EXPIRIES[$name]:-}" "$e" | awk 'NF' | sort -u | tr '\n' ' ')"
    n="$(printf '%s\n' "$st" | awk '$1 == "peer" && $6 == "direct" {n++} END {print n + 0}')"
    samples=$((samples + 1))
    if [[ "$n" -ne 3 ]]; then
      lost=$((lost + 1))
      echo "lost_peer_sample $(date +%T.%N | cut -c1-12) node ${name} direct ${n}"
      printf '%s\n' "$st" | awk '$1 == "peer" {print "  " $2, $5, $6}'
    fi
  done
  tick=$((tick + 1))
  if (( tick % 5 == 0 )); then
    check_refusals
  fi
  sleep 2
done
echo "=== [C] wait for the ping runs to end ==="
for pid in "${PING_PIDS[@]}"; do
  wait "$pid" || true
done
PING_PIDS=()
check_refusals
echo "refusals 0"
echo "status_samples ${samples} lost_peer_samples ${lost}"

echo "=== gate 1: ticket ends crossed ==="
for name in "${NODES[@]}"; do
  crossed=0
  for e in ${EXPIRIES[$name]}; do
    if (( e + SKEW < RUN_END )); then
      crossed=$((crossed + 1))
    fi
  done
  renewed="$(dc logs "$name" 2>&1 | read_all grep -c "The node renewed the SVID" || true)"
  sha_now="$(ticket_sha "$name")"
  echo "node ${name} ticket_ends_crossed ${crossed} renewals ${renewed} svid_expiries ${EXPIRIES[$name]}"
  echo "node ${name} ticket_changed $([[ "$sha_now" != "${ENROLL_SHA[$name]}" ]] && echo yes || echo no)"
  (( crossed >= TR_ENDS )) || fail "The node ${name} crossed ${crossed} ticket ends. The gate is ${TR_ENDS}."
  [[ "$sha_now" != "${ENROLL_SHA[$name]}" ]] || fail "The node ${name} has the ticket from enroll."
done

echo "=== gate 3: lost peers ==="
(( lost == 0 )) || fail "${lost} status samples show a lost peer."

echo "=== gate 4: reply gaps ==="
worst=0
for src in "${NODES[@]}"; do
  for dst in "${NODES[@]}"; do
    [[ "$src" == "$dst" ]] && continue
    f="$WORK/ping-${src}-${dst}.txt"
    read -r got gap last < <(awk '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (p != "") {d = (ts - p) * 1000; if (d > m) m = d}; p = ts; n++} END {printf "%d %.0f %.3f\n", n, m, p}' "$f")
    loss="$(awk '/packet loss/ {for (i = 1; i <= NF; i++) if ($i ~ /%$/) print $i}' "$f")"
    echo "pair ${src}->${dst} replies ${got} loss ${loss:-none} max_gap_ms ${gap} last_reply_before_end_s $(awk -v l="$last" -v e="$RUN_END" 'BEGIN {printf "%.1f", e - l}')"
    if (( gap > worst )); then
      worst="$gap"
    fi
    (( got > 0 )) || fail "No reply on ${src}->${dst}."
    awk -v l="$last" -v e="$RUN_END" 'BEGIN {exit !(l + 0 >= e - 3)}' || fail "The pair ${src}->${dst} stopped before the run end."
  done
done
echo "max_gap_ms_all_pairs ${worst} limit_ms ${TR_GAP_MS}"
(( worst <= TR_GAP_MS )) || fail "A reply gap of ${worst} ms is above ${TR_GAP_MS} ms."

echo "=== gate 5: no restart ==="
for name in "${NODES[@]}"; do
  s="$(started_of "$name")"
  p="$(pid_of "$name")"
  echo "node ${name} started ${s} pid ${p}"
  [[ "$s" == "${START0[$name]}" && "$p" == "${PID0[$name]}" ]] || fail "The node ${name} restarted."
  [[ "${s##* }" == "0" ]] || fail "The node ${name} has a restart count."
done

echo "=== gate 6: a new handshake a->b after the ticket ends ==="
cut_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
dc exec -T a iptables -I OUTPUT -d "${NODE_IP[b]}" -p udp -j DROP
dc exec -T a iptables -I INPUT -s "${NODE_IP[b]}" -p udp -j DROP
wait_log a "The path to b is down" 90 "$cut_at"
heal_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
dc exec -T a iptables -D OUTPUT -d "${NODE_IP[b]}" -p udp -j DROP
dc exec -T a iptables -D INPUT -s "${NODE_IP[b]}" -p udp -j DROP
wait_log a "The path to b is direct" 30 "$heal_at"
hs_out="$(dc exec -T a ping -n -c 5 -i 0.2 "${OVERLAY[b]}" 2>&1 || true)"
printf '%s\n' "$hs_out" | read_all grep "packet loss" | sed 's/^/new_handshake_a_b /'
printf '%s\n' "$hs_out" | read_all grep -q " 0% packet loss" || fail "The new handshake a->b has packet loss."
check_refusals

if [[ "$TR_REVOKE" == "1" ]]; then
  echo "=== gate 7: a revoked node gets no new ticket and loses its peers ==="
  c_sha="$(ticket_sha c)"
  for src in owner a b; do
    dc exec -T "$src" ping -D -n -i "$TR_PING_I" -w 8 "${OVERLAY[c]}" > "$WORK/rv-${src}.txt" 2>&1 &
    PING_PIDS+=("$!")
  done
  sleep 2
  revoked_at_utc="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  revoke_start="$(now_s)"
  dc exec -T owner orblx admin revoke c --coord "$COORD" --coord-name coord \
    --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem | sed 's/^/revoke_c /'
  for pid in "${PING_PIDS[@]}"; do
    wait "$pid" || true
  done
  PING_PIDS=()
  for src in owner a b; do
    before="$(awk -v r="$revoke_start" '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (ts + 0 < r + 0) n++} END {print n + 0}' "$WORK/rv-${src}.txt")"
    last="$(awk '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); v = ts} END {print v}' "$WORK/rv-${src}.txt")"
    ms="$(awk -v l="$last" -v r="$revoke_start" 'BEGIN {printf "%.0f", (l - r) * 1000}')"
    echo "revoke ${src}->c replies_before ${before} last_reply_after_revoke_ms ${ms} limit_ms ${TR_REVOKE_MS}"
    (( before > 0 )) || fail "No reply ${src}->c before the revoke."
    (( ms <= TR_REVOKE_MS )) || fail "${src} reached c ${ms} ms after the revoke."
  done
  wait_log c "The SVID renewal failed" "$(( PERIOD + 40 ))" "$revoked_at_utc"
  if dc logs --since "$revoked_at_utc" c 2>&1 | read_all grep -q "The node renewed the SVID"; then
    fail "The revoked node c renewed."
  fi
  [[ "$(ticket_sha c)" == "$c_sha" ]] || fail "The revoked node c has a new ticket."
  echo "revoked_c new_ticket no renew_refused yes"
fi

dc logs > "$WORK/stack.log" 2>&1
secret_scan "$WORK/stack.log"

echo "proof_ok"

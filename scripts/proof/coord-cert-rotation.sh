#!/usr/bin/env bash
# W25-33 gate d: a node that is offline across a coordinator leaf rotation comes back, renews,
# and reaches its peers. A late node enrolls after the first coordinator leaf end.
# The stack is the W25-26 ticket renewal stack (scripts/proof/compose.ticket-renewal.yml, PR #124)
# with the default lives: node leaf, ticket, and coordinator leaf MAX_USER_TTL (clock.rs).
# t = 0 is the coordinator start. The coordinator renews its leaf at 2/3 of the life.
# Steps:
#  1. Enroll owner, a and b. Start them. Each lists 2 peers and has a direct path to them.
#  2. Stop b (docker compose stop). b is offline.
#  3. Wait for the coordinator line "coord svid renewed". Then start b.
#     Gate d1: b logs "The node renewed the SVID" after its start, in RT_RENEW_S s.
#     Gate d2: b has a direct path to owner and a, and 5 pings each way have 0% loss.
#  4. Wait until the first coordinator leaf end + MAX_SKEW + 5 s. Enroll c and start it.
#     Gate d3: the enroll passes. Each of the 4 nodes lists 3 peers with a direct path, and
#     5 pings each way between c and each other node have 0% loss.
# Gates for the whole run:
#  5. 0 refusals on the nodes ("capability ticket check rejected", "leaf check failed",
#     "The end time has passed").
#  6. 0 "coord handshake failed" and 0 "coord svid renewal failed" lines. 1 or more
#     "coord svid renewed" lines. The coordinator, owner and a did not restart.
#  7. owner <-> a: a ping each RT_PING_I s for the whole run. 0 lost peer samples (owner and
#     a each show the other direct in each 2 s sample) and replies to the run end.
#  8. 0 contended samples (proof-lock sampler).
# The script does not print tokens, keys, tickets, or bundles.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ticket-renewal.yml"
CLOCK="crates/orblx-identity/src/clock.rs"
if [[ ! -f "$FILE" || ! -f "scripts/proof/ticket-renewal.hujson" ]]; then
  echo "FAIL: ${FILE} or scripts/proof/ticket-renewal.hujson is missing. This proof needs PR #124 (W25-26)." >&2
  exit 2
fi
export TR_PROJECT="${RT_PROJECT:-orblx-ccrot}"
export TR_IMAGE="${RT_IMAGE:-orblx-ccrot:local}"
export TR_NET="${RT_NET:-172.28.50}"
RT_BIN="${RT_BIN:-}"
RT_RENEW_S="${RT_RENEW_S:-90}"
RT_PING_I="${RT_PING_I:-0.2}"
COORD="${TR_NET}.10:443"
declare -A NODE_IP=([owner]="${TR_NET}.20" [a]="${TR_NET}.11" [b]="${TR_NET}.12" [c]="${TR_NET}.13")
WORK="$(mktemp -d /tmp/orblx-ccrot.XXXXXX)"
export TR_POLICY="$WORK/policy.hujson"
PING_PIDS=()
REFUSAL='capability ticket check rejected|leaf check failed|The end time has passed'

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$? pid
  for pid in "${PING_PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs, last 60 lines per service (the proof failed) ----"
    dc logs -t --tail 60 2>&1 | sed 's/[A-Za-z0-9_-]\{40,\}/<redacted>/g' || true
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "coord-cert-rotation" "$TR_PROJECT"

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
  local image_dir bin="$RT_BIN"
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

# wait_log SERVICE NEEDLE LIMIT_S [SINCE]: return 1 when the line does not come in time.
wait_log() {
  local service="$1" needle="$2" limit="$3" since="${4:-}" i
  for ((i = 0; i < limit * 2; i++)); do
    if dc logs ${since:+--since "$since"} "$service" 2>&1 | read_all grep -q -- "$needle"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

status_of() {
  dc exec -T "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

listed_peers() {
  status_of "$1" | read_all awk '$1 == "peer" {n++} END {print n + 0}'
}

direct_peers() {
  status_of "$1" | read_all awk '$1 == "peer" && $6 == "direct" {n++} END {print n + 0}'
}

# direct_to NODE PEER: print 1 when NODE shows PEER with path direct.
direct_to() {
  status_of "$1" | read_all awk -v p="$2" '$1 == "peer" && $2 == p && $6 == "direct" {n = 1} END {print n + 0}'
}

overlay_of() {
  status_of owner | read_all awk -v p="$1" '$1 == "overlay_ip" && p == "owner" && !f {print $2; f = 1} $1 == "peer" && $2 == p && !g {print $4; g = 1}'
}

expiry_of() {
  status_of "$1" | read_all awk '$1 == "svid_expiry" && !f {print $2; f = 1}'
}

started_of() {
  docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$(dc ps -q "$1")"
}

pid_of() {
  dc exec -T "$1" cat /var/lib/orblx/orblxd.pid 2>/dev/null | tr -d '\n' || true
}

poke_peers() {
  local name="$1" ip
  for ip in $(status_of "$name" | read_all awk '$1 == "peer" {print $4}'); do
    dc exec -T "$name" ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
  done
}

# wait_mesh NODE COUNT: NODE lists COUNT peers, each with a direct path.
wait_mesh() {
  local name="$1" want="$2" i n
  for ((i = 0; i < 120; i++)); do
    [[ "$(listed_peers "$name")" -eq "$want" ]] && break
    sleep 0.5
  done
  n="$(listed_peers "$name")"
  echo "netmap_peers ${name} ${n}"
  [[ "$n" -eq "$want" ]] || fail "The node ${name} lists ${n} peers from the netmap after 60 s, not ${want}."
  for ((i = 0; i < 30; i++)); do
    poke_peers "$name"
    [[ "$(direct_peers "$name")" -eq "$want" ]] && break
    sleep 0.5
  done
  n="$(direct_peers "$name")"
  echo "direct_peers ${name} ${n}"
  [[ "$n" -eq "$want" ]] || fail "The node ${name} has a direct path to ${n} peers, not ${want}."
}

# ping_gate SRC DST: 5 pings, 0% loss.
ping_gate() {
  local out
  out="$(dc exec -T "$1" ping -n -c 5 -i 0.2 -W 2 "${OVERLAY[$2]}" 2>&1 || true)"
  printf '%s\n' "$out" | read_all grep "packet loss" | sed "s/^/ping $1->$2 /"
  printf '%s\n' "$out" | read_all grep -q " 0% packet loss" || fail "The ping $1->$2 has packet loss."
}

enroll() {
  local name="$1"
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 \
    --out "/var/lib/orblx/tokens/${name}" >/dev/null
  echo "=== [C] enroll ${name} ==="
  dc run --rm --no-deps --entrypoint sh "$name" -c \
    "rm -rf /var/lib/orblx/* && orblx coord enroll --name ${name} --coord ${COORD} --coord-name coord --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint ${NODE_IP[$name]}:443" \
    | read_all grep -E '^(enrolled|name|overlay_ip|svid) ' || fail "The enroll of ${name} failed."
}

coord_lines() {
  dc logs -t --no-log-prefix coord 2>&1 | read_all awk -v re="$1" '$0 ~ re'
}

echo "=== [C] constants from ${CLOCK} ==="
SKEW="$(clock_secs MAX_SKEW)"
TTL="$(clock_secs MAX_USER_TTL)"
export TR_SVID_TTL="$TTL"
echo "max_skew_s ${SKEW} max_user_ttl_s ${TTL} node_svid_ttl_s ${TR_SVID_TTL} coord_svid_ttl_s ${TTL}"

cp "$ROOT/scripts/proof/ticket-renewal.hujson" "$TR_POLICY"
chmod 644 "$TR_POLICY"
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
COORD_START0="$(started_of coord)"
FIRST_COORD_END="$(coord_lines ' coord svid expiry [0-9]+$' | read_all awk '!f {print $NF; f = 1}')"
[[ -n "$FIRST_COORD_END" ]] || fail "The coordinator log has no 'coord svid expiry' line."
echo "coord_first_svid_expiry ${FIRST_COORD_END} coord_start ${COORD_START0}"

declare -A OVERLAY START0 PID0
for name in owner a b; do
  enroll "$name"
done
for name in owner a b; do
  dc up -d "$name"
  wait_log "$name" "The TUN device" 30 || fail "The node ${name} did not start."
  wait_mesh "$name" 2
done
for name in owner a b; do
  OVERLAY[$name]="$(overlay_of "$name")"
  [[ -n "${OVERLAY[$name]}" ]] || fail "No overlay IP for ${name}."
  START0[$name]="$(started_of "$name")"
  PID0[$name]="$(pid_of "$name")"
done
B_EXPIRY0="$(expiry_of b)"
echo "node b svid_expiry ${B_EXPIRY0}"

echo "=== [C] ping owner <-> a every ${RT_PING_I} s for the whole run ==="
PING_SECS=$(( FIRST_COORD_END + SKEW + 240 - $(date +%s) ))
dc exec -T owner ping -D -n -i "$RT_PING_I" -w "$PING_SECS" "${OVERLAY[a]}" > "$WORK/ping-owner-a.txt" 2>&1 &
PING_PIDS+=("$!")
dc exec -T a ping -D -n -i "$RT_PING_I" -w "$PING_SECS" "${OVERLAY[owner]}" > "$WORK/ping-a-owner.txt" 2>&1 &
PING_PIDS+=("$!")

lost=0
samples=0
sample_owner_a() {
  local n m
  n="$(direct_to owner a)"
  m="$(direct_to a owner)"
  samples=$((samples + 1))
  if [[ "$n" -ne 1 || "$m" -ne 1 ]]; then
    lost=$((lost + 1))
    echo "lost_peer_sample $(date +%T.%N | cut -c1-12) owner->a ${n} a->owner ${m}"
  fi
}

echo "=== [C] step 2: stop b ==="
dc stop b >/dev/null
b_stop="$(date +%s)"
echo "b_stopped_unix ${b_stop}"

echo "=== [C] step 3: wait for the coordinator leaf rotation ==="
rotation=""
while [[ -z "$rotation" ]]; do
  rotation="$(coord_lines ' coord svid renewed, new expiry [0-9]+$' | read_all awk '!f {print $1; f = 1}')"
  [[ -n "$rotation" ]] && break
  (( $(date +%s) < FIRST_COORD_END )) || fail "The coordinator did not renew its leaf before its end."
  sample_owner_a
  sleep 2
done
echo "coord_rotation_utc ${rotation}"
(( $(date +%s) < B_EXPIRY0 )) || fail "The leaf of b ended while b was offline. The proof needs b with a good leaf."
b_start_utc="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
dc start b >/dev/null
echo "b_started_unix $(date +%s) offline_s $(( $(date +%s) - b_stop ))"
wait_log b "The node renewed the SVID" "$RT_RENEW_S" "$b_start_utc" \
  || fail "gate d1: b did not renew in ${RT_RENEW_S} s after it came back."
B_EXPIRY1="$(expiry_of b)"
echo "gate_d1 b_renewed yes svid_expiry ${B_EXPIRY0} -> ${B_EXPIRY1}"
(( B_EXPIRY1 > B_EXPIRY0 )) || fail "gate d1: the svid_expiry of b did not move."
wait_mesh b 2
for peer in owner a; do
  ping_gate b "$peer"
  ping_gate "$peer" b
done
echo "gate_d2 b_reaches_peers yes"

echo "=== [C] step 4: wait for the first coordinator leaf end + skew ==="
until (( $(date +%s) > FIRST_COORD_END + SKEW + 5 )); do
  sample_owner_a
  sleep 2
done
echo "after_first_coord_end_plus_skew_unix $(date +%s)"
enroll c
dc up -d c
wait_log c "The TUN device" 30 || fail "The node c did not start."
for name in c owner a b; do
  wait_mesh "$name" 3
done
OVERLAY[c]="$(overlay_of c)"
[[ -n "${OVERLAY[c]}" ]] || fail "No overlay IP for c."
for peer in owner a b; do
  ping_gate c "$peer"
  ping_gate "$peer" c
done
echo "gate_d3 late_c_enrolled yes reaches_peers yes"

echo "=== [C] wait for the owner <-> a ping runs to end ==="
while (( $(date +%s) < FIRST_COORD_END + SKEW + 240 )); do
  sample_owner_a
  sleep 2
done
for pid in "${PING_PIDS[@]}"; do
  wait "$pid" || true
done
PING_PIDS=()
RUN_END="$(date +%s)"

echo "=== gate 5: refusals ==="
hits="$(dc logs -t owner a b c 2>&1 | read_all awk -v re="$REFUSAL" '$0 ~ re {n++} END {print n + 0}')"
echo "refusals ${hits}"

echo "=== gate 6: coordinator ==="
hs="$(coord_lines ' coord handshake failed$' | read_all awk 'END {print NR + 0}')"
rf="$(coord_lines ' coord svid renewal failed' | read_all awk 'END {print NR + 0}')"
rn="$(coord_lines ' coord svid renewed, new expiry ' | read_all awk 'END {print NR + 0}')"
echo "coord_handshake_failed ${hs} coord_svid_renewal_failed ${rf} coord_svid_renewals ${rn}"
COORD_NOW="$(started_of coord)"
echo "coord started ${COORD_NOW}"
LATE_FAIL=()
(( hits == 0 )) || LATE_FAIL+=("${hits} refusals.")
(( hs == 0 && rf == 0 )) || LATE_FAIL+=("${hs} coord handshake failed and ${rf} coord svid renewal failed lines.")
(( rn >= 1 )) || LATE_FAIL+=("The coordinator did not renew its leaf.")
[[ "$COORD_NOW" == "$COORD_START0" && "${COORD_NOW##* }" == "0" ]] || LATE_FAIL+=("The coordinator restarted.")
for name in owner a; do
  s="$(started_of "$name")"
  p="$(pid_of "$name")"
  echo "node ${name} started ${s} pid ${p}"
  [[ "$s" == "${START0[$name]}" && "$p" == "${PID0[$name]}" && "${s##* }" == "0" ]] || LATE_FAIL+=("The node ${name} restarted.")
done

echo "=== gate 7: owner <-> a ==="
for pair in owner-a a-owner; do
  f="$WORK/ping-${pair}.txt"
  read -r got gap last < <(awk '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (p != "") {d = (ts - p) * 1000; if (d > m) m = d}; p = ts; n++} END {printf "%d %.0f %.3f\n", n, m, p}' "$f")
  loss="$(awk '/packet loss/ {for (i = 1; i <= NF; i++) if ($i ~ /%$/) print $i}' "$f")"
  echo "pair ${pair} replies ${got} loss ${loss:-none} max_gap_ms ${gap} last_reply_before_end_s $(awk -v l="$last" -v e="$RUN_END" 'BEGIN {printf "%.1f", e - l}')"
  (( got > 0 )) || LATE_FAIL+=("No reply on ${pair}.")
  awk -v l="$last" -v e="$RUN_END" 'BEGIN {exit !(l + 0 >= e - 10)}' || LATE_FAIL+=("The pair ${pair} stopped before the run end.")
done
echo "status_samples ${samples} lost_peer_samples ${lost}"
(( lost == 0 )) || LATE_FAIL+=("${lost} status samples show a lost peer.")

dc logs > "$WORK/stack.log" 2>&1
secret_scan "$WORK/stack.log" || LATE_FAIL+=("The secret scan failed.")

echo "=== gate 8: contention while the proof held the lock ==="
if [[ -n "${PROOF_LOCK_SAMPLES:-}" && -f "$PROOF_LOCK_SAMPLES" ]]; then
  read -r cs_n cs_busy cs_unknown cs_maxc cs_maxl < <(awk '{n++; if ($2 < 0) u++; if ($2 > 0) b++; if ($2 > c) c = $2; if ($3 > l) l = $3} END {printf "%d %d %d %d %s\n", n, b + 0, u + 0, c + 0, (n ? l : "-")}' "$PROOF_LOCK_SAMPLES")
  echo "contention samples ${cs_n} contended_samples ${cs_busy} unknown_samples ${cs_unknown} max_other_orblx_containers ${cs_maxc} max_load1 ${cs_maxl} cpus $(nproc)"
  (( cs_n > 0 )) || LATE_FAIL+=("The proof-lock sampler has no sample.")
  (( cs_busy == 0 && cs_unknown == 0 )) || LATE_FAIL+=("${cs_busy} contended and ${cs_unknown} unknown samples. The run does not count.")
else
  LATE_FAIL+=("No proof-lock samples. The run does not count.")
fi

if (( ${#LATE_FAIL[@]} > 0 )); then
  for msg in "${LATE_FAIL[@]}"; do
    echo "late_fail ${msg}"
  done
  fail "${LATE_FAIL[0]}"
fi
echo "proof_ok coord-cert-rotation"

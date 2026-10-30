#!/usr/bin/env bash
# W25 HA subnet routers proof. All gates are [C] (Docker on one Linux host).
# router-a and router-b advertise the same route 10.88.125.0/24.
# The client streams UDP to the LAN target 10.88.125.5 through the active router.
# Each run kills the active router (docker kill) and measures the time from the kill
# to the first datagram that reaches the target through the other router.
# The routers masquerade, so the target sees the LAN address of the router.
# Run 1 also checks the ACL and the port ACL through the new router, and then
# watches the route for 60 s after the killed router comes back.
# The script deletes its own containers at the start and at the end.
# The script does not print enroll tokens or private keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ha-routers.yml"
PROJECT="${PROOF_PROJECT:-orblx-w25ha-proof}"
IMAGE="${ORBLX_HA_IMAGE:-orblx-w25ha:local}"
RUNS="${ORBLX_HA_RUNS:-5}"
LIMIT_MS="${ORBLX_HA_LIMIT_MS:-2000}"
WATCH_SECS="${ORBLX_HA_WATCH_SECS:-60}"
CIDR="10.88.125.0/24"
TARGET="10.88.125.5"
COORD="172.30.125.2:443"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/compose.env"

declare -A NODE_IP=([router-a]=172.30.125.3 [router-b]=172.30.125.6 [client]=172.30.125.4 [guest]=172.30.125.5)
declare -A LAN_IP=([router-a]=10.88.125.2 [router-b]=10.88.125.3)

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$PROJECT" --env-file "$ENV_FILE" --progress quiet -f "$FILE" "$@"
}

cleanup() {
  dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
  as_root rm -rf "$WORK" >/dev/null 2>&1 || rm -rf "$WORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1" >&2
  dc --profile nodes logs --tail 80 client router-a router-b guest >&2 || true
  exit 1
}

now_ms() {
  date +%s%3N
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

tool() {
  local state="$1"
  shift
  sed -i "s|^HA_TOOL_STATE=.*|HA_TOOL_STATE=${state}|" "$ENV_FILE"
  dc --profile tool run --rm --no-deps tool "$@"
}

enroll() {
  local name="$1"
  mkdir -p "$WORK/enroll-${name}"
  dc exec -T coord orblx coord token create --state /var/lib/orblx --out "/var/lib/orblx/tokens/${name}" --ttl 3600 >/dev/null
  tool "$WORK/enroll-${name}" coord enroll \
    --name "$name" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx \
    --endpoint "${NODE_IP[$name]}:443" >/dev/null
  echo "enrolled ${name}"
}

fetch_netmap() {
  local name="$1"
  tool "$WORK/enroll-${name}" coord netmap \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --state /var/lib/orblx >/dev/null
}

log_count() {
  local service="$1" pattern="$2"
  { dc logs --no-log-prefix "$service" 2>/dev/null || true; } | grep -c -- "$pattern" || true
}

# The router that the client uses now, from the last route line of the client log.
active_router() {
  { dc logs --no-log-prefix client 2>/dev/null || true; } \
    | sed -n "s/^The HA route ${CIDR//\//\\/} uses \([a-z0-9-]*\)\..*/\1/p" | tail -n 1
}

route_lines() {
  log_count client "The HA route ${CIDR} uses "
}

peer_direct() {
  local node="$1" peer="$2"
  dc exec -T "$node" cat /var/lib/orblx/status.txt 2>/dev/null | grep -q "^peer ${peer} .* path direct "
}

wait_direct() {
  local node="$1" peer="$2" limit="$3"
  for _ in $(seq 1 "$limit"); do
    peer_direct "$node" "$peer" && return 0
    sleep 0.5
  done
  return 1
}

target_log() {
  dc exec -T target cat "/tmp/$1.log" 2>/dev/null || true
}

leak_count() {
  local node="$1"
  dc exec -T "$node" iptables -nvx -L OUTPUT | awk '/orblx-w25ha-leak/ {print $1}'
}

deny_records() {
  local router="$1"
  { dc exec -T "$router" cat /var/lib/orblx/packet-audit.jsonl 2>/dev/null || true; } \
    | jq -c "select(.action == \"packet-deny\" and (.detail | contains(\"dst ${TARGET} \")))" \
    | grep -c . || true
}

probe() {
  local node="$1"
  shift
  dc exec -T "$node" python3 /proof/acl-probe.py "$@"
}

ping_max_ms() {
  local node="$1" dest="$2"
  dc exec -T "$node" ping -c 5 -i 0.2 -W 1 "$dest" 2>/dev/null \
    | sed -n 's|.*= [0-9.]*/[0-9.]*/\([0-9.]*\)/.*|\1|p'
}

echo "=== W25 HA subnet routers proof. All gates are [C] (Docker on one Linux host). ==="
echo "project ${PROJECT} image ${IMAGE} runs ${RUNS} limit_ms ${LIMIT_MS} watch_secs ${WATCH_SECS}"
echo "route ${CIDR} on router-a (lan ${LAN_IP[router-a]}) and router-b (lan ${LAN_IP[router-b]}); target ${TARGET}"
echo "host $(uname -sm) $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
other="$(as_root docker ps --format '{{.Names}}' | grep '^orblx' | grep -vc "^${PROJECT}" || true)"
echo "other_orblx_containers_at_start ${other}"

mkdir -p "$WORK/coord" "$WORK/policy" "$WORK/tool"
for name in router-a router-b client guest; do
  mkdir -p "$WORK/state-${name}"
  : > "$WORK/netmap-${name}.json"
done
cp "$ROOT/scripts/proof/ha-routers.hujson" "$WORK/policy/policy.hujson"
chmod 755 "$WORK/policy"
chmod 644 "$WORK/policy/policy.hujson"
cat > "$ENV_FILE" <<ENV
PROOF_PROJECT=${PROJECT}
ORBLX_HA_IMAGE=${IMAGE}
HA_COORD_STATE=${WORK}/coord
HA_POLICY_DIR=${WORK}/policy
HA_TOOL_STATE=${WORK}/tool
HA_ROUTER_A_STATE=${WORK}/state-router-a
HA_ROUTER_B_STATE=${WORK}/state-router-b
HA_CLIENT_STATE=${WORK}/state-client
HA_GUEST_STATE=${WORK}/state-guest
HA_ROUTER_A_NETMAP=${WORK}/netmap-router-a.json
HA_ROUTER_B_NETMAP=${WORK}/netmap-router-b.json
HA_CLIENT_NETMAP=${WORK}/netmap-client.json
HA_GUEST_NETMAP=${WORK}/netmap-guest.json
ENV

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward

echo "=== [C] build image ==="
BIN="$ROOT/target/debug/orblx"
cargo build -q -p orblx-cli --bin orblx
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$BIN")"
as_root docker build -q -t "$IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start coordinator ==="
dc up -d coord
for _ in $(seq 1 90); do
  as_root test -s "$WORK/coord/trust-bundle.pem" && break
  sleep 1
done
as_root test -s "$WORK/coord/trust-bundle.pem" || fail "The coordinator did not write the trust bundle."
dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson

echo "=== [C] enroll ==="
for name in router-a router-b client guest; do
  enroll "$name"
done

echo "=== [C] both routers advertise ${CIDR} ==="
for name in router-a router-b; do
  tool "$WORK/enroll-${name}" coord advertise \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --state /var/lib/orblx \
    --route "$CIDR" | grep -v -i token || true
done

echo "=== [C] netmaps ==="
for name in router-a router-b client guest; do
  fetch_netmap "$name"
  as_root cat "$WORK/enroll-${name}/netmap.json" > "$WORK/netmap-${name}.json"
done
echo "client netmap routes: $(jq -c '[.peers[] | {name, routes}]' "$WORK/netmap-client.json")"
for name in router-a router-b; do
  jq -e --arg n "$name" --arg c "$CIDR" '.peers[] | select(.name==$n) | .routes == [$c]' "$WORK/netmap-client.json" >/dev/null \
    || fail "The client netmap does not give ${CIDR} to ${name}."
done
echo "[C] the signed netmap gives ${CIDR} to router-a and router-b"

declare -A OVERLAY
for name in router-a router-b client guest; do
  if [[ "$name" == client ]]; then
    OVERLAY[$name]="$(jq -r '.peers[] | select(.name=="client") | .overlay_ip' "$WORK/netmap-guest.json")"
  else
    OVERLAY[$name]="$(jq -r --arg n "$name" '.peers[] | select(.name==$n) | .overlay_ip' "$WORK/netmap-client.json")"
  fi
  [[ -n "${OVERLAY[$name]}" && "${OVERLAY[$name]}" != null ]] || fail "No overlay address for ${name}."
done
echo "overlay router-a ${OVERLAY[router-a]} router-b ${OVERLAY[router-b]} client ${OVERLAY[client]} guest ${OVERLAY[guest]}"

echo "=== [C] node material ==="
"$BIN" node-issue --out "$WORK/nodes" \
  --node "router-a=${OVERLAY[router-a]}" \
  --node "router-b=${OVERLAY[router-b]}" \
  --node "client=${OVERLAY[client]}" \
  --node "guest=${OVERLAY[guest]}" >/dev/null
for name in router-a router-b client guest; do
  cp -a "$WORK/nodes/${name}/." "$WORK/state-${name}/"
done
# The routers use the signed grants, so the port ACL covers the subnet route (W24-A).
for name in router-a router-b; do
  as_root cat "$WORK/enroll-${name}/netmap.pub" > "$WORK/state-${name}/netmap.pub"
  as_root cat "$WORK/enroll-${name}/grants.signed.json" > "$WORK/state-${name}/grants.signed.json"
done

echo "=== [C] start target, routers, client, guest ==="
dc --profile nodes up -d target router-a router-b
for router in router-a router-b; do
  ok=0
  for _ in $(seq 1 60); do
    if [[ "$(log_count "$router" "The node forwards ${CIDR}")" -ge 1 && "$(log_count "$router" 'The packet filter is on.')" -ge 1 ]]; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [[ "$ok" -eq 1 ]] || fail "${router} did not start forwarding with the packet filter on."
done
dc --profile nodes up -d client guest
for node in client guest; do
  for router in router-a router-b; do
    wait_direct "$node" "$router" 120 || fail "${node} has no direct path to ${router}."
  done
done
echo "client log: $(dc logs --no-log-prefix client 2>/dev/null | grep "The HA route ${CIDR} has the routers" | tail -n 1)"
[[ "$(log_count client "The HA route ${CIDR} has the routers router-a, router-b.")" -ge 1 ]] \
  || fail "The client did not see two routers for ${CIDR}."
echo "client: $(dc exec -T client ip route get "$TARGET" | head -n 1)"
dc exec -T client ip route show dev orblx0 | grep -q "^${CIDR}" || fail "The client has no route to ${CIDR}."

echo "---- [C] ping (report each value above 20 ms) ----"
for dest in "${OVERLAY[router-a]}" "${OVERLAY[router-b]}" "$TARGET"; do
  max="$(ping_max_ms client "$dest")"
  flag=""
  if [[ -n "$max" ]] && awk -v m="$max" 'BEGIN {exit !(m > 20)}'; then
    flag=" ABOVE_20MS"
  fi
  echo "ping client -> ${dest} max_ms ${max:-none}${flag}"
done

echo "---- [C] leak counters (OUTPUT on eth0 to ${CIDR}) on client and guest ----"
for node in client guest; do
  dc exec -T "$node" iptables -I OUTPUT 1 -o eth0 -d "$CIDR" -m comment --comment orblx-w25ha-leak
done

echo "=== Gate 0 [C]: traffic uses one router before the first kill ==="
out="$(probe client udp "$TARGET" 9000 3 || true)"
echo "client udp ${TARGET}:9000 (no echo on the target): ${out}"
sleep 0.5
first="$(active_router)"
[[ -n "$first" ]] || fail "The client log has no active router."
echo "active router ${first}"
probe client stream "$TARGET" 9000 1 10 warm >/dev/null
sleep 0.5
warm_srcs="$(target_log u9000 | awk '$4 == "warm" {print $3}' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
echo "target sources for the warm stream: ${warm_srcs}"
[[ "$(target_log u9000 | awk -v ip="${LAN_IP[$first]}" '$4 == "warm" && $3 != ip' | grep -c . || true)" -eq 0 ]] \
  || fail "The warm stream did not use only ${first}."
echo "[C] gate0 ok"

acl_through() {
  local router="$1"
  local d0 d1 t80 t81 u91 g80 a80_0 a80_1 a81
  echo "=== Gate 2 [C]: the ACL and the port ACL apply through ${router} ==="
  d0="$(deny_records "$router")"
  a80_0="$(target_log t8080 | grep -c "accept ${LAN_IP[$router]} " || true)"
  t80="$(probe client tcp "$TARGET" 8080 3)"
  t81="$(probe client tcp "$TARGET" 8081 2)"
  u91="$(probe client udp "$TARGET" 9001 2)"
  g80="$(probe guest tcp "$TARGET" 8080 2)"
  sleep 1
  d1="$(deny_records "$router")"
  a80_1="$(target_log t8080 | grep -c "accept ${LAN_IP[$router]} " || true)"
  a81="$(target_log t8081 | grep -c . || true)"
  u91_rx="$(target_log u9001 | grep -c . || true)"
  echo "client tcp 8080 (allowed): ${t80}"
  echo "client tcp 8081 (no rule): ${t81}"
  echo "client udp 9001 (no rule): ${u91}"
  echo "guest tcp 8080 (no rule for guest): ${g80}"
  echo "target tcp 8080 accepts from ${LAN_IP[$router]}: $((a80_1 - a80_0)); target tcp 8081 accepts: ${a81}; target udp 9001 datagrams: ${u91_rx}"
  echo "${router} packet-deny records for dst ${TARGET}: $((d1 - d0))"
  [[ "$t80" == "tcp ${TARGET}:8080 connected reply ok" ]] || fail "The allowed TCP 8080 flow failed through ${router}."
  [[ $((a80_1 - a80_0)) -ge 1 ]] || fail "The TCP 8080 flow did not come through ${router}."
  [[ "$t81" == *timeout* || "$t81" == *fail* ]] || fail "TCP 8081 was not dropped."
  [[ "$u91" == *"reply none"* ]] || fail "UDP 9001 got a reply."
  [[ "$g80" == *timeout* || "$g80" == *fail* ]] || fail "The guest reached TCP 8080."
  [[ "$a81" -eq 0 && "$u91_rx" -eq 0 ]] || fail "A denied packet reached the target."
  [[ $((d1 - d0)) -ge 3 ]] || fail "${router} did not audit the denied packets."
  dc exec -T "$router" cat /var/lib/orblx/packet-audit.jsonl \
    | jq -c "select(.action == \"packet-deny\" and (.detail | contains(\"dst ${TARGET} \"))) | {actor, target, detail}" | tail -n 3
  echo "[C] gate2 ok through ${router}"
}

declare -a RESULTS=()
declare -a KILLED=()
watch_changes="-"
watch_srcs="-"
watch_moved="-"
leak0_client="$(leak_count client)"
leak0_guest="$(leak_count guest)"

for run in $(seq 1 "$RUNS"); do
  active="$(active_router)"
  case "$active" in
    router-a) standby=router-b ;;
    router-b) standby=router-a ;;
    *) fail "Run ${run}: no active router." ;;
  esac
  echo "=== Gate 1 [C] run ${run}: kill ${active}, standby ${standby} ==="
  wait_direct client "$standby" 120 || fail "Run ${run}: the client has no direct path to ${standby}."
  lines0="$(route_lines)"
  dc exec -d client python3 /proof/acl-probe.py stream "$TARGET" 9000 8 10 "run${run}"
  dc exec -d client python3 /proof/acl-probe.py stream "$TARGET" 9001 8 10 "deny${run}"
  dc exec -d guest python3 /proof/acl-probe.py stream "$TARGET" 9000 8 10 "guest${run}"
  sleep 2
  t_kill="$(now_ms)"
  as_root docker kill "${PROJECT}-${active}-1" >/dev/null
  t_killed="$(now_ms)"
  sleep 7
  log="$(target_log u9000)"
  before="$(printf '%s\n' "$log" | awk -v t="$t_kill" -v ip="${LAN_IP[$active]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 < t' | grep -c . || true)"
  last_old="$(printf '%s\n' "$log" | awk -v t="$t_kill" -v ip="${LAN_IP[$active]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 < t {m=$2} END {print m+0}')"
  first_new="$(printf '%s\n' "$log" | awk -v t="$t_kill" -v ip="${LAN_IP[$standby]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 >= t {print $2; exit}')"
  after_new="$(printf '%s\n' "$log" | awk -v ip="${LAN_IP[$standby]}" -v tag="run${run}" '$4 == tag && $3 == ip' | grep -c . || true)"
  old_after="$(printf '%s\n' "$log" | awk -v t="$t_killed" -v ip="${LAN_IP[$active]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 > t' | grep -c . || true)"
  total="$(printf '%s\n' "$log" | awk -v tag="run${run}" '$4 == tag' | grep -c . || true)"
  denied_rx="$(target_log u9001 | awk -v tag="deny${run}" '$4 == tag' | grep -c . || true)"
  guest_rx="$(printf '%s\n' "$log" | awk -v tag="guest${run}" '$4 == tag' | grep -c . || true)"
  lines1="$(route_lines)"
  [[ "$before" -ge 50 ]] || fail "Run ${run}: only ${before} datagrams came through ${active} before the kill."
  [[ -n "$first_new" ]] || fail "Run ${run}: no datagram came through ${standby} after the kill."
  failover_ms=$((first_new - t_kill))
  gap_ms=$((first_new - last_old))
  echo "run ${run} killed ${active} kill_cmd_ms $((t_killed - t_kill)) failover_ms ${failover_ms} gap_ms ${gap_ms} via_old_before ${before} via_new ${after_new} via_old_after_kill ${old_after} received ${total} denied_9001_rx ${denied_rx} guest_rx ${guest_rx} route_changes $((lines1 - lines0))"
  echo "client log: $(dc logs --no-log-prefix client 2>/dev/null | grep "The HA route ${CIDR} uses " | tail -n 1)"
  [[ "$(active_router)" == "$standby" ]] || fail "Run ${run}: the client log does not name ${standby}."
  [[ "$denied_rx" -eq 0 && "$guest_rx" -eq 0 ]] || fail "Run ${run}: a denied datagram reached the target during the failover."
  [[ "$old_after" -eq 0 ]] || fail "Run ${run}: a datagram came through the killed router."
  [[ "$failover_ms" -le "$LIMIT_MS" ]] || fail "Run ${run}: failover took ${failover_ms} ms (limit ${LIMIT_MS} ms)."
  RESULTS+=("$failover_ms")
  KILLED+=("$active")

  if [[ "$run" -eq 1 ]]; then
    acl_through "$standby"
  fi

  echo "---- [C] run ${run}: restore ${active} ----"
  as_root docker start "${PROJECT}-${active}-1" >/dev/null
  wait_direct client "$active" 120 || fail "Run ${run}: ${active} did not come back."
  sleep 2

  if [[ "$run" -eq 1 ]]; then
    echo "=== Gate 3 [C]: ${active} is back; watch the route for ${WATCH_SECS} s ==="
    w0="$(route_lines)"
    probe client stream "$TARGET" 9000 "$WATCH_SECS" 10 watch
    sleep 1
    w1="$(route_lines)"
    watch_changes=$((w1 - w0))
    watch_srcs="$(target_log u9000 | awk '$4 == "watch" {print $3}' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
    watch_moved="$(target_log u9000 | awk -v ip="${LAN_IP[$active]}" '$4 == "watch" && $3 == ip' | grep -c . || true)"
    echo "route_changes_in_${WATCH_SECS}s ${watch_changes}; target sources ${watch_srcs}; datagrams through ${active} ${watch_moved}"
    echo "status of ${active} on the client: $(dc exec -T client cat /var/lib/orblx/status.txt | grep "^peer ${active} " | awk '{print $6}')"
    [[ "$watch_changes" -eq 0 && "$watch_moved" -eq 0 ]] || fail "The route moved after ${active} came back."
    echo "[C] gate3 ok: the route stays on ${standby}; no failback, no flap"
  fi
done

leak1_client="$(leak_count client)"
leak1_guest="$(leak_count guest)"
echo "=== Gate 4 [C]: no leak to the underlay ==="
echo "client eth0 packets to ${CIDR}: ${leak0_client} -> ${leak1_client}; guest: ${leak0_guest} -> ${leak1_guest}"
[[ "$leak1_client" == "$leak0_client" && "$leak1_guest" == "$leak0_guest" ]] || fail "A packet to ${CIDR} left on eth0."
echo "[C] gate4 ok"

for router in router-a router-b; do
  dc exec -T "$router" orblx audit verify-config --file /var/lib/orblx/packet-audit.jsonl | grep -qx ok \
    || fail "The ${router} packet audit chain did not verify."
done
echo "packet audit verify ok on router-a and router-b"

max=0
for value in "${RESULTS[@]}"; do
  ((value > max)) && max="$value"
done
other_end="$(as_root docker ps --format '{{.Names}}' | grep '^orblx' | grep -vc "^${PROJECT}" || true)"
echo "=== summary ==="
for i in "${!RESULTS[@]}"; do
  echo "run $((i + 1)) killed ${KILLED[$i]} failover_ms ${RESULTS[$i]}"
done
echo "failover_ms_all ${RESULTS[*]} max ${max} limit ${LIMIT_MS} pass ${#RESULTS[@]}/${RUNS}"
echo "failback route_changes_in_${WATCH_SECS}s ${watch_changes} sources ${watch_srcs}"
echo "leak client $((leak1_client - leak0_client)) guest $((leak1_guest - leak0_guest))"
echo "other_orblx_containers_at_end ${other_end}"
echo "proof_ok"

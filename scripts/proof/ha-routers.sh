#!/usr/bin/env bash
# W25-10 HA subnet routers proof. All gates are [C] (Docker on one Linux host).
# router-a and router-b advertise the same route 10.88.125.0/24.
# Gate 1: the policy approves only router-a. router-b carries 0 bytes, also when router-a is down.
# Then the policy approves both routers.
# Gate 2: each run kills the active router (docker kill) and measures the time from the kill
# to the first datagram that reaches the target through the other router. The routers
# masquerade, so the target sees the LAN address of the router.
# Gate 3: the killed router comes back. The proof counts the route changes in 60 s.
# Gate 4: the port ACL and the UDP 53 gate apply on the new router (run 1).
# Gate 5: one TCP flow through the subnet during run 1 (survives or reconnects).
# Gate 6: the container logs have no key or token text.
# The script deletes its own containers at the start and at the end.
# The script does not print enroll tokens or private keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ha-routers.yml"
PROJECT="${PROOF_PROJECT:-orblx-w25ha-proof}"
IMAGE="${ORBLX_HA_IMAGE:-orblx-w25ha:local}"
RUNS="${ORBLX_HA_RUNS:-5}"
LIMIT_MS="${ORBLX_HA_LIMIT_MS:-5000}"
TARGET_MS="${ORBLX_HA_TARGET_MS:-2000}"
TCP_LIMIT_MS="${ORBLX_HA_TCP_LIMIT_MS:-5000}"
WATCH_SECS="${ORBLX_HA_WATCH_SECS:-60}"
CIDR="10.88.125.0/24"
TARGET="10.88.125.5"
NAMESERVER="10.88.125.53"
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

# W25-5: one box proof at a time. The lock waits.
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"

cleanup() {
  if [[ "${ORBLX_HA_KEEP:-0}" == 1 ]]; then
    echo "ORBLX_HA_KEEP=1: the proof keeps the containers and ${WORK}" >&2
  else
    dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
    as_root rm -rf "$WORK" >/dev/null 2>&1 || rm -rf "$WORK" >/dev/null 2>&1 || true
  fi
  proof_lock_end || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1" >&2
  dc --profile nodes logs --tail 80 client router-a router-b guest 2>&1 | grep -v -i -e 'private key' -e token >&2 || true
  exit 1
}

now_ms() {
  date +%s%3N
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
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
  dc logs --no-log-prefix "$service" 2>/dev/null | count_matching -F -- "$pattern"
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
  dc exec -T "$node" cat /var/lib/orblx/status.txt 2>/dev/null | read_all grep -q "^peer ${peer} .* path direct "
}

wait_direct() {
  local node="$1" peer="$2" limit="$3"
  for _ in $(seq 1 "$limit"); do
    peer_direct "$node" "$peer" && return 0
    sleep 0.5
  done
  return 1
}

# W25-14: the reads fail closed. A failed docker exec fails the pipe, and set -e stops
# the proof. Only a missing file inside the container counts as empty.
target_log() {
  dc exec -T target cat "/tmp/$1.log"
}

# Count the non-empty lines of stdin. Print 0 when there is no line. Do not hide a failed writer.
count_lines() {
  local n
  n="$(grep -c .)" || [[ $? -eq 1 ]]
  echo "${n:-0}"
}

# Count the lines of stdin that match the grep arguments. Print 0 when no line matches.
# grep exit 1 (no match) is not an error. grep exit 2 and a failed writer fail.
count_matching() {
  local n
  n="$(grep -c "$@")" || [[ $? -eq 1 ]]
  echo "${n:-0}"
}

# Print a file in a container. A missing file prints nothing. A failed docker exec fails.
cat_in() {
  dc exec -T "$1" sh -c 'cat "$1" 2>/dev/null; exit 0' sh "$2"
}

# Count the running orblx containers of other projects. A failed docker ps fails.
other_orblx_containers() {
  local names
  names="$(as_root docker ps --format '{{.Names}}')"
  printf '%s\n' "$names" | awk -v p="$PROJECT" 'index($0, "orblx") == 1 && index($0, p) != 1 {n++} END {print n + 0}'
}

leak_count() {
  local node="$1"
  dc exec -T "$node" iptables -nvx -L OUTPUT | awk '/orblx-w25ha-leak/ {print $1}'
}

deny_records() {
  local router="$1"
  cat_in "$router" /var/lib/orblx/packet-audit.jsonl \
    | jq -c "select(.action == \"packet-deny\" and (.detail | contains(\"dst ${TARGET} \")))" \
    | count_lines
}

probe() {
  local node="$1"
  shift
  dc exec -T "$node" python3 /proof/acl-probe.py "$@"
}

ping_max_ms() {
  local node="$1" dest="$2"
  { dc exec -T "$node" ping -c 5 -i 0.2 -W 1 "$dest" 2>/dev/null || true; } \
    | sed -n 's|.*= [0-9.]*/[0-9.]*/\([0-9.]*\)/.*|\1|p'
}

# Forward counters on one router. A docker start makes a new network namespace,
# so the proof adds the rules again after each restart.
add_counters() {
  local router="$1"
  dc exec -T "$router" iptables -I FORWARD 1 -d "$CIDR" -m comment --comment orblx-w25ha-fwd
  dc exec -T "$router" iptables -I FORWARD 1 -d "$TARGET" -p tcp --dport 8081 -m comment --comment orblx-w25ha-t8081
  dc exec -T "$router" iptables -I FORWARD 1 -d "$TARGET" -p udp --dport 9001 -m comment --comment orblx-w25ha-u9001
  dc exec -T "$router" iptables -I FORWARD 1 -d "$NAMESERVER" -p udp --dport 53 -m comment --comment orblx-w25ha-dns
}

fwd_bytes() {
  local router="$1" tag="$2"
  dc exec -T "$router" iptables -nvx -L FORWARD | read_all awk -v t="orblx-w25ha-${tag}" '$0 ~ t {print $2; exit}'
}

route_audit_count() {
  cat_in client /var/lib/orblx/route-audit.jsonl \
    | jq -c 'select(.action == "route-failover")' | count_lines
}

grant_reloads() {
  log_count "$1" 'The DNS responder loaded new signed grants.'
}

# Write the policy file in one rename, so the coordinator never reads half a file.
put_policy() {
  cp "$1" "$WORK/policy/policy.next"
  chmod 644 "$WORK/policy/policy.next"
  mv "$WORK/policy/policy.next" "$WORK/policy/policy.hujson"
}

# The repository policy without comments, edited by a Python expression on `data`.
policy_variant() {
  local out="$1" expr="$2"
  grep -v '^\s*//' "$ROOT/scripts/proof/ha-routers.hujson" | python3 -c "import sys,re,json
text=re.sub(r',(\s*[}\]])', r'\1', sys.stdin.read())
data=json.loads(text)
${expr}
print(json.dumps(data, indent=2))" > "$out"
}

# Fetch the netmap and grants of one router and give the grants to the running router.
refresh_router_grants() {
  local router="$1" before
  before="$(grant_reloads "$router")"
  fetch_netmap "$router"
  as_root cat "$WORK/enroll-${router}/grants.signed.json" > "$WORK/state-${router}/grants.next"
  # The node logs a reload only for new bytes. Same bytes: nothing to load.
  if cmp -s "$WORK/state-${router}/grants.next" "$WORK/state-${router}/grants.signed.json"; then
    rm -f "$WORK/state-${router}/grants.next"
    return 0
  fi
  mv "$WORK/state-${router}/grants.next" "$WORK/state-${router}/grants.signed.json"
  for _ in $(seq 1 50); do
    [[ "$(grant_reloads "$router")" -gt "$before" ]] && return 0
    sleep 0.1
  done
  return 1
}

# The largest time between two datagrams of one stream tag at the target.
max_gap_ms() {
  local tag="$1"
  target_log u9000 | awk -v tag="$tag" '$4 == tag {print $2}' | sort -n \
    | awk 'NR > 1 && $1 - p > m {m = $1 - p} {p = $1} END {print m + 0}'
}

deny_to() {
  local router="$1" dst="$2"
  cat_in "$router" /var/lib/orblx/packet-audit.jsonl \
    | jq -c "select(.action == \"packet-deny\" and (.detail | contains(\"dst ${dst} \")))" \
    | count_lines
}

ask_dns() {
  dc exec -T client python3 /proof/dns-ask.py db.corp.lan "$NAMESERVER" 2>/dev/null || echo "db.corp.lan no answer"
}

srcs_of() {
  target_log u9000 | awk -v tag="$1" '$4 == tag {print $3}' | sort | uniq -c | tr -s ' ' | tr '\n' ';'
}

restore_router() {
  local router="$1"
  as_root docker start "${PROJECT}-${router}-1" >/dev/null
  for _ in $(seq 1 60); do
    dc exec -T "$router" true >/dev/null 2>&1 && break
    sleep 0.5
  done
  add_counters "$router"
  wait_direct client "$router" 120 || fail "${router} did not come back."
}

proof_lock_take "ha-routers:${PROJECT}" "${PROJECT}-"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"
proof_compose_clean "${PROJECT}" || exit 1
echo "=== W25-10 HA subnet routers proof. All gates are [C] (Docker on one Linux host). ==="
echo "project ${PROJECT} image ${IMAGE} runs ${RUNS} limit_ms ${LIMIT_MS} target_ms ${TARGET_MS} tcp_limit_ms ${TCP_LIMIT_MS} watch_secs ${WATCH_SECS}"
echo "route ${CIDR} on router-a (lan ${LAN_IP[router-a]}) and router-b (lan ${LAN_IP[router-b]}); target ${TARGET}; nameserver ${NAMESERVER}"
echo "host $(uname -sm) $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "start_kst $(TZ=Asia/Seoul date '+%Y-%m-%d %H:%M:%S')"
other="$(other_orblx_containers)"
echo "other_orblx_containers_at_start ${other}"

mkdir -p "$WORK/coord" "$WORK/policy" "$WORK/tool"
for name in router-a router-b client guest; do
  mkdir -p "$WORK/state-${name}"
  : > "$WORK/netmap-${name}.json"
done
POLICY_BOTH="$WORK/policy-both.json"
POLICY_A="$WORK/policy-a.json"
POLICY_NODNS="$WORK/policy-nodns.json"
policy_variant "$POLICY_BOTH" "pass"
policy_variant "$POLICY_A" "data['autoApprovers']['routes']['${CIDR}'] = ['spiffe://orblx.local/node/router-a']"
policy_variant "$POLICY_NODNS" "data['acls'] = [a for a in data['acls'] if not any(d.endswith(':53') for d in a['dst'])]"
chmod 755 "$WORK/policy"
put_policy "$POLICY_A"
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
BIN="$ROOT/target/release/orblx"
cargo build -q --release -p orblx-cli --bin orblx
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$BIN")"
as_root docker build -q -t "$IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start coordinator (the policy approves ${CIDR} only for router-a) ==="
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

write_netmaps() {
  for name in router-a router-b client guest; do
    fetch_netmap "$name"
    as_root cat "$WORK/enroll-${name}/netmap.json" > "$WORK/netmap-${name}.json"
  done
}

routes_of() {
  jq -c --arg n "$1" '[.peers[] | select(.name==$n) | .routes] | first // []' "$WORK/netmap-client.json"
}

echo "=== [C] netmaps ==="
write_netmaps
echo "client netmap routes: $(jq -c '[.peers[] | {name, routes}]' "$WORK/netmap-client.json")"
[[ "$(routes_of router-a)" == "[\"${CIDR}\"]" ]] || fail "The client netmap does not give ${CIDR} to router-a."
[[ "$(routes_of router-b)" == "[]" || "$(routes_of router-b)" == "null" ]] || fail "The client netmap gives a route to the unapproved router-b."
echo "[C] the signed netmap gives ${CIDR} to router-a only; router-b advertises it without approval"

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

# W25-27: the nodes use only the SVID, the key, and the ticket that the coordinator issued
# through the normal enroll path. The proof does not make lab tickets.
echo "=== [C] node material from the coordinator enroll ==="
for name in router-a router-b client guest; do
  as_root cp -a "$WORK/enroll-${name}/." "$WORK/state-${name}/"
  # The proof user writes in the state directory later (grants.next).
  as_root chown -R "$(id -u):$(id -g)" "$WORK/state-${name}"
  for file in cert.pem key.pem bundle.pem ticket.bin ticket.bin.mac ticket-verifier.pem ticket-mac.key svid-ca.pub; do
    as_root test -s "$WORK/state-${name}/${file}" || fail "The enroll of ${name} did not write ${file}."
  done
  echo "${name}: SVID, key, and ticket from the coordinator enroll"
done
# The routers use the signed grants from the enroll, so the port ACL covers the subnet route (W24-A).
for name in router-a router-b; do
  test -s "$WORK/state-${name}/netmap.pub" || fail "The enroll of ${name} did not write netmap.pub."
  test -s "$WORK/state-${name}/grants.signed.json" || fail "The enroll of ${name} did not write grants.signed.json."
done

echo "=== [C] start target, nameserver, routers, client, guest ==="
dc --profile nodes up -d target landns router-a router-b
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
  add_counters "$router"
done
dc --profile nodes up -d client guest
for node in client guest; do
  for router in router-a router-b; do
    wait_direct "$node" "$router" 120 || fail "${node} has no direct path to ${router}."
  done
done
dc exec -T client ip route show dev orblx0 | read_all grep -q "^${CIDR}" || fail "The client has no route to ${CIDR}."

echo "=== Gate 1 [C]: an unapproved second router carries 0 bytes ==="
b0="$(fwd_bytes router-b fwd)"
probe client stream "$TARGET" 9000 3 10 appr1 >/dev/null
sleep 0.5
echo "router-a up: target sources for appr1: $(srcs_of appr1)"
[[ "$(target_log u9000 | awk -v ip="${LAN_IP[router-a]}" '$4 == "appr1" && $3 == ip' | count_lines)" -ge 100 ]] \
  || fail "The stream did not use router-a."
as_root docker kill "${PROJECT}-router-a-1" >/dev/null
probe client stream "$TARGET" 9000 4 10 appr2 >/dev/null
sleep 0.5
b1="$(fwd_bytes router-b fwd)"
appr2_rx="$(target_log u9000 | awk '$4 == "appr2"' | count_lines)"
echo "router-a down: datagrams at the target for appr2: ${appr2_rx}"
echo "router-b FORWARD bytes to ${CIDR}: ${b0} -> ${b1}"
[[ "$b0" == 0 && "$b1" == 0 && "$appr2_rx" -eq 0 ]] || fail "The unapproved router-b carried traffic."
gate1_unapproved="router-b_bytes ${b1} rx_with_router-a_down ${appr2_rx}"
restore_router router-a
echo "[C] gate1 part 1 ok: unapproved router-b carried 0 bytes"

echo "---- [C] approve ${CIDR} for router-a and router-b ----"
put_policy "$POLICY_BOTH"
ok=0
for _ in $(seq 1 40); do
  fetch_netmap client
  if jq -e --arg c "$CIDR" '.peers[] | select(.name=="router-b") | .routes == [$c]' "$WORK/enroll-client/netmap.json" >/dev/null 2>&1 \
    || as_root jq -e --arg c "$CIDR" '.peers[] | select(.name=="router-b") | .routes == [$c]' "$WORK/enroll-client/netmap.json" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.5
done
[[ "$ok" -eq 1 ]] || fail "The coordinator did not approve ${CIDR} for router-b."
write_netmaps
echo "client netmap routes: $(jq -c '[.peers[] | {name, routes}]' "$WORK/netmap-client.json")"
for name in router-a router-b; do
  [[ "$(routes_of "$name")" == "[\"${CIDR}\"]" ]] || fail "The client netmap does not give ${CIDR} to ${name}."
  refresh_router_grants "$name" || fail "${name} did not load the new grants."
done
# The client reads the route table at start (doc limit), so the proof restarts it.
dc restart client guest >/dev/null
sleep 3
for _ in $(seq 1 60); do
  [[ "$(log_count client "The HA route ${CIDR} has the routers router-a, router-b.")" -ge 1 ]] && break
  sleep 0.5
done
for node in client guest; do
  for router in router-a router-b; do
    wait_direct "$node" "$router" 120 || fail "${node} has no direct path to ${router} after the restart."
  done
done
echo "client log: $(dc logs --no-log-prefix client 2>/dev/null | grep "The HA route ${CIDR} has the routers" | tail -n 1)"
[[ "$(log_count client "The HA route ${CIDR} has the routers router-a, router-b.")" -ge 1 ]] \
  || fail "The client did not see two routers for ${CIDR}."
echo "client: $(dc exec -T client ip route get "$TARGET" | read_all head -n 1)"
echo "[C] gate1 ok: both routes approved"

echo "---- [C] ping (report each value above 20 ms) ----"
# The policy has no ICMP rule to the routers, so only the target (through the active router) answers.
for dest in "$TARGET"; do
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

echo "---- [C] warm stream: traffic uses one router ----"
probe client stream "$TARGET" 9000 2 10 warm >/dev/null
sleep 0.5
first="$(active_router)"
[[ -n "$first" ]] || fail "The client log has no active router."
echo "active router ${first}; target sources for the warm stream: $(srcs_of warm)"
warm_other="$(target_log u9000 | awk -v ip="${LAN_IP[$first]}" '$4 == "warm" && $3 != ip' | count_lines)"
[[ "$warm_other" -eq 0 ]] \
  || fail "The warm stream did not use only ${first}."

acl_through() {
  local router="$1"
  local d0 d1 t80 t81 u91 g80 a80_0 a80_1 a81 u91_rx f81 f91
  echo "=== Gate 4 [C]: the port ACL applies on the new router ${router} ==="
  d0="$(deny_to "$router" "$TARGET")"
  a80_0="$(target_log t8080 | count_matching -F -- "accept ${LAN_IP[$router]} ")"
  t80="$(probe client tcp "$TARGET" 8080 3)"
  t81="$(probe client tcp "$TARGET" 8081 2)"
  u91="$(probe client udp "$TARGET" 9001 2)"
  g80="$(probe guest tcp "$TARGET" 8080 2)"
  sleep 1
  d1="$(deny_to "$router" "$TARGET")"
  a80_1="$(target_log t8080 | count_matching -F -- "accept ${LAN_IP[$router]} ")"
  a81="$(target_log t8081 | count_lines)"
  u91_rx="$(target_log u9001 | count_lines)"
  f81="$(fwd_bytes "$router" t8081)"
  f91="$(fwd_bytes "$router" u9001)"
  echo "client tcp 8080 (allowed): ${t80}"
  echo "client tcp 8081 (no rule): ${t81}"
  echo "client udp 9001 (no rule): ${u91}"
  echo "guest tcp 8080 (no rule for guest): ${g80}"
  echo "target tcp 8080 accepts from ${LAN_IP[$router]}: $((a80_1 - a80_0)); target tcp 8081 accepts: ${a81}; target udp 9001 datagrams: ${u91_rx}"
  echo "${router} FORWARD bytes: tcp 8081 ${f81}; udp 9001 ${f91} (the 9001 stream ran during the kill)"
  echo "${router} packet-deny records for dst ${TARGET}: $((d1 - d0))"
  [[ "$t80" == "tcp ${TARGET}:8080 connected reply ok" ]] || fail "The allowed TCP 8080 flow failed through ${router}."
  [[ $((a80_1 - a80_0)) -ge 1 ]] || fail "The TCP 8080 flow did not come through ${router}."
  [[ "$t81" == *timeout* || "$t81" == *fail* ]] || fail "TCP 8081 was not dropped."
  [[ "$u91" == *"reply none"* ]] || fail "UDP 9001 got a reply."
  [[ "$g80" == *timeout* || "$g80" == *fail* ]] || fail "The guest reached TCP 8080."
  [[ "$a81" -eq 0 && "$u91_rx" -eq 0 ]] || fail "A denied packet reached the target."
  [[ "$f81" == 0 && "$f91" == 0 ]] || fail "${router} forwarded bytes for a denied port."
  [[ $((d1 - d0)) -ge 3 ]] || fail "${router} did not audit the denied packets."
  dc exec -T "$router" cat /var/lib/orblx/packet-audit.jsonl \
    | jq -c "select(.action == \"packet-deny\" and (.detail | contains(\"dst ${TARGET} \"))) | {actor, target, detail}" | tail -n 3
  gate4_ports="tcp8081_bytes ${f81} udp9001_bytes ${f91} deny_records $((d1 - d0))"

  echo "---- Gate 4 [C]: UDP 53 on ${router} ----"
  local q0 q1 n0 n1 ans den x0 x1 dd0 dd1 ok
  n0="$(fwd_bytes "$router" dns)"
  q0="$(log_count landns 'query db.corp.lan')"
  ans="$(ask_dns)"
  sleep 0.3
  n1="$(fwd_bytes "$router" dns)"
  q1="$(log_count landns 'query db.corp.lan')"
  echo "allowed: ${ans}; ${router} FORWARD bytes udp 53 ${n0} -> ${n1}; nameserver queries +$((q1 - q0))"
  [[ "$ans" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]] || fail "The allowed DNS query failed through ${router}."
  [[ "$n1" -gt "$n0" && $((q1 - q0)) -ge 1 ]] || fail "The allowed DNS query did not go through ${router}."
  dd0="$(deny_to "$router" "$NAMESERVER")"
  put_policy "$POLICY_NODNS"
  ok=0
  for _ in $(seq 1 20); do
    refresh_router_grants "$router" || true
    if [[ "$(ask_dns)" == "db.corp.lan no answer" ]]; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [[ "$ok" -eq 1 ]] || fail "${router} did not drop UDP 53 after the rule was removed."
  x0="$(fwd_bytes "$router" dns)"
  q0="$(log_count landns 'query db.corp.lan')"
  den="$(ask_dns)"
  sleep 0.5
  x1="$(fwd_bytes "$router" dns)"
  q1="$(log_count landns 'query db.corp.lan')"
  dd1="$(deny_to "$router" "$NAMESERVER")"
  echo "no rule: ${den}; ${router} FORWARD bytes udp 53 ${x0} -> ${x1}; nameserver queries +$((q1 - q0)); packet-deny records since the rule change +$((dd1 - dd0)) (at most 1 record for each source and port in 10 s)"
  [[ "$x1" == "$x0" && $((q1 - q0)) -eq 0 && $((dd1 - dd0)) -ge 1 ]] || fail "The denied DNS query was not dropped on ${router}."
  gate4_dns="allowed_answer 10.88.24.20 allowed_bytes $((n1 - n0)) denied_bytes $((x1 - x0)) denied_queries $((q1 - q0)) deny_records $((dd1 - dd0))"
  put_policy "$POLICY_BOTH"
  ok=0
  for _ in $(seq 1 20); do
    refresh_router_grants "$router" || true
    if [[ "$(ask_dns)" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]]; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [[ "$ok" -eq 1 ]] || fail "${router} did not allow UDP 53 again."
  echo "[C] gate4 ok through ${router}"
}

echo "---- [C] baseline before the first kill: ping and TCP hold through ${first} ----"
dc exec -d client sh -c "python3 -u /proof/acl-probe.py tcp-hold ${TARGET} 8090 5 > /tmp/hold0.txt 2>&1"
base_ping="$({ dc exec -T client ping -n -i 0.05 -w 5 -W 1 "$TARGET" 2>/dev/null || true; } | grep -E 'packets transmitted|rtt' | tr '\n' ' ')"
sleep 1
base_hold="$(dc exec -T client cat /tmp/hold0.txt 2>/dev/null | grep -v connect_fail | tr '\n' ';' || true)"
echo "baseline ping: ${base_ping}"
echo "baseline tcp hold: ${base_hold}"

declare -a RESULTS=() KILLED=() LOSS=() GAPS=()
watch_changes="-"
watch_srcs="-"
watch_moved="-"
tcp_result="-"
gate4_ports="-"
gate4_dns="-"
audit_example="-"
leak0_client="$(leak_count client)"
leak0_guest="$(leak_count guest)"

for run in $(seq 1 "$RUNS"); do
  active="$(active_router)"
  case "$active" in
    router-a) standby=router-b ;;
    router-b) standby=router-a ;;
    *) fail "Run ${run}: no active router." ;;
  esac
  echo "=== Gate 2 [C] run ${run}: kill ${active}, standby ${standby} ==="
  wait_direct client "$standby" 120 || fail "Run ${run}: the client has no direct path to ${standby}."
  lines0="$(route_lines)"
  audit0="$(route_audit_count)"
  dc exec -d client python3 /proof/acl-probe.py stream "$TARGET" 9000 8 10 "run${run}"
  dc exec -d client python3 /proof/acl-probe.py stream "$TARGET" 9001 8 10 "deny${run}"
  dc exec -d guest python3 /proof/acl-probe.py stream "$TARGET" 9000 8 10 "guest${run}"
  dc exec -d client sh -c "ping -D -n -i 0.05 -w 9 -W 1 ${TARGET} > /tmp/ping${run}.txt 2>&1"
  if [[ "$run" -eq 1 ]]; then
    dc exec -d client sh -c "python3 -u /proof/acl-probe.py tcp-hold ${TARGET} 8090 12 > /tmp/hold.txt 2>&1"
  fi
  sleep 2
  t_kill="$(now_ms)"
  as_root docker kill "${PROJECT}-${active}-1" >/dev/null
  t_killed="$(now_ms)"
  sleep 8
  log="$(target_log u9000)"
  before="$(printf '%s\n' "$log" | awk -v t="$t_kill" -v ip="${LAN_IP[$active]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 < t' | count_lines)"
  first_new="$(printf '%s\n' "$log" | read_all awk -v t="$t_kill" -v ip="${LAN_IP[$standby]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 >= t {print $2; exit}')"
  after_new="$(printf '%s\n' "$log" | awk -v ip="${LAN_IP[$standby]}" -v tag="run${run}" '$4 == tag && $3 == ip' | count_lines)"
  old_after="$(printf '%s\n' "$log" | awk -v t="$t_killed" -v ip="${LAN_IP[$active]}" -v tag="run${run}" '$4 == tag && $3 == ip && $2 > t' | count_lines)"
  total="$(printf '%s\n' "$log" | awk -v tag="run${run}" '$4 == tag' | count_lines)"
  denied_rx="$(target_log u9001 | awk -v tag="deny${run}" '$4 == tag' | count_lines)"
  guest_rx="$(printf '%s\n' "$log" | awk -v tag="guest${run}" '$4 == tag' | count_lines)"
  gap="$(max_gap_ms "run${run}")"
  ping_sum="$(dc exec -T client cat "/tmp/ping${run}.txt" 2>/dev/null | grep 'packets transmitted' || true)"
  ping_tx="$(printf '%s' "$ping_sum" | awk '{print $1}')"
  ping_rx="$(printf '%s' "$ping_sum" | awk '{print $4}')"
  lines1="$(route_lines)"
  audit1="$(route_audit_count)"
  [[ "$before" -ge 50 ]] || fail "Run ${run}: only ${before} datagrams came through ${active} before the kill."
  [[ -n "$first_new" ]] || fail "Run ${run}: no datagram came through ${standby} after the kill."
  [[ -n "$ping_tx" && -n "$ping_rx" ]] || fail "Run ${run}: no ping summary."
  failover_ms=$((first_new - t_kill))
  ping_lost=$((ping_tx - ping_rx))
  echo "run ${run} killed ${active} kill_cmd_ms $((t_killed - t_kill)) failover_ms ${failover_ms} max_gap_ms ${gap} via_old_before ${before} via_new ${after_new} via_old_after_kill ${old_after} received ${total} denied_9001_rx ${denied_rx} guest_rx ${guest_rx} route_changes $((lines1 - lines0))"
  echo "run ${run} ping -i 0.05: ${ping_sum}"
  echo "run ${run} route-failover audit records +$((audit1 - audit0))"
  echo "client log: $(dc logs --no-log-prefix client 2>/dev/null | grep "The HA route ${CIDR} uses " | tail -n 1)"
  [[ "$(active_router)" == "$standby" ]] || fail "Run ${run}: the client log does not name ${standby}."
  [[ "$denied_rx" -eq 0 && "$guest_rx" -eq 0 ]] || fail "Run ${run}: a denied datagram reached the target during the failover."
  [[ "$old_after" -eq 0 ]] || fail "Run ${run}: a datagram came through the killed router."
  [[ "$failover_ms" -le "$LIMIT_MS" ]] || fail "Run ${run}: failover took ${failover_ms} ms (limit ${LIMIT_MS} ms)."
  [[ $((audit1 - audit0)) -eq 1 ]] || fail "Run ${run}: expected 1 route-failover record, got $((audit1 - audit0))."
  audit_example="$(dc exec -T client cat /var/lib/orblx/route-audit.jsonl | jq -c 'select(.action == "route-failover") | {actor, target, action, detail}' | tail -n 1)"
  echo "run ${run} audit record: ${audit_example}"
  RESULTS+=("$failover_ms")
  KILLED+=("$active")
  LOSS+=("${ping_lost}/${ping_tx}")
  GAPS+=("$gap")

  if [[ "$run" -eq 1 ]]; then
    echo "=== Gate 5 [C]: one TCP flow through the subnet during the kill ==="
    for _ in $(seq 1 30); do
      dc exec -T client grep -q '^event end' /tmp/hold.txt 2>/dev/null && break
      sleep 0.5
    done
    hold="$(dc exec -T client cat /tmp/hold.txt 2>/dev/null || true)"
    printf '%s\n' "$hold" | grep -v '^event connect_fail' | read_all head -n 8
    echo "connect_fail events: $(printf '%s\n' "$hold" | grep -c '^event connect_fail' || true)"
    printf '%s\n' "$hold" | read_all grep -q '^event end' || fail "The TCP hold client did not end."
    lost_at="$(printf '%s\n' "$hold" | read_all awk '$2 == "lost" {print $NF; exit}')"
    if [[ -z "$lost_at" ]]; then
      tcp_result="survived connections 1"
    else
      re_at="$(printf '%s\n' "$hold" | read_all awk '$2 == "reconnect" {print $NF; exit}')"
      [[ -n "$re_at" ]] || fail "The TCP flow did not reconnect."
      tcp_reconnect_ms=$((re_at - t_kill))
      tcp_result="reconnected lost_after_kill_ms $((lost_at - t_kill)) reconnect_after_kill_ms ${tcp_reconnect_ms}"
      [[ "$tcp_reconnect_ms" -le "$TCP_LIMIT_MS" ]] || fail "The TCP flow reconnected after ${tcp_reconnect_ms} ms (limit ${TCP_LIMIT_MS} ms)."
    fi
    echo "tcp flow: ${tcp_result}; $(printf '%s\n' "$hold" | grep '^event end')"
    echo "[C] gate5 ok"
    acl_through "$standby"
  fi

  echo "---- [C] run ${run}: restore ${active} ----"
  restore_router "$active"
  sleep 2

  if [[ "$run" -eq 1 ]]; then
    echo "=== Gate 3 [C]: ${active} is back; watch the route for ${WATCH_SECS} s ==="
    w0="$(route_lines)"
    wa0="$(route_audit_count)"
    probe client stream "$TARGET" 9000 "$WATCH_SECS" 10 watch
    sleep 1
    w1="$(route_lines)"
    wa1="$(route_audit_count)"
    watch_changes=$((w1 - w0))
    watch_srcs="$(srcs_of watch)"
    watch_moved="$(target_log u9000 | awk -v ip="${LAN_IP[$active]}" '$4 == "watch" && $3 == ip' | count_lines)"
    echo "route_changes_in_${WATCH_SECS}s ${watch_changes}; route-failover records +$((wa1 - wa0)); target sources ${watch_srcs}; datagrams through ${active} ${watch_moved}"
    echo "status of ${active} on the client: $(dc exec -T client cat /var/lib/orblx/status.txt | grep "^peer ${active} " | awk '{print $6}')"
    [[ "$watch_changes" -le 1 && $((wa1 - wa0)) -le 1 ]] || fail "The route flapped after ${active} came back."
    echo "[C] gate3 ok: ${watch_changes} route changes in ${WATCH_SECS} s"
  fi
done

leak1_client="$(leak_count client)"
leak1_guest="$(leak_count guest)"
echo "=== [C] no leak to the underlay ==="
echo "client eth0 packets to ${CIDR}: ${leak0_client} -> ${leak1_client}; guest: ${leak0_guest} -> ${leak1_guest}"
[[ "$leak1_client" == "$leak0_client" && "$leak1_guest" == "$leak0_guest" ]] || fail "A packet to ${CIDR} left on eth0."

for router in router-a router-b; do
  dc exec -T "$router" orblx audit verify-config --file /var/lib/orblx/packet-audit.jsonl | read_all grep -qx ok \
    || fail "The ${router} packet audit chain did not verify."
done
dc exec -T client orblx audit verify-config --file /var/lib/orblx/route-audit.jsonl | read_all grep -qx ok \
  || fail "The client route audit chain did not verify."
echo "packet audit verify ok on router-a and router-b; route audit verify ok on client ($(route_audit_count) route-failover records)"

echo "=== Gate 6 [C]: no key or token text in the container logs ==="
# The patterns are the real token values and the base64 lines of each private key file.
# The pattern file stays in the temporary work directory, and cleanup removes it.
patterns="$WORK/secret-patterns"
: > "$patterns"
chmod 600 "$patterns"
as_root find "$WORK" -path "$WORK/coord/tokens/*" -type f -exec cat {} + 2>/dev/null \
  | tr -s ' \n' '\n' | awk 'length($0) >= 16' >> "$patterns" || true
as_root grep -rlZ -e 'PRIVATE KEY' "$WORK" 2>/dev/null | as_root xargs -0 -r cat \
  | grep -v -e '-----' | awk 'length($0) >= 16' >> "$patterns" || true
as_root find "$WORK" -type f \( -name '*.key' -o -name '*key.pem' \) -exec grep -I -h -v -e '-----' {} + 2>/dev/null \
  | awk 'length($0) >= 16' >> "$patterns" || true
sort -u -o "$patterns" "$patterns"
secret_patterns="$(grep -c . "$patterns" || true)"
logs_file="$WORK/all-logs.txt"
# W25-14: the scan fails closed. A failed log read or an empty log stops the proof.
dc --profile nodes logs --no-log-prefix coord router-a router-b client guest target landns > "$logs_file" 2>&1 \
  || fail "The proof could not read the container logs."
secret_scan "$logs_file" || fail "The container logs have key or token text, or the log is empty."
secrets="$(grep -c -F -f "$patterns" "$logs_file")" || [[ $? -eq 1 ]] || fail "The secret scan of the logs failed."
echo "secret patterns ${secret_patterns} (token values and key lines); log lines $(grep -c . "$logs_file" || true)"
echo "secret_lines ${secrets}"
[[ "$secret_patterns" -ge 4 ]] || fail "The proof found no token or key to look for."
[[ "$secrets" -eq 0 ]] || fail "The container logs have ${secrets} lines with key or token text."

max=0
for value in "${RESULTS[@]}"; do
  ((value > max)) && max="$value"
done
under_target=0
for value in "${RESULTS[@]}"; do
  ((value <= TARGET_MS)) && under_target=$((under_target + 1))
done
other_end="$(other_orblx_containers)"
echo "=== summary ==="
echo "gate1 unapproved ${gate1_unapproved}"
for i in "${!RESULTS[@]}"; do
  echo "run $((i + 1)) killed ${KILLED[$i]} failover_ms ${RESULTS[$i]} max_gap_ms ${GAPS[$i]} ping_lost ${LOSS[$i]}"
done
echo "failover_ms_all ${RESULTS[*]} max ${max} limit ${LIMIT_MS} pass ${#RESULTS[@]}/${RUNS} at_or_below_target_${TARGET_MS} ${under_target}/${RUNS}"
echo "audit_record ${audit_example}"
echo "failback route_changes_in_${WATCH_SECS}s ${watch_changes} sources ${watch_srcs}"
echo "gate4 ports ${gate4_ports}"
echo "gate4 dns ${gate4_dns}"
echo "gate5 tcp ${tcp_result}"
echo "leak client $((leak1_client - leak0_client)) guest $((leak1_guest - leak0_guest))"
echo "secret_lines ${secrets}"
echo "end_kst $(TZ=Asia/Seoul date '+%Y-%m-%d %H:%M:%S')"
echo "other_orblx_containers_at_end ${other_end}"
echo "proof_ok"

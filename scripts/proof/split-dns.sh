#!/usr/bin/env bash
# W24-F split DNS proof.
# The policy maps corp.lan to 10.88.24.53. That DNS server is behind a subnet router.
# Node a accepts the subnet route. Node a resolves db.corp.lan through the overlay and connects.
# Node c does not accept the route. Node c gets REFUSED. No corp.lan query leaves node c.
# The proof then removes corp.lan from the policy and prints the time to the new answer.
# The script deletes the proof containers at the start and at the end.
# The script does not print enroll tokens or private keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.split-dns.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w24f-proof}"
export ORBLX_SPLIT_IMAGE="${ORBLX_SPLIT_IMAGE:-orblx-w24f:local}"
WORK="$(mktemp -d)"
export SPLIT_COORD_STATE="$WORK/coord"
export SPLIT_POLICY_DIR="$WORK/policy"
export SPLIT_TOOL_STATE="$WORK/tool"
export SPLIT_FETCH_A_STATE="$WORK/enroll-a"
export SPLIT_ROUTER_STATE="$WORK/router"
export SPLIT_A_STATE="$WORK/a"
export SPLIT_C_STATE="$WORK/c"
export SPLIT_ROUTER_NETMAP="$WORK/netmap-router.json"
export SPLIT_A_NETMAP="$WORK/netmap-a.json"
export SPLIT_C_NETMAP="$WORK/netmap-c.json"
COORD="172.30.124.2:443"
ROUTER_IP="172.30.124.3"
A_IP="172.30.124.4"
C_IP="172.30.124.5"
LIMIT_MS=2000

cleanup() {
  dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$(id -u)" -eq 0 ]]; then
    rm -rf "$WORK"
  else
    sudo -n rm -rf "$WORK" >/dev/null 2>&1 || rm -rf "$WORK" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

fail() {
  echo "$1" >&2
  dc logs a c router landns sysdns >&2 || true
  exit 1
}

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir bin
  bin="$ROOT/target/debug/orblx"
  cargo build -p orblx-cli --bin orblx
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t "$ORBLX_SPLIT_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  for _ in $(seq 1 90); do
    if [[ -s "$SPLIT_COORD_STATE/trust-bundle.pem" ]]; then
      return 0
    fi
    sleep 1
  done
  fail "The coordinator did not write the trust bundle."
}

tool() {
  local state="$1"
  shift
  export SPLIT_TOOL_STATE="$state"
  dc --profile tool run --rm --no-deps tool "$@"
}

enroll() {
  local name="$1" endpoint="$2"
  echo "=== [C] token and enroll ${name} ==="
  dc exec -T coord orblx coord token create --state /var/lib/orblx --out "/var/lib/orblx/tokens/${name}" --ttl 3600 >/dev/null
  tool "$WORK/enroll-${name}" coord enroll \
    --name "$name" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx \
    --endpoint "${endpoint}:443"
}

fetch_netmap() {
  local name="$1"
  tool "$WORK/enroll-${name}" coord netmap \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --state /var/lib/orblx >/dev/null
}

overlay_of() {
  local name="$1" file="$2"
  sed -n "s/.*\"name\":\"${name}\",\"overlay_ip\":\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
}

ask() {
  local node="$1" name="$2" server="$3"
  dc exec -T "$node" python3 /proof/dns-ask.py "$name" "$server"
}

# The packets that leave the node on eth0 to UDP port 53.
leak_count() {
  local node="$1"
  dc exec -T "$node" iptables -nvx -L OUTPUT | awk '/orblx-w24f-leak/ {print $1}'
}

lines_for() {
  local service="$1" pattern="$2"
  { dc logs --no-log-prefix "$service" 2>/dev/null || true; } | grep -c -- "$pattern" || true
}

mkdir -p "$SPLIT_COORD_STATE" "$SPLIT_POLICY_DIR" "$SPLIT_ROUTER_STATE" "$SPLIT_A_STATE" "$SPLIT_C_STATE"
cp "$ROOT/scripts/proof/split-dns.hujson" "$SPLIT_POLICY_DIR/policy.hujson"
chmod 755 "$SPLIT_POLICY_DIR"
chmod 644 "$SPLIT_POLICY_DIR/policy.hujson"

echo "=== W24-F split DNS proof. All gates are [C] (Docker on one Linux host). ==="
echo "project ${PROOF_PROJECT} image ${ORBLX_SPLIT_IMAGE}"
echo "policy splitDns corp.lan -> 10.88.24.53 (behind router, route 10.88.24.0/24)"
echo "node a accepts routes. node c does not accept routes."
echo "system resolver of a and c: sysdns 172.30.124.53 (answers every name with 192.0.2.1)"

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle
dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson

enroll router "$ROUTER_IP"
enroll a "$A_IP"
enroll c "$C_IP"

echo "=== [C] advertise routes ==="
tool "$WORK/enroll-router" coord advertise \
  --coord "$COORD" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx \
  --route 10.88.24.0/24

echo "=== [C] netmaps ==="
for name in a c router; do
  fetch_netmap "$name"
done
cat "$WORK/enroll-a/netmap.json" > "$SPLIT_A_NETMAP"
cat "$WORK/enroll-c/netmap.json" > "$SPLIT_C_NETMAP"
cat "$WORK/enroll-router/netmap.json" > "$SPLIT_ROUTER_NETMAP"
echo "---- [C] netmap a split_dns ----"
jq -c '.split_dns' "$SPLIT_A_NETMAP"
jq -e '.split_dns == [{"domain":"corp.lan","nameservers":["10.88.24.53"]}]' "$SPLIT_A_NETMAP" >/dev/null \
  || fail "The signed netmap for a has no corp.lan zone."
jq -e '.peers[] | select(.name=="router") | .routes == ["10.88.24.0/24"]' "$SPLIT_A_NETMAP" >/dev/null \
  || fail "The signed netmap for a has no router route."

router_ip="$(overlay_of router "$SPLIT_A_NETMAP")"
a_ip="$(overlay_of a "$SPLIT_C_NETMAP")"
c_ip="$(overlay_of c "$SPLIT_A_NETMAP")"
[[ -n "$router_ip" && -n "$a_ip" && -n "$c_ip" ]] || fail "The netmap did not include the overlay addresses."
echo "overlay router ${router_ip} a ${a_ip} c ${c_ip}"

echo "=== [C] node material ==="
"$ROOT/target/debug/orblx" node-issue \
  --out "$WORK/nodes" \
  --node "router=${router_ip}" \
  --node "a=${a_ip}" \
  --node "c=${c_ip}" >/dev/null
cp -a "$WORK/nodes/router/." "$SPLIT_ROUTER_STATE/"
# W24-A: the router uses the signed grants, so the port ACL covers its subnet route.
cat "$WORK/enroll-router/netmap.pub" > "$SPLIT_ROUTER_STATE/netmap.pub"
cat "$WORK/enroll-router/grants.signed.json" > "$SPLIT_ROUTER_STATE/grants.signed.json"
cp -a "$WORK/nodes/a/." "$SPLIT_A_STATE/"
cp -a "$WORK/nodes/c/." "$SPLIT_C_STATE/"

echo "=== [C] start sysdns, landns, db, router, a, c, fetch-a ==="
dc --profile nodes up -d sysdns landns db router a c fetch-a

echo "=== [C] wait for the overlay paths ==="
for node in a c; do
  ready=0
  for _ in $(seq 1 40); do
    if dc logs "$node" 2>/dev/null | grep -q 'The path to router is direct.'; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" -eq 1 ]] || fail "Node ${node} did not open a path to the router."
done
dc logs router 2>/dev/null | grep -q 'The node forwards 10.88.24.0/24' || fail "The router did not enable forwarding."
dc logs router 2>/dev/null | grep -q 'The packet filter is on.' || fail "The router packet filter is not on."

echo "---- [C] routes ----"
echo "a: $(dc exec -T a ip route get 10.88.24.53 | head -n 1)"
echo "c: $(dc exec -T c ip route get 10.88.24.53 | head -n 1)"
dc exec -T a ip route show dev orblx0 | grep -q '10.88.24.0/24' || fail "Node a has no route to 10.88.24.0/24."
if dc exec -T c ip route show dev orblx0 | grep -q '10.88.24.0/24'; then
  fail "Node c has the route. Node c must not accept routes."
fi

echo "---- [C] resolvectl domain orblx0 ----"
echo "a: $(dc exec -T a resolvectl domain orblx0 2>&1 || true)"
echo "c: $(dc exec -T c resolvectl domain orblx0 2>&1 || true)"

echo "---- [C] leak counter on a and c (OUTPUT, eth0, udp dport 53) ----"
for node in a c; do
  dc exec -T "$node" iptables -I OUTPUT 1 -o eth0 -p udp --dport 53 -m comment --comment orblx-w24f-leak
done

echo "=== Gate 1 [C]: node a resolves db.corp.lan through the overlay and connects ==="
leak_a0="$(leak_count a)"
out="$(ask a db.corp.lan "$a_ip")"
echo "a direct query to ${a_ip}: ${out}"
[[ "$out" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]] || fail "Node a did not get the db.corp.lan address."
echo "---- [C] a resolvectl query db.corp.lan ----"
resolved_out="$(dc exec -T a resolvectl query db.corp.lan 2>&1 || true)"
printf '%s\n' "$resolved_out"
printf '%s\n' "$resolved_out" | grep -q '10.88.24.20' || fail "systemd-resolved on a did not resolve db.corp.lan."
echo "---- [C] a curl http://db.corp.lan/ (name from the OS resolver) ----"
body="$(dc exec -T a curl -fsS --max-time 10 http://db.corp.lan/)"
echo "body ${body}"
[[ "$body" == "db-ok" ]] || fail "Node a did not connect to db.corp.lan."
landns_from_router="$(lines_for landns 'query db.corp.lan type 1 from 10.88.24.2 ')"
echo "landns queries for db.corp.lan from router LAN address 10.88.24.2: ${landns_from_router}"
[[ "$landns_from_router" -ge 2 ]] || fail "The zone DNS server did not see the queries through the router."
leak_a1="$(leak_count a)"
sys_corp_a="$(lines_for sysdns "corp.lan from ${A_IP}")"
echo "a leak counter delta ${leak_a0} -> ${leak_a1}; sysdns corp.lan queries from a: ${sys_corp_a}"
[[ "$leak_a1" == "$leak_a0" && "$sys_corp_a" -eq 0 ]] || fail "A corp.lan query from a left on eth0."
echo "a log: $(dc logs --no-log-prefix a 2>/dev/null | grep 'for corp.lan through the overlay' | tail -n 1)"
echo "[C] gate1 ok"

echo "=== Gate 2 [C]: node c without the route gets REFUSED and nothing leaks ==="
leak_c0="$(leak_count c)"
for name in db.corp.lan corp.lan x.y.corp.lan; do
  out="$(ask c "$name" "$c_ip")"
  echo "c direct query: ${out}"
  [[ "$out" == "${name} rcode 5 answers 0 address -" ]] || fail "Node c did not get REFUSED for ${name}."
done
resolved_c="$(dc exec -T c resolvectl query db.corp.lan 2>&1 || true)"
echo "c resolvectl query db.corp.lan: ${resolved_c}"
if printf '%s\n' "$resolved_c" | grep -q -e '10.88.24.20' -e '192.0.2.1'; then
  fail "Node c resolved db.corp.lan."
fi
sleep 1
leak_c1="$(leak_count c)"
sys_corp_c="$(lines_for sysdns "corp.lan from ${C_IP}")"
land_total="$(lines_for landns 'query ')"
echo "c leak counter ${leak_c0} -> ${leak_c1} (delta $((leak_c1 - leak_c0)))"
echo "sysdns corp.lan queries from c: ${sys_corp_c}"
echo "c log: $(dc logs --no-log-prefix c 2>/dev/null | grep 'split_refused=' | tail -n 1)"
[[ "$leak_c1" == "$leak_c0" ]] || fail "A query left node c on eth0 to port 53."
[[ "$sys_corp_c" -eq 0 ]] || fail "A corp.lan query from c reached the system resolver."
echo "---- [C] the counter sees a real system resolver query ----"
out="$(ask c example.test "$c_ip")"
echo "c example.test: ${out}"
leak_c2="$(leak_count c)"
echo "c leak counter after example.test ${leak_c1} -> ${leak_c2}"
[[ "$leak_c2" -gt "$leak_c1" ]] || fail "The leak counter did not see a system resolver query."
land_other="$(( land_total - $(lines_for landns ' from 10.88.24.2 ') ))"
echo "landns total queries ${land_total}, from an address other than the router ${land_other}"
[[ "$land_other" -eq 0 ]] || fail "The zone DNS server saw a query that did not come through the router."
echo "[C] gate2 ok"

echo "=== Gate 3 [C]: .orblx names and other names keep the W18-4 behavior ==="
for node in a c; do
  self_ip="$a_ip"
  [[ "$node" == c ]] && self_ip="$c_ip"
  out="$(ask "$node" router "$self_ip")"
  echo "${node}: ${out}"
  [[ "$out" == "router rcode 0 answers 1 address ${router_ip}" ]] || fail "The short name router is wrong on ${node}."
  out="$(ask "$node" missing.orblx "$self_ip")"
  echo "${node}: ${out}"
  [[ "$out" == "missing.orblx rcode 3 answers 0 address -" ]] || fail "missing.orblx is not NXDOMAIN on ${node}."
  out="$(ask "$node" db.corp.lan.orblx "$self_ip")"
  echo "${node}: ${out}"
  [[ "$out" == "db.corp.lan.orblx rcode 3 answers 0 address -" ]] || fail "db.corp.lan.orblx is not NXDOMAIN on ${node}."
  out="$(ask "$node" www.example.test "$self_ip")"
  echo "${node}: ${out}"
  [[ "$out" == "www.example.test rcode 0 answers 1 address 192.0.2.1" ]] || fail "Other names did not go to the system resolver on ${node}."
done
echo "[C] gate3 ok"

echo "=== Gate 4 [C]: remove corp.lan from the policy, no restart ==="
a_start0="$(docker inspect --format '{{.State.StartedAt}} restarts {{.RestartCount}}' "$(dc ps -q a)")"
removed="$WORK/policy-removed.hujson"
jq_policy="$(grep -v '^\s*//' "$SPLIT_POLICY_DIR/policy.hujson")"
printf '%s\n' "$jq_policy" | python3 -c 'import sys,re,json
text=sys.stdin.read()
text=re.sub(r",(\s*[}\]])", r"\1", text)
data=json.loads(text)
data.pop("splitDns")
print(json.dumps(data, indent=2))' > "$removed"
dc exec -d a sh -c "python3 /proof/dns-ask.py --until-not 10.88.24.20 db.corp.lan ${a_ip} 8000 > /tmp/change.txt 2>&1"
sleep 0.3
t0="$(date +%s%3N)"
cp "$removed" "$SPLIT_POLICY_DIR/policy.next"
mv "$SPLIT_POLICY_DIR/policy.next" "$SPLIT_POLICY_DIR/policy.hujson"
dc exec -T fetch-a orblx coord netmap --coord "$COORD" --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx >/dev/null
cat "$WORK/enroll-a/netmap.json" > "$SPLIT_A_NETMAP"
t1="$(date +%s%3N)"
change=""
for _ in $(seq 1 100); do
  change="$(dc exec -T a cat /tmp/change.txt 2>/dev/null || true)"
  [[ -n "$change" ]] && break
  sleep 0.1
done
echo "probe: ${change}"
changed_at="$(printf '%s\n' "$change" | awk '/changed_at_ms/ {print $2}')"
[[ -n "$changed_at" ]] || fail "The answer for db.corp.lan did not change after the policy change."
policy_ms=$((changed_at - t0))
fetch_ms=$((t1 - t0))
netmap_ms=$((changed_at - t1))
jq -c '.split_dns // []' "$SPLIT_A_NETMAP"
a_start1="$(docker inspect --format '{{.State.StartedAt}} restarts {{.RestartCount}}' "$(dc ps -q a)")"
echo "node a container start before [${a_start0}] after [${a_start1}] (orblx is pid 1, no restart)"
[[ "$a_start0" == "$a_start1" ]] || fail "Node a restarted."
echo "policy_change_to_new_answer_ms ${policy_ms} (fetch and write ${fetch_ms} ms, netmap file to new answer ${netmap_ms} ms, limit ${LIMIT_MS} ms)"
[[ "$policy_ms" -le "$LIMIT_MS" ]] || fail "The change took ${policy_ms} ms."
out="$(ask a db.corp.lan "$a_ip")"
echo "a after removal: ${out} (now from the system resolver)"
echo "[C] gate4 ok"

echo "=== Gate 5 [C] (W24-A): the port ACL covers the subnet route ==="
fwd_bytes() {
  dc exec -T router iptables -nvx -L FORWARD | awk '/orblx-w24acl-dns/ {print $2}'
}
router_reloads() {
  lines_for router 'The DNS responder loaded new signed grants.'
}
deny_records() {
  { dc exec -T router cat /var/lib/orblx/packet-audit.jsonl 2>/dev/null || true; } \
    | jq -c 'select(.action == "packet-deny" and .target == "udp/53" and (.detail | contains("dst 10.88.24.53 ")))' \
    | grep -c . || true
}
dc exec -T router iptables -I FORWARD 1 -d 10.88.24.53/32 -p udp --dport 53 -m comment --comment orblx-w24acl-dns
land_q="query db.corp.lan type 1 from 10.88.24.2 "
echo "---- [C] 5a: the policy allows udp 10.88.24.53/32:53 ----"
f0="$(fwd_bytes)"
l0="$(lines_for landns "$land_q")"
out="$(ask a db.corp.lan 10.88.24.53)"
sleep 0.5
f1="$(fwd_bytes)"
l1="$(lines_for landns "$land_q")"
echo "a to 10.88.24.53:53: ${out}"
echo "allowed_fwd_bytes $((f1 - f0)) allowed_landns_queries $((l1 - l0))"
[[ "$out" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]] || fail "The allowed query did not get an answer."
[[ $((f1 - f0)) -gt 0 && $((l1 - l0)) -ge 1 ]] || fail "The allowed query did not reach the zone DNS server."
echo "---- [C] 5b: remove the UDP 53 rule; the router gets new signed grants ----"
denied_policy="$WORK/policy-no-udp53.hujson"
grep -v '^\s*//' "$SPLIT_POLICY_DIR/policy.hujson" | python3 -c 'import sys,re,json
text=re.sub(r",(\s*[}\]])", r"\1", sys.stdin.read())
data=json.loads(text)
data["acls"]=[rule for rule in data["acls"] if rule.get("proto") != "udp"]
print(json.dumps(data, indent=2))' > "$denied_policy"
jq -c '.acls' "$denied_policy"
reload0="$(router_reloads)"
cp "$denied_policy" "$SPLIT_POLICY_DIR/policy.next"
mv "$SPLIT_POLICY_DIR/policy.next" "$SPLIT_POLICY_DIR/policy.hujson"
fetch_netmap router
cat "$WORK/enroll-router/grants.signed.json" > "$SPLIT_ROUTER_STATE/grants.next"
mv "$SPLIT_ROUTER_STATE/grants.next" "$SPLIT_ROUTER_STATE/grants.signed.json"
for _ in $(seq 1 50); do
  [[ "$(router_reloads)" -gt "$reload0" ]] && break
  sleep 0.1
done
[[ "$(router_reloads)" -gt "$reload0" ]] || fail "The router did not load the new grants."
d0="$(deny_records)"
f2="$(fwd_bytes)"
l2="$(lines_for landns "$land_q")"
out="$(ask a db.corp.lan 10.88.24.53 2>&1 | tail -n 1 || true)"
sleep 1
f3="$(fwd_bytes)"
l3="$(lines_for landns "$land_q")"
d1="$(deny_records)"
echo "a to 10.88.24.53:53: ${out}"
echo "denied_fwd_bytes $((f3 - f2)) denied_landns_queries $((l3 - l2)) audit_packet_deny_udp53 $((d1 - d0))"
[[ "$out" != *"rcode"* ]] || fail "The denied query got an answer."
[[ $((f3 - f2)) -eq 0 && $((l3 - l2)) -eq 0 ]] || fail "The denied query reached the subnet."
[[ $((d1 - d0)) -ge 1 ]] || fail "The router did not audit the denied query."
dc exec -T router cat /var/lib/orblx/packet-audit.jsonl \
  | jq -c 'select(.target == "udp/53") | {action, actor, target, detail}' | tail -n 1
dc exec -T router orblx audit verify-config --file /var/lib/orblx/packet-audit.jsonl | grep -qx ok \
  || fail "The router packet audit chain did not verify."
echo "router packet audit verify ok"
body="$(dc exec -T a curl -fsS --max-time 10 http://10.88.24.20/)"
echo "a tcp 10.88.24.20:80 still allowed: body ${body}"
[[ "$body" == "db-ok" ]] || fail "The TCP 80 rule stopped working."
echo "[C] gate5 ok"

echo "=== summary ==="
echo "gate1 a db.corp.lan 10.88.24.20 via router, curl db-ok"
echo "gate2 c REFUSED, leak delta $((leak_c1 - leak_c0)), sysdns corp.lan from c ${sys_corp_c}"
echo "gate3 orblx names and other names unchanged"
echo "gate4 policy_change_to_new_answer_ms ${policy_ms}"
echo "gate5 subnet udp53 allowed fwd_bytes $((f1 - f0)) landns $((l1 - l0)); denied fwd_bytes $((f3 - f2)) landns $((l3 - l2)) audit $((d1 - d0))"
echo "proof_ok"

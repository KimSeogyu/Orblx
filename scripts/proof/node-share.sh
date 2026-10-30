#!/usr/bin/env bash
# Node sharing proof (W25-1).
# The owner has nodes owner, a, and b (token enroll). Guest user bob has nodes g and g2
# (OIDC enroll with the [C] test issuer, subject bob).
# The policy shares TCP 8080 on node b with oidc:bob. Node b also serves TCP 9090.
# Checks:
#   1. g connects to b:8080.
#   2. The netmap of g holds only b and g2. A connect from g to node a fails.
#      Node a counts the TCP and UDP bytes from g and g2 on port 7070: 0 bytes.
#   3. A connect from a to g fails. The acl a -> g does not cross the tenant.
#   4. The script removes the share with one rename of the policy file.
#      g -> b:8080 is denied within LIMIT_MS. The script prints the ms.
#      a -> b:8080 and g -> g2:8080 have no failure during and after the change.
#   5. The unshare and the share again each write exactly 1 coordinator record.
#      The chain verifies ok.
#   6. Port scope (W25-1b): g sends 65536 bytes on TCP and on UDP to b:9090 (not shared).
#      Node b counts 0 bytes from g, and its packet-audit chain has exactly 1 packet-deny
#      record for g tcp/9090. The chain verifies. Node a sends the same to b:9090 as a control.
#      A check from b to g:8080 is refused (the share gives b nothing on g).
# ORBLX_SHARE_POLICY selects the policy. The default has an `acls` list.
# scripts/proof/node-share-noacl.hujson has no `acls` list: then only the shared peers are filtered.
# ORBLX_SHARE_PORT_GATE=0 prints the port checks without the gate.
# The script deletes the orblx-w25a-node-share volumes at the start.
# The script does not print enroll tokens, ID tokens, private keys, or tickets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.node-share.yml"
WORK="$(mktemp -d)"
export POLICY_DIR="$WORK/policy"
export CONFIG_FILE="$WORK/coord.toml"
export IDP_CA_FILE="$WORK/idp-ca.pem"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
ISSUER="https://idp:8443"
CLIENT="orblx-proof"
LIMIT_MS=1000
STATE=/var/lib/orblx
PORT_GATE="${ORBLX_SHARE_PORT_GATE:-1}"
POLICY_SRC="${ORBLX_SHARE_POLICY:-$ROOT/scripts/proof/node-share.hujson}"
mkdir -p "$POLICY_DIR"
: >"$IDP_CA_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  # sudo drops the environment, so pass the Compose variables with env.
  as_root env POLICY_DIR="$POLICY_DIR" CONFIG_FILE="$CONFIG_FILE" IDP_CA_FILE="$IDP_CA_FILE" \
    COORD_ADDR="$COORD_ADDR" \
    docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (tail) ----"
    dc logs --tail 40 2>&1 | grep -v 'PRIVATE KEY' || true
  fi
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

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
  local image_dir
  cargo build -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$TARGET_DIR/debug/orblx")"
  cp "$TARGET_DIR/debug/orblx-test-idp" "$image_dir/orblx-test-idp"
  printf '%s\n' 'COPY orblx-test-idp /usr/local/bin/orblx-test-idp' >>"$image_dir/Dockerfile"
  as_root docker build -q -t orblx-w25a-share:w25 "$image_dir" >/dev/null
  rm -rf "$image_dir"
}

now_ms() {
  date +%s%3N
}

# Replace the policy with one rename, so the coordinator never reads a half file.
put_policy() {
  cp "$1" "$POLICY_DIR/.next.hujson"
  mv -f "$POLICY_DIR/.next.hujson" "$POLICY_DIR/policy.hujson"
}

idp() {
  dc run --rm --no-deps --entrypoint orblx-test-idp idp "$@"
}

wait_log() {
  local service="$1" needle="$2" i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | grep -q -- "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  return 1
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat "$STATE/trust-bundle.pem" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

wait_path() {
  local from="$1" to="$2" i
  for i in $(seq 1 60); do
    if dc exec -T "$from" orblx status --state-dir "$STATE" 2>/dev/null \
      | grep -q "^peer ${to} .* path direct "; then
      echo "path ${from} ${to} direct"
      return 0
    fi
    sleep 1
  done
  echo "The path from ${from} to ${to} did not come up." >&2
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

owner() {
  run_node owner admin "$@" --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

peers_of() {
  dc exec -T "$1" cat "$STATE/netmap.json" | jq -r '[.netmap.peers[]?.name // empty, .peers[]?.name // empty] | sort | join(",")'
}

# get FROM IP PORT: one HTTP GET over the overlay. Exit 0 on HTTP 200.
get() {
  dc exec -T "$1" python3 /tmp/share-get.py "$2" "$3" 0.8
}

expect_ok() {
  local label="$1"
  shift
  if out="$(get "$@")"; then
    echo "check ${label} ok: ${out}"
  else
    echo "check ${label} failed: ${out}" >&2
    exit 1
  fi
}

expect_fail() {
  local label="$1"
  shift
  if out="$(get "$@")"; then
    echo "check ${label} reached the port: ${out}" >&2
    exit 1
  fi
  echo "check ${label} refused: ${out}"
}

# A port check of the packet filter. ORBLX_SHARE_PORT_GATE=0 turns off the gate.
port_check() {
  local label="$1"
  shift
  if out="$(get "$@")"; then
    echo "port_check ${label} reached: ${out}"
    if [[ "$PORT_GATE" == 1 ]]; then
      echo "The port check ${label} reached the port." >&2
      exit 1
    fi
    port_results+=("${label}=reached")
  else
    echo "port_check ${label} refused: ${out}"
    port_results+=("${label}=refused")
  fi
}

records() {
  owner audit --verify | awk '$1 == "verify" && $2 == "ok" {print $4}'
}

probe() {
  local node="$1" mode="$2" label="$3" secs="$4" every="$5"
  shift 5
  dc exec -T "$node" python3 /tmp/probe.py "$mode" "$label" "$secs" "$every" "$@" \
    >"$WORK/probe-${label}.out" 2>&1 &
  pids+=($!)
}

cp "$POLICY_SRC" "$WORK/shared.hujson"
echo "policy $(basename "$POLICY_SRC") acls $(grep -c '"acls"' "$WORK/shared.hujson" || true)"
grep -v 'SHARE-B\|node/b:8080' "$WORK/shared.hujson" >"$WORK/unshared.hujson"
if cmp -s "$WORK/shared.hujson" "$WORK/unshared.hujson"; then
  echo "The unshared policy is the same as the shared policy." >&2
  exit 1
fi
put_policy "$WORK/shared.hujson"
cat >"$CONFIG_FILE" <<CONF
# [C] coordinator config for the node sharing proof.
[oidc]
issuer = "${ISSUER}"
client_id = "${CLIENT}"
allowed_domains = ["example.test"]
allowed_emails = []
ca_file = "/etc/orblx/idp-ca.pem"
CONF

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] init test issuer ==="
idp init --dir /idp --host idp >/dev/null
dc run --rm --no-deps --entrypoint cat idp /idp/ca.pem >"$IDP_CA_FILE"
grep -q 'BEGIN CERTIFICATE' "$IDP_CA_FILE"

echo "=== [C] start test issuer and coordinator ==="
dc up -d idp
wait_log idp "idp serve"
dc up -d coord
if [[ -n "${ORBLX_PROOF_NET_HOOK:-}" ]]; then
  as_root "$ORBLX_PROOF_NET_HOOK"
fi
wait_bundle
wait_log coord "oidc issuer"

for name in owner a b; do
  dc exec -T coord orblx coord token create --state "$STATE" --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done

coord_ip="$(dc run --rm --no-deps --entrypoint getent owner ahostsv4 coord \
  | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}')"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

for name in owner a b; do
  echo "=== [C] enroll ${name} with a token (owner) ==="
  run_node "$name" coord enroll --name "$name" --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" --endpoint "${name}:443"
done
for name in g g2; do
  echo "=== [C] enroll ${name} with an ID token of guest bob ==="
  idp mint --dir /idp --kid rs1 --issuer "$ISSUER" --aud "$CLIENT" --out "/tokens/${name}" \
    --sub bob --email bob@example.test >/dev/null
  run_node "$name" coord enroll --name "$name" --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem --id-token-file "/tokens/${name}" \
    --state "$STATE" --endpoint "${name}:443"
done
wait_log coord "oidc accept sub bob"

nodes="$(owner nodes)"
printf '%s\n' "$nodes"
ip_of() {
  printf '%s\n' "$nodes" | awk -v name="$1" '$1 == "node" && $2 == name {print $3; exit}'
}
a_ip="$(ip_of a)"
b_ip="$(ip_of b)"
g_ip="$(ip_of g)"
g2_ip="$(ip_of g2)"
echo "overlay a ${a_ip} b ${b_ip} g ${g_ip} g2 ${g2_ip}"
dc exec -T coord cat "$STATE/nodes.json" | jq -r '.nodes[] | "store \(.name) owner_kind \(.owner | split(":")[0]) \(if (.owner | startswith("oidc:")) then .owner else "" end)"'

for name in a b g g2; do
  run_node "$name" coord netmap --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" \
    --state "$STATE" >/dev/null
done

echo "=== [C] start nodes a, b, g, and g2 ==="
dc up -d a b g g2
for name in a b g g2; do
  wait_log "$name" 'The TUN device'
done
wait_path a b
wait_path b g
wait_path b g2
wait_path g g2

echo "=== [C] gate 2: netmaps ==="
for name in a b g g2; do
  echo "netmap ${name} peers $(peers_of "$name")"
done
[[ "$(peers_of g)" == "b,g2" ]]
[[ "$(peers_of g2)" == "b,g" ]]
[[ "$(peers_of a)" == "b,owner" ]]
[[ "$(peers_of b)" == "a,g,g2,owner" ]]
dc exec -T g cat "$STATE/grants.signed.json" 2>/dev/null \
  | jq -c '{reach: .grants.reach}' 2>/dev/null || true

echo "=== [C] web servers: b on 8080 and 9090, a, g, and g2 on 8080 ==="
for name in a b g g2; do
  dc exec -d "$name" python3 -m http.server 8080 --bind 0.0.0.0
  dc exec -T "$name" sh -c "cat > /tmp/share-get.py" <"$ROOT/scripts/proof/share-get.py"
  dc exec -T "$name" sh -c "cat > /tmp/probe.py" <"$ROOT/scripts/proof/revoke-probe.py"
  dc exec -T "$name" sh -c "cat > /tmp/share-sink.py" <"$ROOT/scripts/proof/share-sink.py"
done
# Byte counters for gate 2: TCP and UDP 7070 on node a (other owner node) and on g2 (control).
for name in a g2; do
  dc exec -d "$name" python3 /tmp/share-sink.py serve 7070 /tmp/sink-7070.txt
done
# Byte counter for the port gate: TCP and UDP 9090 on node b. Port 9090 is not shared.
dc exec -d b python3 /tmp/share-sink.py serve 9090 /tmp/sink-9090.txt
sleep 1

echo "=== [C] gate 1: the guest reaches the shared node and port ==="
expect_ok "g -> b:8080" g "$b_ip" 8080
expect_ok "g2 -> b:8080" g2 "$b_ip" 8080
echo "=== [C] gate 2: the guest does not reach the other node of the owner ==="
expect_fail "g -> a:8080" g "$a_ip" 8080
expect_fail "g2 -> a:8080" g2 "$a_ip" 8080
# Each guest node sends 65536 bytes on TCP and 65536 bytes on UDP to a:7070.
# The control sends the same from g to g2:7070 (same tenant), so the counter works.
for name in g g2; do
  dc exec -T "$name" python3 /tmp/share-sink.py send "$a_ip" 7070 65536 0.8
done
dc exec -T g python3 /tmp/share-sink.py send "$g2_ip" 7070 65536 0.8
sleep 1
sink_bytes() {
  dc exec -T "$1" cat /tmp/sink-7070.txt | awk -v src="$2" '$1 == src {n += $2} END {print n + 0}'
}
a_from_g="$(sink_bytes a "$g_ip")"
a_from_g2="$(sink_bytes a "$g2_ip")"
g2_from_g="$(sink_bytes g2 "$g_ip")"
echo "gate2_bytes a_from_g ${a_from_g} a_from_g2 ${a_from_g2} control_g2_from_g ${g2_from_g}"
if (( a_from_g != 0 || a_from_g2 != 0 )); then
  echo "Node a got bytes from a guest node." >&2
  exit 1
fi
if (( g2_from_g == 0 )); then
  echo "The control counter got no bytes, so the counter does not work." >&2
  exit 1
fi
echo "=== [C] gate 3: the owner does not reach the guest nodes ==="
expect_fail "a -> g:8080" a "$g_ip" 8080
expect_fail "a -> g2:8080" a "$g2_ip" 8080
echo "=== [C] other access ==="
expect_ok "a -> b:8080" a "$b_ip" 8080
expect_ok "g -> g2:8080" g "$g2_ip" 8080
port_results=()
echo "=== [C] gate 6: the share gives only its ports (gate ${PORT_GATE}) ==="
port_check "g -> b:9090" g "$b_ip" 9090
port_check "b -> g:8080" b "$g_ip" 8080
dc exec -T g python3 /tmp/share-sink.py send "$b_ip" 9090 65536 0.8
dc exec -T a python3 /tmp/share-sink.py send "$b_ip" 9090 65536 0.8
sleep 1
b9090_from_g="$(dc exec -T b cat /tmp/sink-9090.txt | awk -v src="$g_ip" '$1 == src {n += $2} END {print n + 0}')"
b9090_from_a="$(dc exec -T b cat /tmp/sink-9090.txt | awk -v src="$a_ip" '$1 == src {n += $2} END {print n + 0}')"
echo "port_bytes b9090_from_g ${b9090_from_g} control_b9090_from_a ${b9090_from_a}"
# The packet filter writes its records from a thread. Wait for the record.
g_svid="spiffe://orblx.local/node/g"
pd_tcp=0
for _ in $(seq 1 30); do
  dc exec -T b sh -c "cat $STATE/packet-audit.jsonl 2>/dev/null || true" >"$WORK/b-packet-audit.jsonl"
  pd_tcp="$(jq -s --arg g "$g_svid" '[.[] | select(.action == "packet-deny" and .actor == $g and .target == "tcp/9090")] | length' "$WORK/b-packet-audit.jsonl")"
  (( pd_tcp >= 1 )) && break
  sleep 0.2
done
pd_udp="$(jq -s --arg g "$g_svid" '[.[] | select(.action == "packet-deny" and .actor == $g and .target == "udp/9090")] | length' "$WORK/b-packet-audit.jsonl")"
pd_all="$(jq -s '[.[] | select(.action == "packet-deny")] | length' "$WORK/b-packet-audit.jsonl")"
jq -c --arg g "$g_svid" 'select(.actor == $g and .target == "tcp/9090") | {action, actor, target, detail}' "$WORK/b-packet-audit.jsonl"
pd_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/packet-audit.jsonl" 2>&1 | head -1)"
echo "packet_deny b tcp9090_from_g ${pd_tcp} udp9090_from_g ${pd_udp} all ${pd_all} verify ${pd_verify}"
if [[ "$PORT_GATE" == 1 ]]; then
  if (( b9090_from_g != 0 )); then
    echo "Node b got bytes from g on the port that is not shared." >&2
    exit 1
  fi
  if (( b9090_from_a == 0 )); then
    echo "The control counter on b:9090 got no bytes, so the counter does not work." >&2
    exit 1
  fi
  if (( pd_tcp != 1 )); then
    echo "Node b has ${pd_tcp} packet-deny records for g tcp/9090, not 1." >&2
    exit 1
  fi
  if [[ "$pd_verify" != ok* ]]; then
    echo "The packet audit chain of b does not verify." >&2
    exit 1
  fi
fi

echo "=== [C] gate 4: remove the share ==="
records_before="$(records)"
echo "coord_records before_unshare ${records_before}"
pids=()
probe g until-deny g-b-8080 20 50 python3 /tmp/share-get.py "$b_ip" 8080 0.2
probe a hold a-b-8080 8 100 python3 /tmp/share-get.py "$b_ip" 8080 0.8
probe g hold g-g2-8080 8 100 python3 /tmp/share-get.py "$g2_ip" 8080 0.8
sleep 3
put_policy "$WORK/unshared.hujson"
unshare_ms="$(now_ms)"
echo "unshare_ms ${unshare_ms}"
failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=1
done
cat "$WORK/probe-g-b-8080.out"
first="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "first_deny_ms") print $(i + 1)}' "$WORK/probe-g-b-8080.out")"
start="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "deny_run_start_ms") print $(i + 1)}' "$WORK/probe-g-b-8080.out")"
last="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "last_ok_ms") print $(i + 1)}' "$WORK/probe-g-b-8080.out")"
if [[ -z "$first" ]]; then
  echo "g -> b:8080 was not denied." >&2
  exit 1
fi
if (( first < unshare_ms )); then
  echo "g -> b:8080 failed before the unshare." >&2
  exit 1
fi
deny_ms=$(( first - unshare_ms ))
last_ok_after=$(( last - unshare_ms ))
start_after=$(( start - unshare_ms ))
echo "unshare deny_ms ${deny_ms} (end of the first failed GET) first_failed_get_start_ms ${start_after} last_ok_end_ms ${last_ok_after} limit_ms ${LIMIT_MS}"
(( deny_ms <= LIMIT_MS ))
for label in a-b-8080 g-g2-8080; do
  cat "$WORK/probe-${label}.out"
  grep -q "^probe ${label} hold ok [1-9][0-9]* fail 0$" "$WORK/probe-${label}.out"
done
if [[ "$failed" -ne 0 ]]; then
  echo "A probe failed." >&2
  exit 1
fi
expect_fail "g -> b:8080 after unshare" g "$b_ip" 8080
records_unshare="$(records)"
echo "coord_records after_unshare ${records_unshare} new $(( records_unshare - records_before ))"
[[ "$(( records_unshare - records_before ))" -eq 1 ]]
dc exec -T g orblx coord netmap --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" \
  --state "$STATE" >/dev/null
echo "netmap g peers after unshare $(peers_of g)"
[[ "$(peers_of g)" == "g2" ]]

echo "=== [C] gate 5: share again ==="
put_policy "$WORK/shared.hujson"
share_ms="$(now_ms)"
dc exec -T g orblx coord netmap --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" \
  --state "$STATE" >/dev/null
echo "netmap g peers after share $(peers_of g)"
[[ "$(peers_of g)" == "b,g2" ]]
records_share="$(records)"
echo "coord_records after_share ${records_share} new $(( records_share - records_unshare ))"
[[ "$(( records_share - records_unshare ))" -eq 1 ]]
reshare="no"
for i in $(seq 1 100); do
  if get g "$b_ip" 8080 >/dev/null 2>&1; then
    reshare="$(( $(now_ms) - share_ms ))"
    break
  fi
  sleep 0.1
done
echo "share_again g -> b:8080 restore_ms ${reshare} (the nodes did not restart)"
[[ "$reshare" != no ]]

dc exec -T coord cat "$STATE/config-audit.jsonl" >"$WORK/config-audit.jsonl"
jq -c 'select(.action == "share" or .action == "unshare") | {action, actor, target, detail}' \
  "$WORK/config-audit.jsonl"
share_records="$(jq -s '[.[] | select(.action == "share")] | length' "$WORK/config-audit.jsonl")"
unshare_records="$(jq -s '[.[] | select(.action == "unshare")] | length' "$WORK/config-audit.jsonl")"
replace_records="$(jq -s '[.[] | select(.action == "policy-replace")] | length' "$WORK/config-audit.jsonl")"
echo "audit share ${share_records} unshare ${unshare_records} policy_replace ${replace_records}"
[[ "$share_records" -eq 1 && "$unshare_records" -eq 1 && "$replace_records" -eq 0 ]]
jq -s -e '[.[] | select(.action == "unshare")][0]
  | .target == "spiffe://orblx.local/node/b"
  and .actor == "spiffe://orblx.local/coord/coord"
  and .detail == "spiffe://orblx.local/node/b tcp 8080 with oidc:bob"' "$WORK/config-audit.jsonl" >/dev/null
audit_after="$(owner audit --verify)"
printf '%s\n' "$audit_after" | grep '^verify '
grep -q '^verify ok ' <<<"$audit_after"

echo "=== [C] logs hold no key, ID token, or enroll token ==="
{
  dc logs 2>&1
  cat "$WORK"/*.out "$WORK"/config-audit.jsonl
} >"$WORK/all-logs.log"
for name in owner a b; do
  token="$(dc exec -T coord cat "$STATE/tokens/${name}" 2>/dev/null | tr -d ' \n' || true)"
  if [[ -n "$token" ]] && grep -qF "$token" "$WORK/all-logs.log"; then
    echo "A log holds the ${name} enroll token." >&2
    exit 1
  fi
done
for name in g g2; do
  sig="$(dc run --rm --no-deps --entrypoint cut idp -d. -f3 "/tokens/${name}")"
  if [[ -n "$sig" ]] && grep -qF -- "$sig" "$WORK/all-logs.log"; then
    echo "A log holds the ${name} ID token." >&2
    exit 1
  fi
done
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.log" || true)"
echo "secret_grep tokens 0 id_tokens 0 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]]

echo "summary guest oidc:bob shared spiffe://orblx.local/node/b:8080 gate2_bytes_to_a ${a_from_g}+${a_from_g2} unshare_deny_ms ${deny_ms} limit_ms ${LIMIT_MS} other_access_failures 0 share_records ${share_records} unshare_records ${unshare_records} coord_verify ok share_again_restore_ms ${reshare} port_checks ${port_results[*]} b9090_bytes_from_g ${b9090_from_g} packet_deny_tcp9090 ${pd_tcp} packet_audit_verify ${pd_verify%% *}"
echo "proof_ok"

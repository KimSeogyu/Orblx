#!/usr/bin/env bash
# Node lock proof (W23-1).
# The owner makes owner keys K1, K2, and K3. The coordinator gets only the public keys.
# The owner signs nodes a, b, and c with K1 and node d with K2. The coordinator adds
# node arogue without an owner signature. The nodes pin K1 and K2.
# Check 1: the nodes remove arogue from the netmap and refuse its QUIC session.
# Check 2: signed nodes connect.
# Check 3: the owner rotates K1 to K3 and removes K2. Node d (K2 only) is refused.
# Check 4: the coordinator audit chain has the lock records and verifies.
# The script deletes the orblx-w23a-node-lock volumes at the start.
# The script does not print enroll tokens, owner private keys, or signatures.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.node-lock.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export PUB_DIR="$WORK/pub"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
STATE=/var/lib/orblx
KEYS=/var/lib/orblx/owner-keys
NODES=(a ak2 arogue b c)
mkdir -p "$PUB_DIR"

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

resolve_name() {
  local name="$1"
  dc run --rm --no-deps --entrypoint getent owner ahostsv4 "$name" \
    | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
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

build_image() {
  local image_dir
  cargo build -p orblx-cli --bin orblx --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$TARGET_DIR/debug/orblx")"
  docker build -q -t orblx-w23a-lock:w23 "$image_dir"
  rm -rf "$image_dir"
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

wait_log() {
  local service="$1"
  local needle="$2"
  local i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | grep -q "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  dc logs "$service" 2>&1 | tail -20 >&2
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

coord_flags() {
  printf '%s\n' --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

owner() {
  local flags
  mapfile -t flags < <(coord_flags)
  run_node owner admin "$@" "${flags[@]}"
}

owner_lock() {
  local flags
  mapfile -t flags < <(coord_flags)
  run_node owner lock "$@" "${flags[@]}"
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" \
    --endpoint "${name}:443"
}

fetch_netmap() {
  local name="$1"
  shift
  dc exec -T "$name" orblx coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE"
}

netmap_peers() {
  local name="$1"
  dc exec -T "$name" sh -c "jq -r '.peers[].name' $STATE/netmap.json | sort | tr '\n' ' '"
}

wait_path() {
  local from="$1"
  local to="$2"
  local i
  for i in $(seq 1 60); do
    if dc exec -T "$from" orblx status --state-dir "$STATE" 2>/dev/null \
      | grep -q "^peer ${to} .* path direct "; then
      echo "path ${from} ${to} direct"
      return 0
    fi
    sleep 1
  done
  echo "The path from ${from} to ${to} did not come up." >&2
  dc exec -T "$from" orblx status --state-dir "$STATE" >&2 || true
  return 1
}

no_path() {
  local from="$1"
  local to="$2"
  if dc exec -T "$from" orblx status --state-dir "$STATE" 2>/dev/null \
    | grep -q "^peer ${to} .* path direct "; then
    echo "The node ${from} has a direct path to ${to}." >&2
    exit 1
  fi
  echo "path ${from} ${to} none"
}

http_get() {
  local from="$1"
  local ip="$2"
  dc exec -T "$from" python3 -c "
import socket
try:
    s = socket.create_connection(('${ip}', 8080), 4)
    s.sendall(b'GET / HTTP/1.0\r\n\r\n')
    print(s.recv(12).decode(errors='replace').strip())
except OSError as err:
    print('fail', type(err).__name__)
"
}

expect_http() {
  local from="$1"
  local to="$2"
  local want="$3"
  local got
  got="$(http_get "$from" "${ips[$to]}")"
  echo "http ${from} ${to} ${got}"
  if [[ "$want" == ok && "$got" != "HTTP/1.0 200" ]]; then
    echo "The TCP connection from ${from} to ${to} did not work." >&2
    exit 1
  fi
  if [[ "$want" == fail && "$got" != fail* ]]; then
    echo "The TCP connection from ${from} to ${to} worked." >&2
    exit 1
  fi
}

refused_count() {
  local service="$1"
  local peer="$2"
  local since="${3:-}"
  local flags=()
  if [[ -n "$since" ]]; then
    flags=(--since "$since")
  fi
  dc logs "${flags[@]}" "$service" 2>&1 | grep -c "Node lock refused the peer spiffe://orblx.local/node/${peer}" || true
}

cp "$ROOT/scripts/proof/node-lock.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

for name in owner "${NODES[@]}"; do
  dc exec -T coord orblx coord token create \
    --state "$STATE" \
    --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done

coord_ip="$(resolve_name coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

enroll_node owner

echo "=== [C] owner makes K1, K2, K3 in the owner volume ==="
for key in k1 k2 k3; do
  dc run --rm --no-deps --entrypoint sh owner -c \
    "mkdir -p $KEYS && orblx lock keygen --out $KEYS/$key && cp $KEYS/$key.pub /proof/$key.pub"
done
echo "key_file_mode $(dc run --rm --no-deps --entrypoint stat owner -c '%a' "$KEYS/k1")"

echo "=== [C] node lock init with K1 and K2 ==="
owner_lock init --pub-file /proof/k1.pub --pub-file /proof/k2.pub

for name in "${NODES[@]}"; do
  enroll_node "$name"
done

echo "=== [C] approve all nodes. The coordinator adds arogue too ==="
for name in "${NODES[@]}"; do
  owner approve "$name"
done
nodes_out="$(owner nodes)"
printf '%s\n' "$nodes_out"
declare -A ips
for name in "${NODES[@]}"; do
  ips[$name]="$(printf '%s\n' "$nodes_out" | awk -v n="$name" '$1 == "node" && $2 == n {print $3; exit}')"
  echo "overlay ${name} ${ips[$name]}"
done

echo "=== [C] owner signs a, b, c with K1 and ak2 with K2. arogue gets no signature ==="
for name in a b c; do
  owner_lock sign "$name" --key-file "$KEYS/k1"
done
owner_lock sign ak2 --key-file "$KEYS/k2"
owner_lock show

echo "=== [C] the coordinator refuses a bad signature for arogue ==="
if owner_lock sign arogue --key-file "$KEYS/k3" >"$WORK/bad-sign.txt" 2>&1; then
  echo "The coordinator took a signature from an untrusted key." >&2
  exit 1
fi
cat "$WORK/bad-sign.txt"

echo "=== [C] nodes a, ak2, b, c pin K1 and K2. arogue has no node lock ==="
for name in a ak2 b c; do
  run_node "$name" lock trust --pub-file /proof/k1.pub --pub-file /proof/k2.pub --state "$STATE"
done
run_node arogue lock status --state "$STATE"

echo "=== [C] fetch netmaps ==="
for name in "${NODES[@]}"; do
  echo "--- ${name}"
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE"
done
arogue_in_coord="$(dc run --rm --no-deps --entrypoint sh arogue -c "jq -r '.peers[].name' $STATE/netmap.json | sort | tr '\n' ' '")"
echo "arogue_netmap_peers ${arogue_in_coord}"

echo "=== [C] start all nodes ==="
dc up -d "${NODES[@]}"
for name in "${NODES[@]}"; do
  wait_log "$name" 'The TUN device'
done
for name in "${NODES[@]}"; do
  dc exec -d "$name" python3 -m http.server 8080 --bind "${ips[$name]}"
done
sleep 2
for name in a ak2 b c; do
  echo "netmap_peers ${name} $(netmap_peers "$name")"
done
echo "netmap_peers arogue $(netmap_peers arogue)"
for name in a ak2 b c; do
  if netmap_peers "$name" | grep -qw arogue; then
    echo "The node ${name} kept arogue in the netmap." >&2
    exit 1
  fi
done

echo "=== [C] signed nodes connect ==="
wait_path a b
wait_path a c
wait_path a ak2
wait_path ak2 c
expect_http a c ok
expect_http c a ok
expect_http ak2 b ok

echo "=== [C] arogue is refused ==="
wait_log b 'Node lock refused the peer spiffe://orblx.local/node/arogue'
sleep 3
for name in a ak2 b c; do
  no_path "$name" arogue
  no_path arogue "$name"
  expect_http arogue "$name" fail
  expect_http "$name" arogue fail
done
phase1_refused_total=0
for name in a ak2 b c; do
  count="$(refused_count "$name" arogue)"
  echo "refused ${name} arogue ${count}"
  phase1_refused_total=$(( phase1_refused_total + count ))
done
echo "phase1_refused_arogue_total ${phase1_refused_total}"
dc exec -T arogue orblx status --state-dir "$STATE"

echo "=== [C] owner rotates K1 to K3. The tool signs a, b, c again with K3 ==="
owner_lock rotate --key-file "$KEYS/k1" --new-key-file "$KEYS/k3"
echo "=== [C] owner removes K2 with K3 ==="
owner_lock remove --pub-file /proof/k2.pub --key-file "$KEYS/k3"
owner_lock show

echo "=== [C] the coordinator refuses an update from the removed key ==="
if owner_lock remove --pub-file /proof/k3.pub --key-file "$KEYS/k1" >"$WORK/bad-update.txt" 2>&1; then
  echo "The coordinator took an update from a removed key." >&2
  exit 1
fi
cat "$WORK/bad-update.txt"

echo "=== [C] nodes fetch the new netmap and follow the owner chain ==="
for name in a ak2 b c; do
  echo "--- ${name}"
  fetch_netmap "$name"
  dc exec -T "$name" orblx lock status --state "$STATE"
done
for name in a b c; do
  peers="$(netmap_peers "$name")"
  echo "netmap_peers ${name} ${peers}"
  if grep -qw ak2 <<<"$peers" || grep -qw arogue <<<"$peers"; then
    echo "The node ${name} kept ak2 or arogue after the remove." >&2
    exit 1
  fi
done

echo "=== [C] restart all nodes ==="
restart_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
dc restart "${NODES[@]}"
sleep 3
wait_path a b
wait_path a c
wait_path b c
for name in "${NODES[@]}"; do
  dc exec -d "$name" python3 -m http.server 8080 --bind "${ips[$name]}"
done
sleep 2
expect_http a c ok
expect_http b a ok
for i in $(seq 1 60); do
  if [[ "$(refused_count b ak2 "$restart_at")" -gt 0 ]]; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "The node b did not refuse ak2 after the restart." >&2
    exit 1
  fi
  sleep 1
done
sleep 3
for name in a b c; do
  no_path "$name" ak2
  no_path "$name" arogue
  expect_http ak2 "$name" fail
  expect_http arogue "$name" fail
done
after_refused_ak2=0
after_refused_arogue=0
for name in a b c; do
  cd_count="$(refused_count "$name" ak2 "$restart_at")"
  cr_count="$(refused_count "$name" arogue "$restart_at")"
  echo "refused ${name} ak2 ${cd_count} arogue ${cr_count}"
  after_refused_ak2=$(( after_refused_ak2 + cd_count ))
  after_refused_arogue=$(( after_refused_arogue + cr_count ))
done
echo "after_restart refused_ak2_total ${after_refused_ak2} refused_arogue_total ${after_refused_arogue}"

echo "=== [C] coordinator audit chain ==="
audit="$(owner audit)"
printf '%s\n' "$audit" | grep ' lock-' || true
printf '%s\n' "$audit" | grep -q '^verify ok '
declare -A lock_counts
for action in lock-init lock-sign lock-rotate lock-remove; do
  lock_counts[$action]="$(printf '%s\n' "$audit" | grep -c " ${action} " || true)"
  echo "audit ${action} ${lock_counts[$action]}"
  if [[ "${lock_counts[$action]}" -eq 0 ]]; then
    echo "The audit chain has no ${action} record." >&2
    exit 1
  fi
done
printf '%s\n' "$audit" | grep '^verify '

echo "=== [C] logs hold no owner key or enroll token ==="
{
  dc logs 2>&1
  dc exec -T coord cat "$STATE/config-audit.jsonl" "$STATE/node-lock-store.json" 2>/dev/null || true
  cat "$WORK"/*.txt
  for name in a ak2 b c; do
    dc exec -T "$name" cat "$STATE/netmap.json" "$STATE/node-lock.json"
  done
} >"$WORK/all-logs.out"
for key in k1 k2 k3; do
  seed="$(dc run --rm --no-deps --entrypoint cat owner "$KEYS/$key" | tr -d ' \n')"
  if [[ -z "$seed" ]]; then
    echo "The owner key ${key} did not read." >&2
    exit 1
  fi
  if grep -qF "$seed" "$WORK/all-logs.out"; then
    echo "A log or state file holds owner key ${key}." >&2
    exit 1
  fi
  echo "secret_grep owner_${key} 0"
done
for name in owner "${NODES[@]}"; do
  token="$(dc exec -T coord cat "$STATE/tokens/${name}" 2>/dev/null | tr -d ' \n' || true)"
  if [[ -n "$token" ]] && grep -qF "$token" "$WORK/all-logs.out"; then
    echo "A log holds the ${name} enroll token." >&2
    exit 1
  fi
done
echo "secret_grep tokens 0"
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.out" || true)"
echo "secret_grep 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]]
if dc exec -T coord sh -c "ls $STATE | grep -i owner-key"; then
  echo "The coordinator holds an owner key file." >&2
  exit 1
fi
echo "coord_owner_key_files 0"
echo "log_bytes $(wc -c <"$WORK/all-logs.out")"

echo "summary unsigned_arogue_refused_by_nodes ${phase1_refused_total} arogue_http fail signed_http ok lock_versions 2 after_remove_ak2_refused ${after_refused_ak2} after_remove_arogue_refused ${after_refused_arogue} audit_lock_init ${lock_counts[lock-init]} audit_lock_sign ${lock_counts[lock-sign]} audit_lock_rotate ${lock_counts[lock-rotate]} audit_lock_remove ${lock_counts[lock-remove]} audit_verify ok"
echo "proof_ok"

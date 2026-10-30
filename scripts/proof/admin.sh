#!/usr/bin/env bash
# Admin, approval, ping, status, and metrics proof.
# The script deletes the orblx-admin-proof volumes at the start.
# The script does not print enroll tokens or private keys.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.admin.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "admin"

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

resolve_name() {
  local name="$1"
  dc --profile nodes run --rm --no-deps --entrypoint getent a ahostsv4 "$name" \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
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
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir bin
  bin="$ROOT/target/debug/orblx"
  cargo build -p orblx-cli --bin orblx --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -t orblx-admin:w19 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

wait_listener() {
  local i
  for i in $(seq 1 40); do
    if dc logs b 2>&1 | read_all grep -q 'The TUN device'; then
      return 0
    fi
    sleep 1
  done
  echo "The node b did not open the TUN device." >&2
  dc logs b >&2 || true
  return 1
}

run_node() {
  local service="$1"
  shift
  dc --profile nodes run --rm --no-deps --entrypoint orblx "$service" "$@"
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
    --state /var/lib/orblx \
    --endpoint "${name}:443"
}

expect_ping_fail() {
  local label="$1"
  local needle="$2"
  local output status
  echo "=== [C] ${label} ==="
  set +e
  output="$(run_node a ping b \
    --state /var/lib/orblx \
    --coord "${coord_ip}:443" \
    --bundle /var/lib/orblx/bundle.pem \
    --timeout 5 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  if [[ "$status" -eq 0 ]]; then
    echo "The ping from a to b succeeded." >&2
    exit 1
  fi
  printf '%s\n' "$output" | read_all grep -q "$needle"
}

cp "$ROOT/scripts/proof/admin.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build coordinator image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

for name in owner a b; do
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create \
    --state /var/lib/orblx \
    --ttl 3600 \
    --out "/var/lib/orblx/tokens/${name}"
done

echo "=== [C] coordinator address ==="
coord_ip="$(resolve_name coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

enroll_node owner
enroll_node a
enroll_node b

echo "=== [C] admin nodes before approve ==="
run_node owner admin nodes \
  --coord "${coord_ip}:443" \
  --state /var/lib/orblx \
  --bundle /var/lib/orblx/bundle.pem

expect_ping_fail "ping before approve" "not in the netmap"

echo "=== [C] admin approve ==="
run_node owner admin approve a \
  --coord "${coord_ip}:443" \
  --state /var/lib/orblx \
  --bundle /var/lib/orblx/bundle.pem
run_node owner admin approve b \
  --coord "${coord_ip}:443" \
  --state /var/lib/orblx \
  --bundle /var/lib/orblx/bundle.pem

echo "=== [C] admin users ==="
run_node owner admin users \
  --coord "${coord_ip}:443" \
  --state /var/lib/orblx \
  --bundle /var/lib/orblx/bundle.pem

echo "=== [C] admin routes ==="
run_node owner admin routes \
  --coord "${coord_ip}:443" \
  --state /var/lib/orblx \
  --bundle /var/lib/orblx/bundle.pem

echo "=== [C] netmap on a ==="
run_node a coord netmap \
  --coord "${coord_ip}:443" \
  --bundle /var/lib/orblx/bundle.pem \
  --state /var/lib/orblx

echo "=== [C] netmap on b ==="
run_node b coord netmap \
  --coord "${coord_ip}:443" \
  --bundle /var/lib/orblx/bundle.pem \
  --state /var/lib/orblx

echo "=== [C] start node b ==="
dc --profile nodes up -d b
wait_listener

echo "=== [C] ping after approve ==="
ping_ok="$(run_node a ping b \
  --state /var/lib/orblx \
  --coord "${coord_ip}:443" \
  --bundle /var/lib/orblx/bundle.pem \
  --timeout 5)"
printf '%s\n' "$ping_ok"
printf '%s\n' "$ping_ok" | read_all grep -qx 'path direct'
printf '%s\n' "$ping_ok" | read_all grep -q '^rtt_ms '

echo "=== [C] status json ==="
status_json="$(dc exec -T b orblx status --json --state-dir /var/lib/orblx)"
printf '%s\n' "$status_json"
printf '%s\n' "$status_json" | jq -e '.name' >/dev/null
printf '%s\n' "$status_json" | jq -e '.state' >/dev/null

echo "=== [C] node metrics ==="
node_metrics="$(dc exec -T b curl -fsS http://127.0.0.1:9464/metrics)"
printf '%s\n' "$node_metrics"
printf '%s\n' "$node_metrics" | read_all grep -q '^orblx_node_packets_tx '
printf '%s\n' "$node_metrics" | read_all grep -q '^orblx_node_packets_rx '
printf '%s\n' "$node_metrics" | read_all grep -q '^orblx_node_sessions '
tx_count="$(printf '%s\n' "$node_metrics" | read_all awk '/^orblx_node_packets_tx /{print $2; exit}')"
rx_count="$(printf '%s\n' "$node_metrics" | read_all awk '/^orblx_node_packets_rx /{print $2; exit}')"
if [[ -z "$tx_count" || -z "$rx_count" || "$tx_count" -eq 0 || "$rx_count" -eq 0 ]]; then
  echo "The ping left the packet counters at 0." >&2
  exit 1
fi

echo "=== [C] start relay ==="
dc --profile nodes up -d relay
relay_ip=""
for _ in $(seq 1 30); do
  relay_ip="$(resolve_name relay || true)"
  if [[ -n "$relay_ip" ]]; then
    break
  fi
  sleep 1
done
if [[ -z "$relay_ip" ]]; then
  echo "The relay address did not resolve." >&2
  dc logs relay >&2 || true
  exit 1
fi
echo "relay_ip ${relay_ip}"

echo "=== [C] netcheck ==="
netcheck="$(run_node a netcheck \
  --udp "${coord_ip}:443" \
  --quic "${coord_ip}:443" \
  --relay "${relay_ip}:443" \
  --timeout 3)"
printf '%s\n' "$netcheck"
printf '%s\n' "$netcheck" | read_all grep -qx 'udp443 ok'
printf '%s\n' "$netcheck" | read_all grep -qx 'quic443 ok'
printf '%s\n' "$netcheck" | read_all grep -qx 'relay ok'
printf '%s\n' "$netcheck" | read_all grep -q '^nat '

echo "=== [C] relay metrics ==="
relay_metrics="$(dc exec -T relay curl -fsS http://127.0.0.1:9464/metrics)"
printf '%s\n' "$relay_metrics"
printf '%s\n' "$relay_metrics" | read_all grep -q '^orblx_relay_attaches '
printf '%s\n' "$relay_metrics" | read_all grep -q '^orblx_relay_forwards '
printf '%s\n' "$relay_metrics" | read_all grep -q '^orblx_relay_drops '

echo "=== [C] admin revoke ==="
revoke_start="$(date +%s)"
run_node owner admin revoke b \
  --coord "${coord_ip}:443" \
  --state /var/lib/orblx \
  --bundle /var/lib/orblx/bundle.pem
expect_ping_fail "ping after revoke" "revoked"
revoke_stop="$(( $(date +%s) - revoke_start ))"
echo "revoke_stop_s ${revoke_stop}"
if [[ "$revoke_stop" -gt 60 ]]; then
  echo "The revoked node still answered after 60 seconds." >&2
  exit 1
fi

echo "proof_ok"

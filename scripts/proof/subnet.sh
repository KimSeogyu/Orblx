#!/usr/bin/env bash
# Subnet route proof.
# A router container publishes two CIDRs.
# The policy approves 10.88.0.0/24 and holds 10.99.0.0/24.
# A client container reaches a LAN device that has no overlay.
# The script deletes the orblx-subnet-proof containers at the start.
# The script does not print enroll tokens or private keys.
# The Mac steps stay in docs/w18-subnet.md. This script does not run them.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.subnet.yml"
WORK="$(mktemp -d)"
export SUBNET_COORD_STATE="$WORK/coord"
export SUBNET_POLICY="$WORK/policy.hujson"
export SUBNET_TOOL_STATE="$WORK/tool"
export SUBNET_ROUTER_STATE="$WORK/router"
export SUBNET_CLIENT_STATE="$WORK/client"
export SUBNET_ROUTER_NETMAP="$WORK/netmap-router.json"
export SUBNET_CLIENT_NETMAP="$WORK/netmap-client.json"
COORD_IP="172.30.18.2"
ROUTER_IP="172.30.18.3"
CLIENT_IP="172.30.18.4"

cleanup() {
  dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$(id -u)" -eq 0 ]]; then
    rm -rf "$WORK"
  else
    sudo -n rm -rf "$WORK" >/dev/null 2>&1 || rm -rf "$WORK" >/dev/null 2>&1 || true
  fi
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "subnet"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-subnet-proof" || exit 1

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

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
# iptables-nft already accepts the same traffic.
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
  cargo build -p orblx-cli --bin orblx
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -t orblx-subnet:local "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if [[ -s "$SUBNET_COORD_STATE/trust-bundle.pem" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

tool() {
  local state="$1"
  shift
  export SUBNET_TOOL_STATE="$state"
  dc --profile tool run --rm --no-deps tool "$@"
}

mkdir -p "$SUBNET_COORD_STATE" "$WORK/enroll-router" "$WORK/enroll-client" "$SUBNET_ROUTER_STATE" "$SUBNET_CLIENT_STATE"
cp "$ROOT/scripts/proof/subnet.hujson" "$SUBNET_POLICY"
chmod 644 "$SUBNET_POLICY"

echo "=== [C] bridge-nf-call-iptables ==="
if [[ -r /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
  echo "bridge-nf-call-iptables $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
else
  echo "bridge-nf-call-iptables missing"
fi

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

echo "=== [C] policy test ==="
dc exec -T coord orblx policy test --file /var/lib/orblx/policy.hujson

echo "=== [C] token router ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/router --ttl 3600
echo "=== [C] token client ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/client --ttl 3600

echo "=== [C] enroll router ==="
tool "$WORK/enroll-router" coord enroll \
  --name router \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/router \
  --state /var/lib/orblx \
  --endpoint "${ROUTER_IP}:443"

echo "=== [C] enroll client ==="
tool "$WORK/enroll-client" coord enroll \
  --name client \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/client \
  --state /var/lib/orblx \
  --endpoint "${CLIENT_IP}:443"

echo "=== [C] advertise routes ==="
tool "$WORK/enroll-router" coord advertise \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx \
  --route 10.88.0.0/24 \
  --route 10.99.0.0/24

echo "=== [C] netmap on client ==="
tool "$WORK/enroll-client" coord netmap \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx
cp "$WORK/enroll-client/netmap.json" "$SUBNET_CLIENT_NETMAP"
cp "$WORK/enroll-router/netmap.json" "$SUBNET_ROUTER_NETMAP"
echo "=== [C] client netmap routes ==="
cat "$SUBNET_CLIENT_NETMAP"
echo
if grep -q '10.99.0.0/24' "$SUBNET_CLIENT_NETMAP"; then
  echo "The unapproved route is in the signed netmap." >&2
  exit 1
fi
if ! grep -q '10.88.0.0/24' "$SUBNET_CLIENT_NETMAP"; then
  echo "The approved route is missing from the signed netmap." >&2
  exit 1
fi

router_ip="$(sed -n 's/.*"name":"router","overlay_ip":"\([^"]*\)".*/\1/p' "$SUBNET_CLIENT_NETMAP" | read_all head -n 1)"
client_ip="$(sed -n 's/.*"name":"client","overlay_ip":"\([^"]*\)".*/\1/p' "$SUBNET_ROUTER_NETMAP" | read_all head -n 1)"
if [[ -z "$router_ip" || -z "$client_ip" ]]; then
  echo "The netmap did not include both overlay addresses." >&2
  exit 1
fi

echo "=== [C] node material ==="
cargo build -p orblx-cli --bin orblx
"$ROOT/target/debug/orblx" node-issue \
  --out "$WORK/nodes" \
  --node "router=${router_ip}" \
  --node "client=${client_ip}"
cp -a "$WORK/nodes/router/." "$SUBNET_ROUTER_STATE/"
cp -a "$WORK/nodes/client/." "$SUBNET_CLIENT_STATE/"

echo "=== [C] start lan, router, and client ==="
dc --profile nodes up -d lan router client

echo "=== [C] wait for the overlay path ==="
ready=0
for _ in $(seq 1 40); do
  if dc logs client 2>/dev/null | read_all grep -q 'The path to router is direct.'; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "The client did not open a path to the router." >&2
  dc logs router client >&2 || true
  exit 1
fi
if ! dc logs router 2>/dev/null | read_all grep -q 'The node forwards 10.88.0.0/24'; then
  echo "The router did not enable forwarding." >&2
  dc logs router >&2 || true
  exit 1
fi

echo "=== [C] client route table ==="
dc exec -T client ip route
echo "=== [C] routes on orblx0 ==="
dc exec -T client ip route show dev orblx0
route_text="$(dc exec -T client ip route show dev orblx0)"
if ! printf '%s\n' "$route_text" | read_all grep -q '10.88.0.0/24'; then
  echo "The approved route is not installed." >&2
  exit 1
fi
if printf '%s\n' "$route_text" | read_all grep -q '10.99.0.0/24'; then
  echo "The unapproved route is installed." >&2
  exit 1
fi
if printf '%s\n' "$route_text" | read_all grep -q '0.0.0.0/0'; then
  echo "The exit route is installed on the TUN device." >&2
  exit 1
fi
echo "=== [C] path for 1.1.1.1 ==="
dc exec -T client ip route get 1.1.1.1
inet_path="$(dc exec -T client ip route get 1.1.1.1)"
if printf '%s\n' "$inet_path" | read_all grep -q 'orblx0'; then
  echo "Internet traffic entered the TUN device." >&2
  exit 1
fi

echo "=== [C] ping the LAN device ==="
dc exec -T client ping -c 3 -W 2 10.88.0.5

echo "=== [C] HTTP to the LAN device ==="
lan_body="$(dc exec -T client bash -c 'exec 3<>/dev/tcp/10.88.0.5/80; printf "GET / HTTP/1.0\r\n\r\n" >&3; dd bs=1024 count=4 <&3 2>/dev/null')"
printf '%s\n' "$lan_body"
if ! printf '%s\n' "$lan_body" | read_all grep -q 'lan-ok'; then
  echo "The client did not read the LAN page." >&2
  exit 1
fi

echo "proof_ok"

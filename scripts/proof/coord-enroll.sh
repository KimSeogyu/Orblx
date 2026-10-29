#!/usr/bin/env bash
# Token enrollment proof for the coordinator container.
# The script deletes the gyeol-coord-proof volumes at the start.
# The script does not print enroll tokens or private keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.coord.yml"

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

resolve_coord() {
  dc --profile nodes run --rm --no-deps --entrypoint getent node-a ahostsv4 coord \
    | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
# iptables-nft already accepts the same traffic.
open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  if [[ "$(id -u)" -eq 0 ]]; then
    iptables-legacy -P FORWARD ACCEPT
  else
    sudo -n iptables-legacy -P FORWARD ACCEPT
  fi
}

build_image() {
  local image_dir bin
  bin="$ROOT/target/debug/gyeol"
  cargo build -p gyeol-cli --bin gyeol
  image_dir="$(mktemp -d)"
  cp "$bin" "$image_dir/gyeol"
  cp "$ROOT/scripts/proof/Dockerfile" "$image_dir/Dockerfile"
  docker build -t gyeol-coord:w18 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat /var/lib/gyeol/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build coordinator image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

echo "=== [C] token server-a ==="
dc exec -T coord gyeol coord token create --state /var/lib/gyeol --ttl 3600 --out /var/lib/gyeol/tokens/server-a
echo "=== [C] token server-b ==="
dc exec -T coord gyeol coord token create --state /var/lib/gyeol --ttl 3600 --out /var/lib/gyeol/tokens/server-b

if dc exec -T coord cat /var/lib/gyeol/nodes.json | grep -q 'ge1\.'; then
  echo "The node store contains an enroll token." >&2
  exit 1
fi
if dc exec -T coord cat /var/lib/gyeol/nodes.json | grep -q 'PRIVATE KEY'; then
  echo "The node store contains a private key." >&2
  exit 1
fi

echo "=== [C] coordinator address ==="
coord_ip="$(resolve_coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"

echo "=== [C] enroll server-a ==="
dc --profile nodes run --rm node-a \
  coord enroll \
  --name server-a \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/server-a \
  --state /var/lib/gyeol \
  --endpoint server-a:443

echo "=== [C] enroll server-b ==="
dc --profile nodes run --rm node-b \
  coord enroll \
  --name server-b \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/server-b \
  --state /var/lib/gyeol \
  --endpoint server-b:443

echo "=== [C] netmap before restart ==="
before="$(dc --profile nodes run --rm node-a coord netmap --coord ${coord_ip}:443 --bundle /coord-state/trust-bundle.pem --state /var/lib/gyeol)"
printf '%s\n' "$before"

echo "=== [C] restart coordinator ==="
dc restart coord
wait_bundle
sleep 1

echo "=== [C] netmap after restart ==="
after="$(dc --profile nodes run --rm node-a coord netmap --coord ${coord_ip}:443 --bundle /coord-state/trust-bundle.pem --state /var/lib/gyeol)"
printf '%s\n' "$after"

ip_before="$(printf '%s\n' "$before" | awk '/^overlay_ip /{print $2; exit}')"
ip_after="$(printf '%s\n' "$after" | awk '/^overlay_ip /{print $2; exit}')"
peer_before="$(printf '%s\n' "$before" | awk '/^peer /{print $2, $3}')"
peer_after="$(printf '%s\n' "$after" | awk '/^peer /{print $2, $3}')"
if [[ "$ip_before" != "$ip_after" || -z "$ip_before" || "$peer_before" != "$peer_after" ]]; then
  echo "The overlay addresses changed." >&2
  exit 1
fi
echo "same_ip server-a ${ip_before}"
echo "same_peer ${peer_before}"

echo "=== [C] reuse token server-a ==="
set +e
reuse="$(dc --profile nodes run --rm node-a coord enroll --name server-c --coord ${coord_ip}:443 --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/server-a --state /tmp/reuse --endpoint server-c:443 2>&1)"
code=$?
set -e
printf '%s\n' "$reuse"
if [[ "$code" -eq 0 ]]; then
  echo "The reused enroll token was accepted." >&2
  exit 1
fi
if ! printf '%s\n' "$reuse" | grep -q 'already used'; then
  echo "The rejection text is missing." >&2
  exit 1
fi
echo "reused_token rejected"

echo "=== [C] netmap json ==="
dc --profile nodes run --rm --entrypoint cat node-a /var/lib/gyeol/netmap.json
echo

echo "=== [C] gyeol up reads netmap.json ==="
set +e
up_out="$(dc --profile nodes run --rm node-a up --state-dir /var/lib/gyeol 2>&1)"
up_code=$?
set -e
printf '%s\n' "$up_out"
if [[ "$up_code" -eq 0 ]]; then
  echo "gyeol up started without the capability ticket." >&2
  exit 1
fi
if printf '%s\n' "$up_out" | grep -q 'The netmap is not valid'; then
  echo "gyeol up rejected the coordinator netmap." >&2
  exit 1
fi
if ! printf '%s\n' "$up_out" | grep -q 'ticket.bin'; then
  echo "gyeol up did not accept the netmap." >&2
  exit 1
fi
echo "gyeol_up_read_netmap true"
echo
echo "proof_ok"

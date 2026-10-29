#!/usr/bin/env bash
# Run three gyeol nodes in Docker.
# Each node pings the other two overlay addresses.
# One container then restarts and keeps the same overlay IP.
# The script skips the proof when it is not root.
# The script needs Docker and a built gyeol binary.

set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "The W18 Docker proof needs root. The script skips the proof."
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "The W18 Docker proof needs Docker. The script skips the proof."
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "The W18 Docker proof needs Docker Compose."
  exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="$root/target/debug/gyeol"
compose_file="$root/scripts/proof/compose.w18.yml"
work=$(mktemp -d)
image_dir=""

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    docker compose -f "$compose_file" logs || true
  fi
  docker compose -f "$compose_file" down --remove-orphans >/dev/null 2>&1 || true
  if [[ -n "${image_dir}" ]]; then
    rm -rf "$image_dir"
  fi
  if [[ -n "${work}" ]]; then
    rm -rf "$work"
  fi
}
trap cleanup EXIT

if [[ ! -x "$bin" ]]; then
  cargo build -p gyeol-cli --bin gyeol --manifest-path "$root/Cargo.toml"
fi

image_dir=$(mktemp -d)
cp "$bin" "$image_dir/gyeol"
cp "$root/scripts/proof/Dockerfile" "$image_dir/Dockerfile"
docker build -t gyeol-w18:local "$image_dir"

mkdir -p "$work/a" "$work/b" "$work/c"
"$bin" node-issue \
  --out "$work" \
  --node a=100.64.0.1 \
  --node b=100.64.0.2 \
  --node c=100.64.0.3

write_netmap() {
  local path=$1
  local name=$2
  local ip=$3
  local peer1_name=$4
  local peer1_ip=$5
  local peer1_underlay=$6
  local peer2_name=$7
  local peer2_ip=$8
  local peer2_underlay=$9
  cat >"$path" <<EOF
{
  "version": 1,
  "self": {"name": "${name}", "overlay_ip": "${ip}"},
  "peers": [
    {
      "name": "${peer1_name}",
      "overlay_ip": "${peer1_ip}",
      "svid": "spiffe://gyeol.local/node/${peer1_name}",
      "endpoints": ["${peer1_underlay}:443"],
      "routes": ["${peer1_ip}/32"]
    },
    {
      "name": "${peer2_name}",
      "overlay_ip": "${peer2_ip}",
      "svid": "spiffe://gyeol.local/node/${peer2_name}",
      "endpoints": ["${peer2_underlay}:443"],
      "routes": ["${peer2_ip}/32"]
    }
  ]
}
EOF
}

write_netmap "$work/netmap-a.json" a 100.64.0.1 b 100.64.0.2 172.28.18.12 c 100.64.0.3 172.28.18.13
write_netmap "$work/netmap-b.json" b 100.64.0.2 a 100.64.0.1 172.28.18.11 c 100.64.0.3 172.28.18.13
write_netmap "$work/netmap-c.json" c 100.64.0.3 a 100.64.0.1 172.28.18.11 b 100.64.0.2 172.28.18.12

export W18_STATE_A="$work/a"
export W18_STATE_B="$work/b"
export W18_STATE_C="$work/c"
export W18_NETMAP_A="$work/netmap-a.json"
export W18_NETMAP_B="$work/netmap-b.json"
export W18_NETMAP_C="$work/netmap-c.json"

docker compose -f "$compose_file" up -d --remove-orphans

record_ip() {
  awk -F'"' '/overlay_ip/ { print $4; exit }' "$1"
}

wait_direct() {
  local node=$1
  local peer=$2
  local attempt
  for attempt in $(seq 1 40); do
    if docker compose -f "$compose_file" exec -T "$node" gyeol status | grep -q "peer ${peer} overlay_ip .* path direct "; then
      return 0
    fi
    sleep 1
  done
  echo "The path from ${node} to ${peer} is not direct."
  docker compose -f "$compose_file" exec -T "$node" gyeol status || true
  return 1
}

ping_peer() {
  local node=$1
  local ip=$2
  docker compose -f "$compose_file" exec -T "$node" ping -c 3 -W 2 "$ip"
  echo "${node} to ${ip} ok"
}

echo "W18 Linux daemon proof"
echo "image gyeol-w18:local"
echo "node a overlay 100.64.0.1 underlay 172.28.18.11"
echo "node b overlay 100.64.0.2 underlay 172.28.18.12"
echo "node c overlay 100.64.0.3 underlay 172.28.18.13"

wait_direct node-a b
wait_direct node-a c
wait_direct node-b a
wait_direct node-b c
wait_direct node-c a
wait_direct node-c b

echo "---- status a ----"
docker compose -f "$compose_file" exec -T node-a gyeol status
echo "---- status b ----"
docker compose -f "$compose_file" exec -T node-b gyeol status
echo "---- status c ----"
docker compose -f "$compose_file" exec -T node-c gyeol status

echo "---- ping ----"
ping_peer node-a 100.64.0.2
ping_peer node-a 100.64.0.3
ping_peer node-b 100.64.0.1
ping_peer node-b 100.64.0.3
ping_peer node-c 100.64.0.1
ping_peer node-c 100.64.0.2

overlay_before=$(docker compose -f "$compose_file" exec -T node-b gyeol status | awk '/^overlay_ip / { print $2; exit }')
json_before=$(record_ip "$work/b/node.json")
echo "---- restart b ----"
echo "overlay_ip_before ${overlay_before}"
echo "node_json_before ${json_before}"
docker compose -f "$compose_file" restart node-b
wait_direct node-b a
wait_direct node-b c
wait_direct node-a b
wait_direct node-c b

overlay_after=$(docker compose -f "$compose_file" exec -T node-b gyeol status | awk '/^overlay_ip / { print $2; exit }')
json_after=$(record_ip "$work/b/node.json")
tun_after=$(docker compose -f "$compose_file" exec -T node-b ip -4 -o addr show dev gyeol0 | awk '{ print $4 }')
echo "---- status b after restart ----"
docker compose -f "$compose_file" exec -T node-b gyeol status
echo "overlay_ip_after ${overlay_after}"
echo "node_json_after ${json_after}"
echo "tun_address_after ${tun_after}"

if [[ "$overlay_before" != "100.64.0.2" || "$overlay_after" != "100.64.0.2" ]]; then
  echo "The overlay IP changed."
  exit 1
fi
if [[ "$json_before" != "100.64.0.2" || "$json_after" != "100.64.0.2" ]]; then
  echo "The state file overlay IP changed."
  exit 1
fi
if [[ "$tun_after" != "100.64.0.2/32" ]]; then
  echo "The TUN address is ${tun_after}."
  exit 1
fi
echo "restart_same_ip true"

echo "---- ping after restart ----"
ping_peer node-a 100.64.0.2
ping_peer node-b 100.64.0.1
ping_peer node-b 100.64.0.3
ping_peer node-c 100.64.0.2

echo "W18 proof passed"

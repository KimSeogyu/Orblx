#!/usr/bin/env bash
# Run three orblx nodes in Docker and resolve overlay names.
# Each node answers <node>.lab.orblx and the short name <node>.
# The script skips the proof when it is not root.
# The script needs Docker and a built orblx binary.

set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "The W18 name proof needs root. The script skips the proof."
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "The W18 name proof needs Docker. The script skips the proof."
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "The W18 name proof needs Docker Compose."
  exit 1
fi

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
# iptables-nft already accepts the same traffic.
if command -v iptables-legacy >/dev/null 2>&1; then
  if iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
    if ! command -v iptables-nft >/dev/null 2>&1 || iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT'; then
      echo "set iptables-legacy FORWARD ACCEPT"
      iptables-legacy -P FORWARD ACCEPT
    fi
  fi
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="$root/target/debug/orblx"
compose_file="$root/scripts/proof/compose.w18.yml"
work=$(mktemp -d)
image_dir=""

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    docker compose -f "$compose_file" logs || true
    echo "---- resolver ----"
    docker compose -f "$compose_file" exec -T node-a resolvectl status || true
    docker compose -f "$compose_file" exec -T node-a cat /etc/nsswitch.conf || true
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
  cargo build -p orblx-cli --bin orblx --manifest-path "$root/Cargo.toml"
fi

image_dir=$(mktemp -d)
cp "$bin" "$image_dir/orblx"
cp "$root/scripts/proof/Dockerfile" "$image_dir/Dockerfile"
cp "$root/scripts/proof/entrypoint.sh" "$image_dir/entrypoint.sh"
docker build -t orblx-w18:local "$image_dir"

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
  "self": {"name": "${name}", "overlay_ip": "${ip}", "owner": "lab"},
  "peers": [
    {
      "name": "${peer1_name}",
      "overlay_ip": "${peer1_ip}",
      "owner": "lab",
      "svid": "spiffe://orblx.local/node/${peer1_name}",
      "endpoints": ["${peer1_underlay}:443"],
      "routes": ["${peer1_ip}/32"]
    },
    {
      "name": "${peer2_name}",
      "overlay_ip": "${peer2_ip}",
      "owner": "lab",
      "svid": "spiffe://orblx.local/node/${peer2_name}",
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

wait_direct() {
  local node=$1
  local peer=$2
  local attempt
  for attempt in $(seq 1 40); do
    if docker compose -f "$compose_file" exec -T "$node" orblx status | grep -q "peer ${peer} overlay_ip .* path direct "; then
      return 0
    fi
    sleep 1
  done
  echo "The path from ${node} to ${peer} is not direct."
  docker compose -f "$compose_file" exec -T "$node" orblx status || true
  return 1
}

ping_name() {
  local node=$1
  local host=$2
  local attempt
  for attempt in $(seq 1 20); do
    if docker compose -f "$compose_file" exec -T "$node" ping -c 1 -W 2 "$host" >/dev/null 2>&1; then
      docker compose -f "$compose_file" exec -T "$node" ping -c 3 -W 2 "$host"
      echo "${node} to ${host} ok"
      return 0
    fi
    sleep 1
  done
  echo "The name ${host} did not resolve on ${node}."
  docker compose -f "$compose_file" exec -T "$node" resolvectl status || true
  docker compose -f "$compose_file" exec -T "$node" cat /etc/nsswitch.conf || true
  return 1
}

start_http() {
  local node=$1
  local ip=$2
  docker compose -f "$compose_file" exec -d "$node" \
    sh -c "printf 'ok\n' > /tmp/orblx-name.txt && cd /tmp && python3 -m http.server 8080 --bind ${ip}"
}

wait_http() {
  local from=$1
  local ip=$2
  local attempt
  for attempt in $(seq 1 20); do
    if docker compose -f "$compose_file" exec -T "$from" curl -fsS --max-time 2 "http://${ip}:8080/orblx-name.txt" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The HTTP server on ${ip} did not answer."
  return 1
}

curl_name() {
  local node=$1
  local host=$2
  echo "---- curl ${node} http://${host}:8080/orblx-name.txt ----"
  docker compose -f "$compose_file" exec -T "$node" curl -fsS --max-time 10 "http://${host}:8080/orblx-name.txt"
  echo "${node} to http://${host}:8080/orblx-name.txt ok"
}

echo "W18 overlay name proof"
echo "image orblx-w18:local"
echo "owner lab"
echo "node a overlay 100.64.0.1 name a.lab.orblx"
echo "node b overlay 100.64.0.2 name b.lab.orblx"
echo "node c overlay 100.64.0.3 name c.lab.orblx"

wait_direct node-a b
wait_direct node-a c
wait_direct node-b a
wait_direct node-b c
wait_direct node-c a
wait_direct node-c b

echo "---- resolvectl domain node-a ----"
docker compose -f "$compose_file" exec -T node-a resolvectl domain orblx0
echo "---- resolvectl dns node-a ----"
docker compose -f "$compose_file" exec -T node-a resolvectl dns orblx0

start_http node-a 100.64.0.1
start_http node-b 100.64.0.2
start_http node-c 100.64.0.3
wait_http node-a 100.64.0.2
wait_http node-b 100.64.0.1
wait_http node-a 100.64.0.3

echo "---- ping ----"
ping_name node-a b
ping_name node-a b.lab.orblx
ping_name node-a c
ping_name node-a c.lab.orblx
ping_name node-b a
ping_name node-b a.lab.orblx
ping_name node-c b
ping_name node-c b.lab.orblx

echo "---- http ----"
curl_name node-a b.lab.orblx
curl_name node-b a.lab.orblx
curl_name node-a c.lab.orblx

echo "proof_ok"

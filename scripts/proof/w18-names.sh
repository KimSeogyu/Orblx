#!/usr/bin/env bash
# Run three orblx nodes in Docker and resolve overlay names.
# Each node answers <node>.lab.orblx and the short name <node>.
# The policy denies node a to node c.
# On node a, c and c.lab.orblx are NXDOMAIN.
# Node b still resolves and answers.
# W24: the datapath on c also drops TCP from a (the ACL has no rule for it).
# The script stops with exit 1 when it is not root.
# The script needs Docker and a built orblx binary.

set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# W25-14: this proof needs root. It stops at once without root.
require_root "$@"

export PATH="/usr/local/cargo/bin:/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"

if ! command -v docker >/dev/null 2>&1; then
  echo "The W18 name proof needs Docker. The script skips the proof."
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "The W18 name proof needs Docker Compose."
  exit 1
fi

# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "w18-names"

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
# iptables-nft already accepts the same traffic.
if command -v iptables-legacy >/dev/null 2>&1; then
  if iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP'; then
    if ! command -v iptables-nft >/dev/null 2>&1 || iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT'; then
      echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
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
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

if [[ ! -x "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --manifest-path "$root/Cargo.toml"
fi

# shellcheck source=stage-image.sh
source "$root/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$root" "$bin")"
docker build -t orblx-w18:local "$image_dir"

mkdir -p "$work/a" "$work/b" "$work/c"
"$bin" node-issue \
  --out "$work" \
  --policy "$root/scripts/proof/w18-names.hujson" \
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
    if docker compose -f "$compose_file" exec -T "$node" orblx status 2>/dev/null | read_all grep -q "peer ${peer} overlay_ip .* path direct "; then
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
      local out
      out=$(docker compose -f "$compose_file" exec -T "$node" ping -c 3 -W 2 "$host")
      printf '%s\n' "$out"
      if printf '%s\n' "$out" | read_all grep -q 'DUP!'; then
        echo "The ping from ${node} to ${host} got duplicate replies."
        return 1
      fi
      echo "[C] ${node} to ${host} ok"
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
  echo "---- [C] curl ${node} http://${host}:8080/orblx-name.txt ----"
  docker compose -f "$compose_file" exec -T "$node" curl -fsS --max-time 10 "http://${host}:8080/orblx-name.txt"
  echo "[C] ${node} to http://${host}:8080/orblx-name.txt ok"
}

expect_nxdomain() {
  local node=$1
  local name=$2
  local server=$3
  echo "---- [C] dns ${node} ${name} ----"
  docker compose -f "$compose_file" exec -T "$node" \
    python3 -c 'import socket,sys
name,server=sys.argv[1],sys.argv[2]
def encode(qname):
    out=b""
    for label in qname.strip(".").split("."):
        raw=label.encode()
        out+=bytes([len(raw)])+raw
    return out+b"\x00"
query=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+encode(name)+b"\x00\x01\x00\x01"
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(query,(server,53))
data,_=sock.recvfrom(512)
rcode=data[3]&15
answers=int.from_bytes(data[6:8],"big")
print("%s rcode %s answers %s"%(name,rcode,answers))
if rcode!=3 or answers!=0:
    raise SystemExit("The name %s is not NXDOMAIN."%name)
' "$name" "$server"
  echo "[C] ${node} ${name} nxdomain"
}

echo "=== REAL W18 overlay name proof ==="
echo "image orblx-w18:local"
echo "owner lab"
echo "policy deny a to c"
echo "node a overlay 100.64.0.1 name a.lab.orblx"
echo "node b overlay 100.64.0.2 name b.lab.orblx"
echo "node c overlay 100.64.0.3 name c.lab.orblx"

wait_direct node-a b
wait_direct node-a c
wait_direct node-b a
wait_direct node-b c
wait_direct node-c a
wait_direct node-c b

echo "---- [C] resolvectl domain node-a ----"
docker compose -f "$compose_file" exec -T node-a resolvectl domain orblx0
echo "---- [C] resolvectl dns node-a ----"
docker compose -f "$compose_file" exec -T node-a resolvectl dns orblx0

start_http node-a 100.64.0.1
start_http node-b 100.64.0.2
start_http node-c 100.64.0.3
wait_http node-a 100.64.0.2
wait_http node-b 100.64.0.1
wait_http node-b 100.64.0.3
# W24: the policy has an ACL list, so the datapath on c drops TCP from a.
if docker compose -f "$compose_file" exec -T node-a curl -fsS --max-time 3 "http://100.64.0.3:8080/orblx-name.txt" >/dev/null 2>&1; then
  echo "Node a reached the HTTP server on c. The datapath must drop it."
  exit 1
fi
echo "[C] node-a to http://100.64.0.3:8080 dropped by the datapath"

echo "---- [C] ping ----"
ping_name node-a b
ping_name node-a b.lab.orblx
expect_nxdomain node-a c 100.64.0.1
expect_nxdomain node-a c.lab.orblx 100.64.0.1
echo "---- [C] resolvectl query node-a c.lab.orblx ----"
docker compose -f "$compose_file" exec -T node-a resolvectl query c.lab.orblx || true
ping_name node-b a
ping_name node-b a.lab.orblx
ping_name node-c b
ping_name node-c b.lab.orblx

echo "---- [C] http ----"
curl_name node-a b.lab.orblx
curl_name node-b a.lab.orblx

echo "proof_ok"

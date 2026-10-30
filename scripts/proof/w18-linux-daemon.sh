#!/usr/bin/env bash
# Run three orblx nodes in Docker.
# Each node pings the other two overlay addresses.
# One container then restarts and keeps the same overlay IP.
# W25-27: a coordinator container issues the node SVIDs and tickets through the
# normal enroll path (orblx coord enroll). The proof uses no lab tickets.
# W18_SVID_TTL=SECONDS sets the coordinator SVID and ticket life (1 to 900; empty
# means the default 900 s). W18_TICKET_ENDS=N (default 0) adds a ping window that
# crosses N or more ticket ends with no lost peer.
# The script stops with exit 1 when it is not root.
# The script needs Docker and a built orblx binary.

set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# shellcheck source=scripts/proof/enroll-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/enroll-lib.sh"
# W25-14: this proof needs root. It stops at once without root.
require_root "$@"

if ! command -v docker >/dev/null 2>&1; then
  echo "The W18 Docker proof needs Docker. The script skips the proof."
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "The W18 Docker proof needs Docker Compose."
  exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="$root/target/debug/orblx"
compose_file="$root/scripts/proof/compose.w18.yml"
work=$(mktemp -d)
env_file=""
image_dir=""
coord_addr="172.28.18.10:443"
svid_ttl="${W18_SVID_TTL:-}"
ticket_ends_want="${W18_TICKET_ENDS:-0}"
if [[ -n "$svid_ttl" && ! "$svid_ttl" =~ ^[1-9][0-9]*$ ]] || [[ -n "$svid_ttl" && "$svid_ttl" -gt 900 ]]; then
  echo "W18_SVID_TTL must be from 1 to 900 seconds."
  exit 1
fi
if [[ ! "$ticket_ends_want" =~ ^[0-9]+$ ]]; then
  echo "W18_TICKET_ENDS must be a whole number."
  exit 1
fi

require_toolchain() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "The W18 Docker proof needs cargo on PATH."
    exit 1
  fi
  if ! command -v rustc >/dev/null 2>&1; then
    echo "The W18 Docker proof needs rustc on PATH."
    exit 1
  fi
  local msrv rustc_ver oldest
  msrv=$(awk '
    $0 ~ /^\[workspace\.package\]/ { in_pkg = 1; next }
    in_pkg && $0 ~ /^\[/ { in_pkg = 0 }
    in_pkg && $1 == "rust-version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "$root/Cargo.toml")
  if [[ -z "$msrv" ]]; then
    echo "The crate MSRV is missing from Cargo.toml."
    exit 1
  fi
  rustc_ver=$(rustc --version | awk '{ print $2 }')
  oldest=$(printf '%s\n%s\n' "$msrv" "$rustc_ver" | sort -V | read_all head -n 1)
  if [[ "$oldest" != "$msrv" ]]; then
    echo "rustc ${rustc_ver} is older than the crate MSRV ${msrv}."
    exit 1
  fi
}

compose() {
  if [[ -n "$env_file" && -f "$env_file" ]]; then
    docker compose --env-file "$env_file" -f "$compose_file" "$@"
  else
    docker compose -f "$compose_file" "$@"
  fi
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    compose logs || true
  fi
  compose down --remove-orphans >/dev/null 2>&1 || true
  if [[ -n "${image_dir}" ]]; then
    rm -rf "$image_dir"
  fi
  if [[ -n "${work}" ]]; then
    rm -rf "$work"
  fi
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "w18-linux-daemon"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-w18" || exit 1

require_toolchain

if [[ ! -x "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --manifest-path "$root/Cargo.toml"
fi

# shellcheck source=stage-image.sh
source "$root/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$root" "$bin")"
docker build -t orblx-w18:local "$image_dir"

mkdir -p "$work/coord" "$work/a" "$work/b" "$work/c"

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
      "svid": "spiffe://orblx.local/node/${peer1_name}",
      "endpoints": ["${peer1_underlay}:443"],
      "routes": ["${peer1_ip}/32"]
    },
    {
      "name": "${peer2_name}",
      "overlay_ip": "${peer2_ip}",
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

env_file="$work/w18.env"
cat >"$env_file" <<EOF
W18_STATE_A=$work/a
W18_STATE_B=$work/b
W18_STATE_C=$work/c
W18_NETMAP_A=$work/netmap-a.json
W18_NETMAP_B=$work/netmap-b.json
W18_NETMAP_C=$work/netmap-c.json
W18_COORD_STATE=$work/coord
W18_SVID_TTL=$svid_ttl
EOF
echo "env_file ${env_file}"

echo "=== [C] start coordinator ==="
compose up -d coord
proof_coord_wait_bundle "$work/coord"
for name in a b c; do
  compose exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out "/var/lib/orblx/tokens/${name}"
done
proof_coord_enroll "$bin" "$coord_addr" "$work/coord" "$work/coord/tokens/a" a "$work/a" 172.28.18.11:443 100.64.0.1
proof_coord_enroll "$bin" "$coord_addr" "$work/coord" "$work/coord/tokens/b" b "$work/b" 172.28.18.12:443 100.64.0.2
proof_coord_enroll "$bin" "$coord_addr" "$work/coord" "$work/coord/tokens/c" c "$work/c" 172.28.18.13:443 100.64.0.3
proof_ticket_guard coord "$work/a" "$work/b" "$work/c"

compose up -d --remove-orphans

record_ip() {
  awk -F'"' '/overlay_ip/ { print $4; exit }' "$1"
}

wait_direct() {
  local node=$1
  local peer=$2
  local attempt
  for attempt in $(seq 1 40); do
    if compose exec -T "$node" orblx status | read_all grep -q "peer ${peer} overlay_ip .* path direct "; then
      return 0
    fi
    sleep 1
  done
  echo "The path from ${node} to ${peer} is not direct."
  compose exec -T "$node" orblx status || true
  return 1
}

ping_peer() {
  local node=$1
  local ip=$2
  compose exec -T "$node" ping -c 3 -W 2 "$ip"
  echo "${node} to ${ip} ok"
}

echo "W18 Linux daemon proof"
echo "image orblx-w18:local"
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
compose exec -T node-a orblx status
echo "---- status b ----"
compose exec -T node-b orblx status
echo "---- status c ----"
compose exec -T node-c orblx status

echo "---- ping ----"
ping_peer node-a 100.64.0.2
ping_peer node-a 100.64.0.3
ping_peer node-b 100.64.0.1
ping_peer node-b 100.64.0.3
ping_peer node-c 100.64.0.1
ping_peer node-c 100.64.0.2

overlay_before=$(compose exec -T node-b orblx status | read_all awk '/^overlay_ip / { print $2; exit }')
json_before=$(record_ip "$work/b/node.json")
echo "---- restart b ----"
echo "overlay_ip_before ${overlay_before}"
echo "node_json_before ${json_before}"
compose restart node-b
wait_direct node-b a
wait_direct node-b c
wait_direct node-a b
wait_direct node-c b

overlay_after=$(compose exec -T node-b orblx status | read_all awk '/^overlay_ip / { print $2; exit }')
json_after=$(record_ip "$work/b/node.json")
tun_after=$(compose exec -T node-b ip -4 -o addr show dev orblx0 | awk '{ print $4 }')
echo "---- status b after restart ----"
compose exec -T node-b orblx status
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

# W25-27: ping every peer pair across W18_TICKET_ENDS ticket ends.
# A ticket ends at its expires time plus 60 s clock skew. The window ends 15 s after the
# Nth end of the latest ticket on disk, so every node crosses N or more ends of the
# tickets it holds. A pair with a 2 s gap or more than 3 lost pings is a lost peer.
cross_pair() {
  local node=$1
  local ip=$2
  local secs=$3
  local out=$4
  compose exec -T "$node" ping -n -D -O -i 1 -W 1 -w "$secs" "$ip" >"$out" 2>&1 || true
}

cross_lost() {
  local out=$1
  awk '
    /packets transmitted/ { sent = $1; got = $4; seen = 1 }
    /no answer/ { run++; if (run > max) max = run; next }
    /bytes from/ { run = 0 }
    END {
      if (!seen) { print "no_summary"; exit }
      if (max >= 2 || got < sent - 3) { printf "lost sent %d received %d max_gap %d\n", sent, got, max; exit }
      printf "ok sent %d received %d max_gap %d\n", sent, got, max
    }
  ' "$out"
}

if [[ "$ticket_ends_want" -gt 0 ]]; then
  ttl_used="${svid_ttl:-900}"
  latest=0
  for name in a b c; do
    expires=$(proof_ticket_expires "$work/$name")
    if [[ "$expires" -gt "$latest" ]]; then
      latest=$expires
    fi
  done
  window_start=$(date +%s)
  window_end=$((latest + 60 + (ticket_ends_want - 1) * ttl_used + 15))
  window_secs=$((window_end - window_start))
  echo "---- ticket ends ----"
  echo "ticket_ttl_s ${ttl_used}"
  echo "ticket_ends_want ${ticket_ends_want}"
  echo "ticket_window_s ${window_secs}"
  pids=()
  for pair in "node-a 100.64.0.2" "node-a 100.64.0.3" "node-b 100.64.0.1" "node-b 100.64.0.3" "node-c 100.64.0.1" "node-c 100.64.0.2"; do
    read -r node ip <<<"$pair"
    cross_pair "$node" "$ip" "$window_secs" "$work/cross-${node}-${ip}.txt" &
    pids+=("$!")
  done
  # Record the ticket each node has on disk while the pings run.
  : >"$work/cross-expires.txt"
  while [[ "$(date +%s)" -lt "$window_end" ]]; do
    for name in a b c; do
      echo "$name $(proof_ticket_expires "$work/$name")" >>"$work/cross-expires.txt"
    done
    sleep 5
  done
  for pid in "${pids[@]}"; do
    wait "$pid"
  done
  lost_peers=0
  for pair in "node-a 100.64.0.2" "node-a 100.64.0.3" "node-b 100.64.0.1" "node-b 100.64.0.3" "node-c 100.64.0.1" "node-c 100.64.0.2"; do
    read -r node ip <<<"$pair"
    result=$(cross_lost "$work/cross-${node}-${ip}.txt")
    echo "ticket_cross ${node} to ${ip} ${result}"
    if [[ "$result" != ok* ]]; then
      lost_peers=$((lost_peers + 1))
      cat "$work/cross-${node}-${ip}.txt"
    fi
  done
  min_ends=""
  for name in a b c; do
    ends=$(awk -v n="$name" -v s="$window_start" -v e="$window_end" '
      $1 == n && !seen[$2]++ && $2 + 60 >= s && $2 + 60 <= e { c++ }
      END { print c + 0 }
    ' "$work/cross-expires.txt")
    echo "ticket_ends_crossed ${name} ${ends}"
    if [[ -z "$min_ends" || "$ends" -lt "$min_ends" ]]; then
      min_ends=$ends
    fi
  done
  echo "ticket_cross_lost_peers ${lost_peers}"
  if [[ "$min_ends" -lt "$ticket_ends_want" ]]; then
    echo "A node crossed ${min_ends} ticket ends, fewer than ${ticket_ends_want}."
    exit 1
  fi
  if [[ "$lost_peers" -ne 0 ]]; then
    echo "${lost_peers} peer pairs lost the path across the ticket ends."
    exit 1
  fi
  wait_direct node-a b
  wait_direct node-a c
  wait_direct node-b a
  wait_direct node-b c
  wait_direct node-c a
  wait_direct node-c b
  echo "ticket_cross_ok true"
fi

echo "W18 proof passed"

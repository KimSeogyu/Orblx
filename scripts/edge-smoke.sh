#!/usr/bin/env bash
# Run the Week 4 edge lab.
# The userspace lab needs no extra privileges.
# The netns lab needs root, iproute2, and iptables.
# The lab does not complete a hole punch.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

mode=${1:-all}

if [[ "$mode" != "--netns-only" ]]; then
  echo "=== userspace lab ==="
  userspace=$(cargo run -q -p gyeol-cli -- edge-smoke)
  printf '%s\n' "$userspace"
  grep -q "Allocate Ready" <<<"$userspace"
  grep -q "Direct Stub" <<<"$userspace"
  grep -q "hole-punch complete false" <<<"$userspace"
  local_port=$(awk '/^local / { n = split($2, a, ":"); print a[n] }' <<<"$userspace")
  reflex_port=$(awk '/^reflexive / { n = split($2, a, ":"); print a[n] }' <<<"$userspace")
  nat_port=$(awk '/^lab nat / { n = split($3, a, ":"); print a[n] }' <<<"$userspace")
  if [[ "$reflex_port" != "$nat_port" ]]; then
    echo "The reflexive port is ${reflex_port}. The NAT port is ${nat_port}."
    exit 1
  fi
  if [[ "$local_port" == "$reflex_port" ]]; then
    echo "The local port and the reflexive port are the same."
    exit 1
  fi
  echo "userspace lab: reflexive port ${reflex_port} is the NAT port."
fi

if [[ "$mode" == "--userspace-only" ]]; then
  exit 0
fi

if ! command -v ip >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
  echo "=== netns lab skipped ==="
  echo "Install iproute2 and iptables to run the source-NAT lab."
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  if ! sudo -n true 2>/dev/null; then
    echo "=== netns lab skipped ==="
    echo "Root is required for the source-NAT lab."
    exit 0
  fi
  echo "=== netns source NAT lab ==="
  cargo build -q -p gyeol-cli
  exec sudo -n -E env PATH="$PATH" "$0" --netns-only
fi

echo "=== netns source NAT lab ==="
bin="$root/target/debug/gyeol"
if [[ ! -x "$bin" ]]; then
  echo "The gyeol binary is missing. Build it before the netns lab."
  exit 1
fi

ns_c=gyeol-w4-client
ns_n=gyeol-w4-nat
ns_s=gyeol-w4-stun
pid=""
log=$(mktemp)
cout=$(mktemp)

cleanup() {
  if [[ -n "${pid}" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  ip netns del "$ns_c" 2>/dev/null || true
  ip netns del "$ns_n" 2>/dev/null || true
  ip netns del "$ns_s" 2>/dev/null || true
  rm -f "$log" "$cout"
}
trap cleanup EXIT

ip netns del "$ns_c" 2>/dev/null || true
ip netns del "$ns_n" 2>/dev/null || true
ip netns del "$ns_s" 2>/dev/null || true

ip netns add "$ns_c"
ip netns add "$ns_n"
ip netns add "$ns_s"

ip link add veth-c type veth peer name veth-nc
ip link set veth-c netns "$ns_c"
ip link set veth-nc netns "$ns_n"
ip link add veth-ns type veth peer name veth-s
ip link set veth-ns netns "$ns_n"
ip link set veth-s netns "$ns_s"

ip netns exec "$ns_c" ip addr add 10.20.0.2/24 dev veth-c
ip netns exec "$ns_c" ip link set veth-c up
ip netns exec "$ns_c" ip link set lo up
ip netns exec "$ns_c" ip route add default via 10.20.0.1

ip netns exec "$ns_n" ip addr add 10.20.0.1/24 dev veth-nc
ip netns exec "$ns_n" ip link set veth-nc up
ip netns exec "$ns_n" ip addr add 10.30.0.2/24 dev veth-ns
ip netns exec "$ns_n" ip link set veth-ns up
ip netns exec "$ns_n" ip link set lo up

ip netns exec "$ns_s" ip addr add 10.30.0.1/24 dev veth-s
ip netns exec "$ns_s" ip link set veth-s up
ip netns exec "$ns_s" ip link set lo up

ip netns exec "$ns_n" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$ns_n" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec "$ns_n" sysctl -w net.ipv4.conf.veth-nc.rp_filter=0 >/dev/null
ip netns exec "$ns_n" sysctl -w net.ipv4.conf.veth-ns.rp_filter=0 >/dev/null
ip netns exec "$ns_n" iptables -t nat -A POSTROUTING -s 10.20.0.0/24 -o veth-ns -j MASQUERADE
ip netns exec "$ns_n" iptables -P FORWARD ACCEPT

ip netns exec "$ns_s" "$bin" stun-serve --listen 10.30.0.1:3478 >"$log" 2>&1 &
pid=$!

ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ip netns exec "$ns_c" "$bin" stun --server 10.30.0.1:3478 --bind 10.20.0.2:0 --timeout 2 >"$cout" 2>&1; then
    ok=1
    break
  fi
  sleep 0.2
done

echo "stun-serve log:"
cat "$log" || true
echo "stun client:"
cat "$cout" || true

if [[ "$ok" -ne 1 ]]; then
  echo "The netns STUN gather failed."
  exit 1
fi

local_ip=$(awk '/^local / { split($2, a, ":"); print a[1] }' "$cout")
reflex_ip=$(awk '/^reflexive / { split($2, a, ":"); print a[1] }' "$cout")
if [[ "$local_ip" != "10.20.0.2" ]]; then
  echo "The local address is ${local_ip}. The expected address is 10.20.0.2."
  exit 1
fi
if [[ "$reflex_ip" != "10.30.0.2" ]]; then
  echo "The reflexive address is ${reflex_ip}. The expected NAT address is 10.30.0.2."
  exit 1
fi
echo "netns lab: local ${local_ip} and reflexive ${reflex_ip}."
echo "The reflexive address is the NAT address. The hole punch is not part of this lab."

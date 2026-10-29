#!/usr/bin/env bash
# Run one Relay lab in network namespaces.
# same-udp: two peers behind one NAT. Peer-to-peer traffic is dropped. Relay UDP/443.
# dual-udp: two peers behind two NATs. Relay UDP/443.
# dual-tcp: two NATs. UDP/443 is dropped. Relay TCP/443.
# The script needs root, iproute2, and iptables.
# The orblx binary must already be built.

set -euo pipefail

export PATH="/usr/sbin:/sbin:${PATH:-/usr/bin}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "The Relay netns lab needs root."
  exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/target/debug/orblx"
kind=${1:-same-udp}

if [[ ! -x "$bin" ]]; then
  echo "The orblx binary is missing. Build it before the Relay netns lab."
  exit 1
fi

case "$kind" in
  same-udp | dual-udp | dual-tcp) ;;
  *)
    echo "The lab kind ${kind} is not same-udp, dual-udp, or dual-tcp."
    exit 1
    ;;
esac

prefix="orblx-w6-${kind}"
work=$(mktemp -d)
stun_pid=""
relay_pid=""
server_pid=""
client_pid=""
namespaces=()

cleanup() {
  local pid ns
  for pid in "${server_pid:-}" "${client_pid:-}" "${relay_pid:-}" "${stun_pid:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if ((${#namespaces[@]} > 0)); then
    for ns in "${namespaces[@]}"; do
      ip netns del "$ns" 2>/dev/null || true
    done
  fi
  if [[ -n "${work:-}" ]]; then
    rm -rf "$work"
  fi
}
trap cleanup EXIT

add_ns() {
  local ns=$1
  ip netns del "$ns" 2>/dev/null || true
  ip netns add "$ns"
  namespaces+=("$ns")
}

up_lo() {
  ip netns exec "$1" ip link set lo up
}

expect_line() {
  local file=$1
  local line=$2
  if ! grep -qx "$line" "$file"; then
    echo "The file does not contain: ${line}"
    echo "---- $file ----"
    cat "$file" || true
    exit 1
  fi
}

check_peer() {
  local file=$1
  local local_ip=$2
  local reflex_ip=$3
  local transport=$4
  echo "---- $file ----"
  cat "$file"
  expect_line "$file" "direct_attempted false"
  expect_line "$file" "relay_is_up true"
  expect_line "$file" "direct_is_up false"
  expect_line "$file" "echo ok true"
  expect_line "$file" "transport ${transport}"
  expect_line "$file" "stick reconnect"
  expect_line "$file" "tcp framing quic-style"
  if [[ "$transport" == "tcp" ]]; then
    expect_line "$file" "framing quic-style"
  else
    expect_line "$file" "framing udp-datagram"
  fi
  local got_local got_reflex elapsed session
  got_local=$(awk '/^local / { print $2; exit }' "$file")
  got_reflex=$(awk '/^reflexive / { print $2; exit }' "$file")
  elapsed=$(awk '/^elapsed_ms / { print $2; exit }' "$file")
  session=$(awk '/^session_id / { print $2; exit }' "$file")
  if [[ "${got_local%:*}" != "$local_ip" ]]; then
    echo "The local address is ${got_local}. The expected address starts with ${local_ip}."
    exit 1
  fi
  if [[ "${got_reflex%:*}" != "$reflex_ip" ]]; then
    echo "The reflexive address is ${got_reflex}. The expected NAT address is ${reflex_ip}."
    exit 1
  fi
  if [[ "$got_local" == "$got_reflex" ]]; then
    echo "The local address and the reflexive address are the same."
    exit 1
  fi
  if [[ -z "$elapsed" || "$elapsed" -gt 8000 ]]; then
    echo "The elapsed time is ${elapsed} ms. The budget is 8000 ms."
    exit 1
  fi
  if [[ "$session" != "$session_hex" ]]; then
    echo "The session id is ${session}. The expected id is ${session_hex}."
    exit 1
  fi
}

check_audit() {
  local file=$1
  echo "---- audit ----"
  cat "$file" || true
  if ! grep -q '^forward ' "$file"; then
    echo "The Relay did not forward a payload."
    exit 1
  fi
  if awk '$1 == "forward" && $4 != "0" { found = 1 } END { exit found ? 0 : 1 }' "$file"; then
    echo "The Relay audit saw the probe plaintext."
    exit 1
  fi
  local forwards
  forwards=$(grep -c '^forward ' "$file")
  echo "audit forwards ${forwards}"
  echo "audit plaintext_hits 0"
}

setup_same() {
  local ns_a="${prefix}-a"
  local ns_b="${prefix}-b"
  local ns_n="${prefix}-nat"
  local ns_p="${prefix}-pub"
  add_ns "$ns_a"
  add_ns "$ns_b"
  add_ns "$ns_n"
  add_ns "$ns_p"

  ip link add veth-a type veth peer name veth-na
  ip link set veth-a netns "$ns_a"
  ip link set veth-na netns "$ns_n"
  ip link add veth-b type veth peer name veth-nb
  ip link set veth-b netns "$ns_b"
  ip link set veth-nb netns "$ns_n"
  ip link add veth-n type veth peer name veth-p
  ip link set veth-n netns "$ns_n"
  ip link set veth-p netns "$ns_p"

  ip netns exec "$ns_a" ip addr add 10.20.1.2/24 dev veth-a
  ip netns exec "$ns_a" ip link set veth-a up
  up_lo "$ns_a"
  ip netns exec "$ns_a" ip route add default via 10.20.1.1

  ip netns exec "$ns_b" ip addr add 10.20.2.2/24 dev veth-b
  ip netns exec "$ns_b" ip link set veth-b up
  up_lo "$ns_b"
  ip netns exec "$ns_b" ip route add default via 10.20.2.1

  ip netns exec "$ns_n" ip addr add 10.20.1.1/24 dev veth-na
  ip netns exec "$ns_n" ip link set veth-na up
  ip netns exec "$ns_n" ip addr add 10.20.2.1/24 dev veth-nb
  ip netns exec "$ns_n" ip link set veth-nb up
  ip netns exec "$ns_n" ip addr add 10.30.0.2/24 dev veth-n
  ip netns exec "$ns_n" ip link set veth-n up
  up_lo "$ns_n"
  ip netns exec "$ns_n" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "$ns_n" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec "$ns_n" iptables -t nat -A POSTROUTING -s 10.20.0.0/16 -o veth-n -j MASQUERADE
  ip netns exec "$ns_n" iptables -A FORWARD -s 10.20.1.0/24 -d 10.20.2.0/24 -j DROP
  ip netns exec "$ns_n" iptables -A FORWARD -s 10.20.2.0/24 -d 10.20.1.0/24 -j DROP
  ip netns exec "$ns_n" iptables -P FORWARD ACCEPT

  ip netns exec "$ns_p" ip addr add 10.30.0.1/24 dev veth-p
  ip netns exec "$ns_p" ip link set veth-p up
  up_lo "$ns_p"

  peer_a_ns=$ns_a
  peer_b_ns=$ns_b
  relay_ns=$ns_p
  peer_a_ip=10.20.1.2
  peer_b_ip=10.20.2.2
  peer_a_reflex=10.30.0.2
  peer_b_reflex=10.30.0.2
}

setup_dual() {
  local ns_a="${prefix}-a"
  local ns_na="${prefix}-na"
  local ns_b="${prefix}-b"
  local ns_nb="${prefix}-nb"
  local ns_r="${prefix}-r"
  local ns_p="${prefix}-p"
  add_ns "$ns_a"
  add_ns "$ns_na"
  add_ns "$ns_b"
  add_ns "$ns_nb"
  add_ns "$ns_r"
  add_ns "$ns_p"

  ip link add veth-a type veth peer name veth-a-nat
  ip link set veth-a netns "$ns_a"
  ip link set veth-a-nat netns "$ns_na"
  ip link add veth-b type veth peer name veth-b-nat
  ip link set veth-b netns "$ns_b"
  ip link set veth-b-nat netns "$ns_nb"
  ip link add veth-na-p type veth peer name veth-na-br
  ip link set veth-na-p netns "$ns_na"
  ip link set veth-na-br netns "$ns_p"
  ip link add veth-nb-p type veth peer name veth-nb-br
  ip link set veth-nb-p netns "$ns_nb"
  ip link set veth-nb-br netns "$ns_p"
  ip link add veth-r type veth peer name veth-r-br
  ip link set veth-r netns "$ns_r"
  ip link set veth-r-br netns "$ns_p"

  ip netns exec "$ns_a" ip addr add 10.21.0.2/24 dev veth-a
  ip netns exec "$ns_a" ip link set veth-a up
  up_lo "$ns_a"
  ip netns exec "$ns_a" ip route add default via 10.21.0.1

  ip netns exec "$ns_b" ip addr add 10.22.0.2/24 dev veth-b
  ip netns exec "$ns_b" ip link set veth-b up
  up_lo "$ns_b"
  ip netns exec "$ns_b" ip route add default via 10.22.0.1

  ip netns exec "$ns_na" ip addr add 10.21.0.1/24 dev veth-a-nat
  ip netns exec "$ns_na" ip link set veth-a-nat up
  ip netns exec "$ns_na" ip addr add 10.30.0.2/24 dev veth-na-p
  ip netns exec "$ns_na" ip link set veth-na-p up
  up_lo "$ns_na"
  ip netns exec "$ns_na" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "$ns_na" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec "$ns_na" iptables -t nat -A POSTROUTING -s 10.21.0.0/24 -o veth-na-p -j MASQUERADE
  ip netns exec "$ns_na" iptables -P FORWARD ACCEPT

  ip netns exec "$ns_nb" ip addr add 10.22.0.1/24 dev veth-b-nat
  ip netns exec "$ns_nb" ip link set veth-b-nat up
  ip netns exec "$ns_nb" ip addr add 10.30.0.3/24 dev veth-nb-p
  ip netns exec "$ns_nb" ip link set veth-nb-p up
  up_lo "$ns_nb"
  ip netns exec "$ns_nb" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "$ns_nb" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec "$ns_nb" iptables -t nat -A POSTROUTING -s 10.22.0.0/24 -o veth-nb-p -j MASQUERADE
  ip netns exec "$ns_nb" iptables -P FORWARD ACCEPT

  ip netns exec "$ns_p" ip link add br0 type bridge
  ip netns exec "$ns_p" ip link set veth-na-br master br0
  ip netns exec "$ns_p" ip link set veth-nb-br master br0
  ip netns exec "$ns_p" ip link set veth-r-br master br0
  ip netns exec "$ns_p" ip link set veth-na-br up
  ip netns exec "$ns_p" ip link set veth-nb-br up
  ip netns exec "$ns_p" ip link set veth-r-br up
  ip netns exec "$ns_p" ip link set br0 up
  up_lo "$ns_p"

  ip netns exec "$ns_r" ip addr add 10.30.0.1/24 dev veth-r
  ip netns exec "$ns_r" ip link set veth-r up
  up_lo "$ns_r"

  if [[ "$kind" == "dual-tcp" ]]; then
    ip netns exec "$ns_na" iptables -I FORWARD 1 -p udp --dport 443 -j DROP
    ip netns exec "$ns_na" iptables -I FORWARD 1 -p udp --sport 443 -j DROP
    ip netns exec "$ns_nb" iptables -I FORWARD 1 -p udp --dport 443 -j DROP
    ip netns exec "$ns_nb" iptables -I FORWARD 1 -p udp --sport 443 -j DROP
  fi

  peer_a_ns=$ns_a
  peer_b_ns=$ns_b
  relay_ns=$ns_r
  peer_a_ip=10.21.0.2
  peer_b_ip=10.22.0.2
  peer_a_reflex=10.30.0.2
  peer_b_reflex=10.30.0.3
}

echo "=== Relay netns lab ${kind} ==="

if [[ "$kind" == "same-udp" ]]; then
  setup_same
  transport=udp
  preference=udp
  udp_timeout_ms=1000
else
  setup_dual
  if [[ "$kind" == "dual-tcp" ]]; then
    transport=tcp
    preference=auto
    udp_timeout_ms=800
  else
    transport=udp
    preference=udp
    udp_timeout_ms=1000
  fi
fi

"$bin" direct-issue --out "$work/id" >/dev/null
session_hex=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
needle_hex=$(python3 -c 'print(b"orblx-w6-relay-probe".hex())')

ip netns exec "$relay_ns" "$bin" stun-serve --listen 10.30.0.1:3478 >"$work/stun.log" 2>&1 &
stun_pid=$!

ok=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if ip netns exec "$peer_a_ns" "$bin" stun --server 10.30.0.1:3478 --bind "${peer_a_ip}:0" --timeout 2 >"$work/stun-a.out" 2>"$work/stun-a.err"; then
    ok=1
    break
  fi
  sleep 0.2
done
if [[ "$ok" -ne 1 ]]; then
  echo "The Relay netns STUN gather failed."
  cat "$work/stun.log" || true
  cat "$work/stun-a.err" || true
  exit 1
fi
echo "---- stun peer A ----"
cat "$work/stun-a.out"

ip netns exec "$relay_ns" "$bin" relay \
  --udp 10.30.0.1:443 \
  --tcp 10.30.0.1:443 \
  --audit-absent "$needle_hex" \
  --audit-file "$work/audit.log" >"$work/relay.log" 2>&1 &
relay_pid=$!

ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if grep -q '^relay udp 10.30.0.1:443$' "$work/relay.log" && grep -q '^relay tcp 10.30.0.1:443$' "$work/relay.log"; then
    ok=1
    break
  fi
  sleep 0.2
done
if [[ "$ok" -ne 1 ]]; then
  echo "The Relay did not bind port 443."
  cat "$work/relay.log" || true
  exit 1
fi
echo "---- relay ----"
cat "$work/relay.log"

ip netns exec "$peer_a_ns" "$bin" relay-peer \
  --role server \
  --bind "${peer_a_ip}:0" \
  --stun 10.30.0.1:3478 \
  --session "$session_hex" \
  --relay 10.30.0.1:443 \
  --transport "$preference" \
  --udp-timeout-ms "$udp_timeout_ms" \
  --timeout 12 \
  --ready-file "$work/server.ready" \
  --cert "$work/id/server.pem" \
  --key "$work/id/server.key" \
  --bundle "$work/id/bundle.pem" \
  --ticket "$work/id/ticket.bin" >"$work/server.out" 2>"$work/server.err" &
server_pid=$!

ip netns exec "$peer_b_ns" "$bin" relay-peer \
  --role client \
  --bind "${peer_b_ip}:0" \
  --stun 10.30.0.1:3478 \
  --session "$session_hex" \
  --relay 10.30.0.1:443 \
  --transport "$preference" \
  --udp-timeout-ms "$udp_timeout_ms" \
  --timeout 12 \
  --wait-ready "$work/server.ready" \
  --cert "$work/id/client.pem" \
  --key "$work/id/client.key" \
  --bundle "$work/id/bundle.pem" \
  --ticket "$work/id/ticket.bin" >"$work/client.out" 2>"$work/client.err" &
client_pid=$!

server_ec=0
client_ec=0
set +e
wait "$server_pid"
server_ec=$?
wait "$client_pid"
client_ec=$?
set -e
server_pid=""
client_pid=""

if [[ -s "$work/server.err" ]]; then
  echo "server stderr:"
  cat "$work/server.err" || true
fi
if [[ -s "$work/client.err" ]]; then
  echo "client stderr:"
  cat "$work/client.err" || true
fi
if [[ "$server_ec" -ne 0 || "$client_ec" -ne 0 ]]; then
  echo "A Relay peer failed. Server status ${server_ec}. Client status ${client_ec}."
  echo "server stdout:"
  cat "$work/server.out" || true
  echo "client stdout:"
  cat "$work/client.out" || true
  echo "relay log:"
  cat "$work/relay.log" || true
  exit 1
fi

check_peer "$work/server.out" "$peer_a_ip" "$peer_a_reflex" "$transport"
check_peer "$work/client.out" "$peer_b_ip" "$peer_b_reflex" "$transport"
check_audit "$work/audit.log"
echo "Relay netns ${kind}: transport ${transport}, echo ok, payload opaque."
cleanup
trap - EXIT

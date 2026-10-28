#!/usr/bin/env bash
# Run the Week 5 edge lab.
# The userspace lab needs no extra privileges.
# UDP port 443 needs permission to bind that port.
# The netns lab needs root, iproute2, and iptables.
# The lab sends hole-punch datagrams.
# The lab proves direct QUIC.
# The lab does not use Relay.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

mode=${1:-all}

need() {
  local file=$1
  local key=$2
  local want=$3
  local got
  got=$(awk -v key="$key" '$1 == key { print $2; exit }' "$file")
  if [[ "$got" != "$want" ]]; then
    echo "The line ${key} is ${got}. The expected value is ${want}."
    echo "---- $file ----"
    cat "$file" || true
    exit 1
  fi
}

need_at_least() {
  local file=$1
  local prefix=$2
  local min=$3
  local got
  got=$(awk -v prefix="$prefix" 'index($0, prefix) == 1 { print $NF; exit }' "$file")
  if [[ -z "$got" || "$got" -lt "$min" ]]; then
    echo "The value for ${prefix} is ${got}. The minimum is ${min}."
    echo "---- $file ----"
    cat "$file" || true
    exit 1
  fi
}

check_userspace() {
  local text=$1
  printf '%s\n' "$text"
  local file
  file=$(mktemp)
  printf '%s\n' "$text" >"$file"
  need "$file" "same-nat" "true"
  if ! grep -q '^server direct_is_up true$' "$file"; then
    echo "The server Direct flag is not true."
    cat "$file"
    rm -f "$file"
    exit 1
  fi
  if ! grep -q '^client direct_is_up true$' "$file"; then
    echo "The client Direct flag is not true."
    cat "$file"
    rm -f "$file"
    exit 1
  fi
  if ! grep -q '^echo ok true$' "$file"; then
    echo "The QUIC echo did not succeed."
    cat "$file"
    rm -f "$file"
    exit 1
  fi
  need_at_least "$file" "server punch packets " 1
  need_at_least "$file" "client punch packets " 1
  need_at_least "$file" "server punch received " 1
  need_at_least "$file" "client punch received " 1
  local elapsed budget
  elapsed=$(awk '/^elapsed_ms / { print $2; exit }' "$file")
  budget=$(awk '/^budget_ms / { print $2; exit }' "$file")
  if [[ -z "$elapsed" || -z "$budget" || "$elapsed" -gt "$budget" ]]; then
    echo "The elapsed time is ${elapsed} ms. The budget is ${budget} ms."
    rm -f "$file"
    exit 1
  fi
  local server_local server_reflex client_local client_reflex
  server_local=$(awk '/^server local / { print $3; exit }' "$file")
  server_reflex=$(awk '/^server reflexive / { print $3; exit }' "$file")
  client_local=$(awk '/^client local / { print $3; exit }' "$file")
  client_reflex=$(awk '/^client reflexive / { print $3; exit }' "$file")
  local server_reflex_ip client_reflex_ip
  server_reflex_ip=${server_reflex%:*}
  client_reflex_ip=${client_reflex%:*}
  if [[ "$server_reflex_ip" != "$client_reflex_ip" ]]; then
    echo "The reflexive addresses are not on one NAT."
    rm -f "$file"
    exit 1
  fi
  if [[ "$server_local" == "$server_reflex" || "$client_local" == "$client_reflex" ]]; then
    echo "A host candidate matches its reflexive candidate."
    rm -f "$file"
    exit 1
  fi
  rm -f "$file"
  echo "userspace lab: hole punch sent, direct_is_up true, echo ok."
}

run_userspace() {
  echo "=== userspace lab ==="
  local userspace
  userspace=$(cargo run -q -p gyeol-cli -- edge-smoke)
  check_userspace "$userspace"
}

run_udp443() {
  echo "=== UDP 443 lab ==="
  local bin="$root/target/debug/gyeol"
  if [[ ! -x "$bin" ]]; then
    cargo build -q -p gyeol-cli
  fi
  local text
  text=$("$bin" edge-smoke --bind 127.0.0.1:443)
  local file
  file=$(mktemp)
  printf '%s\n' "$text" >"$file"
  if ! grep -q '^quic port 443$' "$file"; then
    echo "The QUIC server port is not 443."
    cat "$file"
    rm -f "$file"
    exit 1
  fi
  if ! grep -q '^policy port 443$' "$file"; then
    echo "The policy port is not 443."
    rm -f "$file"
    exit 1
  fi
  rm -f "$file"
  check_userspace "$text"
  echo "UDP 443 lab: direct QUIC is up on port 443."
}

check_peer() {
  local file=$1
  local expect_local_ip=$2
  local expect_port=$3
  echo "---- $file ----"
  cat "$file"
  if ! grep -q '^direct_is_up true$' "$file"; then
    echo "direct_is_up is not true in $file."
    exit 1
  fi
  if ! grep -q '^echo ok true$' "$file"; then
    echo "The QUIC echo is not ok in $file."
    exit 1
  fi
  need_at_least "$file" "punch packets " 1
  need_at_least "$file" "punch received " 1
  local quic_port elapsed local_addr reflex_addr
  quic_port=$(awk '/^quic port / { print $3; exit }' "$file")
  elapsed=$(awk '/^elapsed_ms / { print $2; exit }' "$file")
  local_addr=$(awk '/^local / { print $2; exit }' "$file")
  reflex_addr=$(awk '/^reflexive / { print $2; exit }' "$file")
  if [[ "$quic_port" != "$expect_port" ]]; then
    echo "The QUIC port is ${quic_port}. The expected port is ${expect_port}."
    exit 1
  fi
  if [[ -z "$elapsed" || "$elapsed" -gt 3000 ]]; then
    echo "The elapsed time is ${elapsed} ms. The budget is 3000 ms."
    exit 1
  fi
  local local_ip reflex_ip
  local_ip=${local_addr%:*}
  reflex_ip=${reflex_addr%:*}
  if [[ "$local_ip" != "$expect_local_ip" ]]; then
    echo "The local address is ${local_addr}. The expected address starts with ${expect_local_ip}."
    exit 1
  fi
  if [[ "$reflex_ip" != "10.30.0.2" ]]; then
    echo "The reflexive address is ${reflex_addr}. The expected NAT address is 10.30.0.2."
    exit 1
  fi
  if [[ "$local_addr" == "$reflex_addr" ]]; then
    echo "The local address and the reflexive address are the same."
    exit 1
  fi
}

run_netns() {
  echo "=== netns source NAT lab ==="
  local bin="$root/target/debug/gyeol"
  if [[ ! -x "$bin" ]]; then
    echo "The gyeol binary is missing. Build it before the netns lab."
    exit 1
  fi
  if ! command -v ip >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    echo "Install iproute2 and iptables to run the source-NAT lab."
    exit 1
  fi

  local ns_a=gyeol-w5-a
  local ns_b=gyeol-w5-b
  local ns_n=gyeol-w5-nat
  local ns_s=gyeol-w5-stun
  local work
  work=$(mktemp -d)
  local server_out="$work/server.out"
  local client_out="$work/client.out"
  local server_err="$work/server.err"
  local client_err="$work/client.err"
  local stun_log="$work/stun.log"
  local stun_pid=""
  local server_pid=""
  local client_pid=""

  cleanup() {
    local pid
    for pid in "${server_pid:-}" "${client_pid:-}" "${stun_pid:-}"; do
      if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
      fi
    done
    ip netns del "${ns_a:-}" 2>/dev/null || true
    ip netns del "${ns_b:-}" 2>/dev/null || true
    ip netns del "${ns_n:-}" 2>/dev/null || true
    ip netns del "${ns_s:-}" 2>/dev/null || true
    if [[ -n "${work:-}" ]]; then
      rm -rf "$work"
    fi
  }
  trap cleanup EXIT

  ip netns del "$ns_a" 2>/dev/null || true
  ip netns del "$ns_b" 2>/dev/null || true
  ip netns del "$ns_n" 2>/dev/null || true
  ip netns del "$ns_s" 2>/dev/null || true

  ip netns add "$ns_a"
  ip netns add "$ns_b"
  ip netns add "$ns_n"
  ip netns add "$ns_s"

  ip link add veth-a type veth peer name veth-na
  ip link set veth-a netns "$ns_a"
  ip link set veth-na netns "$ns_n"
  ip link add veth-b type veth peer name veth-nb
  ip link set veth-b netns "$ns_b"
  ip link set veth-nb netns "$ns_n"
  ip link add veth-n type veth peer name veth-s
  ip link set veth-n netns "$ns_n"
  ip link set veth-s netns "$ns_s"

  ip netns exec "$ns_a" ip addr add 10.20.0.2/24 dev veth-a
  ip netns exec "$ns_a" ip link set veth-a up
  ip netns exec "$ns_a" ip link set lo up
  ip netns exec "$ns_a" ip route add default via 10.20.0.1

  ip netns exec "$ns_b" ip addr add 10.20.0.3/24 dev veth-b
  ip netns exec "$ns_b" ip link set veth-b up
  ip netns exec "$ns_b" ip link set lo up
  ip netns exec "$ns_b" ip route add default via 10.20.0.1

  ip netns exec "$ns_n" ip link add br0 type bridge
  ip netns exec "$ns_n" ip link set veth-na master br0
  ip netns exec "$ns_n" ip link set veth-nb master br0
  ip netns exec "$ns_n" ip addr add 10.20.0.1/24 dev br0
  ip netns exec "$ns_n" ip link set veth-na up
  ip netns exec "$ns_n" ip link set veth-nb up
  ip netns exec "$ns_n" ip link set br0 up
  ip netns exec "$ns_n" ip link set lo up
  ip netns exec "$ns_n" ip addr add 10.30.0.2/24 dev veth-n
  ip netns exec "$ns_n" ip link set veth-n up

  ip netns exec "$ns_s" ip addr add 10.30.0.1/24 dev veth-s
  ip netns exec "$ns_s" ip link set veth-s up
  ip netns exec "$ns_s" ip link set lo up

  ip netns exec "$ns_n" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "$ns_n" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec "$ns_n" sysctl -w net.ipv4.conf.br0.rp_filter=0 >/dev/null
  ip netns exec "$ns_n" sysctl -w net.ipv4.conf.veth-n.rp_filter=0 >/dev/null
  ip netns exec "$ns_n" iptables -t nat -A POSTROUTING -s 10.20.0.0/24 -o veth-n -j MASQUERADE
  ip netns exec "$ns_n" iptables -P FORWARD ACCEPT

  "$bin" direct-issue --out "$work/id"

  ip netns exec "$ns_s" "$bin" stun-serve --listen 10.30.0.1:3478 >"$stun_log" 2>&1 &
  stun_pid=$!

  local ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ip netns exec "$ns_a" "$bin" stun --server 10.30.0.1:3478 --bind 10.20.0.2:0 --timeout 2 >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 0.2
  done
  if [[ "$ok" -ne 1 ]]; then
    echo "The netns STUN gather failed."
    cat "$stun_log" || true
    exit 1
  fi

  local token
  token=$(python3 -c 'import secrets; print(secrets.token_hex(8))')

  ip netns exec "$ns_a" "$bin" direct-peer \
    --role server \
    --bind 10.20.0.2:443 \
    --stun 10.30.0.1:3478 \
    --token "$token" \
    --publish "$work/server.cand" \
    --peer-file "$work/client.cand" \
    --cert "$work/id/server.pem" \
    --key "$work/id/server.key" \
    --bundle "$work/id/bundle.pem" \
    --ticket "$work/id/ticket.bin" \
    --timeout 3 >"$server_out" 2>"$server_err" &
  server_pid=$!

  ip netns exec "$ns_b" "$bin" direct-peer \
    --role client \
    --bind 10.20.0.3:0 \
    --stun 10.30.0.1:3478 \
    --token "$token" \
    --publish "$work/client.cand" \
    --peer-file "$work/server.cand" \
    --cert "$work/id/client.pem" \
    --key "$work/id/client.key" \
    --bundle "$work/id/bundle.pem" \
    --ticket "$work/id/ticket.bin" \
    --timeout 3 >"$client_out" 2>"$client_err" &
  client_pid=$!

  local server_ec=0
  local client_ec=0
  set +e
  wait "$server_pid"
  server_ec=$?
  wait "$client_pid"
  client_ec=$?
  set -e
  server_pid=""
  client_pid=""

  echo "stun-serve log:"
  cat "$stun_log" || true
  if [[ -s "$server_err" ]]; then
    echo "server stderr:"
    cat "$server_err" || true
  fi
  if [[ -s "$client_err" ]]; then
    echo "client stderr:"
    cat "$client_err" || true
  fi
  if [[ "$server_ec" -ne 0 || "$client_ec" -ne 0 ]]; then
    echo "A direct peer failed. Server status ${server_ec}. Client status ${client_ec}."
    echo "server stdout:"
    cat "$server_out" || true
    echo "client stdout:"
    cat "$client_out" || true
    exit 1
  fi

  check_peer "$server_out" "10.20.0.2" "443"
  check_peer "$client_out" "10.20.0.3" "443"
  echo "netns lab: two peers behind one NAT. Hole punch sent. direct_is_up true. QUIC port 443."
  cleanup
  trap - EXIT
}

if [[ "$mode" == "all" || "$mode" == "--userspace-only" ]]; then
  run_userspace
fi

if [[ "$mode" == "--userspace-only" ]]; then
  exit 0
fi

if [[ "$mode" == "all" && "$(id -u)" -ne 0 ]]; then
  if ! command -v ip >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    echo "=== privileged labs skipped ==="
    echo "Install iproute2 and iptables, and run as root, for the UDP 443 and netns labs."
    exit 0
  fi
  if ! sudo -n true 2>/dev/null; then
    echo "=== privileged labs skipped ==="
    echo "Root is required for UDP port 443 and the source-NAT lab."
    exit 0
  fi
  cargo build -q -p gyeol-cli
  exec sudo -n -E env PATH="$PATH" "$0" --privileged
fi

if [[ "$mode" == "all" ]]; then
  mode=--privileged
fi

if [[ "$mode" == "--privileged" || "$mode" == "--udp443-only" ]]; then
  run_udp443
fi

if [[ "$mode" == "--udp443-only" ]]; then
  exit 0
fi

if [[ "$mode" == "--privileged" || "$mode" == "--netns-only" ]]; then
  if ! command -v ip >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    echo "=== netns lab skipped ==="
    echo "Install iproute2 and iptables to run the source-NAT lab."
    if [[ "$mode" == "--netns-only" ]]; then
      exit 1
    fi
    exit 0
  fi
  run_netns
fi

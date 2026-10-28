#!/usr/bin/env bash
# Run the Orblx connector TUN lab for two HTTPS apps.
# The lab needs Linux, root, and CAP_NET_ADMIN.
# When the TUN device is not available, the script prints K3 and exits 0.
# The userspace proof is scripts/connector-smoke.sh.

set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/sbin:/sbin:${PATH:-/usr/bin}"
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

k3() {
  echo "K3 tun_ready false"
  echo "$1"
  echo "Use scripts/connector-smoke.sh for the userspace proof."
  exit 0
}

wait_log() {
  local file=$1
  local pattern=$2
  local pid=$3
  local _try
  for _try in $(seq 1 100); do
    if grep -q "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  k3 "K3: This host is not Linux. The TUN device in this tree is a Linux TUN device."
fi

if [[ ! -e /dev/net/tun ]]; then
  k3 "K3: /dev/net/tun is absent."
fi

if [[ "$(id -u)" -ne 0 ]]; then
  k3 "K3: This process is not root. The TUN device needs CAP_NET_ADMIN."
fi

cap_eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)
# CAP_NET_ADMIN is bit 12.
python3 - "$cap_eff" <<'PY' || k3 "K3: CAP_NET_ADMIN is absent."
import sys
value = int(sys.argv[1], 16)
if value & (1 << 12) == 0:
    raise SystemExit(1)
PY

if ! command -v ip >/dev/null 2>&1; then
  k3 "K3: The ip command is absent. The TUN lab needs iproute2."
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is absent. The TUN lab needs curl."
  exit 1
fi

echo "K3 tun_ready true"
bin="$root/target/debug/gyeol"
if [[ ! -x "$bin" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Build target/debug/gyeol before you run this script."
    exit 1
  fi
  cargo build -p gyeol-cli
fi

work=$(mktemp -d)
ns_h=orblx-w9-hub
ns_s=orblx-w9-spoke
hub_pid=""
apps_pid=""
spoke_pid=""

cleanup() {
  for pid in "${apps_pid:-}" "${hub_pid:-}" "${spoke_pid:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  ip netns del "$ns_h" 2>/dev/null || true
  ip netns del "$ns_s" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$bin" connector issue --out "$work/lab"

ip netns del "$ns_h" 2>/dev/null || true
ip netns del "$ns_s" 2>/dev/null || true
ip netns add "$ns_h"
ip netns add "$ns_s"
ip link add veth-h type veth peer name veth-s
ip link set veth-h netns "$ns_h"
ip link set veth-s netns "$ns_s"
ip netns exec "$ns_h" ip link set lo up
ip netns exec "$ns_s" ip link set lo up
ip netns exec "$ns_h" ip addr add 10.66.0.1/24 dev veth-h
ip netns exec "$ns_h" ip link set veth-h up
ip netns exec "$ns_s" ip addr add 10.66.0.2/24 dev veth-s
ip netns exec "$ns_s" ip link set veth-s up
ip netns exec "$ns_h" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec "$ns_s" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null

ip netns exec "$ns_h" "$bin" hello-quic server \
  --cert "$work/lab/hub-cert.pem" \
  --key "$work/lab/hub-key.pem" \
  --bundle "$work/lab/trust-bundle.pem" \
  --ticket "$work/lab/hub-ticket.bin" \
  --listen 10.66.0.1:443 \
  --tun-address 10.8.0.1 \
  --tun-name orblxh \
  >"$work/hub.log" 2>&1 &
hub_pid=$!

ready=0
for _ in $(seq 1 50); do
  if ip netns exec "$ns_h" ip link show orblxh >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$hub_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
  echo "K3: The hub TUN device did not open."
  echo "---- hub log ----"
  cat "$work/hub.log" || true
  echo "K3 tun_ready false"
  echo "Use scripts/connector-smoke.sh for the userspace proof."
  exit 0
fi

ip netns exec "$ns_h" ip addr add 10.8.0.10/32 dev orblxh
ip netns exec "$ns_h" ip addr add 10.8.0.11/32 dev orblxh

ip netns exec "$ns_h" "$bin" connector apps \
  --dir "$work/lab" \
  --bind-a 10.8.0.10:443 \
  --bind-b 10.8.0.11:443 \
  >"$work/apps.log" 2>&1 &
apps_pid=$!

if ! wait_log "$work/apps.log" "listens on" "$apps_pid"; then
  echo "The app listeners did not start."
  echo "---- apps log ----"
  cat "$work/apps.log" || true
  exit 1
fi

ip netns exec "$ns_s" "$bin" hello-quic client \
  --cert "$work/lab/spoke-cert.pem" \
  --key "$work/lab/spoke-key.pem" \
  --bundle "$work/lab/trust-bundle.pem" \
  --ticket "$work/lab/spoke-ticket.bin" \
  --connect 10.66.0.1:443 \
  --tun-address 10.8.0.2 \
  --tun-name orblxs \
  >"$work/spoke.log" 2>&1 &
spoke_pid=$!

ready=0
for _ in $(seq 1 50); do
  if ip netns exec "$ns_s" ip link show orblxs >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$spoke_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
  echo "K3: The spoke TUN device did not open."
  echo "---- spoke log ----"
  cat "$work/spoke.log" || true
  echo "K3 tun_ready false"
  echo "Use scripts/connector-smoke.sh for the userspace proof."
  exit 0
fi

if ! wait_log "$work/spoke.log" "The peer SPIFFE ID" "$spoke_pid"; then
  echo "The spoke did not complete the QUIC session."
  echo "---- hub log ----"
  cat "$work/hub.log" || true
  echo "---- spoke log ----"
  cat "$work/spoke.log" || true
  exit 1
fi

fetch() {
  local host=$1
  local ip=$2
  ip netns exec "$ns_s" curl --fail --silent --show-error \
    --resolve "${host}:443:${ip}" \
    --cacert "$work/lab/app-ca.pem" \
    "https://${host}/"
}

body_a=$(fetch app-a.orblx.test 10.8.0.10)
body_b=$(fetch app-b.orblx.test 10.8.0.11)
printf 'app-a %s\n' "$body_a"
printf 'app-b %s\n' "$body_b"

if [[ "$body_a" != "app-a" || "$body_b" != "app-b" ]]; then
  echo "The TUN path did not return both app bodies."
  echo "---- hub log ----"
  cat "$work/hub.log" || true
  echo "---- apps log ----"
  cat "$work/apps.log" || true
  echo "---- spoke log ----"
  cat "$work/spoke.log" || true
  exit 1
fi

echo "The TUN connector path passed."

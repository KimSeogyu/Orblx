#!/usr/bin/env bash
# Measure one local TUN round trip.
# The bench needs Linux, /dev/net/tun, CAP_NET_ADMIN, and the ip command.
# When the TUN device is not available, the script prints K3 and exits 0.
# The bench does not use WireGuard, Headscale, or DERP.

set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/sbin:/sbin:${PATH:-/usr/bin}"
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
export CARGO_TERM_COLOR=never

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

k3() {
  echo "K3 tun_ready false"
  echo "$1"
  exit 0
}

# CAP_NET_ADMIN is bit 12. The low 32 bits of CapEff hold that bit.
has_cap() {
  local cap_eff low
  cap_eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)
  if [[ -z "$cap_eff" ]]; then
    return 1
  fi
  low=${cap_eff: -8}
  if (( (16#$low & 4096) == 0 )); then
    return 1
  fi
  return 0
}

if [[ "$(uname -s)" != "Linux" ]]; then
  k3 "K3: This host is not Linux. The TUN device in this tree is a Linux TUN device."
fi

if [[ ! -e /dev/net/tun ]]; then
  k3 "K3: /dev/net/tun is absent."
fi

if ! command -v ip >/dev/null 2>&1; then
  k3 "K3: The ip command is absent. The TUN bench needs iproute2."
fi

if [[ "${1:-}" != "--as-root" ]]; then
  if [[ "$(id -u)" -ne 0 ]] && ! has_cap; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
      k3 "K3: This process is not root. The TUN device needs CAP_NET_ADMIN."
    fi
    if ! command -v cargo >/dev/null 2>&1; then
      echo "Build target/release/tun-bench before you run this script."
      exit 1
    fi
    cargo build --release -p gyeol-datapath --bin tun-bench
    exec sudo -n --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME "$root/scripts/tun-bench.sh" --as-root
  fi
fi

if ! has_cap; then
  k3 "K3: CAP_NET_ADMIN is absent."
fi

bin="$root/target/release/tun-bench"
if [[ ! -x "$bin" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Build target/release/tun-bench before you run this script."
    exit 1
  fi
  cargo build --release -p gyeol-datapath --bin tun-bench
fi

echo "host_uname=$(uname -a)"
echo "host_id=$(id)"
echo "host_euid=$(id -u)"
echo "host_cap_eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)"
echo "host_tun=$(stat -c '%A %n' /dev/net/tun)"
echo "host_ip_path=$(command -v ip)"
echo "host_ip=$(ip -V 2>&1 | head -n 1)"
echo "tun_bench_command=scripts/tun-bench.sh"
exec "$bin"

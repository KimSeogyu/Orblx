#!/usr/bin/env bash
# Enroll two nodes at the coordinator with 1 minute node SVIDs and tickets
# (W25-27: the tickets come from the coordinator enroll path) and keep one
# session up for at least 6 minutes, across 2 or more ticket ends.
# The script pings once per second and reports loss.
# The script skips the proof when it is not root or when Docker is absent.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# W25-14: this proof needs root. It stops at once without root.
require_root "$@"

if ! command -v docker >/dev/null 2>&1; then
  echo "The SVID renewal proof needs Docker. The script skips the proof."
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "The SVID renewal proof needs Docker Compose."
  exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="$root/target/debug/orblx"
compose_file="$root/scripts/proof/compose.svid.yml"
work=$(mktemp -d)
env_file=""
image_dir=""
ping_count=370
# W25-27: the coordinator SVID and ticket life (ORBLX_SVID_TTL). The ping crosses
# 2 or more ticket ends. A ticket ends at its expires time plus 60 s clock skew.
svid_ttl=60
min_ticket_ends=2
ticket_skew=60

require_toolchain() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "The SVID renewal proof needs cargo on PATH."
    exit 1
  fi
  if ! command -v rustc >/dev/null 2>&1; then
    echo "The SVID renewal proof needs rustc on PATH."
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
  docker compose --env-file "$env_file" -f "$compose_file" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    if [[ -n "$env_file" && -f "$env_file" ]]; then
      compose logs || true
    fi
  fi
  if [[ -n "$env_file" && -f "$env_file" ]]; then
    compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "$image_dir" ]]; then
    rm -rf "$image_dir"
  fi
  rm -rf "$work"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "svid-renew"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-svid" || exit 1

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  iptables-legacy -P FORWARD ACCEPT
}

require_toolchain
open_legacy_forward

if [[ ! -x "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --manifest-path "$root/Cargo.toml"
fi

# shellcheck source=stage-image.sh
source "$root/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$root" "$bin")"
docker build -t orblx-svid:local "$image_dir"

mkdir -p "$work/coord" "$work/a" "$work/b"

cat >"$work/netmap-a.json" <<'EOF'
{
  "version": 1,
  "self": {"name": "a", "overlay_ip": "100.64.0.1"},
  "peers": [{
    "name": "b",
    "overlay_ip": "100.64.0.2",
    "svid": "spiffe://orblx.local/node/b",
    "endpoints": ["172.28.19.12:443"],
    "routes": ["100.64.0.2/32"]
  }]
}
EOF
cat >"$work/netmap-b.json" <<'EOF'
{
  "version": 1,
  "self": {"name": "b", "overlay_ip": "100.64.0.2"},
  "peers": [{
    "name": "a",
    "overlay_ip": "100.64.0.1",
    "svid": "spiffe://orblx.local/node/a",
    "endpoints": ["172.28.19.11:443"],
    "routes": ["100.64.0.1/32"]
  }]
}
EOF

env_file="$work/svid.env"
cat >"$env_file" <<EOF
SVID_COORD_STATE=$work/coord
SVID_STATE_A=$work/a
SVID_STATE_B=$work/b
SVID_NETMAP_A=$work/netmap-a.json
SVID_NETMAP_B=$work/netmap-b.json
SVID_TTL=$svid_ttl
EOF
echo "env_file ${env_file}"

echo "=== [C] start coordinator ==="
compose up -d coord
for _ in $(seq 1 90); do
  if compose exec -T coord cat /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
compose exec -T coord cat /var/lib/orblx/trust-bundle.pem >/dev/null

echo "=== [C] token a ==="
compose exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/a
echo "=== [C] token b ==="
compose exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/b

copy_token() {
  local name=$1
  mkdir -p "$work/tokens"
  compose exec -T coord cat "/var/lib/orblx/tokens/${name}" >"$work/tokens/${name}"
  chmod 600 "$work/tokens/${name}"
}
copy_token a
copy_token b

echo "=== [C] enroll a ==="
"$bin" coord enroll \
  --name a \
  --coord 172.28.19.10:443 \
  --coord-name coord \
  --bundle "$work/coord/trust-bundle.pem" \
  --token-file "$work/tokens/a" \
  --state "$work/a" \
  --endpoint 172.28.19.11:443
echo "=== [C] enroll b ==="
"$bin" coord enroll \
  --name b \
  --coord 172.28.19.10:443 \
  --coord-name coord \
  --bundle "$work/coord/trust-bundle.pem" \
  --token-file "$work/tokens/b" \
  --state "$work/b" \
  --endpoint 172.28.19.12:443

echo "=== [C] coordinator tickets ==="
proof_ticket_guard coord "$work/a" "$work/b"
first_expires=$(proof_ticket_expires "$work/a")
b_expires=$(proof_ticket_expires "$work/b")
if [[ "$b_expires" -lt "$first_expires" ]]; then
  first_expires=$b_expires
fi

echo "=== [C] start nodes ==="
compose up -d node-a node-b

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
wait_direct node-a b
wait_direct node-b a

echo "=== [C] ping every second ==="
ping_log="$work/ping.txt"
ping_start=$(date +%s)
compose exec -T node-a ping -n -D -O -i 1 -c "$ping_count" -W 1 100.64.0.2 >"$ping_log"
ping_end=$(date +%s)
cat "$ping_log"

sent=$(awk '/packets transmitted/ { print $1; exit }' "$ping_log")
received=$(awk '/packets transmitted/ { print $4; exit }' "$ping_log")
loss=$(awk -F',' '/packet loss/ { gsub(/[^0-9.]/, "", $3); print $3; exit }' "$ping_log")
consecutive=0
max_consecutive=0
while IFS= read -r line; do
  if [[ "$line" == *"no answer"* ]]; then
    consecutive=$((consecutive + 1))
    if [[ "$consecutive" -gt "$max_consecutive" ]]; then
      max_consecutive=$consecutive
    fi
  elif [[ "$line" == *"bytes from"* ]]; then
    consecutive=0
  fi
done <"$ping_log"

mapfile -t expiry_lines < <(compose logs node-a | awk '/The node renewed the SVID/ { print $NF }' | sed 's/\.$//')
end_expiry=$(compose exec -T node-a orblx status | read_all awk '/^svid_expiry / { print $2; exit }')

echo "ping_seconds ${ping_count}"
echo "sent ${sent}"
echo "received ${received}"
echo "loss_percent ${loss}"
echo "max_consecutive_loss ${max_consecutive}"
echo "svid_expiry_end ${end_expiry}"
echo "renew_lines ${#expiry_lines[@]}"

if [[ -z "$sent" || -z "$received" ]]; then
  echo "The ping summary is missing."
  exit 1
fi
if [[ "$max_consecutive" -ge 2 ]]; then
  echo "The packet loss window is over 2 seconds."
  exit 1
fi
if [[ "$received" -lt $((sent - 3)) ]]; then
  echo "The ping loss is too high."
  exit 1
fi
if [[ "${#expiry_lines[@]}" -lt 2 ]]; then
  echo "The node did not renew the SVID."
  exit 1
fi
# W25-27: count the ticket ends inside the ping window. The first ticket ends at the
# enroll ticket expires time plus the skew; each renewed ticket ends at most one
# ticket life later.
ticket_ends=0
ticket_end=$((first_expires + ticket_skew))
while [[ "$ticket_end" -le "$ping_end" ]]; do
  if [[ "$ticket_end" -ge "$ping_start" ]]; then
    ticket_ends=$((ticket_ends + 1))
  fi
  ticket_end=$((ticket_end + svid_ttl))
done
echo "ticket_ttl_s ${svid_ttl}"
echo "ticket_ends_crossed ${ticket_ends}"
if [[ "$ticket_ends" -lt "$min_ticket_ends" ]]; then
  echo "The ping crossed fewer than ${min_ticket_ends} ticket ends."
  exit 1
fi
echo "loss_window_ok true"
echo "proof_ok"

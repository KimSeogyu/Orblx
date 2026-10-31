#!/usr/bin/env bash
# W25-40: SSH logins across node SVID renewals, on one Linux host with containers.
#
# The coordinator issues node SVIDs with a short life (SSH_RENEW_TTL, default 120 s).
# The node renews at 2/3 of the life, and each renewal writes a new node key.
# Gate b: node a logs in to node b before the first renewal of b, after it, and after the
# second renewal. The client pins the key of the current cert.pem of node b each time.
# Gate c: one session that opens before the first renewal of b and ends after it.
# The script does not print private keys, tickets, or SVID proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
bin="$root/target/debug/orblx"
compose_file="$root/scripts/proof/compose.ssh-renew.yml"
work=$(mktemp -d)
env_file="$work/ssh-renew.env"
image_dir=""
ttl="${SSH_RENEW_TTL:-120}"
# Gate c: the session runs this long. It opens before the first renewal of b.
session_secs="${SSH_RENEW_SESSION_SECS:-75}"

compose() {
  docker compose --env-file "$env_file" --progress quiet -f "$compose_file" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && -f "$env_file" ]]; then
    echo "---- docker logs ----"
    compose logs || true
  fi
  if [[ -f "$env_file" ]]; then
    compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "$image_dir" ]]; then
    rm -rf "$image_dir"
  fi
  rm -rf "$work"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ssh-renew"
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-ssh-renew" || exit 1

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  iptables-legacy -P FORWARD ACCEPT
}

echo "=== [REAL] one Linux host ==="
uname -s
uname -m
rustc --version

echo "=== [C] build image ==="
cargo build -p orblx-cli --bin orblx --locked
# shellcheck source=stage-image.sh
source "$root/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$root" "$bin")"
docker build --no-cache -q -t orblx-ssh-renew:local "$image_dir" >/dev/null
rm -rf "$image_dir"
image_dir=""
open_legacy_forward

mkdir -p "$work/coord" "$work/a" "$work/b" "$work/tokens"
cp "$root/scripts/proof/ssh-renew.hujson" "$work/coord/policy.hujson"
cp "$root/scripts/proof/ssh-renew.hujson" "$work/b/policy.hujson"

write_netmap() {
  local path=$1 name=$2 ip=$3 peer=$4 peer_ip=$5 peer_underlay=$6
  cat >"$path" <<NETMAP
{
  "version": 1,
  "self": {"name": "${name}", "overlay_ip": "${ip}"},
  "peers": [{
    "name": "${peer}",
    "overlay_ip": "${peer_ip}",
    "svid": "spiffe://orblx.local/node/${peer}",
    "endpoints": ["${peer_underlay}:443"],
    "routes": ["${peer_ip}/32"]
  }]
}
NETMAP
}
write_netmap "$work/netmap-a.json" a 100.64.0.1 b 100.64.0.2 172.28.19.12
write_netmap "$work/netmap-b.json" b 100.64.0.2 a 100.64.0.1 172.28.19.11

cat >"$env_file" <<ENV
SSH_RENEW_COORD_STATE=$work/coord
SSH_RENEW_STATE_A=$work/a
SSH_RENEW_STATE_B=$work/b
SSH_RENEW_NETMAP_A=$work/netmap-a.json
SSH_RENEW_NETMAP_B=$work/netmap-b.json
SSH_RENEW_TTL=$ttl
ENV

echo "=== [C] start coordinator (node SVID life ${ttl} s) ==="
compose up -d coord
for _ in $(seq 1 90); do
  [[ -s "$work/coord/trust-bundle.pem" ]] && break
  sleep 1
done
[[ -s "$work/coord/trust-bundle.pem" ]]

for name in a b; do
  compose exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 \
    --out "/var/lib/orblx/tokens-${name}" >/dev/null
  cp "$work/coord/tokens-${name}" "$work/tokens/${name}"
  chmod 600 "$work/tokens/${name}"
done
enroll() {
  local name=$1 underlay=$2
  echo "=== [C] enroll ${name} ==="
  "$bin" coord enroll --name "$name" --coord 172.28.19.10:443 --coord-name coord \
    --bundle "$work/coord/trust-bundle.pem" --token-file "$work/tokens/${name}" \
    --state "$work/${name}" --endpoint "${underlay}:443" >/dev/null
}
enroll a 172.28.19.11
enroll b 172.28.19.12

echo "=== [C] start nodes ==="
compose up -d node-a node-b
wait_log() {
  local node=$1 pattern=$2 limit=$3
  for _ in $(seq 1 "$limit"); do
    if compose logs "$node" 2>/dev/null | read_all grep -q -- "$pattern"; then
      return 0
    fi
    sleep 1
  done
  return 1
}
wait_log node-b 'ssh_listen ' 60 || { echo "Node b did not listen for SSH." >&2; exit 1; }
for _ in $(seq 1 60); do
  compose exec -T node-a orblx status 2>/dev/null | read_all grep -q "peer b overlay_ip .* path direct " && break
  sleep 1
done

renewals_b() {
  compose logs node-b 2>/dev/null | read_all grep -c 'The node renewed the SVID' || true
}
# The SHA-256 of the public key of the current node b SVID. No private key is read.
key_b() {
  openssl x509 -in "$work/b/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -c1-16
}
# Copy the current node a SVID (no ticket) and the current node b cert into node a.
stage_login() {
  compose exec -T node-a sh -c 'rm -rf /tmp/id && mkdir -m 700 /tmp/id &&
    cp /var/lib/orblx/cert.pem /var/lib/orblx/key.pem /var/lib/orblx/bundle.pem /tmp/id/'
  compose exec -T node-b cat /var/lib/orblx/cert.pem | compose exec -T node-a sh -c "cat > /tmp/${1}.pem"
}
ssh_b() {
  local peer=$1 command=$2
  compose exec -T node-a orblx ssh alice@b --identity /tmp/id --netmap /etc/orblx/netmap.json \
    --peer-cert "/tmp/${peer}.pem" --command "$command"
}
login() {
  local label=$1 out
  stage_login "peer-${label}"
  out="$(ssh_b "peer-${label}" 'printf '\''%s\n'\'' "$ORBLX_SSH_USER"' 2>&1 | tr -d '\r')" || true
  echo "login ${label} renewals_b $(renewals_b) host_key $(key_b) out ${out}"
  [[ "$out" == "alice" ]]
}
wait_renewal() {
  local want=$1 limit=$((ttl * 2))
  for _ in $(seq 1 "$limit"); do
    (( $(renewals_b) >= want )) && return 0
    sleep 1
  done
  echo "renewal_not_active node b renewals $(renewals_b) want ${want} after ${limit} s" >&2
  return 1
}

echo "=== [C] gate b: login before the first renewal ==="
(( $(renewals_b) == 0 )) || { echo "Node b renewed before the first login." >&2; exit 1; }
key0="$(key_b)"
login before

echo "=== [C] gate c: a session opens before the first renewal ==="
stage_login peer-session
session_out="$work/session.out"
session_start_renewals="$(renewals_b)"
( ssh_b peer-session "sleep ${session_secs}; printf '%s\n' survived" >"$session_out" 2>&1
  echo "exit $?" >>"$session_out" ) &
session_pid=$!

echo "=== [C] gate b: login after renewal 1 ==="
wait_renewal 1
key1="$(key_b)"
echo "host_key_rotated_1 $([[ "$key1" != "$key0" ]] && echo yes || echo no)"
[[ "$key1" != "$key0" ]]
login after-1
if ssh_b peer-before 'true' >/dev/null 2>&1; then
  echo "The old node b key still opened a session." >&2
  exit 1
fi
echo "denied old_host_key_1"

wait "$session_pid" || true
session_end_renewals="$(renewals_b)"
echo "session_renewals_b start ${session_start_renewals} end ${session_end_renewals}"
sed 's/^/  session: /' "$session_out" | tr -d '\r'
(( session_end_renewals > session_start_renewals )) || {
  echo "gate_c inconclusive: the session did not span a renewal" >&2
  exit 1
}
if grep -qx 'survived' <(tr -d '\r' <"$session_out") && grep -qx 'exit 0' "$session_out"; then
  echo "gate_c survived"
elif grep -qx 'exit 0' "$session_out"; then
  echo "gate_c closed_cleanly_without_output"
else
  echo "gate_c closed $(tail -1 "$session_out")"
fi

echo "=== [C] gate b: login after renewal 2 ==="
wait_renewal 2
key2="$(key_b)"
echo "host_key_rotated_2 $([[ "$key2" != "$key1" ]] && echo yes || echo no)"
[[ "$key2" != "$key1" ]]
login after-2
echo "proof_ok ssh-renew"

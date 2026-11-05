#!/usr/bin/env bash
# W25-40: SSH logins across node SVID renewals, on one Linux host with containers.
#
# The coordinator issues node SVIDs with a short life (SSH_RENEW_TTL, default 180 s).
# W25-45: the coordinator refuses a node SVID life under 180 s.
# The node renews at 2/3 of the life. That gap is one renewal interval.
# Each renewal writes a new node key.
# Gate b: node a logs in to node b before the first renewal of b, after it, and after the
# second renewal. The login after the second renewal ends within one renewal interval.
# The client pins the key of the current cert.pem of node b each time.
# Gate c: one PTY shell opens before the first renewal of b and ends after it.
# An exec command stops at 30 s, so gate c does not use --command.
# The shell prints keepalive every 10 s so the client receives a packet.
# The script does not print private keys, tickets, or SVID proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
bin="$root/target/release/orblx"
compose_file="$root/scripts/proof/compose.ssh-renew.yml"
work=$(mktemp -d)
env_file="$work/ssh-renew.env"
image_dir=""
ttl="${SSH_RENEW_TTL:-180}"
# One renewal interval. The node renews at 2/3 of the SVID life.
renew_interval=$((ttl * 2 / 3))
# Gate c: the shell stays open for one renewal interval.
# At the TTL floor of 180 s the shell runs for 120 s, so it can span renewal 1.
# The shell prints keepalive every 10 s. The client closes a quiet session after 30 s.
session_secs="${SSH_RENEW_SESSION_SECS:-$renew_interval}"
renewal1_at=""
renewal_2_seen_at=""

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
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ssh-renew" "orblx-ssh-renew"
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
rustc -V
echo "cargo profile=release"

echo "=== [C] build image ==="
cargo build --release -p orblx-cli --bin orblx --locked
# shellcheck source=stage-image.sh
source "$root/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$root" "$bin")"
docker build --network host --no-cache -q -t orblx-ssh-renew:local "$image_dir" >/dev/null
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
# Gate c uses a PTY shell. The exec path stops after 30 s.
# The remote shell prints keepalive every 10 s, then prints SURVIVED.
# The typed line shows SURV""IVED. The output line shows SURVIVED and the unix time.
ssh_shell() {
  local peer=$1 keep_step=10 keep_count
  # N sleeps of 10 s cover session_secs. Each echo sends a packet before the 30 s close.
  keep_count=$(( (session_secs + keep_step - 1) / keep_step ))
  printf 'i=0; while [ "$i" -lt %s ]; do echo keepalive $(date +%%s); sleep %s; i=$((i+1)); done; echo SURV""IVED at $(date +%%s); exit\n' \
    "$keep_count" "$keep_step" \
    | compose exec -T node-a orblx ssh alice@b --shell --identity /tmp/id \
      --netmap /etc/orblx/netmap.json --peer-cert "/tmp/${peer}.pem"
}
# Print the unix time from the SURVIVED output line.
# Skip a keepalive line and a line that still has the typed SURV""IVED text.
shell_end_at() {
  local line end=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    [[ "$line" == *'SURV""IVED'* ]] && continue
    [[ "$line" == *keepalive* ]] && continue
    if [[ "$line" =~ SURVIVED[[:space:]]at[[:space:]]([0-9]+) ]]; then
      end="${BASH_REMATCH[1]}"
    fi
  done <"$1"
  printf '%s\n' "$end"
}
login() {
  local label=$1 out
  stage_login "peer-${label}"
  out="$(ssh_b "peer-${label}" 'printf '\''%s\n'\'' "$ORBLX_SSH_USER"' 2>&1 | tr -d '\r')" || true
  echo "login ${label} renewals_b $(renewals_b) host_key $(key_b) out ${out}"
  [[ "$out" == "alice" ]]
}
wait_renewal() {
  local want=$1 limit=$((ttl * 2)) seen count
  for _ in $(seq 1 "$limit"); do
    count="$(renewals_b)"
    if (( count >= want )); then
      seen="$(date +%s)"
      if (( want == 1 )); then
        renewal1_at="$seen"
        echo "renewal1_at ${renewal1_at} renewals_b ${count}"
      elif (( want == 2 )); then
        renewal_2_seen_at="$seen"
        echo "renewal_2_seen_at ${renewal_2_seen_at} renewals_b ${count}"
      fi
      return 0
    fi
    sleep 1
  done
  echo "renewal_not_active node b renewals $(renewals_b) want ${want} after ${limit} s" >&2
  return 1
}

echo "=== [C] gate b: login before the first renewal ==="
(( $(renewals_b) == 0 )) || { echo "Node b renewed before the first login." >&2; exit 1; }
key0="$(key_b)"
login before

echo "=== [C] gate c: a shell opens before the first renewal ==="
stage_login peer-session
session_out="$work/session.out"
session_start_renewals="$(renewals_b)"
(
  set +e
  ssh_shell peer-session >"$session_out" 2>&1
  echo "exit $?" >>"$session_out"
) &
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
shell_end="$(shell_end_at "$session_out")"
echo "session_renewals_b start ${session_start_renewals} end ${session_end_renewals}"
echo "shell_end ${shell_end:-none} renewal1_at ${renewal1_at}"
sed 's/^/  session: /' "$session_out" | tr -d '\r'
(( session_end_renewals > session_start_renewals )) || {
  echo "gate_c inconclusive: the session did not span a renewal" >&2
  exit 1
}
grep -qx 'exit 0' "$session_out" || {
  echo "gate_c shell did not exit 0." >&2
  exit 1
}
[[ -n "$shell_end" ]] || {
  echo "gate_c did not show SURVIVED." >&2
  exit 1
}
(( shell_end > renewal1_at )) || {
  echo "gate_c shell_end ${shell_end} is not after renewal 1 at ${renewal1_at}." >&2
  exit 1
}
echo "gate_c survived"

echo "=== [C] gate b: login after renewal 2 ==="
wait_renewal 2
key2="$(key_b)"
echo "host_key_rotated_2 $([[ "$key2" != "$key1" ]] && echo yes || echo no)"
[[ "$key2" != "$key1" ]]
login after-2
after_2_at="$(date +%s)"
echo "after_2_login_at ${after_2_at} renewal_2_seen_at ${renewal_2_seen_at} interval ${renew_interval} renewals_b $(renewals_b)"
if (( after_2_at > renewal_2_seen_at + renew_interval )); then
  echo "gate_b login after renewal 2 is later than one renewal interval." >&2
  exit 1
fi
echo "gate_b after-2 within one renewal interval"
echo "proof_ok ssh-renew"

#!/usr/bin/env bash
# SSH proof for three node containers on one Linux host.
# The containers stand in for other hosts.
# The script does not print private keys, tickets, or SVID proofs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ssh.yml"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/ssh.env"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose --env-file "$ENV_FILE" --progress quiet -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    dc logs || true
  fi
  dc down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

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

wait_direct() {
  local node=$1
  local peer=$2
  local attempt
  for attempt in $(seq 1 40); do
    if dc exec -T "$node" orblx status 2>/dev/null | grep -q "peer ${peer} overlay_ip .* path direct "; then
      return 0
    fi
    sleep 1
  done
  echo "The node ${node} did not reach ${peer}." >&2
  return 1
}

wait_listen() {
  local node=$1
  local attempt
  for attempt in $(seq 1 40); do
    if dc logs "$node" 2>/dev/null | grep -q 'ssh_listen '; then
      return 0
    fi
    sleep 1
  done
  echo "The node ${node} did not listen for SSH." >&2
  return 1
}

ssh_from() {
  local node=$1
  local target=$2
  local identity=$3
  local peer=$4
  dc exec -T "$node" orblx ssh "$target" \
    --identity "$identity" \
    --netmap /etc/orblx/netmap.json \
    --peer-cert "$peer" \
    --command 'printf '\''%s\n'\'' "$ORBLX_SSH_USER"'
}

expect_deny() {
  local label=$1
  shift
  if ssh_from "$@"; then
    echo "The session ${label} was accepted." >&2
    return 1
  fi
  echo "denied ${label}"
}

echo "=== [REAL] one Linux host ==="
uname -s
uname -m

echo "=== [C] build image ==="
cargo build -p orblx-cli --bin orblx
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
IMAGE_DIR="$(stage_proof_image "$ROOT" "$ROOT/target/debug/orblx")"
as_root docker build -t orblx-ssh:local "$IMAGE_DIR"
rm -rf "$IMAGE_DIR"

echo "=== [C] issue SVIDs ==="
"$ROOT/target/debug/orblx" node-issue \
  --out "$WORK" \
  --node a=100.64.0.1 \
  --node b=100.64.0.2 \
  --node c=100.64.0.3 \
  --user alice \
  --user mallory \
  --agent helper \
  --agent-parent alice \
  --agent-host 100.64.0.2 \
  --agent-user alice

for name in a b c; do
  cp "$ROOT/scripts/proof/ssh.hujson" "$WORK/$name/policy.hujson"
done
mkdir -p "$WORK/peers"
cp "$WORK/b/cert.pem" "$WORK/peers/b.pem"
cp "$WORK/c/cert.pem" "$WORK/peers/c.pem"

write_netmap "$WORK/netmap-a.json" a 100.64.0.1 b 100.64.0.2 172.28.19.12 c 100.64.0.3 172.28.19.13
write_netmap "$WORK/netmap-b.json" b 100.64.0.2 a 100.64.0.1 172.28.19.11 c 100.64.0.3 172.28.19.13
write_netmap "$WORK/netmap-c.json" c 100.64.0.3 a 100.64.0.1 172.28.19.11 b 100.64.0.2 172.28.19.12

cat >"$ENV_FILE" <<EOF
SSH_STATE_A=$WORK/a
SSH_STATE_B=$WORK/b
SSH_STATE_C=$WORK/c
SSH_NETMAP_A=$WORK/netmap-a.json
SSH_NETMAP_B=$WORK/netmap-b.json
SSH_NETMAP_C=$WORK/netmap-c.json
SSH_USERS=$WORK/users
SSH_AGENTS=$WORK/agents
SSH_PEERS=$WORK/peers
EOF

open_legacy_forward
echo "=== [C] start nodes ==="
dc up -d --remove-orphans
wait_direct node-a b
wait_direct node-a c
wait_direct node-b a
wait_listen node-b
wait_listen node-c

echo "=== [C] alice to node b ==="
alice_out="$(ssh_from node-a alice@b /var/lib/orblx-id/users/alice /var/lib/orblx-peers/b.pem)"
printf '%s\n' "$alice_out"
[[ "$alice_out" == "alice" ]]

echo "=== [C] admin revoke of node b through deny.json ==="
stamp="$(date +%s)"
cat >"$WORK/b/deny.json" <<EOF
{"version":1,"generated_at":${stamp},"revoked_uris":["spiffe://orblx.local/node/b"],"revoked_ticket_nonces":[]}
EOF
start_sec="$(date +%s)"
expect_deny node-b node-a alice@b /var/lib/orblx-id/users/alice /var/lib/orblx-peers/b.pem
end_sec="$(date +%s)"
elapsed="$((end_sec - start_sec))"
echo "node_revoke_seconds ${elapsed}"
[[ "$elapsed" -lt 60 ]]
stamp="$(date +%s)"
cat >"$WORK/b/deny.json" <<EOF
{"version":2,"generated_at":${stamp},"revoked_uris":[],"revoked_ticket_nonces":[]}
EOF
alice_out="$(ssh_from node-a alice@b /var/lib/orblx-id/users/alice /var/lib/orblx-peers/b.pem)"
printf '%s\n' "$alice_out"
[[ "$alice_out" == "alice" ]]

echo "=== [C] mallory denied ==="
expect_deny mallory node-a mallory@b /var/lib/orblx-id/users/mallory /var/lib/orblx-peers/b.pem

echo "=== [C] alice to node c denied ==="
expect_deny host node-a alice@c /var/lib/orblx-id/users/alice /var/lib/orblx-peers/c.pem

echo "=== [C] agent one shot ==="
agent_out="$(ssh_from node-a alice@b /var/lib/orblx-id/agents/helper /var/lib/orblx-peers/b.pem)"
printf '%s\n' "$agent_out"
[[ "$agent_out" == "alice" ]]
expect_deny replay node-a alice@b /var/lib/orblx-id/agents/helper /var/lib/orblx-peers/b.pem

echo "=== [C] revoke alice ==="
stamp="$(date +%s)"
cat >"$WORK/b/deny.json" <<EOF
{"version":3,"generated_at":${stamp},"revoked_uris":["spiffe://orblx.local/user/alice"],"revoked_ticket_nonces":[]}
EOF
start_sec="$(date +%s)"
expect_deny revoked node-a alice@b /var/lib/orblx-id/users/alice /var/lib/orblx-peers/b.pem
end_sec="$(date +%s)"
elapsed="$((end_sec - start_sec))"
echo "revoke_seconds ${elapsed}"
[[ "$elapsed" -lt 60 ]]

echo "=== [C] audit chain on node b ==="
b_audit="$(dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl)"
printf '%s\n' "$b_audit"
echo "$b_audit" | grep -q '^ok$'
echo "$b_audit" | grep -Eq '^start [1-9]'
echo "$b_audit" | grep -Eq '^end [1-9]'
echo "$b_audit" | grep -Eq '^deny [1-9]'
echo "=== [C] audit chain on node c ==="
c_audit="$(dc exec -T node-c orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl)"
printf '%s\n' "$c_audit"
echo "$c_audit" | grep -Eq '^deny [1-9]'

echo "proof_ok"

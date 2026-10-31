#!/usr/bin/env bash
# SSH proof for three node containers on one Linux host.
# The containers stand in for other hosts.
# The script does not print private keys, tickets, or SVID proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

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
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ssh"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-ssh" || exit 1

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
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
    if dc exec -T "$node" orblx status 2>/dev/null | read_all grep -q "peer ${peer} overlay_ip .* path direct "; then
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
    if dc logs "$node" 2>/dev/null | read_all grep -q 'ssh_listen '; then
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
SSH_REC_C=$WORK/c-rec
EOF
mkdir -p "$WORK/c-rec"

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

echo "=== [C] recorded session on node b ==="
rec_out="$(ssh_from node-a rec@b /var/lib/orblx-id/users/alice /var/lib/orblx-peers/b.pem)"
printf '%s\n' "$rec_out"
[[ "$rec_out" == "rec" ]]
shopt -s nullglob
rec_files=("$WORK"/b/recordings/*.cast)
shopt -u nullglob
echo "recording_files ${#rec_files[@]}"
[[ "${#rec_files[@]}" -eq 1 ]]
rec_file="${rec_files[0]}"
echo "recording_file recordings/$(basename "$rec_file")"
echo "---- recording ----"
cat "$rec_file"
echo "---- end recording ----"
rec_sha="$(sha256sum "$rec_file" | cut -d' ' -f1)"
echo "recording_sha256 ${rec_sha}"
grep -q "\"kind\":\"record\".*\"recording_sha256\":\"${rec_sha}\"" "$WORK/b/ssh-audit.jsonl"
echo "chain_has_recording_sha256 yes"
b_audit="$(dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl)"
printf '%s\n' "$b_audit"
echo "$b_audit" | read_all grep -qx 'record 1'

echo "=== [C] one changed byte in the recording fails verify ==="
cp "$rec_file" "$WORK/recording.orig"
printf 'X' | dd of="$rec_file" bs=1 seek=1 count=1 conv=notrunc status=none
if bad="$(dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl 2>&1)"; then
  echo "The changed recording passed verify." >&2
  exit 1
fi
printf 'verify_failed %s\n' "$bad"
echo "$bad" | read_all grep -q 'recording check failed'
cp "$WORK/recording.orig" "$rec_file"
dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl | read_all grep -qx ok
echo "verify_after_restore ok"

echo "=== [C] read-only recording directory on node c fails closed ==="
if dc exec -T node-c sh -c 'touch /var/lib/orblx/recordings/probe' 2>/dev/null; then
  echo "The recording directory on node c is writable." >&2
  exit 1
fi
echo "recording_dir_read_only yes"
expect_deny recording node-a rec@c /var/lib/orblx-id/users/alice /var/lib/orblx-peers/c.pem
c_rec_deny="$(grep -c '"kind":"deny".*"reason":"recording"' "$WORK/c/ssh-audit.jsonl" || true)"
echo "deny_recording ${c_rec_deny}"
[[ "$c_rec_deny" -ge 1 ]]

echo "=== [C] rule without recording on node b works as before ==="
alice_out="$(ssh_from node-a alice@b /var/lib/orblx-id/users/alice /var/lib/orblx-peers/b.pem)"
printf '%s\n' "$alice_out"
[[ "$alice_out" == "alice" ]]
shopt -s nullglob
rec_files=("$WORK"/b/recordings/*.cast)
shopt -u nullglob
echo "recording_files ${#rec_files[@]}"
[[ "${#rec_files[@]}" -eq 1 ]]

echo "=== [C] interactive PTY shell on node b is recorded ==="
# The input goes in with pauses, as a person types. The shell does not
# echo the line after `stty -echo`, so the recording keeps only a marker.
pty_out="$(
  {
    sleep 2
    printf 'echo pty-$((6*7))\n'
    sleep 2
    printf 'stty -echo; read -r s; stty echo; echo got-${#s}\n'
    sleep 2
    printf 'hidden-w23\n'
    sleep 2
    printf 'exit\n'
    sleep 2
  } | dc exec -T -e TERM=xterm-256color node-a orblx ssh rec@b \
    --identity /var/lib/orblx-id/users/alice \
    --netmap /etc/orblx/netmap.json \
    --peer-cert /var/lib/orblx-peers/b.pem \
    --shell
)"
printf '%s\n' "$pty_out" | tr -d '\r' | grep -E '^(pty-42|got-10)$'
printf '%s\n' "$pty_out" | tr -d '\r' | read_all grep -qx 'pty-42'
printf '%s\n' "$pty_out" | tr -d '\r' | read_all grep -qx 'got-10'
shopt -s nullglob
rec_files=("$WORK"/b/recordings/*.cast)
shopt -u nullglob
echo "recording_files ${#rec_files[@]}"
[[ "${#rec_files[@]}" -eq 2 ]]
pty_file=""
for candidate in "${rec_files[@]}"; do
  [[ "$candidate" == "$rec_file" ]] || pty_file="$candidate"
done
echo "pty_recording_file recordings/$(basename "$pty_file")"
echo "---- pty recording ----"
cat "$pty_file"
echo "---- end pty recording ----"
if grep -q 'hidden-w23' "$pty_file"; then
  echo "The hidden input is in the recording." >&2
  exit 1
fi
echo "hidden_input_not_recorded yes"
python3 - "$pty_file" <<'PY'
import json
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
header = json.loads(lines[0])
events = [json.loads(line) for line in lines[1:]]
times = [event[0] for event in events]
assert times == sorted(times), "The event times are not in order."
codes = {event[1] for event in events}
assert codes <= {"i", "o", "r", "m"}, codes
first_input = next(n for n, e in enumerate(events) if e[1] == "i" and "pty-" in e[2])
first_output = next(n for n, e in enumerate(events) if e[1] == "o" and "pty-42" in e[2])
assert first_input < first_output, "The output is before its input."
assert any(e[1] == "m" for e in events), "The hidden input has no marker."
print("pty_header width %d height %d term %s" % (
    header["width"], header["height"], header.get("env", {}).get("TERM", "-")))
print("pty_events %d input %d output %d marker %d" % (
    len(events),
    sum(1 for e in events if e[1] == "i"),
    sum(1 for e in events if e[1] == "o"),
    sum(1 for e in events if e[1] == "m")))
print("pty_time_order ok input_before_output ok")
PY
pty_sha="$(sha256sum "$pty_file" | cut -d' ' -f1)"
echo "pty_recording_sha256 ${pty_sha}"
grep -q "\"kind\":\"record\".*\"recording_sha256\":\"${pty_sha}\"" "$WORK/b/ssh-audit.jsonl"
echo "chain_has_pty_recording_sha256 yes"
b_audit="$(dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl)"
printf '%s\n' "$b_audit"
echo "$b_audit" | read_all grep -qx 'record 2'

echo "=== [C] one changed byte in the PTY recording fails verify ==="
cp "$pty_file" "$WORK/pty.orig"
size="$(stat -c %s "$pty_file")"
printf 'X' | dd of="$pty_file" bs=1 seek="$((size - 3))" count=1 conv=notrunc status=none
if bad="$(dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl 2>&1)"; then
  echo "The changed PTY recording passed verify." >&2
  exit 1
fi
printf 'verify_failed %s\n' "$bad"
echo "$bad" | read_all grep -q 'recording check failed'
cp "$WORK/pty.orig" "$pty_file"
dc exec -T node-b orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl | read_all grep -qx ok
echo "verify_after_restore ok"

echo "=== [C] PTY shell with a read-only recording directory on node c fails closed ==="
if c_out="$(printf 'echo leaked\nexit\n' | dc exec -T node-a orblx ssh rec@c \
  --identity /var/lib/orblx-id/users/alice \
  --netmap /etc/orblx/netmap.json \
  --peer-cert /var/lib/orblx-peers/c.pem \
  --shell 2>&1)"; then
  echo "The PTY shell on node c was accepted." >&2
  exit 1
fi
printf '%s\n' "$c_out"
echo "$c_out" | read_all grep -q 'The SSH shell was refused.'
if echo "$c_out" | read_all grep -q leaked; then
  echo "The refused shell ran input." >&2
  exit 1
fi
echo "denied pty_recording"
c_rec_deny="$(grep -c '"kind":"deny".*"reason":"recording"' "$WORK/c/ssh-audit.jsonl" || true)"
echo "deny_recording ${c_rec_deny}"
[[ "$c_rec_deny" -ge 2 ]]

echo "=== [C] PTY shell without recording on node b ==="
plain_out="$(
  {
    sleep 2
    printf 'echo plain-$ORBLX_SSH_USER\n'
    sleep 2
    printf 'exit\n'
    sleep 2
  } | dc exec -T node-a orblx ssh alice@b \
    --identity /var/lib/orblx-id/users/alice \
    --netmap /etc/orblx/netmap.json \
    --peer-cert /var/lib/orblx-peers/b.pem \
    --shell
)"
printf '%s\n' "$plain_out" | tr -d '\r' | grep -x 'plain-alice'
shopt -s nullglob
rec_files=("$WORK"/b/recordings/*.cast)
shopt -u nullglob
echo "recording_files ${#rec_files[@]}"
[[ "${#rec_files[@]}" -eq 2 ]]

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
echo "$b_audit" | read_all grep -q '^ok$'
echo "$b_audit" | read_all grep -Eq '^start [1-9]'
echo "$b_audit" | read_all grep -Eq '^end [1-9]'
echo "$b_audit" | read_all grep -Eq '^deny [1-9]'
echo "=== [C] audit chain on node c ==="
c_audit="$(dc exec -T node-c orblx audit verify --file /var/lib/orblx/ssh-audit.jsonl)"
printf '%s\n' "$c_audit"
echo "$c_audit" | read_all grep -Eq '^deny [1-9]'

echo "proof_ok"

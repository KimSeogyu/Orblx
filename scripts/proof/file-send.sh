#!/usr/bin/env bash
# File send proof (W23-3).
# Nodes a, b, and c enroll. The ACL lets a send files to b on TCP 4243.
# The ACL lets c reach b only on TCP 8080.
# Check 1: a sends a random file to b. The SHA-256 on b is the same as on a.
# Check 2: a sends the same name again. The receiver does not replace the file.
# Check 3: c sends a file to b over the overlay. The signed grants for b do not allow c on
#          TCP 4243. Since W24, the datapath on b drops the packets, so the receiver
#          does not see the connection. The packet audit on b has a record for c.
#          The inbox has no new file and no part file.
# Check 4: b sends a file to its own receiver (not through the datapath). The grants do not
#          allow b. The receiver refuses it. The inbox has no new file and no part file.
# Check 5: the receiver audit chain has sender, size, and SHA-256 for each file, and verifies.
# The script deletes the orblx-w23a-file-send volumes at the start.
# The script does not print enroll tokens or private keys.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.file-send.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
STATE=/var/lib/orblx
INBOX=/var/lib/orblx/inbox
PORT=4243
NODES=(a b c)
SIZE_BYTES=$(( 8 * 1024 * 1024 ))

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "file-send"

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

resolve_name() {
  local name="$1"
  dc run --rm --no-deps --entrypoint getent a ahostsv4 "$name" \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir
  cargo build -p orblx-cli --bin orblx --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$TARGET_DIR/debug/orblx")"
  docker build -q -t orblx-w23a-file:w23 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat "$STATE/trust-bundle.pem" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

wait_log() {
  local service="$1"
  local needle="$2"
  local i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | read_all grep -q "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  dc logs "$service" 2>&1 | tail -20 >&2
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

wait_path() {
  local from="$1"
  local to="$2"
  local i
  for i in $(seq 1 60); do
    if dc exec -T "$from" orblx status --state-dir "$STATE" 2>/dev/null \
      | read_all grep -q "^peer ${to} .* path direct "; then
      echo "path ${from} ${to} direct"
      return 0
    fi
    sleep 1
  done
  echo "The path from ${from} to ${to} did not come up." >&2
  dc exec -T "$from" orblx status --state-dir "$STATE" >&2 || true
  return 1
}

http_get() {
  local from="$1"
  local ip="$2"
  dc exec -T "$from" python3 -c "
import socket
try:
    s = socket.create_connection(('${ip}', 8080), 4)
    s.sendall(b'GET / HTTP/1.0\r\n\r\n')
    print(s.recv(12).decode(errors='replace').strip())
except OSError as err:
    print('fail', type(err).__name__)
"
}

# List the inbox on b: every entry, with dot files.
inbox_list() {
  dc exec -T b sh -c "ls -la $INBOX | tail -n +2"
}

inbox_names() {
  dc exec -T b sh -c "ls -A $INBOX | sort | tr '\n' ' '"
}

no_part_files() {
  local parts
  parts="$(dc exec -T b sh -c "find $INBOX -mindepth 1 -name '.*' | wc -l")"
  echo "inbox_dot_files ${parts}"
  if [[ "$parts" -ne 0 ]]; then
    echo "The inbox has a part file or a temp file." >&2
    exit 1
  fi
}

expect_inbox() {
  local want="$1"
  local got
  got="$(inbox_names)"
  echo "inbox_names ${got}"
  if [[ "$got" != "$want" ]]; then
    echo "The inbox is not: ${want}" >&2
    exit 1
  fi
}

cp "$ROOT/scripts/proof/file-send.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

for name in "${NODES[@]}"; do
  dc exec -T coord orblx coord token create \
    --state "$STATE" \
    --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done

coord_ip="$(resolve_name coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

declare -A ips
for name in "${NODES[@]}"; do
  echo "=== [C] enroll ${name} ==="
  out="$(run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" \
    --endpoint "${name}:443")"
  printf '%s\n' "$out"
  ips[$name]="$(printf '%s\n' "$out" | read_all awk '/^overlay_ip /{print $2; exit}')"
  if [[ -z "${ips[$name]}" ]]; then
    echo "The node ${name} has no overlay address." >&2
    exit 1
  fi
done

echo "=== [C] fetch netmaps ==="
for name in "${NODES[@]}"; do
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE" >/dev/null
  echo "netmap ${name} written"
done

echo "=== [C] start all nodes ==="
dc up -d "${NODES[@]}"
for name in "${NODES[@]}"; do
  wait_log "$name" 'The TUN device'
done
wait_path a b
wait_path c b

echo "=== [C] node b: HTTP on 8080 and the file receiver on ${PORT} ==="
dc exec -d b python3 -m http.server 8080 --bind "${ips[b]}"
dc exec -d b sh -c "orblx file receive --dir $INBOX --state $STATE >/tmp/file-receive.log 2>&1"
for i in $(seq 1 30); do
  if dc exec -T b grep -q '^file_receive listen' /tmp/file-receive.log 2>/dev/null; then
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    echo "The file receiver did not start." >&2
    dc exec -T b cat /tmp/file-receive.log >&2 || true
    exit 1
  fi
  sleep 1
done
dc exec -T b cat /tmp/file-receive.log
sleep 1

echo "=== [C] the datapath lets c reach b on 8080 ==="
got="$(http_get c "${ips[b]}")"
echo "http c b:8080 ${got}"
[[ "$got" == "HTTP/1.0 200" ]]

echo "=== [C] check 1: a sends ${SIZE_BYTES} random bytes to b ==="
dc exec -T a sh -c "head -c ${SIZE_BYTES} /dev/urandom >/tmp/payload.bin"
sender_sha="$(dc exec -T a sha256sum /tmp/payload.bin | awk '{print $1}')"
echo "sender_sha256 ${sender_sha}"
send_out="$(dc exec -T a orblx file send /tmp/payload.bin --to b --state "$STATE")"
printf '%s\n' "$send_out"
grep -q "^file_sent from spiffe://orblx.local/node/a to spiffe://orblx.local/node/b name payload.bin size ${SIZE_BYTES} sha256 ${sender_sha}$" <<<"$send_out"
receiver_sha="$(dc exec -T b sha256sum "$INBOX/payload.bin" | awk '{print $1}')"
receiver_size="$(dc exec -T b stat -c '%s' "$INBOX/payload.bin")"
echo "receiver_sha256 ${receiver_sha}"
echo "receiver_size ${receiver_size}"
if [[ "$receiver_sha" != "$sender_sha" || "$receiver_size" -ne "$SIZE_BYTES" ]]; then
  echo "The receiver file is not the sender file." >&2
  exit 1
fi
echo "sha256_match yes"
expect_inbox "payload.bin "
no_part_files

echo "=== [C] check 2: a sends the same name again. The receiver keeps the first file ==="
dc exec -T a sh -c "head -c 4096 /dev/urandom >/tmp/payload.bin"
if dc exec -T a orblx file send /tmp/payload.bin --to b --state "$STATE" >"$WORK/again.txt" 2>&1; then
  echo "The receiver replaced a file." >&2
  exit 1
fi
cat "$WORK/again.txt"
grep -q 'reply deny exists' "$WORK/again.txt"
again_sha="$(dc exec -T b sha256sum "$INBOX/payload.bin" | awk '{print $1}')"
echo "receiver_sha256_after_again ${again_sha}"
[[ "$again_sha" == "$sender_sha" ]]
expect_inbox "payload.bin "
no_part_files

echo "=== [C] check 3: c sends to b. The ACL does not allow c on ${PORT} ==="
dc exec -T c sh -c "head -c 65536 /dev/urandom >/tmp/from-c.bin"
if dc exec -T c orblx file send /tmp/from-c.bin --to b --state "$STATE" --timeout 5 >"$WORK/from-c.txt" 2>&1; then
  echo "Node c sent a file." >&2
  exit 1
fi
cat "$WORK/from-c.txt"
if grep -q 'reply deny acl' "$WORK/from-c.txt"; then
  echo "The receiver saw the connection from c. The datapath must drop it." >&2
  exit 1
fi
dc exec -T b cat "$STATE/packet-audit.jsonl" >"$WORK/packet-audit.jsonl"
jq -e -s '
  any(.[]; .action == "packet-deny"
    and .actor == "spiffe://orblx.local/node/c"
    and .target == "tcp/4243")
' "$WORK/packet-audit.jsonl" >/dev/null
echo "packet_audit c tcp/4243 deny"
expect_inbox "payload.bin "
no_part_files

echo "=== [C] check 4: b sends to its own receiver. The grants do not allow b ==="
dc exec -T b sh -c "head -c 65536 /dev/urandom >/tmp/from-b.bin"
if dc exec -T b orblx file send /tmp/from-b.bin --to b --state "$STATE" \
  --addr "${ips[b]}:${PORT}" >"$WORK/from-b.txt" 2>&1; then
  echo "Node b sent a file to itself." >&2
  exit 1
fi
cat "$WORK/from-b.txt"
grep -q 'reply deny acl' "$WORK/from-b.txt"
expect_inbox "payload.bin "
no_part_files
echo "=== [C] inbox on b ==="
inbox_list

echo "=== [C] receiver log ==="
dc exec -T b cat /tmp/file-receive.log
refused_lines="$(dc exec -T b grep -c '^file_refused ' /tmp/file-receive.log || true)"
received_lines="$(dc exec -T b grep -c '^file_received ' /tmp/file-receive.log || true)"
echo "receiver_lines received ${received_lines} refused ${refused_lines}"
[[ "$received_lines" -eq 1 && "$refused_lines" -eq 2 ]]

echo "=== [C] check 5: receiver audit chain ==="
dc exec -T b cat "$STATE/file-audit.jsonl" >"$WORK/file-audit.jsonl"
jq -c '{action, actor, target, detail}' "$WORK/file-audit.jsonl"
records="$(wc -l <"$WORK/file-audit.jsonl" | tr -d ' ')"
echo "audit_records ${records}"
[[ "$records" -eq 3 ]]
jq -e -s --arg sha "$sender_sha" --arg size "$SIZE_BYTES" '
  .[0].action == "file-receive"
  and .[0].actor == "spiffe://orblx.local/node/a"
  and .[0].target == "payload.bin"
  and .[0].detail == ("size " + $size + " sha256 " + $sha)
  and .[1].action == "file-deny"
  and .[1].actor == "spiffe://orblx.local/node/a"
  and (.[1].detail | startswith("reason exists size 4096 sha256 "))
  and .[2].action == "file-deny"
  and .[2].actor == "spiffe://orblx.local/node/b"
  and .[2].target == "from-b.bin"
  and (.[2].detail | startswith("reason acl size 65536 sha256 "))
' "$WORK/file-audit.jsonl" >/dev/null
echo "audit_fields ok"
verify="$(dc exec -T b orblx audit verify-config --file "$STATE/file-audit.jsonl")"
printf '%s\n' "$verify"
grep -qx 'ok' <<<"$verify"

echo "=== [C] logs hold no key or enroll token ==="
{
  dc logs 2>&1
  dc exec -T b cat /tmp/file-receive.log "$STATE/file-audit.jsonl"
  cat "$WORK"/*.txt
} >"$WORK/all-logs.out"
for name in "${NODES[@]}"; do
  token="$(dc exec -T coord cat "$STATE/tokens/${name}" 2>/dev/null | tr -d ' \n' || true)"
  if [[ -n "$token" ]] && grep -qF "$token" "$WORK/all-logs.out"; then
    echo "A log holds the ${name} enroll token." >&2
    exit 1
  fi
done
echo "secret_grep tokens 0"
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.out" || true)"
echo "secret_grep 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]]

echo "summary file_size ${SIZE_BYTES} sha256_match yes resend exists_refused deny_c datapath_dropped deny_b acl_refused inbox_files 1 inbox_dot_files 0 audit_records ${records} audit_verify ok"
echo "proof_ok"

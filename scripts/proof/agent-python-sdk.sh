#!/usr/bin/env bash
# Python agent SDK proof.
# An example agent on node a uses the orblx_agent Python package. It asks for
# one grant for the api service on node b, waits for the human owner, and
# calls `orblx gateway` on b. The proof checks 200 after the approval, a deny
# outside the path scope, a deny within 1 s after the end, the audit chain,
# and that no log holds a key, a ticket, or a use proof.
# The script deletes the orblx-agent-proof volumes at the start.
# The script does not print enroll tokens, private keys, tickets, or use proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.agent.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIMIT_MS=1000
TTL_SECS=20
STATE=/var/lib/orblx

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
PROOF_MIN_FREE_GIB=12  # reason: the floor (PROOF_DISK_FLOOR_GIB): one build output and one proof image. No bigger measure for this proof.
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "agent-python-sdk" "${PROOF_PROJECT:-}"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${PROOF_PROJECT:-orblx-agent-proof}" || exit 1

dc() {
  docker compose --progress quiet -p "${PROOF_PROJECT:-orblx-agent-proof}" --profile nodes -f "$FILE" "$@"
}

resolve_name() {
  local name="$1"
  dc --profile nodes run --rm --no-deps --entrypoint getent owner ahostsv4 "$name" \
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
  docker build -q -t "${ORBLX_AGENT_IMAGE:-orblx-agent:w21}" "$image_dir"
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
  return 1
}

wait_file_line() {
  local service="$1"
  local path="$2"
  local needle="$3"
  local i
  for i in $(seq 1 60); do
    if dc exec -T "$service" grep -q "$needle" "$path" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "The file ${path} on ${service} has no line: ${needle}" >&2
  dc exec -T "$service" cat "$path" >&2 || true
  return 1
}

run_node() {
  local service="$1"
  shift
  dc --profile nodes run --rm --no-deps --entrypoint orblx "$service" "$@"
}

coord_flags() {
  printf '%s\n' --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

owner() {
  local flags
  mapfile -t flags < <(coord_flags)
  run_node owner admin "$@" "${flags[@]}"
}

on_a() {
  dc exec -T a orblx "$@"
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" \
    --endpoint "${name}:443"
}

field() {
  local key="$1"
  awk -v key="$key" '$1 == key {print $2; exit}'
}

grant_fetch() {
  local id="$1"
  local out="$2"
  local flags
  mapfile -t flags < <(coord_flags)
  on_a agent grant fetch --id "$id" --out "$out" --wait 5 "${flags[@]}"
}

cp "$ROOT/scripts/proof/agent.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

for name in owner a b; do
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

enroll_node owner
enroll_node a
enroll_node b

echo "=== [C] approve nodes a and b ==="
owner approve a
owner approve b
nodes="$(owner nodes)"
printf '%s\n' "$nodes"
b_ip="$(printf '%s\n' "$nodes" | read_all awk '$1 == "node" && $2 == "b" {print $3; exit}')"
echo "b_ip ${b_ip}"

for name in a b; do
  echo "=== [C] netmap on ${name} ==="
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" \
    --bundle "$STATE/bundle.pem" \
    --state "$STATE"
done

echo "=== [C] start nodes a and b ==="
dc --profile nodes up -d a b
wait_log a 'The TUN device'
wait_log b 'The TUN device'
for i in $(seq 1 60); do
  if dc exec -T a orblx status --state-dir "$STATE" 2>/dev/null | read_all grep -q '^peer b .* path direct '; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "The path from a to b did not come up." >&2
    exit 1
  fi
  sleep 1
done
dc exec -T a orblx status --state-dir "$STATE"





echo "=== [C] start the upstream and the api gateway on b ==="
dc exec -T b sh -c "cat >$STATE/upstream.py" <<'PY'
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        hdr = "present" if self.headers.get("orblx-agent-proof") or self.headers.get("orblx-agent-nonce") else "absent"
        text = "upstream ok method %s path %s agent %s grant %s proof_hdr %s body_len %d\n" % (
            self.command, self.path.split("?")[0], self.headers.get("x-orblx-agent"),
            self.headers.get("x-orblx-grant"), hdr, len(body))
        data = text.encode()
        self.send_response(200)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = reply
    do_POST = reply

    def log_message(self, fmt, *args):
        # Log the method and the path only. The query is not logged.
        print("upstream %s %s" % (self.command, self.path.split("?")[0]), flush=True)

http.server.ThreadingHTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
PY
dc exec -d b sh -c "python3 $STATE/upstream.py >$STATE/upstream.log 2>&1"
dc exec -d b sh -c "orblx gateway --listen ${b_ip}:8080 --service api \
  --target 127.0.0.1:8081 --audit $STATE/gateway-audit-api.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/gateway-api.log 2>&1"
wait_file_line b "$STATE/gateway-api.log" 'agent gateway service api'
sleep 2

echo "=== [C] copy the SDK and the example agent to node a ==="
dc exec -T a mkdir -p /opt/orblx-sdk
tar -C "$ROOT/sdk/python" -cf - orblx_agent examples | dc exec -T a tar -C /opt/orblx-sdk -xf -
dc exec -T a python3 -c "import sys; sys.path.insert(0, '/opt/orblx-sdk'); import orblx_agent; print('sdk_version', orblx_agent.__version__)"

echo "=== [C] start the example agent on a ==="
dc exec -d a sh -c "cd /opt/orblx-sdk && PYTHONPATH=/opt/orblx-sdk python3 examples/example_agent.py \
  --coord ${coord_ip}:443 --state $STATE --agent sdkbot --node b --service api --port 8080 \
  --path /api --ttl ${TTL_SECS} --out $STATE/sdk-g1 --approve-wait 120 \
  --log $STATE/sdk-agent-debug.log >$STATE/sdk-agent.log 2>&1; echo sdk_exit \$? >>$STATE/sdk-agent.log"
wait_file_line a "$STATE/sdk-agent.log" '^sdk grant_id '
grant1="$(dc exec -T a awk '$1 == "sdk" && $2 == "grant_id" {print $3; exit}' "$STATE/sdk-agent.log")"
echo "grant_id ${grant1}"

echo "=== [C] the agent waits: the grant stays pending ==="
sleep 3
if dc exec -T a grep -q '^sdk grant_issued' "$STATE/sdk-agent.log"; then
  echo "The agent got the grant before the approval." >&2
  exit 1
fi
owner grants

echo "=== [C] the human owner approves the grant ==="
owner grant-approve "$grant1"

echo "=== [C] wait for the example agent ==="
for i in $(seq 1 120); do
  if dc exec -T a grep -q '^sdk_exit ' "$STATE/sdk-agent.log" 2>/dev/null; then
    break
  fi
  sleep 1
done
agent_out="$(dc exec -T a cat "$STATE/sdk-agent.log")"
printf '%s\n' "$agent_out"
printf '%s\n' "$agent_out" | read_all grep -qx 'sdk_exit 0'
printf '%s\n' "$agent_out" | read_all grep -qx 'sdk agent_ok'
printf '%s\n' "$agent_out" | read_all grep -q '^sdk call status 200 '
printf '%s\n' "$agent_out" | read_all grep -q '^sdk post status 200 .*body_len 9'
printf '%s\n' "$agent_out" | read_all grep -q '^sdk out_of_scope status 403 reason path$'
expiry_line="$(printf '%s\n' "$agent_out" | grep '^sdk expiry ')"
ttl_delta="$(awk '{for (i = 1; i < NF; i++) if ($i == "deny_after_end_ms") print $(i + 1)}' <<<"$expiry_line")"
ttl_reason="$(awk '{print $NF}' <<<"$expiry_line")"
echo "sdk_deny_after_end_ms ${ttl_delta} reason ${ttl_reason}"
[[ "$ttl_reason" == "expired" ]]
if (( ttl_delta > LIMIT_MS )); then
  echo "The gateway did not stop the grant within ${LIMIT_MS} ms after the end." >&2
  exit 1
fi

echo "=== [C] SDK debug log ==="
dc exec -T a cat "$STATE/sdk-agent-debug.log"

echo "=== [C] gateway log and audit chain ==="
dc exec -T b cat "$STATE/gateway-api.log"
api_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/gateway-audit-api.jsonl")"
printf '%s\n' "$api_verify"
printf '%s\n' "$api_verify" | read_all grep -qx ok
for reason in path expired; do
  hits="$(dc exec -T b grep -c "reason ${reason} " "$STATE/gateway-audit-api.jsonl" || true)"
  echo "api_chain_deny ${reason} ${hits}"
  [[ "$hits" -ge 1 ]]
done
use_hits="$(dc exec -T b grep -c '"agent-use"' "$STATE/gateway-audit-api.jsonl")"
echo "api_chain_use ${use_hits}"
[[ "$use_hits" -ge 2 ]]

echo "=== [C] coordinator audit chain ==="
coord_audit="$(owner audit)"
printf '%s\n' "$coord_audit" | grep ' agent-' || true
printf '%s\n' "$coord_audit" | read_all grep -q " agent-approve ${grant1} actor spiffe://orblx.local/node/owner "
printf '%s\n' "$coord_audit" | read_all grep -q '^verify ok '
printf '%s\n' "$coord_audit" | grep '^verify '

echo "=== [C] logs hold no key, ticket, or use proof ==="
{
  dc logs coord a b 2>&1
  dc exec -T b cat "$STATE/gateway-api.log" "$STATE/upstream.log" "$STATE/gateway-audit-api.jsonl"
  dc exec -T a cat "$STATE/sdk-agent.log" "$STATE/sdk-agent-debug.log"
  dc exec -T coord cat "$STATE/config-audit.jsonl" 2>/dev/null || true
} >"$WORK/all-logs.out"
G="$STATE/sdk-g1"
ticket_hex="$(dc exec -T a sh -c "od -An -tx1 $G/ticket.bin | tr -d ' \n'")"
key_line="$(dc exec -T a sed -n 2p "$G/agent.key.pem")"
for secret in "$ticket_hex" "$key_line"; do
  if grep -qF "$secret" "$WORK/all-logs.out"; then
    echo "A log holds a grant secret." >&2
    exit 1
  fi
done
echo "secret_grep sdk-g1 ticket 0 key 0"
for needle in 'PRIVATE KEY' 'T0JMWEFHVDE' 'ge1.' 'orblx-agent-proof' 'redacted' 'hello sdk'; do
  hits="$(grep -ciF "$needle" "$WORK/all-logs.out" || true)"
  echo "secret_grep '${needle}' ${hits}"
  if [[ "$hits" -ne 0 ]]; then
    echo "A log holds ${needle}." >&2
    exit 1
  fi
done
echo "log_bytes $(wc -c <"$WORK/all-logs.out")"

echo "summary sdk_call 200 sdk_out_of_scope 403_path sdk_deny_after_end_ms ${ttl_delta} limit_ms ${LIMIT_MS}"
echo "proof_ok"

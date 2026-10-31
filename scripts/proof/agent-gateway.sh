#!/usr/bin/env bash
# Agent gateway proof.
# An agent on node a gets one grant for the api service on node b,
# port 8080, path prefix /api. `orblx gateway` on b forwards an HTTP request
# only with a valid grant proof, a new nonce, and a path inside the prefix.
# The proof checks: no grant, other service, other port, other path, replay,
# and the end time. It checks the audit chain and greps the logs for tokens.
# W24-B: a changed signed header is refused, and a restart with the audit
# chain file removed still refuses a replay (the nonce file).
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
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "agent-gateway" "${PROOF_PROJECT:-}"
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

api_request() {
  local port="$1"
  local ttl="$2"
  local flags
  mapfile -t flags < <(coord_flags)
  on_a agent grant request --agent bot --node b --service api --port "$port" --ttl "$ttl" \
    --path /api "${flags[@]}"
}

# Run one `orblx agent http` call. Save the output for the request count.
# The call can run in a subshell, so each output goes to its own file.
http() {
  local label="$1"
  shift
  local out
  out="$(mktemp "$WORK/http-XXXXXX.txt")"
  echo "=== [C] ${label} ===" >&2
  set +e
  on_a agent http "$@" >"$out" 2>&1
  local status=$?
  set -e
  cat "$out" >&2
  cat "$out"
  return "$status"
}

expect_http() {
  local label="$1"
  local needle="$2"
  shift 2
  local output
  output="$(http "$label" "$@" || true)"
  if ! printf '%s\n' "$output" | read_all grep -q -- "$needle"; then
    echo "The request did not give: ${needle}" >&2
    exit 1
  fi
}

# Print the PID of the api gateway on b. The image has no pgrep.
gateway_pid() {
  dc exec -T b sh -c 'for d in /proc/[0-9]*; do
    # pipe-ok: this runs in the container sh, which has no pipefail.
    if tr "\0" " " <"$d/cmdline" 2>/dev/null | grep -q "^orblx gateway .*--service api "; then
      basename "$d"
    fi
  done' | read_all head -n1
}

echo "=== [C] start the upstream and the gateways on b ==="
dc exec -T b sh -c "cat >$STATE/upstream.py" <<'PY'
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        hdr = "present" if self.headers.get("orblx-agent-proof") or self.headers.get("orblx-agent-nonce") else "absent"
        text = "upstream ok method %s path %s agent %s grant %s proof_hdr %s body_len %d kind %s\n" % (
            self.command, self.path.split("?")[0], self.headers.get("x-orblx-agent"),
            self.headers.get("x-orblx-grant"), hdr, len(body), self.headers.get("x-kind"))
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
dc exec -d b sh -c "orblx gateway --listen ${b_ip}:5432 --service db \
  --target 127.0.0.1:8081 --audit $STATE/gateway-audit-db.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/gateway-db.log 2>&1"
wait_file_line b "$STATE/gateway-api.log" 'agent gateway service api'
wait_file_line b "$STATE/gateway-db.log" 'agent gateway service db'
sleep 2

echo "=== [C] grant request: api port 8080 path /api ttl ${TTL_SECS} ==="
reply="$(api_request 8080 "$TTL_SECS")"
printf '%s\n' "$reply"
grant1="$(printf '%s\n' "$reply" | field grant_id)"
owner grant-approve "$grant1"
fetched="$(grant_fetch "$grant1" "$STATE/agent-g1")"
printf '%s\n' "$fetched"
printf '%s\n' "$fetched" | read_all grep -qx 'grant_path /api'
expires1_ms="$(printf '%s\n' "$fetched" | field grant_expires_ms)"
G="$STATE/agent-g1"

expect_http "GET in scope is forwarded" "status 200 .*proof_hdr absent" \
  --grant "$G" --path '/api/items?q=1'
expect_http "the upstream sees the agent and the grant" "agent spiffe://orblx.local/agent/bot grant ${grant1}" \
  --grant "$G" --path /api/items
expect_http "POST with a body is forwarded" "status 200 .*method POST .*body_len 11" \
  --grant "$G" --method POST --path /api/items --body 'hello agent'
expect_http "no grant is refused" "status 403 reason missing" \
  --to "${b_ip}:8080" --path /api/items
expect_http "other path /admin is refused" "status 403 reason path" \
  --grant "$G" --path /admin
expect_http "other path /apix is refused" "status 403 reason path" \
  --grant "$G" --path /apix
expect_http "dot path /api/../admin is refused" "status 403 reason path" \
  --grant "$G" --path /api/../admin
expect_http "other service name is refused" "status 403 reason ticket" \
  --grant "$G" --service db --path /api/items
echo "=== [C] other port 5432 (gateway db) is refused ==="
on_a agent http --grant "$G" --to "${b_ip}:5432" --service db --path /api/items \
  >"$WORK/db.txt" 2>&1 || true
cat "$WORK/db.txt"
grep -q 'status 403 reason destination' "$WORK/db.txt"
db_count="$(grep -c '^http attempt ' "$WORK/db.txt")"

echo "=== [C] replay: the same request bytes two times ==="
replay="$(http "replay" --grant "$G" --path /api/items --repeat 2 || true)"
printf '%s\n' "$replay" | read_all grep -q '^http attempt 1 status 200 '
printf '%s\n' "$replay" | read_all grep -q '^http attempt 2 status 403 reason replay '

echo "=== [C] loop until the end time ==="
ttl_out="$(http "TTL loop" --grant "$G" --path /api/items --every-ms 50 --max-wait 60)"
ttl_first="$(printf '%s\n' "$ttl_out" | awk '$2 == "first_deny_ms" {print $3}')"
ttl_last="$(printf '%s\n' "$ttl_out" | awk '$2 == "last_ok_ms" {print $3}')"
ttl_reason="$(printf '%s\n' "$ttl_out" | awk '$2 == "deny_reason" {print $3}')"
loop_attempts="$(printf '%s\n' "$ttl_out" | awk '$2 == "attempts" {print $3}')"
ttl_delta=$(( ttl_first - expires1_ms ))
echo "ttl_expires_ms ${expires1_ms} last_ok_ms ${ttl_last} first_deny_ms ${ttl_first} reason ${ttl_reason}"
echo "ttl_deny_after_end_ms ${ttl_delta}"
[[ "$ttl_reason" == "expired" ]]
if (( ttl_delta > LIMIT_MS || ttl_last >= expires1_ms )); then
  echo "The gateway did not stop the grant within ${LIMIT_MS} ms after the end." >&2
  exit 1
fi
expect_http "a request after the end is refused" "status 403 reason expired" \
  --grant "$G" --path /api/items
wait_file_line b "$STATE/gateway-api.log" "agent grant ${grant1} expired"
guard_ttl_ms="$(dc exec -T b awk '/^agent deny reason expired /{print $NF; exit}' "$STATE/gateway-api.log")"
echo "gateway_expired_deny_ms ${guard_ttl_ms} gateway_deny_after_end_ms $(( guard_ttl_ms - expires1_ms ))"

echo "=== [C] restart replay: grant 2, one request, gateway restart, same bytes ==="
reply="$(api_request 8080 120)"
printf '%s\n' "$reply"
grant2="$(printf '%s\n' "$reply" | field grant_id)"
owner grant-approve "$grant2"
grant_fetch "$grant2" "$STATE/agent-g2"
G2="$STATE/agent-g2"
first_ms="$(date +%s%3N)"
expect_http "grant 2 request is forwarded and saved" "status 200 " \
  --grant "$G2" --path /api/items --save-request "$STATE/saved-request.bin"
dc exec -T a stat -c 'saved_request mode %a' "$STATE/saved-request.bin"
old_pid="$(gateway_pid)"
echo "gateway api pid ${old_pid} stop"
dc exec -T b sh -c "kill ${old_pid}"
for i in $(seq 1 50); do
  if [[ -z "$(gateway_pid)" ]]; then
    break
  fi
  sleep 0.1
done
[[ -z "$(gateway_pid)" ]]
dc exec -d b sh -c "orblx gateway --listen ${b_ip}:8080 --service api \
  --target 127.0.0.1:8081 --audit $STATE/gateway-audit-api.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/gateway-api-2.log 2>&1"
wait_file_line b "$STATE/gateway-api-2.log" 'agent gateway service api'
dc exec -T b cat "$STATE/gateway-api-2.log"
echo "gateway api pid $(gateway_pid) start"
sleep 1
restart_out="$(http "restart replay: the saved bytes again" --to "${b_ip}:8080" \
  --send-file "$STATE/saved-request.bin" || true)"
replay_ms="$(date +%s%3N)"
printf '%s\n' "$restart_out" | read_all grep -q '^http attempt 1 status 403 reason replay '
restart_gap=$(( replay_ms - first_ms ))
echo "restart_replay_after_first_ms ${restart_gap} result refused replay"
if (( restart_gap >= 60000 )); then
  echo "The replay was not inside the 60 s proof window." >&2
  exit 1
fi
expect_http "a new request with grant 2 after the restart is forwarded" "status 200 " \
  --grant "$G2" --path /api/items
wait_file_line b "$STATE/gateway-api-2.log" 'agent deny reason replay '
restart_record="$(dc exec -T b grep -c 'reason replay ' "$STATE/gateway-audit-api.jsonl")"
echo "api_chain_replay_records ${restart_record}"
[[ "$restart_record" -ge 2 ]]
dc exec -T a rm -f "$STATE/saved-request.bin"

echo "=== [C] gateway logs ==="
dc exec -T b cat "$STATE/gateway-api.log"
dc exec -T b cat "$STATE/gateway-api-2.log"
dc exec -T b cat "$STATE/gateway-db.log"

echo "=== [C] gateway audit chains ==="
api_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/gateway-audit-api.jsonl")"
printf '%s\n' "$api_verify"
db_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/gateway-audit-db.jsonl")"
printf '%s\n' "$db_verify"
printf '%s\n' "$api_verify" | read_all grep -qx ok
printf '%s\n' "$db_verify" | read_all grep -qx ok
count_of() {
  awk -v key="$2" '$1 == key {print $2; exit}' <<<"$1"
}
api_use="$(count_of "$api_verify" agent-use)"
api_deny="$(count_of "$api_verify" agent-deny)"
api_grant="$(count_of "$api_verify" agent-grant)"
api_expire="$(count_of "$api_verify" agent-expire)"
db_deny="$(count_of "$db_verify" agent-deny)"
# Each single send prints one "http attempt" line. The loop prints its count.
single="$(cat "$WORK"/http-*.txt | grep -c '^http attempt ')"
sent=$(( single + loop_attempts ))
echo "api_chain grant ${api_grant} use ${api_use} deny ${api_deny} expire ${api_expire}"
echo "api_requests_sent ${sent} api_requests_recorded $(( api_use + api_deny ))"
echo "db_requests_sent ${db_count} db_requests_recorded ${db_deny}"
[[ "$api_grant" -ge 1 && "$api_expire" -ge 1 ]]
[[ $(( api_use + api_deny )) -eq "$sent" ]]
[[ "$db_deny" -eq "$db_count" ]]
for action in agent-use agent-deny; do
  dc exec -T b grep -c "\"${action}\"" "$STATE/gateway-audit-api.jsonl"
done
for reason in missing path ticket replay expired; do
  hits="$(dc exec -T b grep -c "reason ${reason} " "$STATE/gateway-audit-api.jsonl" || true)"
  echo "api_chain_deny ${reason} ${hits}"
  [[ "$hits" -ge 1 ]]
done

echo "=== [C] W24-B grant 3 for the header and nonce file checks ==="
reply="$(api_request 8080 120)"
printf '%s\n' "$reply"
grant3="$(printf '%s\n' "$reply" | field grant_id)"
owner grant-approve "$grant3"
grant_fetch "$grant3" "$STATE/agent-g3"
G3="$STATE/agent-g3"
expect_http "W24-B a signed header goes to the upstream" "status 200 .*kind read$" \
  --grant "$G3" --path /api/items --header 'X-Kind: read' --save-request "$STATE/hdr-request.bin"
header_denied=0
for change in 's/^x-kind: read/x-kind: write/' 's/^x-kind: read/x-kinx: read/' 's/^host: /host: 1/'; do
  dc exec -T a sh -c "sed '${change}' $STATE/hdr-request.bin >$STATE/hdr-changed.bin"
  if dc exec -T a cmp -s "$STATE/hdr-request.bin" "$STATE/hdr-changed.bin"; then
    echo "The change ${change} did not change the request." >&2
    exit 1
  fi
  expect_http "W24-B changed header (${change}) is refused" "status 403 reason ticket " \
    --to "${b_ip}:8080" --send-file "$STATE/hdr-changed.bin"
  header_denied=$(( header_denied + 1 ))
done
echo "header_change_refused ${header_denied} of 3"
dc exec -T a rm -f "$STATE/hdr-request.bin" "$STATE/hdr-changed.bin"

echo "=== [C] W24-B restart with the audit chain file removed ==="
NONCES="$STATE/gateway-audit-api.jsonl.nonces"
nf_first_ms="$(date +%s%3N)"
expect_http "grant 3 request is forwarded and saved" "status 200 " \
  --grant "$G3" --path /api/items --save-request "$STATE/saved-request-3.bin"
dc exec -T b stat -c 'nonce_file mode %a' "$NONCES"
nonce_lines="$(dc exec -T b sh -c "wc -l <$NONCES")"
echo "nonce_file_lines_before ${nonce_lines}"
old_pid="$(gateway_pid)"
echo "gateway api pid ${old_pid} stop"
dc exec -T b sh -c "kill ${old_pid}"
for i in $(seq 1 50); do
  if [[ -z "$(gateway_pid)" ]]; then
    break
  fi
  sleep 0.1
done
[[ -z "$(gateway_pid)" ]]
dc exec -T b orblx audit verify-config --file "$STATE/gateway-audit-api.jsonl" | read_all grep -qx ok
dc exec -T b rm "$STATE/gateway-audit-api.jsonl"
if dc exec -T b test -e "$STATE/gateway-audit-api.jsonl"; then
  echo "The audit chain file is still there." >&2
  exit 1
fi
echo "audit_file removed"
dc exec -d b sh -c "orblx gateway --listen ${b_ip}:8080 --service api \
  --target 127.0.0.1:8081 --audit $STATE/gateway-audit-api.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/gateway-api-3.log 2>&1"
wait_file_line b "$STATE/gateway-api-3.log" 'agent gateway service api'
dc exec -T b cat "$STATE/gateway-api-3.log"
loaded="$(dc exec -T b awk '/^agent gateway service api /{for (i = 1; i < NF; i++) if ($i == "nonces_loaded") print $(i + 1); exit}' "$STATE/gateway-api-3.log")"
echo "nonces_loaded_after_audit_removed ${loaded}"
[[ "$loaded" -ge 1 ]]
sleep 1
nf_out="$(http "W24-B replay after restart without the audit file" --to "${b_ip}:8080" \
  --send-file "$STATE/saved-request-3.bin" || true)"
nf_replay_ms="$(date +%s%3N)"
printf '%s\n' "$nf_out" | read_all grep -q '^http attempt 1 status 403 reason replay '
nf_gap=$(( nf_replay_ms - nf_first_ms ))
echo "noaudit_replay_after_first_ms ${nf_gap} result refused replay"
(( nf_gap < 60000 ))
expect_http "a new request with grant 3 after the restart is forwarded" "status 200 " \
  --grant "$G3" --path /api/items
new_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/gateway-audit-api.jsonl")"
printf '%s\n' "$new_verify"
printf '%s\n' "$new_verify" | read_all grep -qx ok
new_replay="$(dc exec -T b grep -c 'reason replay ' "$STATE/gateway-audit-api.jsonl")"
echo "new_chain_replay_records ${new_replay}"
[[ "$new_replay" -eq 1 ]]
dc exec -T a rm -f "$STATE/saved-request-3.bin"
dc exec -T b cat "$NONCES" >"$WORK/nonces.txt"
echo "nonce_file_lines_after $(wc -l <"$WORK/nonces.txt")"

echo "=== [C] coordinator audit chain ==="
coord_audit="$(owner audit)"
printf '%s\n' "$coord_audit" | grep ' agent-' || true
printf '%s\n' "$coord_audit" | read_all grep -q '^verify ok '
printf '%s\n' "$coord_audit" | grep '^verify '

echo "=== [C] logs hold no key, ticket, or use proof ==="
{
  dc logs coord a b 2>&1
  dc exec -T b cat "$STATE/gateway-api.log" "$STATE/gateway-api-2.log" "$STATE/gateway-api-3.log" \
    "$STATE/gateway-db.log" \
    "$STATE/upstream.log" \
    "$STATE/gateway-audit-api.jsonl" "$STATE/gateway-audit-db.jsonl"
  dc exec -T coord cat "$STATE/config-audit.jsonl" 2>/dev/null || true
  cat "$WORK"/*.txt
} >"$WORK/all-logs.out"
for grant_dir in "$G" "$G3"; do
  ticket_hex="$(dc exec -T a sh -c "od -An -tx1 $grant_dir/ticket.bin | tr -d ' \n'")"
  key_line="$(dc exec -T a sed -n 2p "$grant_dir/agent.key.pem")"
  for secret in "$ticket_hex" "$key_line"; do
    if grep -qF "$secret" "$WORK/all-logs.out"; then
      echo "A log holds a grant secret." >&2
      exit 1
    fi
  done
  echo "secret_grep $(basename "$grant_dir") ticket 0 key 0"
done
for needle in 'PRIVATE KEY' 'T0JMWEFHVDE' 'ge1.' 'orblx-agent-proof' 'q=1'; do
  hits="$(grep -ciF "$needle" "$WORK/all-logs.out" || true)"
  echo "secret_grep '${needle}' ${hits}"
  if [[ "$hits" -ne 0 ]]; then
    echo "A log holds ${needle}." >&2
    exit 1
  fi
done
echo "log_bytes $(wc -c <"$WORK/all-logs.out")"

echo "summary ttl_deny_after_end_ms ${ttl_delta} gateway_ttl_after_end_ms $(( guard_ttl_ms - expires1_ms )) restart_replay_after_first_ms ${restart_gap} restart_replay refused api_requests ${sent} limit_ms ${LIMIT_MS}"
echo "summary_w24b header_change_refused ${header_denied}/3 noaudit_replay refused noaudit_replay_after_first_ms ${nf_gap} nonces_loaded ${loaded}"
echo "proof_ok"

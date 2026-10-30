#!/usr/bin/env bash
# Agent JIT grant proof.
# An agent on node a asks for one grant to one service and one port on node b.
# The owner approves the grant. The guard on b admits only that service and port.
# The proof measures the stop time after the grant end and after a revoke.
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
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "agent-grant" "${PROOF_PROJECT:-}"
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

grant_request() {
  local port="$1"
  local ttl="$2"
  local flags
  mapfile -t flags < <(coord_flags)
  on_a agent grant request --agent bot --node b --service web --port "$port" --ttl "$ttl" \
    "${flags[@]}"
}

grant_fetch() {
  local id="$1"
  local out="$2"
  local flags
  mapfile -t flags < <(coord_flags)
  on_a agent grant fetch --id "$id" --out "$out" --wait 5 "${flags[@]}"
}

expect_denied() {
  local label="$1"
  local needle="$2"
  shift 2
  local output status
  echo "=== [C] ${label} ==="
  set +e
  output="$(on_a agent connect "$@" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  if [[ "$status" -ne 3 ]]; then
    echo "The connection was not denied. status ${status}" >&2
    exit 1
  fi
  printf '%s\n' "$output" | read_all grep -q "connect denied reason ${needle}"
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

echo "=== [C] start local services and guards on b ==="
dc exec -d b python3 -m http.server 8081 --bind 127.0.0.1
dc exec -d b python3 -m http.server 5433 --bind 127.0.0.1
dc exec -d b sh -c "orblx agent guard --listen ${b_ip}:8080 --service web \
  --target 127.0.0.1:8081 --audit $STATE/agent-audit-web.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/guard-web.log 2>&1"
dc exec -d b sh -c "orblx agent guard --listen ${b_ip}:5432 --service db \
  --target 127.0.0.1:5433 --audit $STATE/agent-audit-db.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/guard-db.log 2>&1"
wait_file_line b "$STATE/guard-web.log" 'agent guard service web'
wait_file_line b "$STATE/guard-db.log" 'agent guard service db'
sleep 2

echo "=== [C] grant 1 request: web port 8080 ttl ${TTL_SECS} ==="
reply="$(grant_request 8080 "$TTL_SECS")"
printf '%s\n' "$reply"
grant1="$(printf '%s\n' "$reply" | field grant_id)"
printf '%s\n' "$reply" | read_all grep -qx 'grant_state pending'

echo "=== [C] grant request above 300 s is refused ==="
if grant_request 8080 301 >"$WORK/long.txt" 2>&1; then
  echo "The coordinator accepted a 301 s grant." >&2
  exit 1
fi
cat "$WORK/long.txt"

echo "=== [C] fetch before approve stays pending ==="
set +e
pending="$(grant_fetch "$grant1" "$STATE/agent-g1" 2>&1)"
status=$?
set -e
printf '%s\n' "$pending"
[[ "$status" -eq 3 ]]
printf '%s\n' "$pending" | read_all grep -qx 'grant_state pending'

echo "=== [C] owner lists and approves grant 1 ==="
owner grants
owner grant-approve "$grant1"

echo "=== [C] fetch grant 1 ==="
fetched="$(grant_fetch "$grant1" "$STATE/agent-g1")"
printf '%s\n' "$fetched"
expires1_ms="$(printf '%s\n' "$fetched" | field grant_expires_ms)"
dc exec -T a ls -l "$STATE/agent-g1"

echo "=== [C] second fetch is refused ==="
if grant_fetch "$grant1" "$STATE/agent-g1b" >"$WORK/second.txt" 2>&1; then
  echo "The coordinator delivered the grant two times." >&2
  exit 1
fi
cat "$WORK/second.txt"

echo "=== [C] agent connects to web on b ==="
ok_out="$(on_a agent connect --grant "$STATE/agent-g1" --send 'GET / HTTP/1.0\r\n\r\n')"
printf '%s\n' "$ok_out"
printf '%s\n' "$ok_out" | read_all grep -q '^connect ok '
printf '%s\n' "$ok_out" | read_all grep -q '^reply HTTP/1.0 200'

expect_denied "other port 5432 is refused" destination \
  --grant "$STATE/agent-g1" --to "${b_ip}:5432" --service db
# The proof names web, but the guard on 5432 serves db. The use signature fails.
expect_denied "other port 5432 with the web name is refused" ticket \
  --grant "$STATE/agent-g1" --to "${b_ip}:5432" --service web
# The proof names db, but the guard on 8080 serves web. The use signature fails.
expect_denied "other service name on port 8080 is refused" ticket \
  --grant "$STATE/agent-g1" --to "${b_ip}:8080" --service db

echo "=== [C] connect without a grant is refused ==="
raw="$(dc exec -T a python3 -c "
import socket
s = socket.create_connection(('${b_ip}', 8080), 5)
s.sendall(b'GET / HTTP/1.0\r\n\r\n')
print(s.recv(200).decode(errors='replace').strip())
")"
printf 'raw reply %s\n' "$raw"
[[ "$raw" == "orblx-deny missing" ]]

echo "=== [C] TTL loop until the guard denies ==="
ttl_out="$(on_a agent connect --grant "$STATE/agent-g1" --every-ms 50 --max-wait 60)"
printf '%s\n' "$ttl_out"
ttl_first="$(printf '%s\n' "$ttl_out" | awk '$2 == "first_deny_ms" {print $3}')"
ttl_last="$(printf '%s\n' "$ttl_out" | awk '$2 == "last_ok_ms" {print $3}')"
ttl_reason="$(printf '%s\n' "$ttl_out" | awk '$2 == "deny_reason" {print $3}')"
ttl_delta=$(( ttl_first - expires1_ms ))
echo "ttl_expires_ms ${expires1_ms} last_ok_ms ${ttl_last} first_deny_ms ${ttl_first} reason ${ttl_reason}"
echo "ttl_deny_after_end_ms ${ttl_delta}"
[[ "$ttl_reason" == "expired" ]]
if (( ttl_delta > LIMIT_MS || ttl_last >= expires1_ms )); then
  echo "The guard did not stop the grant within ${LIMIT_MS} ms after the end." >&2
  exit 1
fi
wait_file_line b "$STATE/guard-web.log" "agent grant ${grant1} expired"
guard_ttl_ms="$(dc exec -T b awk '/^agent deny reason expired /{print $NF; exit}' "$STATE/guard-web.log")"
echo "guard_expired_deny_ms ${guard_ttl_ms} guard_deny_after_end_ms $(( guard_ttl_ms - expires1_ms ))"

echo "=== [C] coordinator records the expiry without a list call ==="
# The script does not call "admin grants" after the end until this check is done.
coord_line=""
for i in $(seq 1 100); do
  coord_line="$(dc logs coord 2>&1 | read_all grep -m1 "coord agent grant ${grant1} expired " || true)"
  if [[ -n "$coord_line" ]]; then
    break
  fi
  sleep 0.1
done
seen_by_script_ms="$(date +%s%3N)"
printf '%s
' "$coord_line"
if [[ -z "$coord_line" ]]; then
  echo "The coordinator did not record the expiry of grant ${grant1}." >&2
  exit 1
fi
coord_seen_ms="$(awk '{for (i = 1; i < NF; i++) if ($i == "seen_ms") print $(i + 1)}' <<<"$coord_line")"
coord_expire_delta=$(( coord_seen_ms - expires1_ms ))
echo "coord_expire_seen_ms ${coord_seen_ms} coord_expire_after_end_ms ${coord_expire_delta}"
echo "script_saw_expire_ms ${seen_by_script_ms} script_saw_after_end_ms $(( seen_by_script_ms - expires1_ms ))"
if (( coord_expire_delta < 0 || coord_expire_delta > 3000 )); then
  echo "The coordinator expire record is not within 3000 ms after the end." >&2
  exit 1
fi
early_audit="$(owner audit)"
printf '%s
' "$early_audit" | grep " agent-expire " || true
printf '%s
' "$early_audit" | read_all grep -q " agent-expire .*${grant1}"
printf '%s
' "$early_audit" | read_all grep -q '^verify ok '
printf '%s
' "$early_audit" | grep '^verify '

echo "=== [C] owner lists grants after the end ==="
owner grants

echo "=== [C] grant 2 request, approve, fetch ==="
reply="$(grant_request 8080 300)"
printf '%s\n' "$reply"
grant2="$(printf '%s\n' "$reply" | field grant_id)"
owner grant-approve "$grant2"
grant_fetch "$grant2" "$STATE/agent-g2"

echo "=== [C] grant 3 for the same agent name: request, approve, fetch ==="
reply="$(grant_request 8080 300)"
printf '%s\n' "$reply"
grant3="$(printf '%s\n' "$reply" | field grant_id)"
owner grant-approve "$grant3"
grant_fetch "$grant3" "$STATE/agent-g3"
g3_before="$(on_a agent connect --grant "$STATE/agent-g3" --send 'GET / HTTP/1.0\r\n\r\n')"
printf '%s\n' "$g3_before"
printf '%s\n' "$g3_before" | read_all grep -q '^reply HTTP/1.0 200'

echo "=== [C] revoke loop: revoke grant 2 only ==="
on_a agent connect --grant "$STATE/agent-g2" --every-ms 50 --max-wait 60 >"$WORK/revoke-loop.txt" 2>&1 &
loop_pid=$!
sleep 2
revoke_out="$(owner grant-revoke "$grant2")"
printf '%s\n' "$revoke_out"
wait "$loop_pid"
cat "$WORK/revoke-loop.txt"
revoke_start="$(printf '%s\n' "$revoke_out" | field revoke_start_ms)"
revoke_done="$(printf '%s\n' "$revoke_out" | field revoke_done_ms)"
rv_first="$(awk '$2 == "first_deny_ms" {print $3}' "$WORK/revoke-loop.txt")"
rv_last="$(awk '$2 == "last_ok_ms" {print $3}' "$WORK/revoke-loop.txt")"
rv_reason="$(awk '$2 == "deny_reason" {print $3}' "$WORK/revoke-loop.txt")"
rv_delta=$(( rv_first - revoke_done ))
rv_delta_start=$(( rv_first - revoke_start ))
echo "revoke_start_ms ${revoke_start} revoke_done_ms ${revoke_done} last_ok_ms ${rv_last} first_deny_ms ${rv_first} reason ${rv_reason}"
echo "revoke_deny_after_done_ms ${rv_delta}"
echo "revoke_deny_after_start_ms ${rv_delta_start}"
[[ "$rv_reason" == "revoked" ]]
if (( rv_delta > LIMIT_MS )); then
  echo "The guard did not stop the grant within ${LIMIT_MS} ms after the revoke." >&2
  exit 1
fi
wait_file_line b "$STATE/guard-web.log" "agent grant ${grant2} revoked"
guard_rv_ms="$(dc exec -T b awk '/^agent deny reason revoked /{print $NF; exit}' "$STATE/guard-web.log")"
echo "guard_revoked_deny_ms ${guard_rv_ms} guard_deny_after_revoke_done_ms $(( guard_rv_ms - revoke_done ))"

echo "=== [C] grant 3 for the same agent name still works after the revoke ==="
g3_after="$(on_a agent connect --grant "$STATE/agent-g3" --send 'GET / HTTP/1.0\r\n\r\n')"
printf '%s\n' "$g3_after"
printf '%s\n' "$g3_after" | read_all grep -q '^connect ok '
printf '%s\n' "$g3_after" | read_all grep -q '^reply HTTP/1.0 200'
expect_denied "grant 2 stays refused" revoked --grant "$STATE/agent-g2"
if dc exec -T b grep -q "agent grant ${grant3} revoked" "$STATE/guard-web.log"; then
  echo "The guard revoked grant 3." >&2
  exit 1
fi
echo "other_grant_same_agent status 200 after_revoke ok"

echo "=== [C] a new grant for the same agent name after the revoke ==="
reply="$(grant_request 8080 300)"
printf '%s\n' "$reply"
grant4="$(printf '%s\n' "$reply" | field grant_id)"
owner grant-approve "$grant4"
grant_fetch "$grant4" "$STATE/agent-g4"
g4_out="$(on_a agent connect --grant "$STATE/agent-g4" --send 'GET / HTTP/1.0\r\n\r\n')"
printf '%s\n' "$g4_out"
printf '%s\n' "$g4_out" | read_all grep -q '^reply HTTP/1.0 200'
echo "new_grant_same_agent status 200"

echo "=== [C] the deny set holds the ticket nonce, not the agent name ==="
deny_text="$(dc exec -T coord cat "$STATE/deny.json")"
if grep -q 'spiffe://orblx.local/agent/bot' <<<"$deny_text"; then
  echo "The deny set holds the agent name." >&2
  exit 1
fi
g2_nonce_count="$(grep -c '[0-9a-f]\{32\}' <<<"$deny_text" || true)"
echo "deny_agent_uri 0 deny_nonce_lines ${g2_nonce_count}"

echo "=== [C] guard logs ==="
dc exec -T b cat "$STATE/guard-web.log"
dc exec -T b cat "$STATE/guard-db.log"

echo "=== [C] guard audit chains ==="
web_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/agent-audit-web.jsonl")"
printf '%s\n' "$web_verify"
db_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/agent-audit-db.jsonl")"
printf '%s\n' "$db_verify"
for action in agent-grant agent-use agent-deny agent-expire agent-revoke; do
  count="$(printf '%s\n' "$web_verify" | read_all awk -v key="$action" '$1 == key {print $2; exit}')"
  echo "web_chain ${action} ${count:-0}"
  if [[ -z "$count" || "$count" -eq 0 ]]; then
    echo "The web guard chain has no ${action} record." >&2
    exit 1
  fi
done
dc exec -T b grep -c '"agent-deny"' "$STATE/agent-audit-db.jsonl"

echo "=== [C] coordinator audit chain ==="
coord_audit="$(owner audit)"
printf '%s\n' "$coord_audit" | grep ' agent-' || true
printf '%s\n' "$coord_audit" | read_all grep -q '^verify ok '
for action in agent-grant agent-approve agent-revoke agent-expire; do
  if ! printf '%s\n' "$coord_audit" | read_all grep -q " ${action} "; then
    echo "The coordinator chain has no ${action} record." >&2
    exit 1
  fi
done
printf '%s\n' "$coord_audit" | grep '^verify '

echo "=== [C] logs hold no key, ticket, or use proof ==="
{
  dc logs coord a b 2>&1
  dc exec -T b cat "$STATE/guard-web.log" "$STATE/guard-db.log" \
    "$STATE/agent-audit-web.jsonl" "$STATE/agent-audit-db.jsonl"
  dc exec -T coord cat "$STATE/config-audit.jsonl" 2>/dev/null || true
  cat "$WORK"/*.txt
} >"$WORK/all-logs.out"
for grant in agent-g1 agent-g2 agent-g3 agent-g4; do
  ticket_hex="$(dc exec -T a sh -c "od -An -tx1 $STATE/$grant/ticket.bin | tr -d ' \n'")"
  key_line="$(dc exec -T a sed -n 2p "$STATE/$grant/agent.key.pem")"
  if grep -qF "$ticket_hex" "$WORK/all-logs.out"; then
    echo "A log holds the ${grant} ticket." >&2
    exit 1
  fi
  if grep -qF "$key_line" "$WORK/all-logs.out"; then
    echo "A log holds the ${grant} key." >&2
    exit 1
  fi
  echo "secret_grep ${grant} ticket 0 key 0"
done
for needle in 'PRIVATE KEY' 'T0JMWEFHVDE' 'ge1.'; do
  hits="$(grep -cF "$needle" "$WORK/all-logs.out" || true)"
  echo "secret_grep '${needle}' ${hits}"
  if [[ "$hits" -ne 0 ]]; then
    echo "A log holds ${needle}." >&2
    exit 1
  fi
done
echo "log_bytes $(wc -c <"$WORK/all-logs.out")"

echo "summary other_grant_after_revoke 200 coord_expire_after_end_ms ${coord_expire_delta} ttl_deny_after_end_ms ${ttl_delta} guard_ttl_after_end_ms $(( guard_ttl_ms - expires1_ms )) revoke_deny_after_done_ms ${rv_delta} revoke_deny_after_start_ms ${rv_delta_start} guard_revoke_after_done_ms $(( guard_rv_ms - revoke_done )) limit_ms ${LIMIT_MS}"
echo "proof_ok"

#!/usr/bin/env bash
# Revoke-all proof (W24-D).
# Node a is the principal. Node c is another principal. Node b serves:
#   the agent guard for service web on TCP 8080, the orblx SSH server on TCP 22,
#   and the file receiver on TCP 4243.
# Node a has two issued agent grants and one pending grant. Node c has one issued
# grant for the same agent name.
# Before the revoke, probes on a and c use each surface again and again:
#   agent grant (each grant of a), SVID at the coordinator, SSH to b, file send to b.
# The owner runs one command: `orblx admin revoke-all a`.
# Checks:
#   1. Each surface of a denies within LIMIT_MS after revoke_done_ms. The script prints the ms.
#      W24: the datapath of b ends the session of a. A surface on the overlay can then fail
#      with a timeout (datapath_drop) before the app check. The script accepts this when the
#      last good run ended and the failed run started LIMIT_MS or less after revoke_done_ms.
#   2. The probes of c have no failure during and after the revoke.
#   3. The coordinator chain has exactly 1 new record, the revoke-all record.
#   4. The coordinator chain and the chains on b verify ok.
# The script deletes the orblx-w24d-revoke-all volumes at the start.
# The script does not print enroll tokens, private keys, tickets, or SVID proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.revoke-all.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LIMIT_MS=1000
STATE=/var/lib/orblx
INBOX=/var/lib/orblx/inbox
PROBE_SECS=30
HOLD_SECS=16
GET='GET / HTTP/1.0\r\n\r\n'

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  # sudo drops the environment, so pass the Compose variables with env.
  as_root env POLICY_FILE="$POLICY_FILE" COORD_ADDR="$COORD_ADDR" \
    docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (tail) ----"
    dc logs --tail 40 2>&1 | grep -v 'PRIVATE KEY' || true
  fi
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
proof_lock_take "revoke-all"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-w24d-revoke-all" || exit 1

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
  as_root docker build -q -t orblx-w24d-revoke:w24 "$image_dir"
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
  return 1
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
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

coord_flags() {
  printf '%s\n' --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

owner() {
  local flags
  mapfile -t flags < <(coord_flags)
  run_node owner admin "$@" "${flags[@]}"
}

field() {
  local key="$1"
  awk -v key="$key" '$1 == key {print $2; exit}'
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

# Ask, approve, and fetch one grant for agent bot on node NODE. Print the grant id.
issue_grant() {
  local node="$1"
  local out="$2"
  local flags reply id
  mapfile -t flags < <(coord_flags)
  reply="$(dc exec -T "$node" orblx agent grant request --agent bot --node b --service web \
    --port 8080 --ttl 300 "${flags[@]}")"
  id="$(printf '%s\n' "$reply" | field grant_id)"
  owner grant-approve "$id" >&2
  dc exec -T "$node" orblx agent grant fetch --id "$id" --out "$out" --wait 5 "${flags[@]}" \
    | grep -E '^(grant_id|grant_state) ' >&2
  printf '%s\n' "$id"
}

# The client errors of a surface when the datapath of b drops the packets (W24).
# "deny_output connect ok to" with no reply line: the connect passed before the drop, the reply did not.
DATAPATH_DROP='os error 11|os error 104|os error 110|timed out|timeout|deny_output connect ok to '

# A datapath drop: the last good run of a ended LIMIT_MS or less after revoke_done_ms,
# and the next run (it starts after the last good run) gets no reply.
# The script prints both times. The end of the failed run is the client timeout.
datapath_ms() {
  local label="$1"
  local file="$2"
  local last="$3"
  local start end
  start="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "deny_run_start_ms") print $(i + 1)}' "$file")"
  end="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "first_deny_ms") print $(i + 1)}' "$file")"
  # A slow run (SSH) can start before the revoke and fail after it.
  if (( end < revoke_start )); then
    echo "The surface ${label} failed before the revoke." >&2
    exit 1
  fi
  local last_after=$(( last - revoke_done ))
  local start_after=$(( start - revoke_done ))
  echo "surface ${label} datapath_drop last_ok_after_done_ms ${last_after} failed_run_start_after_done_ms ${start_after}"
  if (( last_after > LIMIT_MS || start_after > LIMIT_MS )); then
    echo "The datapath did not drop the surface ${label} within ${LIMIT_MS} ms." >&2
    exit 1
  fi
  results+=("${label}=datapath:${start_after}")
}

# Check the deny reason of one probe and print the deny ms after revoke_done_ms.
# The fourth argument "overlay" also accepts a datapath drop (W24).
deny_ms() {
  local label="$1"
  local file="$2"
  local needle="$3"
  local first last
  cat "$file"
  first="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "first_deny_ms") print $(i + 1)}' "$file")"
  last="$(awk '$3 == "ok" {for (i = 1; i < NF; i++) if ($i == "last_ok_ms") print $(i + 1)}' "$file")"
  if [[ -z "$first" ]]; then
    echo "The surface ${label} did not deny." >&2
    exit 1
  fi
  local overlay="${4:-no}"
  if ! grep -q -- "$needle" "$file"; then
    # W24: the datapath of b ends the session of a revoked peer. Then a surface on the
    # overlay fails with a timeout before the app check on b sees it.
    if [[ "$overlay" == overlay ]] && grep -qE "$DATAPATH_DROP" "$file"; then
      datapath_ms "$label" "$file" "$last"
      return 0
    fi
    echo "The surface ${label} failed, but not with: ${needle}" >&2
    exit 1
  fi
  if (( first < revoke_start )); then
    echo "The surface ${label} failed before the revoke." >&2
    exit 1
  fi
  local after_done=$(( first - revoke_done ))
  local after_start=$(( first - revoke_start ))
  echo "surface ${label} last_ok_ms ${last} first_deny_ms ${first} deny_after_done_ms ${after_done} deny_after_start_ms ${after_start}"
  if (( after_done > LIMIT_MS )); then
    echo "The surface ${label} did not deny within ${LIMIT_MS} ms." >&2
    exit 1
  fi
  results+=("${label}=${after_done}")
}

cp "$ROOT/scripts/proof/revoke-all.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
if [[ -n "${ORBLX_PROOF_NET_HOOK:-}" ]]; then
  as_root "$ORBLX_PROOF_NET_HOOK"
fi
wait_bundle

for name in owner a b c; do
  dc exec -T coord orblx coord token create \
    --state "$STATE" \
    --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done

coord_ip="$(dc run --rm --no-deps --entrypoint getent owner ahostsv4 coord \
  | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}')"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

for name in owner a b c; do
  enroll_node "$name"
done

echo "=== [C] approve nodes a, b, and c ==="
for name in a b c; do
  owner approve "$name"
done
nodes="$(owner nodes)"
printf '%s\n' "$nodes"
b_ip="$(printf '%s\n' "$nodes" | read_all awk '$1 == "node" && $2 == "b" {print $3; exit}')"
echo "b_ip ${b_ip}"

for name in a b c; do
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE" >/dev/null
  echo "netmap ${name} written"
done

echo "=== [C] node b: SSH policy file ==="
dc run --rm --no-deps --entrypoint sh -T b -c "cat > $STATE/policy.hujson" <"$POLICY_FILE"
echo "policy b written"

echo "=== [C] start nodes a, b, and c ==="
dc up -d a b c
for name in a b c; do
  wait_log "$name" 'The TUN device'
done
wait_path a b
wait_path c b
wait_log b 'ssh_listen '

echo "=== [C] node b: web, agent guard on 8080, file receiver on 4243 ==="
dc exec -d b python3 -m http.server 8081 --bind 127.0.0.1
dc exec -d b sh -c "orblx agent guard --listen ${b_ip}:8080 --service web \
  --target 127.0.0.1:8081 --audit $STATE/agent-audit-web.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/guard-web.log 2>&1"
dc exec -d b sh -c "orblx file receive --dir $INBOX --state $STATE >/tmp/file-receive.log 2>&1"
wait_file_line b "$STATE/guard-web.log" 'agent guard service web'
wait_file_line b /tmp/file-receive.log '^file_receive listen'

echo "=== [C] agent grants: a1 and a2 for a, c1 for c (same agent name bot) ==="
grant_a1="$(issue_grant a "$STATE/agent-a1")"
grant_a2="$(issue_grant a "$STATE/agent-a2")"
grant_c1="$(issue_grant c "$STATE/agent-c1")"
mapfile -t flags < <(coord_flags)
pending_reply="$(dc exec -T a orblx agent grant request --agent bot --node b --service web \
  --port 8080 --ttl 300 "${flags[@]}")"
grant_a3="$(printf '%s\n' "$pending_reply" | field grant_id)"
echo "grants a1 ${grant_a1} a2 ${grant_a2} a3_pending ${grant_a3} c1 ${grant_c1}"
owner grants

echo "=== [C] peer certificate of b and SVID copies for the coordinator probe ==="
dc exec -T b cat "$STATE/cert.pem" >"$WORK/b-cert.pem"
for name in a c; do
  dc exec -T "$name" sh -c "cat > /tmp/b-cert.pem" <"$WORK/b-cert.pem"
  dc exec -T "$name" sh -c "rm -rf /tmp/svid && mkdir -p /tmp/svid && cp -a $STATE/. /tmp/svid/"
  # The node state holds a node ticket.bin. An SSH login with a node SVID has no ticket,
  # so the SSH identity directory holds only the SVID and the bundle.
  dc exec -T "$name" sh -c "rm -rf /tmp/sshid && mkdir -p /tmp/sshid && cp $STATE/cert.pem $STATE/key.pem $STATE/bundle.pem /tmp/sshid/"
  dc exec -T "$name" sh -c "cat > /tmp/probe.py" <"$ROOT/scripts/proof/revoke-probe.py"
done

echo "=== [C] each surface works for a and c before the revoke ==="
for name in a c; do
  dc exec -T "$name" orblx agent connect --grant "$STATE/agent-${name}1" --send "$GET" \
    | grep -E '^(connect ok|reply HTTP/1.0 200)'
  dc exec -T "$name" orblx coord netmap --coord "${coord_ip}:443" \
    --bundle /tmp/svid/bundle.pem --state /tmp/svid >/dev/null
  echo "svid ${name} coordinator netmap ok"
  dc exec -T "$name" orblx ssh root@b --identity /tmp/sshid --netmap "$STATE/netmap.json" \
    --peer-cert /tmp/b-cert.pem --command 'echo ssh_ok'
  dc exec -T "$name" sh -c "head -c 4096 /dev/urandom >/tmp/probe.bin"
  dc exec -T "$name" orblx file send /tmp/probe.bin --to b --name "before-${name}.bin" \
    --state "$STATE" | grep '^file_sent '
done
dc exec -T a orblx agent connect --grant "$STATE/agent-a2" --send "$GET" | grep '^connect ok'

probe() {
  local node="$1"
  local mode="$2"
  local label="$3"
  local secs="$4"
  local every="$5"
  shift 5
  dc exec -T "$node" python3 /tmp/probe.py "$mode" "$label" "$secs" "$every" "$@" \
    >"$WORK/probe-${label}.out" 2>&1 &
  pids+=($!)
}

surface_cmds() {
  local name="$1"
  local mode="$2"
  local secs="$3"
  local every="$4"
  local grants=("$name"1)
  if [[ "$name" == a ]]; then
    grants=(a1 a2)
  fi
  local grant
  for grant in "${grants[@]}"; do
    # A run is good only with an HTTP reply. A connect with no reply (read timeout) fails (W24).
    # pipe-ok: the probe command runs in the container sh, which has no pipefail.
    probe "$name" "$mode" "${name}-grant-${grant}" "$secs" "$every" \
      sh -c 'out="$(orblx agent connect --grant "$1" --send "$2" 2>&1)"; code=$?; printf "%s\n" "$out"; [ "$code" -eq 0 ] && printf "%s\n" "$out" | grep -q "^reply HTTP"' \
      sh "$STATE/agent-${grant}" "$GET"
  done
  probe "$name" "$mode" "${name}-svid" "$secs" "$every" \
    orblx coord netmap --coord "${coord_ip}:443" --bundle /tmp/svid/bundle.pem --state /tmp/svid
  probe "$name" "$mode" "${name}-ssh" "$secs" "$every" \
    orblx ssh root@b --identity /tmp/sshid --netmap "$STATE/netmap.json" \
    --peer-cert /tmp/b-cert.pem --command true
  probe "$name" "$mode" "${name}-file" "$secs" "$every" \
    orblx file send /tmp/probe.bin --to b --name "${mode}-${name}-{n}.bin" --state "$STATE"
}

echo "=== [C] start probes: a until deny, c must not fail for ${HOLD_SECS} s ==="
pids=()
surface_cmds a until-deny "$PROBE_SECS" 50
surface_cmds c hold "$HOLD_SECS" 100
audit_before="$(owner audit --verify)"
printf '%s\n' "$audit_before"
records_before="$(printf '%s\n' "$audit_before" | awk '$1 == "verify" && $2 == "ok" {print $4}')"
sleep 3

echo "=== [C] owner: one command revokes all access of a ==="
revoke_out="$(owner revoke-all a)"
printf '%s\n' "$revoke_out"
revoke_start="$(printf '%s\n' "$revoke_out" | field revoke_start_ms)"
revoke_done="$(printf '%s\n' "$revoke_out" | field revoke_done_ms)"
printf '%s\n' "$revoke_out" | read_all grep -qx 'revoked_all spiffe://orblx.local/node/a'
printf '%s\n' "$revoke_out" | read_all grep -qx 'grants_revoked 3'
printf '%s\n' "$revoke_out" | read_all grep -qx 'grant_nonces_denied 2'

failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=1
done

echo "=== [C] deny time of each surface of a (limit ${LIMIT_MS} ms after revoke_done_ms) ==="
results=()
deny_ms grant-a1 "$WORK/probe-a-grant-a1.out" 'connect denied reason revoked' overlay
deny_ms grant-a2 "$WORK/probe-a-grant-a2.out" 'connect denied reason revoked' overlay
deny_ms svid "$WORK/probe-a-svid.out" 'deny_output'
deny_ms ssh "$WORK/probe-a-ssh.out" 'The SSH session was refused' overlay
deny_ms file "$WORK/probe-a-file.out" 'reply deny identity' overlay
dc logs --no-log-prefix b 2>&1 | read_all grep -m1 -e 'The peer a is in the deny list.' -e 'The node ended the session with a.' || true

echo "=== [C] probes of c during and after the revoke ==="
for label in c-grant-c1 c-svid c-ssh c-file; do
  cat "$WORK/probe-${label}.out"
  grep -q "^probe ${label} hold ok [1-9][0-9]* fail 0$" "$WORK/probe-${label}.out"
done
if [[ "$failed" -ne 0 ]]; then
  echo "A probe failed." >&2
  exit 1
fi
echo "other_principal c failures 0"

echo "=== [C] after the revoke ==="
if dc exec -T a orblx agent grant fetch --id "$grant_a3" --out "$STATE/agent-a3" --wait 1 \
  "${flags[@]}" >"$WORK/a3.txt" 2>&1; then
  echo "Node a fetched the pending grant after the revoke." >&2
  exit 1
fi
cat "$WORK/a3.txt"
owner grants | tee "$WORK/grants-after.txt"
grep -q "^grant ${grant_a1} revoked " "$WORK/grants-after.txt"
grep -q "^grant ${grant_a2} revoked " "$WORK/grants-after.txt"
grep -q "^grant ${grant_a3} revoked " "$WORK/grants-after.txt"
grep -q "^grant ${grant_c1} issued " "$WORK/grants-after.txt"
c_after="$(dc exec -T c orblx agent connect --grant "$STATE/agent-c1" --send "$GET")"
printf '%s\n' "$c_after" | read_all grep -q '^reply HTTP/1.0 200'
echo "c grant c1 after revoke 200"
dc exec -T c orblx ssh root@b --identity /tmp/sshid --netmap "$STATE/netmap.json" \
  --peer-cert /tmp/b-cert.pem --command 'echo ssh_ok'
dc exec -T c orblx file send /tmp/probe.bin --to b --name after-c.bin --state "$STATE" \
  | grep '^file_sent '
deny_text="$(dc exec -T coord cat "$STATE/deny.json")"
deny_uris="$(jq -c '.revoked_uris' <<<"$deny_text")"
deny_nonces="$(jq '.revoked_ticket_nonces | length' <<<"$deny_text")"
echo "coord deny revoked_uris ${deny_uris} nonces ${deny_nonces} version $(jq '.version' <<<"$deny_text")"
[[ "$deny_uris" == '["spiffe://orblx.local/node/a"]' && "$deny_nonces" -eq 2 ]]

echo "=== [C] coordinator audit chain ==="
dc exec -T coord cat "$STATE/config-audit.jsonl" >"$WORK/config-audit.jsonl"
audit_after="$(owner audit --verify)"
printf '%s\n' "$audit_after"
records_after="$(printf '%s\n' "$audit_after" | awk '$1 == "verify" && $2 == "ok" {print $4}')"
new_records=$(( records_after - records_before ))
echo "coord_records before ${records_before} after ${records_after} new ${new_records}"
jq -c 'select(.at_unix >= 0) | select(.action == "revoke") | {action, actor, target, detail}' \
  "$WORK/config-audit.jsonl"
revoke_all_records="$(jq -s '[.[] | select(.action == "revoke" and (.detail | contains("scope all")))] | length' \
  "$WORK/config-audit.jsonl")"
echo "revoke_all_records ${revoke_all_records}"
jq -s -e '[.[] | select(.action == "revoke" and (.detail | contains("scope all")))][0]
  | .target == "spiffe://orblx.local/node/a"
  and .actor == "spiffe://orblx.local/node/owner"
  and (.detail | contains("grants 3 nonces 2"))' "$WORK/config-audit.jsonl" >/dev/null
[[ "$new_records" -eq 1 && "$revoke_all_records" -eq 1 ]]
grep -q '^verify ok ' <<<"$audit_after"

echo "=== [C] chains on node b ==="
dc exec -T b orblx audit verify-config --file "$STATE/agent-audit-web.jsonl" | tee "$WORK/guard-verify.txt"
grep -qx 'ok' "$WORK/guard-verify.txt"
dc exec -T b orblx audit verify-config --file "$STATE/file-audit.jsonl" | tee "$WORK/file-verify.txt"
grep -qx 'ok' "$WORK/file-verify.txt"
dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" | tee "$WORK/ssh-verify.txt"
grep -qx 'ok' "$WORK/ssh-verify.txt"
dc exec -T b cat "$STATE/ssh-audit.jsonl" >"$WORK/ssh-audit.jsonl"
ssh_revoked="$(jq -s '[.[] | select(.kind == "deny" and .reason == "revoked")] | length' "$WORK/ssh-audit.jsonl")"
echo "ssh_chain deny revoked ${ssh_revoked}"
# W24: when the datapath drops the SSH surface first, the SSH server sees no login of a.
if [[ " ${results[*]} " != *" ssh=datapath:"* ]]; then
  [[ "$ssh_revoked" -ge 1 ]]
fi
dc exec -T b cat "$STATE/file-audit.jsonl" >"$WORK/file-audit.jsonl"
file_identity="$(jq -s '[.[] | select(.action == "file-deny" and (.actor | startswith("spiffe://orblx.local/node/a")) and (.detail | startswith("reason identity")))] | length' "$WORK/file-audit.jsonl")"
file_c_after="$(jq -s '[.[] | select(.action == "file-receive" and .actor == "spiffe://orblx.local/node/c")] | length' "$WORK/file-audit.jsonl")"
echo "file_chain deny_identity_a ${file_identity} receive_c ${file_c_after}"
if [[ " ${results[*]} " != *" file=datapath:"* ]]; then
  [[ "$file_identity" -ge 1 ]]
fi

echo "=== [C] logs hold no key, ticket, or enroll token ==="
{
  dc logs 2>&1
  dc exec -T b cat "$STATE/guard-web.log" /tmp/file-receive.log
  cat "$WORK"/*.out "$WORK"/*.txt "$WORK"/*.jsonl
} >"$WORK/all-logs.log"
for name in owner a b c; do
  token="$(dc exec -T coord cat "$STATE/tokens/${name}" 2>/dev/null | tr -d ' \n' || true)"
  if [[ -n "$token" ]] && grep -qF "$token" "$WORK/all-logs.log"; then
    echo "A log holds the ${name} enroll token." >&2
    exit 1
  fi
done
for grant in a1 a2; do
  ticket_hex="$(dc exec -T a sh -c "od -An -tx1 $STATE/agent-${grant}/ticket.bin | tr -d ' \n'")"
  if grep -qF "$ticket_hex" "$WORK/all-logs.log"; then
    echo "A log holds the ${grant} ticket." >&2
    exit 1
  fi
done
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.log" || true)"
echo "secret_grep tokens 0 tickets 0 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]]

echo "summary principal spiffe://orblx.local/node/a ${results[*]} limit_ms ${LIMIT_MS} other_principal_failures 0 coord_new_records ${new_records} revoke_all_records ${revoke_all_records} coord_verify ok"
echo "proof_ok"

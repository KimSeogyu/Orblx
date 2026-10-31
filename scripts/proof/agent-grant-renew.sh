#!/usr/bin/env bash
# W25-30 agent grant renewal proof.
# One running agent loop on node a crosses 5 or more grant ends with no restart.
# Each grant has a TTL of 60 s. Before a grant ends, the agent requests the
# next grant, the owner approves it, and the agent fetches it to the same
# grant directory. The loop reads the directory again before each connection.
# The coordinator issues each ticket through the normal fetch path.
# Gap gate (PO method): for each of the switches, the time from the last guard
# use of the old grant to the first guard use of the new grant is 200 ms or less.
# Phase 2 (gate): a second loop must never take a next grant with another
# scope or a revoked next grant. It stops at the grant end with deny expired.
# W25-39: the run also records the time of each step of each request: the agent
# steps, the TUN read and write of each TCP packet on a and b, and the guard steps.
# A plain TCP RTT probe (python, no orblx code) runs on the same overlay pair at the
# same time. agent-latency-split.py prints the split. Gate: request p99 <= 100 ms.
# The script does not print enroll tokens, private keys, tickets, or use proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.agent.yml"
PROJECT="${PROOF_PROJECT:-orblx-w25-30-renew}"
export ORBLX_AGENT_IMAGE="${ORBLX_AGENT_IMAGE:-orblx-w25-30-renew:w25}"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
STATE=/var/lib/orblx
TTL_SECS="${RENEW_TTL_SECS:-60}"
ENDS="${RENEW_ENDS:-6}"
LEAD_SECS="${RENEW_LEAD_SECS:-20}"
EVERY_MS=50
GAP_LIMIT_MS=200
REQUEST_P99_LIMIT_MS=100
PROBE_PORT=9090
export ORBLX_DP_TRACE_FILE="$STATE/dp-trace.txt"
export ORBLX_DP_TRACE_PORTS="8080,${PROBE_PORT}"
GRANT_DIR="$STATE/agent-cur"
GATE_DIR="$STATE/agent-gate"
STAGE_DIR="$STATE/agent-stage"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  docker compose --progress quiet -p "$PROJECT" --profile nodes -f "$FILE" "$@"
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# The proof takes the box proof lock itself (proof-lock.sh, FIFO).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "agent-grant-renew" "$PROJECT"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# as_root and dc are defined above, so a docker failure is not a false clean.
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$PROJECT" || exit 1

resolve_name() {
  local name="$1"
  dc --profile nodes run --rm --no-deps --entrypoint getent owner ahostsv4 "$name" \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
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
  docker build -q -t "$ORBLX_AGENT_IMAGE" "$image_dir"
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
  echo "=== [C] enroll ${name} with a coordinator token ==="
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

now_ms() {
  date +%s%3N
}

# Request, approve, and fetch one grant to the grant directory.
# Prints "grant ID expires_ms MS fetched_ms MS".
next_grant() {
  local out="${1:-$GRANT_DIR}" port="${2:-8080}"
  local flags reply id fetched expires
  mapfile -t flags < <(coord_flags)
  reply="$(on_a agent grant request --agent bot --node b --service web --port "$port" \
    --ttl "$TTL_SECS" "${flags[@]}")"
  printf '%s\n' "$reply" >&2
  id="$(printf '%s\n' "$reply" | field grant_id)"
  printf '%s\n' "$reply" | read_all grep -qx 'grant_state pending'
  owner grant-approve "$id" >&2
  fetched="$(on_a agent grant fetch --id "$id" --out "$out" --wait 5 "${flags[@]}")"
  printf '%s\n' "$fetched" >&2
  expires="$(printf '%s\n' "$fetched" | field grant_expires_ms)"
  echo "grant ${id} expires_ms ${expires} fetched_ms $(now_ms)"
}

# Request and approve one grant, with no fetch. Prints the grant ID.
approved_grant() {
  local flags reply id
  mapfile -t flags < <(coord_flags)
  reply="$(on_a agent grant request --agent bot --node b --service web --port 8080 \
    --ttl "$TTL_SECS" "${flags[@]}")"
  printf '%s\n' "$reply" >&2
  id="$(printf '%s\n' "$reply" | field grant_id)"
  owner grant-approve "$id" >&2
  echo "$id"
}

# The deny list version in the node state of a.
deny_version_a() {
  dc exec -T a cat "$STATE/deny.json" | read_all awk 'match($0, /"version": *[0-9]+/) {v = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", v); print v; exit}'
}

# Copy one complete grant set from STAGE_DIR to GATE_DIR, as fetch writes it:
# each file is an atomic rename, and grant.json is last.
stage_to_gate() {
  dc exec -T a sh -c "set -e; for f in agent.crt.pem agent.key.pem ticket.bin grant.json; do \
    cp -p $STAGE_DIR/\$f $GATE_DIR/\$f.tmp; mv $GATE_DIR/\$f.tmp $GATE_DIR/\$f; done"
}

container_starts() {
  local name
  for name in a b coord; do
    printf '%s %s\n' "$name" \
      "$(docker inspect -f '{{.State.StartedAt}} restarts {{.RestartCount}}' "$(dc ps -q "$name")")"
  done
}

cp "$ROOT/scripts/proof/agent.hujson" "$POLICY_FILE"
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
  run_node "$name" coord netmap --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE"
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

echo "=== [C] start the web service and the guard on b ==="
dc exec -d b python3 -m http.server 8081 --bind 127.0.0.1
dc exec -d b sh -c "ORBLX_AGENT_TIMING=1 orblx agent guard --listen ${b_ip}:8080 --service web \
  --target 127.0.0.1:8081 --audit $STATE/agent-audit-web.jsonl \
  --coord ${coord_ip}:443 --state $STATE --bundle $STATE/bundle.pem \
  --poll-ms 200 --stale-ms 2000 >$STATE/guard-web.log 2>&1"
wait_file_line b "$STATE/guard-web.log" 'agent guard service web'
sleep 2

echo "=== [C] grant 1 (TTL ${TTL_SECS} s) ==="
next_grant | tee -a "$WORK/grants.txt"
first_end="$(awk 'NR == 1 {print $4}' "$WORK/grants.txt")"
# The loop runs to 20 s after the end of grant ENDS.
last_end=$(( first_end + (ENDS - 1) * (TTL_SECS - LEAD_SECS) * 1000 ))
max_wait=$(( (last_end - $(now_ms)) / 1000 + 20 ))
echo "plan ends ${ENDS} ttl_s ${TTL_SECS} lead_s ${LEAD_SECS} every_ms ${EVERY_MS} max_wait_s ${max_wait}"

echo "=== [C] start the plain TCP RTT probe (echo on b ${b_ip}:${PROBE_PORT}, probe on a) ==="
for name in a b; do
  dc exec -T "$name" sh -c "cat >/tmp/tcp-rtt-probe.py" <"$ROOT/scripts/proof/tcp-rtt-probe.py"
done
dc exec -d b python3 /tmp/tcp-rtt-probe.py serve "$b_ip" "$PROBE_PORT"
sleep 1
dc exec -d a sh -c "python3 /tmp/tcp-rtt-probe.py probe ${b_ip} ${PROBE_PORT} ${max_wait} ${EVERY_MS} >$STATE/probe.txt 2>&1"

echo "=== [C] containers before the loop ==="
container_starts | tee "$WORK/starts-before.txt"

echo "=== [C] start one agent loop (no restart until the end) ==="
dc exec -T a sh -c "orblx agent connect --grant $GRANT_DIR --every-ms $EVERY_MS \
  --max-wait $max_wait --trace-file $STATE/agent-loop-trace.txt >$STATE/agent-loop.log 2>&1; echo \"loop_exit \$?\" >>$STATE/agent-loop.log" &
loop_pid=$!
echo "loop_started_ms $(now_ms) (one process for the whole run)"

for n in $(seq 1 "$ENDS"); do
  end_ms="$(awk -v n="$n" 'NR == n {print $4}' "$WORK/grants.txt")"
  wake_ms=$(( end_ms - LEAD_SECS * 1000 ))
  wait_ms=$(( wake_ms - $(now_ms) ))
  if (( wait_ms > 0 )); then
    sleep "$(awk -v ms="$wait_ms" 'BEGIN {printf "%.3f", ms / 1000}')"
  fi
  echo "=== [C] grant $(( n + 1 )): request, owner approve, fetch $(( (end_ms - $(now_ms)) / 1000 )) s before grant ${n} ends ==="
  next_grant | tee -a "$WORK/grants.txt"
done

wait "$loop_pid" || true
echo "=== [C] agent loop output ==="
dc exec -T a cat "$STATE/agent-loop.log" | tee "$WORK/loop.txt"

echo "=== [C] agent loop trace (one line per attempt) ==="
dc exec -T a cat "$STATE/agent-loop-trace.txt" | tee "$WORK/trace.txt"

echo "=== [C] W25-39 request time split (one line per attempt, then percentiles) ==="
dc exec -T b cat "$STATE/guard-web.log" >"$WORK/guard-timing.txt"
dc exec -T a cat "$STATE/dp-trace.txt" >"$WORK/dp-a.txt"
dc exec -T b cat "$STATE/dp-trace.txt" >"$WORK/dp-b.txt"
dc exec -T a cat "$STATE/probe.txt" >"$WORK/probe.txt"
echo "dp_trace_lines a $(wc -l <"$WORK/dp-a.txt") b $(wc -l <"$WORK/dp-b.txt") probe_lines $(wc -l <"$WORK/probe.txt")"
if [[ -n "${LATENCY_KEEP_DIR:-}" ]]; then
  mkdir -p "$LATENCY_KEEP_DIR"
  cp "$WORK/dp-a.txt" "$WORK/dp-b.txt" "$WORK/probe.txt" "$WORK/trace.txt" "$WORK/guard-timing.txt" "$LATENCY_KEEP_DIR/"
  echo "latency_raw_kept ${LATENCY_KEEP_DIR}"
fi
python3 "$ROOT/scripts/proof/agent-latency-split.py" "$WORK/trace.txt" "$WORK/guard-timing.txt" \
  "$WORK/dp-a.txt" "$WORK/dp-b.txt" "$WORK/probe.txt" | tee "$WORK/latency-split.txt"
# W25-39 fix: read the p99 value by name (the split_gate line), not by column.
request_p99="$(awk '$1 == "split_gate" && $2 == "request_p99_ms" {print $3}' "$WORK/latency-split.txt")"
echo "request_p99_ms ${request_p99} limit_ms ${REQUEST_P99_LIMIT_MS} (gate at the end)"

echo "=== [C] containers after the loop ==="
container_starts | tee "$WORK/starts-after.txt"
if ! diff -q "$WORK/starts-before.txt" "$WORK/starts-after.txt" >/dev/null; then
  echo "A container restarted during the loop." >&2
  exit 1
fi
echo "container_restarts 0"

echo "=== [C] guard log ==="
dc exec -T b cat "$STATE/guard-web.log" >"$WORK/guard.txt"
cat "$WORK/guard.txt"

echo "=== [C] check the loop ==="
loop_exit="$(awk '$1 == "loop_exit" {print $2}' "$WORK/loop.txt")"
attempts="$(awk '$1 == "loop" && $2 == "attempts" {print $3}' "$WORK/loop.txt")"
ok_attempts="$(awk '$1 == "loop" && $2 == "ok_attempts" {print $3}' "$WORK/loop.txt")"
switches="$(awk '$1 == "loop" && $2 == "grant_switches" {print $3}' "$WORK/loop.txt")"
max_gap="$(awk '$1 == "loop" && $2 == "max_ok_gap_ms" {print $3}' "$WORK/loop.txt")"
failed="$(grep -c '^loop attempt .* failed' "$WORK/loop.txt" || true)"
denies_client="$(grep -c '^loop deny_reason' "$WORK/loop.txt" || true)"
denies_guard="$(grep -c '^agent deny ' "$WORK/guard.txt" || true)"
echo "loop_exit ${loop_exit} attempts ${attempts} ok_attempts ${ok_attempts} failed ${failed} client_denies ${denies_client} guard_denies ${denies_guard} switches ${switches} loop_max_ok_gap_ms ${max_gap}"
# Exit code 3: no deny before --max-wait.
[[ "$loop_exit" == 3 ]]
[[ "$attempts" == "$ok_attempts" && "$failed" -eq 0 && "$denies_client" -eq 0 && "$denies_guard" -eq 0 ]]
(( switches >= ENDS ))

echo "=== [C] gap at each grant switch (guard use times) ==="
# The PO method (W25-30): for each switch, the gap is the time from the last
# guard use of the old grant to the first guard use of the new grant.
# The limit is GAP_LIMIT_MS for all switches.
awk '$1 == "agent" && $2 == "use" {print $NF, $4}' "$WORK/guard.txt" | sort -n >"$WORK/uses-id.txt"
awk '{print $1}' "$WORK/uses-id.txt" >"$WORK/uses.txt"
ends_crossed=0
worst=0
n=0
while read -r _ _ _ from _ to _ switch_ms _ _; do
  n=$(( n + 1 ))
  last_old="$(awk -v id="$from" '$2 == id {t = $1} END {print t + 0}' "$WORK/uses-id.txt")"
  first_new="$(awk -v id="$to" '$2 == id {print $1; exit}' "$WORK/uses-id.txt")"
  first_new="${first_new:-0}"
  gap=$(( first_new - last_old ))
  echo "switch ${n} from ${from} to ${to} loop_switch_ms ${switch_ms} last_old_use_ms ${last_old} first_new_use_ms ${first_new} gap_ms ${gap} limit_ms ${GAP_LIMIT_MS}"
  if (( last_old == 0 || first_new == 0 || gap < 0 || gap > GAP_LIMIT_MS )); then
    echo "The gap at switch ${n} (${from} to ${to}) is not in 0..${GAP_LIMIT_MS} ms." >&2
    exit 1
  fi
  (( gap > worst )) && worst="$gap"
done < <(grep '^loop grant_switch ' "$WORK/loop.txt")
if (( n < ENDS )); then
  echo "Only ${n} switches are in the loop log." >&2
  exit 1
fi
echo "=== [C] access after each grant end (information and no-loss check) ==="
for k in $(seq 1 "$ENDS"); do
  read -r id end_ms < <(awk -v k="$k" 'NR == k {print $2, $4}' "$WORK/grants.txt")
  # Information only: the largest gap between two uses in the 2 s around the end.
  window="$(awk -v e="$end_ms" 'prev != "" && $1 >= e - 1000 && prev <= e + 1000 {g = $1 - prev; if (g > m) m = g} {prev = $1} END {print m + 0}' "$WORK/uses.txt")"
  before="$(awk -v e="$end_ms" '$1 < e {c++} END {print c + 0}' "$WORK/uses.txt")"
  after="$(awk -v e="$end_ms" '$1 >= e && $1 < e + 5000 {c++} END {print c + 0}' "$WORK/uses.txt")"
  echo "end ${k} grant ${id} expires_ms ${end_ms} window_max_gap_ms ${window} uses_5s_after ${after} uses_before ${before}"
  if (( after == 0 )); then
    echo "No use in the 5 s after the end of grant ${id}." >&2
    exit 1
  fi
  ends_crossed=$(( ends_crossed + 1 ))
done

echo "=== [C] gap split (information only, no gate) ==="
# trace: start_ms (before the grant directory read), send_ms (before connect), done_ms (after the reply).
# Each ok attempt has one guard use, in the same order. Same host clock for all containers.
trace_ok="$(awk '$1 == "trace" && $11 == "ok"' "$WORK/trace.txt" | wc -l)"
uses_n="$(wc -l <"$WORK/uses.txt")"
echo "trace_ok_lines ${trace_ok} guard_uses ${uses_n}"
if [[ "$trace_ok" -eq "$uses_n" ]]; then
  awk '$1 == "trace" && $11 == "ok" {print $5, $7, $9}' "$WORK/trace.txt" | paste -d' ' - "$WORK/uses.txt" >"$WORK/split.txt"
  # Fields: start send done guard. Per attempt: refresh = send - start, to_guard = guard - send,
  # from_guard = done - guard, sleep = next start - done.
  awk -v lim="$GAP_LIMIT_MS" '
    NR > 1 {
      cgap = $2 - psend; ggap = $4 - pguard
      sleep = $1 - pdone; refresh = $2 - $1
      if (cgap > lim || ggap > lim)
        printf "big_gap at_send_ms %d client_gap_ms %d guard_gap_ms %d prev_request_ms %d prev_to_guard_ms %d prev_from_guard_ms %d sleep_ms %d refresh_ms %d this_to_guard_ms %d\n", $2, cgap, ggap, pdone - psend, pguard - psend, pdone - pguard, sleep, refresh, $4 - $2
    }
    {psend = $2; pdone = $3; pguard = $4}' "$WORK/split.txt"
  for f in request:3-2 to_guard:4-2 from_guard:3-4 refresh:2-1; do
    name="${f%%:*}"; a="${f#*:}"; a1="${a%-*}"; a2="${a#*-}"
    awk -v a="$a1" -v b="$a2" '{print $a - $b}' "$WORK/split.txt" | sort -n |
      awk -v name="$name" '{v[NR] = $1} END {printf "split %s_ms p50 %d p90 %d p99 %d max %d n %d\n", name, v[int(NR * .5)], v[int(NR * .9)], v[int(NR * .99)], v[NR], NR}'
  done
  awk 'NR > 1 {print $1 - pdone} {pdone = $3}' "$WORK/split.txt" | sort -n |
    awk '{v[NR] = $1} END {printf "split sleep_ms p50 %d p90 %d p99 %d max %d n %d\n", v[int(NR * .5)], v[int(NR * .9)], v[int(NR * .99)], v[NR], NR}'
else
  echo "split_skipped trace and guard counts differ"
fi
grep -c "^agent grant .* expired " "$WORK/guard.txt" | read_all awk '{print "guard_expire_lines " $1}'

echo "=== [C] phase 2 (gate): no other-scope and no revoked next grant ==="
gate_line="$(next_grant "$GATE_DIR" | tee -a "$WORK/gate-grants.txt")"
echo "$gate_line"
gate_id="$(printf '%s\n' "$gate_line" | read_all awk '{print $2; exit}')"
gate_end="$(printf '%s\n' "$gate_line" | read_all awk '{print $4; exit}')"
gate_wait=$(( (gate_end - $(now_ms)) / 1000 + 20 ))
dc exec -T a sh -c "orblx agent connect --grant $GATE_DIR --every-ms $EVERY_MS \
  --max-wait $gate_wait >$STATE/agent-gate.log 2>&1; echo \"loop_exit \$?\" >>$STATE/agent-gate.log" &
gate_pid=$!
echo "gate_loop_started_ms $(now_ms) grant ${gate_id} expires_ms ${gate_end} max_wait_s ${gate_wait}"
sleep 3

echo "=== [C] gate: a newer grant with another scope (port 8082) to the same directory ==="
scope_line="$(next_grant "$GATE_DIR" 8082)"
echo "$scope_line"
scope_id="$(printf '%s\n' "$scope_line" | read_all awk '{print $2; exit}')"
sleep 3

echo "=== [C] gate: revoked before fetch: the fetch must fail ==="
early_id="$(approved_grant)"
owner grant-revoke "$early_id"
mapfile -t flags < <(coord_flags)
if on_a agent grant fetch --id "$early_id" --out "$STAGE_DIR-early" --wait 5 "${flags[@]}"; then
  echo "The coordinator delivered a revoked grant." >&2
  exit 1
fi
echo "gate revoked_before_fetch ${early_id} fetch_refused 1"

echo "=== [C] gate: revoked after fetch: the set goes to the directory after the revoke ==="
late_line="$(next_grant "$STAGE_DIR")"
echo "$late_line"
late_id="$(printf '%s\n' "$late_line" | read_all awk '{print $2; exit}')"
revoke_out="$(owner grant-revoke "$late_id")"
printf '%s\n' "$revoke_out"
want_version="$(printf '%s\n' "$revoke_out" | field deny_version)"
if [[ -z "$want_version" ]]; then
  echo "The revoke reply has no deny_version." >&2
  exit 1
fi
for i in $(seq 1 50); do
  have_version="$(deny_version_a || true)"
  if [[ -n "$have_version" && "$have_version" -ge "$want_version" ]]; then
    break
  fi
  if [[ "$i" -eq 50 ]]; then
    echo "The deny list on a did not reach version ${want_version}." >&2
    exit 1
  fi
  sleep 0.2
done
echo "gate deny_version_a ${have_version} want ${want_version} at_ms $(now_ms)"
stage_to_gate
echo "gate revoked_set_written ${late_id} at_ms $(now_ms)"

wait "$gate_pid" || true
echo "=== [C] gate loop output ==="
dc exec -T a cat "$STATE/agent-gate.log" | tee "$WORK/gate-loop.txt"
dc exec -T b cat "$STATE/guard-web.log" >"$WORK/guard-all.txt"
gate_exit="$(awk '$1 == "loop_exit" {print $2}' "$WORK/gate-loop.txt")"
gate_reason="$(awk '$1 == "loop" && $2 == "deny_reason" {print $3}' "$WORK/gate-loop.txt")"
gate_deny_ms="$(awk '$1 == "loop" && $2 == "first_deny_start_ms" {print $3}' "$WORK/gate-loop.txt")"
gate_switches="$(awk '$1 == "loop" && $2 == "grant_switches" {print $3}' "$WORK/gate-loop.txt")"
kept_scope="$(grep -c '^loop grant_kept reason scope ' "$WORK/gate-loop.txt" || true)"
kept_revoked="$(grep -c '^loop grant_kept reason revoked ' "$WORK/gate-loop.txt" || true)"
uses_scope="$(grep -c "^agent use grant ${scope_id} " "$WORK/guard-all.txt" || true)"
uses_late="$(grep -c "^agent use grant ${late_id} " "$WORK/guard-all.txt" || true)"
uses_early="$(grep -c "^agent use grant ${early_id} " "$WORK/guard-all.txt" || true)"
guard_revoked_denies="$(grep -c '^agent deny reason revoked ' "$WORK/guard-all.txt" || true)"
echo "gate loop_exit ${gate_exit} deny_reason ${gate_reason} first_deny_start_ms ${gate_deny_ms} grant_end_ms ${gate_end} switches ${gate_switches} kept_scope ${kept_scope} kept_revoked ${kept_revoked} uses_scope_grant ${uses_scope} uses_revoked_grant ${uses_late} uses_early_revoked ${uses_early} guard_revoked_denies ${guard_revoked_denies}"
# Exit code 0: the guard denied. The deny is at the end of the gate grant.
[[ "$gate_exit" == 0 && "$gate_reason" == expired ]]
(( gate_deny_ms >= gate_end ))
[[ "$gate_switches" == 0 ]]
(( kept_scope >= 1 && kept_revoked >= 1 ))
(( uses_scope == 0 && uses_late == 0 && uses_early == 0 && guard_revoked_denies == 0 ))
echo "gate_ok"

echo "=== [C] audit chains ==="
web_verify="$(dc exec -T b orblx audit verify-config --file "$STATE/agent-audit-web.jsonl")"
printf '%s\n' "$web_verify"
coord_audit="$(owner audit)"
printf '%s\n' "$coord_audit" | grep ' agent-' || true
printf '%s\n' "$coord_audit" | read_all grep -q '^verify ok '
printf '%s\n' "$coord_audit" | grep '^verify '
approves="$(printf '%s\n' "$coord_audit" | grep -c ' agent-approve ' || true)"
echo "coord_agent_approve ${approves}"
(( approves >= ENDS + 1 ))

echo "=== [C] logs hold no key, ticket, or use proof ==="
{
  dc logs coord a b 2>&1
  cat "$WORK/guard-all.txt" "$WORK/loop.txt" "$WORK/gate-loop.txt"
  dc exec -T b cat "$STATE/agent-audit-web.jsonl"
  dc exec -T coord cat "$STATE/config-audit.jsonl" 2>/dev/null || true
} >"$WORK/all-logs.out"
ticket_hex="$(dc exec -T a sh -c "od -An -tx1 $GRANT_DIR/ticket.bin | tr -d ' \n'")"
key_line="$(dc exec -T a sed -n 2p "$GRANT_DIR/agent.key.pem")"
if grep -qF "$ticket_hex" "$WORK/all-logs.out" || grep -qF "$key_line" "$WORK/all-logs.out"; then
  echo "A log holds the last grant ticket or key." >&2
  exit 1
fi
echo "secret_grep last_grant ticket 0 key 0"
for needle in 'PRIVATE KEY' 'T0JMWEFHVDE' 'ge1.'; do
  hits="$(grep -cF "$needle" "$WORK/all-logs.out" || true)"
  echo "secret_grep '${needle}' ${hits}"
  if [[ "$hits" -ne 0 ]]; then
    echo "A log holds ${needle}." >&2
    exit 1
  fi
done

echo "=== [C] W25-39 gate: agent request p99 ==="
if ! awk -v v="$request_p99" -v lim="$REQUEST_P99_LIMIT_MS" 'BEGIN {exit !(v != "" && v + 0 <= lim)}'; then
  echo "The agent request p99 ${request_p99} ms is more than ${REQUEST_P99_LIMIT_MS} ms." >&2
  exit 1
fi
echo "request_p99_ok ${request_p99} limit_ms ${REQUEST_P99_LIMIT_MS}"

echo "summary gate loop_exit ${gate_exit} deny_reason ${gate_reason} switches ${gate_switches} kept_scope ${kept_scope} kept_revoked ${kept_revoked} revoked_before_fetch_refused 1"
echo "summary ends_crossed ${ends_crossed} ttl_s ${TTL_SECS} attempts ${attempts} ok_attempts ${ok_attempts} lost 0 worst_switch_gap_ms ${worst} loop_max_ok_gap_ms ${max_gap} limit_ms ${GAP_LIMIT_MS} switches ${switches} restarts 0 request_p99_ms ${request_p99}"
echo "proof_ok"

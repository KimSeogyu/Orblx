#!/usr/bin/env bash
# W25-18 proof: the coordinator removes an ephemeral node that stays offline longer than T.
# The host is REAL. The coordinator, the nodes, and the load clients are [C] containers
# (compose.ephemeral-nodes.yml). T is EPH_T seconds (default 6). The node SVID life is
# EPH_SVID_TTL seconds (default 120), so a node renews in the run.
# Nodes: a, b, and n1 are not ephemeral. e1 to e4 and load1 to load20 are ephemeral
# (`orblx coord token create --ephemeral`).
# Gates:
#   1. The default token is not ephemeral. An ephemeral token makes an ephemeral node.
#   2. e1 stops. The coordinator removes it after T. Then:
#      - a and b do not have e1 in the netmap 2000 ms or less after the removal record.
#      - e1 starts again with its old SVID. The renew fails, and e1 gets 0 bytes.
#      - The removal wrote 1 node-remove record with reason ephemeral.
#      - The name e1 cannot enroll again. A new node gets the address of e1.
#   3. e2 stops and starts again before T. The coordinator does not remove e2.
#   4. n1 is not ephemeral. It stops for more than 10 x T. The coordinator keeps n1.
#   5. e3 stops. The coordinator restarts (SIGKILL) and is down for 2 x T. e3 keeps its
#      offline time: no removal before T, and the removal comes 1500 ms or less after T.
#      e4 runs through the restart and stays.
#   6. 20 load clients stop at the same time. The coordinator removes all 20.
#      c pings d each 50 ms in this time with 0 lost pings (c and d enroll just before).
#   7. The W23-4 gates use nat-realism.sh.
#   The config chain passes `orblx audit verify-config`. The logs hold 0 keys and 0 tokens.
# A node is offline from the end of its last coordinator request. A running node holds a
# `policy-wait` request for up to 20 s (DENY_WAIT_HOLD), so the coordinator sees a stopped
# node offline up to 20 s after the stop. The script prints the time from the stop.
# The script never prints a key or a token. It prints proof_ok.
# Environment:
#   PROOF_PROJECT  Compose project name (default orblx-w25q-eph-proof).
#   EPH_IMAGE      Image tag (default orblx-w25q-eph:local).
#   EPH_BIN        An orblx binary to use. Without it, the script builds target/debug/orblx.
#   EPH_T          The offline limit T in seconds (default 6).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.ephemeral-nodes.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w25q-eph-proof}"
export EPH_IMAGE="${EPH_IMAGE:-orblx-w25q-eph:local}"
export EPH_T="${EPH_T:-6}"
export EPH_SVID_TTL="${EPH_SVID_TTL:-120}"
T_MS=$((EPH_T * 1000))
NETMAP_LIMIT_MS=2000
RESTART_LATE_MS=1500
LOAD_NODES=20
COORD="172.30.218.2:443"
WORK="$(mktemp -d)"
export EPH_LAB="$WORK/lab"
mkdir -p "$EPH_LAB/coord" "$EPH_LAB/policy"
chmod 755 "$WORK" "$EPH_LAB"
cp "$ROOT/scripts/proof/ephemeral-nodes.hujson" "$EPH_LAB/policy/policy.hujson"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root env PROOF_PROJECT="$PROOF_PROJECT" EPH_IMAGE="$EPH_IMAGE" EPH_T="$EPH_T" \
    EPH_SVID_TTL="$EPH_SVID_TTL" EPH_LAB="$EPH_LAB" \
    docker compose --progress quiet -f "$FILE" "$@"
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc --profile nodes --profile tool --profile load down -v --remove-orphans >/dev/null 2>&1 || true
  as_root rm -rf "$WORK" >/dev/null 2>&1 || true
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ephemeral-nodes:${PROOF_PROJECT}" "${PROOF_PROJECT}-"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"
proof_compose_clean "$PROOF_PROJECT" || exit 1

fail() {
  echo "FAIL: $1" >&2
  dc --profile nodes --profile load logs --no-color coord a b e1 e2 e3 e4 >&2 || true
  exit 1
}

now_ms() {
  date +%s%3N
}

# Read one file of the lab. The containers write the files as root.
lab_cat() {
  as_root cat "$EPH_LAB/$1"
}

# Print the names of the nodes in the store with the ephemeral flag.
store_nodes() {
  lab_cat coord/nodes.json | jq -r '.nodes[] | "\(.name) \(.ephemeral // false) \(.overlay_ip)"'
}

in_store() {
  store_nodes | has_line "^$1 "
}

# Print the offline ms of NAME from ephemeral.json (saved_ms - last_seen_ms), or "none".
offline_ms_of() {
  lab_cat coord/ephemeral.json 2>/dev/null \
    | jq -r --arg n "$1" 'if .last_seen_ms[$n] then (.saved_ms - .last_seen_ms[$n]) else "none" end'
}

peer_in_netmap() {
  lab_cat "$1/netmap.json" 2>/dev/null | jq -r '.peers[].name' | has_line "^$2\$"
}

# Print the docker log time of the last coordinator line with NEEDLE as UNIX ms.
coord_line_ms() {
  local stamp
  stamp="$(dc logs -t --no-color coord 2>&1 | grep -F -- "$1" | tail -n 1 | awk '{print $3}')"
  [[ -n "$stamp" ]] || return 1
  date -d "$stamp" +%s%3N
}

remove_records() {
  lab_cat coord/config-audit.jsonl \
    | jq -r --arg n "$1" 'select(.action == "node-remove" and .target == $n) | .detail'
}

remove_count() {
  remove_records "$1" | awk 'END {print NR}'
}

wait_removed() {
  local name="$1" limit_s="$2"
  for _ in $(seq 1 $((limit_s * 10))); do
    in_store "$name" || return 0
    sleep 0.1
  done
  fail "The coordinator did not remove ${name} in ${limit_s} s."
}

# Wait until SERVICE printed NEEDLE COUNT times (a restart keeps the old log lines).
wait_log_count() {
  local service="$1" needle="$2" count="$3" limit_s="${4:-60}" got
  for _ in $(seq 1 "$limit_s"); do
    got="$(dc logs --no-color "$service" 2>&1 | grep -cF -- "$needle" || true)"
    [[ "$got" -ge "$count" ]] && return 0
    sleep 1
  done
  fail "The service ${service} did not print ${count} times: ${needle}"
}

wait_log() {
  local service="$1" needle="$2" limit_s="${3:-60}"
  for _ in $(seq 1 "$limit_s"); do
    dc logs --no-color "$service" 2>&1 | read_all grep -qF -- "$needle" && return 0
    sleep 1
  done
  fail "The service ${service} did not print: ${needle}"
}

token() {
  local name="$1" flag="${2:-}" out
  # shellcheck disable=SC2086
  out="$(dc exec -T coord orblx coord token create --state /var/lib/orblx \
    --out "/var/lib/orblx/tokens/${name}" --ttl 3600 $flag)"
  printf '%s\n' "$out" | grep -E '^(ephemeral|token_id) ' | sed "s/^/token ${name} /"
}

enroll() {
  local name="$1" endpoint="$2" out
  out="$(dc --profile tool run --rm --no-deps tool coord enroll \
    --name "$name" --coord "$COORD" --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" --state "/work/${name}" \
    --endpoint "${endpoint}:443" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out" | grep -E '^(name|overlay_ip) '
}

load_peers() {
  lab_cat "$1/netmap.json" | jq -r '.peers[].name' | awk '/^load/ {n++} END {print n + 0}'
}

# In a container the node is pid 1. A pid file from the last run names pid 1, and the new
# run sees pid 1 alive ("The node is already running."). Delete the stale file of a
# stopped container before the start. This is a test step only; the node code is not changed.
clear_stale_pid() {
  local state
  state="$(dc --profile nodes ps -a --format '{{.State}}' "$1")"
  [[ "$state" != running ]] || fail "The container $1 still runs."
  if as_root test -e "$EPH_LAB/$1/orblxd.pid"; then
    echo "$1 stale pid file: yes (deleted before the start)"
    as_root rm -f "$EPH_LAB/$1/orblxd.pid"
  else
    echo "$1 stale pid file: no"
  fi
}

ip_of() {
  store_nodes | awk -v n="$1" '$1 == n {ip = $3} END {print ip}'
}

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool --profile load down -v --remove-orphans >/dev/null 2>&1 || true

echo "=== [C] image ==="
BIN="${EPH_BIN:-}"
if [[ -z "$BIN" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/orblx"
fi
# shellcheck source=scripts/proof/stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$BIN")"
as_root docker build -q -t "$EPH_IMAGE" "$image_dir"
rm -rf "$image_dir"

echo "=== [C] start coordinator (T ${EPH_T} s, SVID life ${EPH_SVID_TTL} s) ==="
dc up -d coord
for _ in $(seq 1 60); do
  as_root test -s "$EPH_LAB/coord/trust-bundle.pem" && break
  sleep 1
done
as_root test -s "$EPH_LAB/coord/trust-bundle.pem" || fail "The coordinator did not write the trust bundle."
dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson
wait_log coord "ephemeral offline_secs ${EPH_T} loaded 0"
dc logs --no-color coord 2>&1 | read_all grep -q '^policy load failed' && fail "The policy did not load."

echo "=== Gate 1 [C]: the default token is not ephemeral ==="
dc exec -T coord mkdir -p /var/lib/orblx/tokens
for n in a b n1; do token "$n"; done
for n in e1 e2 e3 e4; do token "$n" --ephemeral; done
declare -A NODE_IP=([a]=172.30.218.4 [b]=172.30.218.5 [n1]=172.30.218.6 [e1]=172.30.218.11 [e2]=172.30.218.12 [e3]=172.30.218.13 [e4]=172.30.218.14)
for n in a b n1 e1 e2 e3 e4; do enroll "$n" "${NODE_IP[$n]}"; done
store_nodes | sed 's/^/store /'
for n in a b n1; do store_nodes | has_line "^$n false " || fail "Node ${n} is ephemeral."; done
for n in e1 e2 e3 e4; do store_nodes | has_line "^$n true " || fail "Node ${n} is not ephemeral."; done
echo "[C] gate1 ok"

echo "=== [C] start a, b, n1, e1 to e4 ==="
dc --profile nodes up -d a b n1 e1 e2 e3 e4
a_ip="$(ip_of a)"; b_ip="$(ip_of b)"; e1_ip="$(ip_of e1)"; e2_ip="$(ip_of e2)"
echo "overlay a ${a_ip} b ${b_ip} e1 ${e1_ip} e2 ${e2_ip}"
for _ in $(seq 1 60); do
  dc exec -T a ping -n -c 1 -W 1 "$b_ip" >/dev/null 2>&1 \
    && dc exec -T a ping -n -c 1 -W 1 "$e1_ip" >/dev/null 2>&1 && break
  sleep 1
done
echo "---- [C] overlay ping a to b, e1, e2 ----"
dc exec -T a ping -n -c 5 -i 0.2 -W 1 "$b_ip" | tail -n 2
dc exec -T a ping -n -c 5 -i 0.2 -W 1 "$e1_ip" | tail -n 2
dc exec -T a ping -n -c 5 -i 0.2 -W 1 "$e2_ip" | tail -n 2
for peer in b e1; do
  peer_in_netmap a "$peer" || fail "The netmap of a does not have ${peer}."
done
peer_in_netmap b e1 || fail "The netmap of b does not have e1."

echo "=== Gate 4 [C] start: n1 (not ephemeral) stops ==="
dc --profile nodes kill n1 >/dev/null
n1_stop_ms="$(now_ms)"
echo "n1_stop_ms ${n1_stop_ms}"

echo "=== Gate 2 [C]: e1 stops, the coordinator removes it ==="
# Watch the netmaps of a and b each 20 ms. The file has the time e1 left each netmap.
as_root sh -c "
  a_done=0; b_done=0
  while [ \$a_done = 0 ] || [ \$b_done = 0 ]; do
    if [ \$a_done = 0 ] && jq -e '[.peers[].name] | index(\"e1\") == null' '$EPH_LAB/a/netmap.json' >/dev/null 2>&1; then
      echo a \$(date +%s%3N) >> '$WORK/netmap-gone'; a_done=1
    fi
    if [ \$b_done = 0 ] && jq -e '[.peers[].name] | index(\"e1\") == null' '$EPH_LAB/b/netmap.json' >/dev/null 2>&1; then
      echo b \$(date +%s%3N) >> '$WORK/netmap-gone'; b_done=1
    fi
    sleep 0.02
  done" &
watcher=$!
dc --profile nodes stop -t 10 e1 >/dev/null
e1_stop_ms="$(now_ms)"
wait_removed e1 $((EPH_T + 40))
e1_seen_removed_ms="$(now_ms)"
wait "$watcher"
removed_ms="$(coord_line_ms 'ephemeral removed e1 ')" || fail "The coordinator did not log the removal of e1."
dc logs --no-color coord 2>&1 | grep -F 'ephemeral removed e1 '
as_root cat "$WORK/netmap-gone"
gone_a="$(as_root awk '$1 == "a" {print $2}' "$WORK/netmap-gone")"
gone_b="$(as_root awk '$1 == "b" {print $2}' "$WORK/netmap-gone")"
netmap_a=$((gone_a - removed_ms)); netmap_b=$((gone_b - removed_ms))
(( netmap_a < 0 )) && netmap_a=0
(( netmap_b < 0 )) && netmap_b=0
echo "e1 stop_to_removal_ms $((removed_ms - e1_stop_ms)) (T ${T_MS} ms, a stopped node holds a poll for up to 20000 ms)"
echo "e1 removal_to_netmap_ms a ${netmap_a} b ${netmap_b} (limit ${NETMAP_LIMIT_MS})"
(( removed_ms - e1_stop_ms > T_MS )) || fail "The coordinator removed e1 before T."
(( netmap_a <= NETMAP_LIMIT_MS && netmap_b <= NETMAP_LIMIT_MS )) || fail "A peer kept e1 in the netmap for more than ${NETMAP_LIMIT_MS} ms."
records="$(remove_records e1)"
echo "e1 node-remove records $(remove_count e1): ${records}"
[[ "$(remove_count e1)" -eq 1 ]] || fail "The removal of e1 did not write exactly 1 record."
[[ "$records" == "reason ephemeral offline_ms "* ]] || fail "The record does not have reason ephemeral."
offline_rec="$(awk '{print $4}' <<<"$records")"
(( offline_rec > T_MS )) || fail "The record has offline_ms ${offline_rec}, not more than T."
lab_cat coord/deny.json | jq -r '.revoked_uris[]' | has_line '^spiffe://orblx.local/node/e1$' \
  || fail "The deny list does not have e1."

echo "---- [C] e1 starts again with its old SVID ----"
renew_fail0="$(dc --profile nodes logs --no-color e1 2>&1 | grep -c 'The SVID renewal failed' || true)"
clear_stale_pid e1
dc --profile nodes start e1 >/dev/null
for _ in $(seq 1 $((EPH_SVID_TTL + 15))); do
  got="$(dc --profile nodes logs --no-color e1 2>&1 | grep -c 'The SVID renewal failed' || true)"
  [[ "$got" -gt "$renew_fail0" ]] && break
  sleep 1
done
echo "---- [C] e1 log after the start (full) ----"
dc --profile nodes logs --since "$(date -u -d "@$((removed_ms / 1000))" +%Y-%m-%dT%H:%M:%SZ)" --no-color e1 2>&1 || true
echo "e1 renew_fail_lines before ${renew_fail0} after ${got}"
[[ "$got" -gt "$renew_fail0" ]] || fail "e1 did not try to renew."
dc --profile nodes logs --no-color e1 2>&1 | read_all grep -q 'The node renewed the SVID' \
  && [[ "$(dc --profile nodes logs --no-color e1 2>&1 | grep -c 'The node renewed the SVID' || true)" -gt 0 ]] \
  && echo "note: e1 renewed before the removal (expected with SVID life ${EPH_SVID_TTL} s)"
renewed_after="$(dc --profile nodes logs --since "$(date -u -d "@$((removed_ms / 1000))" +%Y-%m-%dT%H:%M:%SZ)" --no-color e1 2>&1 | grep -c 'The node renewed the SVID' || true)"
echo "e1 renew_ok_after_removal ${renewed_after}"
[[ "$renewed_after" -eq 0 ]] || fail "e1 renewed its SVID after the removal."
rx0="$(dc --profile nodes exec -T e1 cat /sys/class/net/orblx0/statistics/rx_bytes 2>/dev/null || echo none)"
ping_e1="$(dc exec -T a ping -n -c 20 -i 0.2 -W 1 "$e1_ip" 2>&1 || true)"
rx1="$(dc --profile nodes exec -T e1 cat /sys/class/net/orblx0/statistics/rx_bytes 2>/dev/null || echo none)"
printf '%s\n' "$ping_e1" | tail -n 2
e1_replies="$(printf '%s\n' "$ping_e1" | awk '/packets transmitted/ {print $4}')"
echo "e1 orblx0 rx_bytes before ${rx0} after ${rx1}"
[[ "$e1_replies" == 0 ]] || fail "e1 answered ${e1_replies} pings after the removal."
if [[ "$rx0" != none && "$rx1" != none ]]; then
  echo "e1 rx_bytes_after_removal $((rx1 - rx0))"
  [[ "$((rx1 - rx0))" -eq 0 ]] || fail "e1 got bytes after the removal."
else
  echo "e1 rx_bytes_after_removal 0 (e1 has no orblx0: $(dc --profile nodes ps -a --format '{{.Service}} {{.State}}' e1))"
fi
dc --profile nodes stop -t 10 e1 >/dev/null

echo "---- [C] the name e1 cannot enroll again; a new node gets the address ----"
token e1 --ephemeral
re_out="$(enroll e1 172.30.218.11 || true)"
echo "re-enroll e1: ${re_out}"
[[ "$re_out" == *"The node name is revoked."* ]] || fail "The name e1 enrolled again."
token r1
r1_out="$(enroll r1 172.30.218.21)"
echo "$r1_out"
r1_ip="$(awk '$1 == "overlay_ip" {print $2}' <<<"$r1_out")"
echo "e1_ip ${e1_ip} r1_ip ${r1_ip}"
[[ "$r1_ip" == "$e1_ip" ]] || fail "The address of e1 was not used again."
echo "[C] gate2 ok"

echo "=== Gate 3 [C]: e2 stops and comes back before T ==="
dc --profile nodes stop -t 10 e2 >/dev/null
e2_stop_ms="$(now_ms)"
off=none
for _ in $(seq 1 300); do
  off="$(offline_ms_of e2)"
  [[ "$off" =~ ^[0-9]+$ ]] && (( off >= T_MS / 2 )) && break
  sleep 0.1
done
echo "e2 offline_ms_at_restart ${off} (T ${T_MS}) stop_to_restart_ms $(( $(now_ms) - e2_stop_ms ))"
[[ "$off" =~ ^[0-9]+$ ]] && (( off >= T_MS / 2 && off < T_MS )) || fail "e2 did not reach T/2 offline."
clear_stale_pid e2
dc --profile nodes start e2 >/dev/null
max_off=0
for _ in $(seq 1 $((EPH_T * 3 * 10))); do
  o="$(offline_ms_of e2)"
  [[ "$o" =~ ^[0-9]+$ ]] && (( o > max_off )) && max_off="$o"
  sleep 0.1
done
for _ in $(seq 1 30); do
  dc exec -T a ping -n -c 1 -W 1 "$e2_ip" >/dev/null 2>&1 && break
  sleep 1
done
e2_ping="$(dc exec -T a ping -n -c 5 -i 0.2 -W 1 "$e2_ip" 2>&1 || true)"
printf '%s\n' "$e2_ping" | tail -n 2
[[ "$(printf '%s\n' "$e2_ping" | awk '/packets transmitted/ {print $4}')" -gt 0 ]] || fail "e2 did not answer after the start."
echo "e2 in_store $(in_store e2 && echo yes || echo no) node-remove $(remove_count e2) max_offline_ms ${max_off}"
in_store e2 || fail "The coordinator removed e2."
[[ "$(remove_count e2)" -eq 0 ]] || fail "The chain has a removal of e2."
echo "[C] gate3 ok"

echo "=== Gate 5 [C]: coordinator restart keeps the offline time ==="
dc --profile nodes kill e3 >/dev/null
for _ in $(seq 1 300); do
  off="$(offline_ms_of e3)"
  [[ "$off" =~ ^[0-9]+$ ]] && (( off >= T_MS / 3 )) && break
  sleep 0.1
done
dc kill -s SIGKILL coord >/dev/null
kill_ms="$(now_ms)"
saved="$(lab_cat coord/ephemeral.json)"
off_before="$(offline_ms_of e3)"
e4_before="$(offline_ms_of e4)"
echo "coord killed. e3 offline_ms_at_save ${off_before} e4 offline_ms_at_save ${e4_before}"
jq -c . <<<"$saved"
[[ "$off_before" =~ ^[0-9]+$ ]] && (( off_before < T_MS )) || fail "e3 was not offline less than T at the kill."
sleep $((EPH_T * 2))
dc start coord >/dev/null
wait_log_count coord "ephemeral offline_secs ${EPH_T} loaded" 2 30
dc logs --no-color coord 2>&1 | grep -F "ephemeral offline_secs ${EPH_T} loaded"
start_ms="$(coord_line_ms "ephemeral offline_secs ${EPH_T} loaded")"
echo "coord down_ms $((start_ms - kill_ms))"
(( start_ms > kill_ms )) || fail "The start time of the coordinator is not after the kill."
wait_removed e3 $((EPH_T + 10))
removed3_ms="$(coord_line_ms 'ephemeral removed e3 ')" || fail "The coordinator did not log the removal of e3."
dc logs --no-color coord 2>&1 | grep -F 'ephemeral removed e3 '
expect=$((T_MS - off_before))
delay=$((removed3_ms - start_ms))
echo "e3 start_to_removal_ms ${delay} expected_ms ${expect} late_limit_ms ${RESTART_LATE_MS}"
rec3="$(remove_records e3)"
echo "e3 node-remove records $(remove_count e3): ${rec3}"
off3="$(awk '{print $4}' <<<"$rec3")"
(( off3 > T_MS )) || fail "The coordinator removed e3 early (offline_ms ${off3})."
(( delay + 100 >= expect )) || fail "The coordinator removed e3 ${delay} ms after the start, before ${expect} ms."
(( delay <= expect + RESTART_LATE_MS )) || fail "The coordinator removed e3 late: ${delay} ms, expected ${expect} ms."
[[ "$(remove_count e3)" -eq 1 ]] || fail "The removal of e3 did not write exactly 1 record."
sleep $((EPH_T + 2))
echo "e4 in_store $(in_store e4 && echo yes || echo no) node-remove $(remove_count e4)"
in_store e4 || fail "The coordinator removed e4, which ran through the restart."
for _ in $(seq 1 30); do
  dc exec -T a ping -n -c 1 -W 1 "$b_ip" >/dev/null 2>&1 && break
  sleep 1
done
dc exec -T a ping -n -c 10 -i 0.2 -W 1 "$b_ip" | tail -n 2
echo "[C] gate5 ok"

echo "=== Gate 6 [C]: ${LOAD_NODES} ephemeral clients stop at once, c pings d ==="
dc exec -T coord sh -c "for i in \$(seq 1 ${LOAD_NODES}); do orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/load\$i --ttl 3600 --ephemeral >/dev/null || exit 1; done"
dc --profile load up -d load
# Each client starts its watch right after its own enroll. With a short T, a client that waits
# for the other enrolls would be offline for longer than T and the coordinator would remove it.
dc --profile load exec -d load sh -c "mkdir -p /tmp/load; for i in \$(seq 1 ${LOAD_NODES}); do orblx coord enroll --name load\$i --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/load\$i --state /tmp/load/\$i --endpoint 172.30.218.9:\$((20000 + i)) >/tmp/load/\$i.enroll 2>&1 || { echo enroll_failed >/tmp/load/\$i.enroll; continue; }; orblx coord netmap --coord ${COORD} --bundle /tmp/load/\$i/bundle.pem --state /tmp/load/\$i --watch >/tmp/load/\$i.log 2>&1 & done; wait"
for _ in $(seq 1 60); do
  # Count the clients that got a first policy, not the policy lines (a client can get more than one).
  ups="$(dc --profile load exec -T load sh -c 'grep -l "^policy_update " /tmp/load/*.log 2>/dev/null | wc -l' | tr -d '[:space:]' || true)"
  ups="${ups:-0}"
  [[ "$ups" -ge "$LOAD_NODES" ]] && break
  sleep 1
done
echo "load_first_updates ${ups}"
echo "load_enroll_failed $(dc --profile load exec -T load sh -c 'cat /tmp/load/*.enroll 2>/dev/null' | grep -c '^enroll_failed' || true)"
[[ "$ups" -ge "$LOAD_NODES" ]] || fail "Not all load clients got the first policy."
load_eph="$(store_nodes | awk '$1 ~ /^load/ && $2 == "true"' | awk 'END {print NR}')"
echo "load_ephemeral_in_store ${load_eph}"
[[ "$load_eph" -eq "$LOAD_NODES" ]] || fail "Not all load clients are ephemeral."
# c and d are new nodes that are not ephemeral. They enroll here, so their capability
# tickets are new. The node ticket life is the SVID life (EPH_SVID_TTL), and an SVID renew
# does not give the node a new ticket (see docs/w25-ephemeral-nodes.md). The tickets of a
# and b from gate 1 have expired at this point, so a new handshake of a and b fails.
for n in c d; do token "$n"; done
enroll c 172.30.218.7
enroll d 172.30.218.8
for n in c d; do store_nodes | has_line "^$n false " || fail "Node ${n} is ephemeral."; done
dc --profile nodes up -d c d
d_ip="$(ip_of d)"
for _ in $(seq 1 60); do
  dc exec -T c ping -n -c 1 -W 1 "$d_ip" >/dev/null 2>&1 && break
  sleep 1
done
dc exec -T c ping -n -c 5 -i 0.2 -W 1 "$d_ip" | tail -n 2
for _ in $(seq 1 30); do
  [[ "$(load_peers c)" -eq "$LOAD_NODES" ]] && break
  sleep 0.5
done
echo "netmap_load_peers_before c $(load_peers c) d $(load_peers d)"
[[ "$(load_peers c)" -eq "$LOAD_NODES" ]] || fail "The netmap of c does not have all load clients."
PINGS=600
dc exec -d c sh -c "ping -n -i 0.05 -W 1 -c ${PINGS} ${d_ip} >/tmp/ping-g6.log 2>&1"
sleep 2
# A new config record changes the deny list version of each node, so each load client
# starts a new poll now. Then the 20 polls end at about the same time.
token sync1
enroll sync1 172.30.218.22
sleep 0.5
dc --profile load kill load >/dev/null
load_stop_ms="$(now_ms)"
for _ in $(seq 1 $(( (EPH_T + 40) * 10 ))); do
  left="$(store_nodes | awk '$1 ~ /^load/' | awk 'END {print NR}')"
  [[ "$left" -eq 0 ]] && break
  sleep 0.1
done
echo "load_left_in_store ${left}"
[[ "$left" -eq 0 ]] || fail "The coordinator did not remove all load clients."
dc logs -t --no-color coord 2>&1 | grep -F 'ephemeral removed load' >"$WORK/load-removed.txt" || true
# A line of `docker compose logs -t` is: coord-1 | TIME text.
first_rm="$(awk 'NR == 1 {print $3}' "$WORK/load-removed.txt")"
last_rm="$(awk 'END {print $3}' "$WORK/load-removed.txt")"
first_rm_ms="$(date -d "$first_rm" +%s%3N)"; last_rm_ms="$(date -d "$last_rm" +%s%3N)"
echo "load_removed $(awk 'END {print NR}' "$WORK/load-removed.txt") stop_to_first_ms $((first_rm_ms - load_stop_ms)) stop_to_last_ms $((last_rm_ms - load_stop_ms)) spread_ms $((last_rm_ms - first_rm_ms))"
for i in $(seq 1 "$LOAD_NODES"); do
  [[ "$(remove_count "load$i")" -eq 1 ]] || fail "load${i} does not have exactly 1 removal record."
done
for _ in $(seq 1 30); do
  [[ "$(load_peers a)" -eq 0 && "$(load_peers b)" -eq 0 && "$(load_peers c)" -eq 0 && "$(load_peers d)" -eq 0 ]] && break
  sleep 0.2
done
echo "netmap_load_peers a $(load_peers a) b $(load_peers b) c $(load_peers c) d $(load_peers d)"
[[ "$(load_peers a)" -eq 0 && "$(load_peers b)" -eq 0 && "$(load_peers c)" -eq 0 && "$(load_peers d)" -eq 0 ]] \
  || fail "A peer kept a load client in the netmap."
for _ in $(seq 1 120); do
  dc exec -T c sh -c 'cat /tmp/ping-g6.log' | read_all grep -q 'packets transmitted' && break
  sleep 1
done
dc exec -T c sh -c 'tail -n 2 /tmp/ping-g6.log' | steady_ping_gate "c->d during the removal of ${LOAD_NODES} nodes" "$PINGS" 0 1000 \
  || fail "c lost pings to d while the coordinator removed the load clients."
echo "[C] gate6 ok"

echo "=== Gate 4 [C]: n1 (not ephemeral) stays after 10 x T ==="
n1_off=$(( $(now_ms) - n1_stop_ms ))
echo "n1 stopped_ms ${n1_off} (10 x T is $((10 * T_MS)) ms) in_store $(in_store n1 && echo yes || echo no) node-remove $(remove_count n1)"
(( n1_off > 10 * T_MS )) || fail "n1 was not stopped for 10 x T."
in_store n1 || fail "KILL: the coordinator removed n1, which is not ephemeral."
echo "---- [C] every node-remove target was ephemeral ----"
lab_cat coord/config-audit.jsonl | jq -r 'select(.action == "node-remove") | .target' | sort >"$WORK/removed-names"
lab_cat coord/config-audit.jsonl | jq -r 'select(.action == "enroll") | .target' | sort >"$WORK/enrolled-names"
echo "node_remove_total $(awk 'END {print NR}' "$WORK/removed-names") unique $(sort -u "$WORK/removed-names" | awk 'END {print NR}')"
for n in a b c d n1 r1 sync1 e2 e4; do
  [[ "$(remove_count "$n")" -eq 0 ]] || fail "KILL: the chain has a removal of ${n}."
done
expected_removed="$(printf '%s\n' e1 e3 $(seq -f 'load%g' 1 "$LOAD_NODES") | sort)"
[[ "$(cat "$WORK/removed-names")" == "$expected_removed" ]] || fail "The removed names are not e1, e3, and the load clients."
echo "[C] gate4 ok"

echo "=== [C] audit verify-config ==="
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
printf '%s\n' "$verify_out"
[[ "${verify_out%%$'\n'*}" == ok ]] || fail "audit verify-config did not print ok"

echo "=== [C] logs hold no key or enroll token ==="
dc --profile nodes --profile load logs --no-color >"$WORK/all-logs.out" 2>&1 || fail "docker compose logs failed."
echo "log_lines $(awk 'END {print NR}' "$WORK/all-logs.out")"
secret_scan "$WORK/all-logs.out" || fail "A log holds a private key or an enroll token, or the log is empty."
if [[ -n "${PROOF_LOG:-}" && -s "${PROOF_LOG}" ]]; then
  secret_scan "$PROOF_LOG" || fail "The proof log holds a private key or an enroll token."
fi

echo "summary T_ms ${T_MS} e1_stop_to_removal_ms $((removed_ms - e1_stop_ms)) removal_to_netmap_ms a ${netmap_a} b ${netmap_b} e1_renew_after_removal 0 e1_replies 0 e2_kept 1 n1_kept 1 e3_restart_delay_ms ${delay} expected_ms ${expect} load_removed ${LOAD_NODES} c_d_lost 0"
echo "proof_ok"

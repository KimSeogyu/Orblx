#!/usr/bin/env bash
# Revoke follow-up proof (W25-2).
# Node a is the principal. Node c is another principal. Node b runs the orblx SSH server.
# Gate 1: open SSH sessions of a on b close within LIMIT_MS after revoke_done_ms.
#   One session is an interactive shell with a terminal. One session is a command.
#   Each session writes the time in ms to a file on b each 50 ms. The last time in the
#   file is the close time. The open session of c must not close.
# Gate 2: `orblx admin revoke-undo a` restores SSH access of a, with exactly 1 new
#   coordinator record (action unrevoke). The chain verifies ok.
# Gate 3: 50 more enrolled nodes fetch the deny file. Mode poll: each 500 ms (the W24-D loop).
#   Mode wait: `deny-wait` with the ETag (the W25-2 loop of `orblx up`).
#   The script prints the coordinator CPU in percent of one core for each mode.
#   The last mode must be within 5 percent.
# The script deletes the orblx-w25a-revoke-followup volumes at the start.
# The script does not print enroll tokens, private keys, or SVID material.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.revoke-followup.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROFILE="${ORBLX_PROOF_PROFILE:-release}"
LIMIT_MS=1000
STATE=/var/lib/orblx
LOAD=/var/lib/load
LOAD_NODES="${ORBLX_LOAD_NODES:-50}"
LOAD_SECS="${ORBLX_LOAD_SECS:-60}"
BASE_SECS=30
CPU_LIMIT_PCT=5
# The node loop of W25-2 is `wait`. `poll` is the W24-D loop, measured for the gate decision.
POLL_MODES="${ORBLX_POLL_MODES:-poll wait}"

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
trap cleanup EXIT

now_ms() {
  date +%s%3N
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir flag=()
  if [[ "$PROFILE" == release ]]; then
    flag=(--release)
  fi
  cargo build "${flag[@]}" -p orblx-cli --bin orblx --locked
  cargo build "${flag[@]}" -p orblx-coord --example deny_poll --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$TARGET_DIR/$PROFILE/orblx")"
  cp "$TARGET_DIR/$PROFILE/examples/deny_poll" "$image_dir/deny_poll"
  printf '%s\n' 'COPY deny_poll /usr/local/bin/deny_poll' >>"$image_dir/Dockerfile"
  as_root docker build -q -t orblx-w25a-revoke:w25 "$image_dir"
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
    if dc logs "$service" 2>&1 | grep -q "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  return 1
}

wait_path() {
  local from="$1"
  local to="$2"
  local i
  for i in $(seq 1 60); do
    if dc exec -T "$from" orblx status --state-dir "$STATE" 2>/dev/null \
      | grep -q "^peer ${to} .* path direct "; then
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

ssh_cmd() {
  printf '%s' "orblx ssh root@b --identity /tmp/sshid --netmap $STATE/netmap.json --peer-cert /tmp/b-cert.pem"
}

# Print the coordinator utime plus stime in clock ticks.
coord_ticks() {
  dc exec -T coord sh -c '
    for p in /proc/[0-9]*; do
      if tr "\0" " " <"$p/cmdline" 2>/dev/null | grep -q "orblx coord serve"; then
        sed "s/.*) //" "$p/stat" | awk "{print \$12 + \$13}"
        exit 0
      fi
    done
    exit 1'
}

# Print the last ms value in a tick file on b. Print 0 when the file is missing.
# A writer truncates the file before it writes, so one read can be empty.
# Read again until the value is not empty.
tick() {
  dc exec -T b sh -c "for n in 1 2 3 4 5 6 7 8 9 10; do v=\$(cat $1 2>/dev/null); [ -n \"\$v\" ] && break; sleep 0.01; done; echo \${v:-0}" | tr -d '\r\n '
}

cp "$ROOT/scripts/proof/revoke-followup.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image (${PROFILE}) ==="
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
  | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}')"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

for name in owner a b c; do
  enroll_node "$name"
done
nodes="$(owner nodes)"
printf '%s\n' "$nodes"

for name in a b c; do
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE" >/dev/null
  echo "netmap ${name} written"
done

echo "=== [C] node b: SSH policy file ==="
dc run --rm --no-deps --entrypoint sh -T b -c "cat > $STATE/policy.hujson" <"$POLICY_FILE"
echo "policy b written"

echo "=== [C] start nodes a, b, and c ==="
dc up -d a b c load
for name in a b c; do
  wait_log "$name" 'The TUN device'
done
wait_path a b
wait_path c b
wait_log b 'ssh_listen '

echo "=== [C] SSH identity and peer certificate on a and c ==="
dc exec -T b cat "$STATE/cert.pem" >"$WORK/b-cert.pem"
for name in a c; do
  dc exec -T "$name" sh -c "cat > /tmp/b-cert.pem" <"$WORK/b-cert.pem"
  # An SSH login with a node SVID has no ticket, so the directory holds only the SVID and the bundle.
  dc exec -T "$name" sh -c "rm -rf /tmp/sshid && mkdir -p /tmp/sshid && cp $STATE/cert.pem $STATE/key.pem $STATE/bundle.pem /tmp/sshid/"
  dc exec -T "$name" sh -c "$(ssh_cmd) --command 'echo ssh_ok'"
done

echo "=== [C] gate 1: open sessions, then one revoke-all ==="
LOOP='i=0; while [ $i -lt 400 ]; do date +%s%3N >FILE; sleep 0.05; i=$((i + 1)); done; echo finished'
# Shell session of a: the client gets a terminal from script(1). The input pipe stays open.
shell_loop="${LOOP//FILE//tmp/w25b-tick-a-shell}"
# The input waits 2 s, so the remote shell is open before the first line comes.
dc exec -T a sh -c "(sleep 2; printf '%s\n' '${shell_loop}'; sleep 40) \
  | script -qfec \"$(ssh_cmd) --shell\" /dev/null >/tmp/shell-a.out 2>&1; echo client_exit_ms \$(date +%s%3N) >>/tmp/shell-a.out" &
shell_pid=$!
cmd_loop="${LOOP//FILE//tmp/w25b-tick-a-cmd}"
dc exec -T a sh -c "$(ssh_cmd) --command '${cmd_loop}' >/tmp/cmd-a.out 2>&1; echo client_exit_ms \$(date +%s%3N) >>/tmp/cmd-a.out" &
cmd_pid=$!
c_loop="${LOOP//FILE//tmp/w25b-tick-c-cmd}"
dc exec -T c sh -c "$(ssh_cmd) --command '${c_loop}'" >"$WORK/cmd-c.out" 2>&1 &
c_pid=$!
sleep 5
for file in /tmp/w25b-tick-a-shell /tmp/w25b-tick-a-cmd /tmp/w25b-tick-c-cmd; do
  first="$(tick "$file")"
  sleep 0.3
  second="$(tick "$file")"
  echo "session ${file} before revoke tick ${first} then ${second}"
  if [[ "$second" -le "$first" ]]; then
    echo "The session that writes ${file} does not run before the revoke." >&2
    dc exec -T a sh -c 'cat /tmp/shell-a.out /tmp/cmd-a.out' 2>&1 | grep -v 'PRIVATE KEY' | tail -20 || true
    exit 1
  fi
done
audit_before="$(owner audit --verify)"
records_before_revoke="$(printf '%s\n' "$audit_before" | awk '$1 == "verify" && $2 == "ok" {print $4}')"

revoke_out="$(owner revoke-all a)"
printf '%s\n' "$revoke_out"
revoke_start="$(printf '%s\n' "$revoke_out" | field revoke_start_ms)"
revoke_done="$(printf '%s\n' "$revoke_out" | field revoke_done_ms)"
printf '%s\n' "$revoke_out" | grep -qx 'revoked_all spiffe://orblx.local/node/a'
sleep 3

results=()
for kind in shell cmd; do
  file="/tmp/w25b-tick-a-${kind}"
  last="$(tick "$file")"
  sleep 0.5
  again="$(tick "$file")"
  if [[ "$again" != "$last" ]]; then
    echo "The ${kind} session of a still runs after the revoke." >&2
    exit 1
  fi
  if (( last < revoke_start - 200 )); then
    echo "The ${kind} session of a stopped before the revoke." >&2
    exit 1
  fi
  close_ms=$(( last - revoke_done ))
  echo "session a ${kind} last_tick_ms ${last} revoke_done_ms ${revoke_done} close_after_done_ms ${close_ms}"
  if (( close_ms > LIMIT_MS )); then
    echo "The ${kind} session of a did not close within ${LIMIT_MS} ms." >&2
    exit 1
  fi
  results+=("ssh_${kind}=${close_ms}")
done
c_tick="$(tick /tmp/w25b-tick-c-cmd)"
echo "session c cmd tick_ms ${c_tick} after_done_ms $(( c_tick - revoke_done ))"
if (( c_tick - revoke_done < 2500 )); then
  echo "The session of c stopped after the revoke of a." >&2
  exit 1
fi
wait "$c_pid" || true
cat "$WORK/cmd-c.out"
grep -q '^finished' "$WORK/cmd-c.out"
echo "session c finished ok"
wait "$shell_pid" || true
wait "$cmd_pid" || true
dc exec -T a sh -c 'grep client_exit_ms /tmp/shell-a.out /tmp/cmd-a.out' | sed 's/^/client /'

echo "=== [C] node b: SSH chain has the revoked session ends ==="
dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" | tee "$WORK/ssh-verify.txt"
grep -qx 'ok' "$WORK/ssh-verify.txt"
dc exec -T b cat "$STATE/ssh-audit.jsonl" >"$WORK/ssh-audit.jsonl"
ssh_revoked="$(jq -s '[.[] | select(.reason == "revoked")] | length' "$WORK/ssh-audit.jsonl")"
echo "ssh_chain revoked ${ssh_revoked}"
[[ "$ssh_revoked" -ge 2 ]]

echo "=== [C] gate 2: SSH of a is refused, then revoke-undo restores it ==="
if dc exec -T a sh -c "timeout 15 $(ssh_cmd) --command 'echo ssh_ok'" >"$WORK/ssh-refused.txt" 2>&1; then
  echo "Node a logged in after the revoke." >&2
  exit 1
fi
echo "ssh a after revoke refused"
audit_mid="$(owner audit --verify)"
records_before="$(printf '%s\n' "$audit_mid" | awk '$1 == "verify" && $2 == "ok" {print $4}')"
echo "coord_records before_revoke ${records_before_revoke} before_undo ${records_before}"
undo_out="$(owner revoke-undo a)"
printf '%s\n' "$undo_out"
undo_done="$(printf '%s\n' "$undo_out" | field revoke_done_ms)"
printf '%s\n' "$undo_out" | grep -qx 'unrevoked spiffe://orblx.local/node/a'
printf '%s\n' "$undo_out" | grep -qx 'svid_restored yes'
restored=""
for _ in $(seq 1 150); do
  if dc exec -T a sh -c "timeout 5 $(ssh_cmd) --command 'echo ssh_ok'" >"$WORK/ssh-restore.txt" 2>&1 \
    && grep -q '^ssh_ok' "$WORK/ssh-restore.txt"; then
    restored="$(now_ms)"
    break
  fi
  sleep 0.2
done
if [[ -z "$restored" ]]; then
  echo "SSH of a did not come back after the undo." >&2
  exit 1
fi
restore_ms=$(( restored - undo_done ))
echo "ssh a restored after_undo_ms ${restore_ms}"
if owner revoke-undo a >"$WORK/undo-again.txt" 2>&1; then
  echo "A second undo did not fail." >&2
  exit 1
fi
echo "second undo refused"
dc exec -T coord cat "$STATE/config-audit.jsonl" >"$WORK/config-audit.jsonl"
audit_after="$(owner audit --verify)"
grep -q '^verify ok ' <<<"$audit_after"
records_after="$(printf '%s\n' "$audit_after" | awk '$1 == "verify" && $2 == "ok" {print $4}')"
new_records=$(( records_after - records_before ))
unrevoke_records="$(jq -s '[.[] | select(.action == "unrevoke")] | length' "$WORK/config-audit.jsonl")"
jq -c 'select(.action == "unrevoke") | {action, actor, target, detail}' "$WORK/config-audit.jsonl"
echo "coord_records before_undo ${records_before} after ${records_after} new ${new_records} unrevoke_records ${unrevoke_records}"
[[ "$new_records" -eq 1 && "$unrevoke_records" -eq 1 ]]
jq -s -e '[.[] | select(.action == "unrevoke")][0]
  | .target == "spiffe://orblx.local/node/a"
  and .actor == "spiffe://orblx.local/node/owner"' "$WORK/config-audit.jsonl" >/dev/null

echo "=== [C] gate 3: ${LOAD_NODES} more nodes fetch the deny file (${POLL_MODES}) ==="
dirs=()
for i in $(seq 1 "$LOAD_NODES"); do
  dc exec -T coord orblx coord token create --state "$STATE" --ttl 3600 \
    --out "$STATE/tokens/l${i}" >/dev/null
  dc exec -T load orblx coord enroll --name "l${i}" --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/l${i}" \
    --state "$LOAD/l${i}" --endpoint "load:443" >/dev/null
  dirs+=("$LOAD/l${i}")
done
echo "load nodes enrolled ${#dirs[@]}"
hz="$(dc exec -T coord getconf CLK_TCK | tr -d '\r\n')"
sleep 5
base_start="$(coord_ticks)"
sleep "$BASE_SECS"
base_end="$(coord_ticks)"
base_pct="$(awk -v t=$(( base_end - base_start )) -v hz="$hz" -v s="$BASE_SECS" 'BEGIN {printf "%.2f", t * 100 / hz / s}')"
echo "coord_cpu base nodes 3 ticks $(( base_end - base_start )) hz ${hz} seconds ${BASE_SECS} cpu_pct ${base_pct}"
poll_lines=()
for mode in $POLL_MODES; do
  load_start="$(coord_ticks)"
  start_ms="$(now_ms)"
  poll_out="$(dc exec -T load deny_poll "${coord_ip}:443" coord 500 "$LOAD_SECS" "${dirs[@]}" --mode "$mode")"
  end_ms="$(now_ms)"
  load_end="$(coord_ticks)"
  printf '%s\n' "$poll_out"
  secs="$(awk -v ms=$(( end_ms - start_ms )) 'BEGIN {printf "%.3f", ms / 1000}')"
  ticks=$(( load_end - load_start ))
  load_pct="$(awk -v t="$ticks" -v hz="$hz" -v s="$secs" 'BEGIN {printf "%.2f", t * 100 / hz / s}')"
  net_pct="$(awk -v a="$load_pct" -v b="$base_pct" 'BEGIN {printf "%.2f", a - b}')"
  client_ticks="$(printf '%s\n' "$poll_out" | awk '{for (i = 1; i < NF; i++) if ($i == "client_cpu_ticks") print $(i + 1)}')"
  client_pct="$(awk -v t="$client_ticks" -v hz="$hz" -v s="$secs" -v n="$LOAD_NODES" 'BEGIN {printf "%.3f", t * 100 / hz / s / n}')"
  poll_fail="$(printf '%s\n' "$poll_out" | awk '{for (i = 1; i < NF; i++) if ($i == "fail") print $(i + 1)}')"
  echo "coord_cpu load mode ${mode} nodes $(( LOAD_NODES + 3 )) ticks ${ticks} seconds ${secs} cpu_pct ${load_pct} net_of_base_pct ${net_pct} client_cpu_pct_per_node ${client_pct}"
  [[ "$poll_fail" -eq 0 ]]
  if awk -v p="$load_pct" -v l="$CPU_LIMIT_PCT" 'BEGIN {exit !(p > l)}'; then
    poll_gate="over_${CPU_LIMIT_PCT}_pct"
  else
    poll_gate="within_${CPU_LIMIT_PCT}_pct"
  fi
  echo "poll_cost mode ${mode} cpu_pct ${load_pct} limit_pct ${CPU_LIMIT_PCT} result ${poll_gate}"
  poll_lines+=("${mode}=${load_pct}%:${poll_gate}")
done

echo "=== [C] logs hold no key or enroll token ==="
{
  dc logs 2>&1
  cat "$WORK"/*.out "$WORK"/*.txt "$WORK"/*.jsonl 2>/dev/null
  dc exec -T a cat /tmp/shell-a.out /tmp/cmd-a.out
} >"$WORK/all-logs.log"
for name in owner a b c l1 "l${LOAD_NODES}"; do
  token="$(dc exec -T coord cat "$STATE/tokens/${name}" 2>/dev/null | tr -d ' \n' || true)"
  if [[ -n "$token" ]] && grep -qF "$token" "$WORK/all-logs.log"; then
    echo "A log holds the ${name} enroll token." >&2
    exit 1
  fi
done
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.log" || true)"
echo "secret_grep tokens 0 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]]

echo "summary principal spiffe://orblx.local/node/a ${results[*]} limit_ms ${LIMIT_MS} other_session_ok undo_new_records ${new_records} unrevoke_records ${unrevoke_records} undo_restore_ms ${restore_ms} poll_cost ${poll_lines[*]}"
# The last mode is the node loop of this version. Its cost must be within the limit.
if [[ "$poll_gate" != within_* ]]; then
  echo "The deny fetch cost of the node loop is over ${CPU_LIMIT_PCT} percent of one core." >&2
  exit 1
fi
echo "proof_ok"

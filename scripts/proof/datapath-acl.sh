#!/usr/bin/env bash
# Datapath ACL proof (W24).
# The host is REAL. The coordinator and nodes a, b, and c are [C] containers.
# The policy lets a reach b on TCP 8080, UDP 9000 and 9500, and ICMP. It lets c reach b on TCP 8080.
# The receiving node drops each other packet in the datapath (default deny).
# Check 1: an allowed port connects (a and c to b on TCP 8080, a to b on UDP 9000).
# Check 2: a denied port times out. The listener on b sees no connection and no byte.
# Check 3: ICMP works as written: a pings b, c does not, b does not ping a.
#          No rule lets b open a flow to a. The replies on the a to b flows still pass.
# Check 4: the receiver writes a sampled and rate limited packet-deny audit chain.
#          The chain verifies.
# Check 5: a policy without an ACL list gives the old behavior: every port and ping passes,
#          and the audit chain gets no new record.
# Check 6: the ACL list comes back and the filter drops the denied port again.
# Check 7: the owner (c) runs `orblx admin revoke-all a`. Node a sends UDP to a port of b
#          that has no check of its own. The last datagram from a reaches b 1000 ms or less
#          after revoke_done_ms. The script prints the ms (revoke_drop_ms).
# The script deletes the orblx-w24acl-proof volumes at the start.
# The script does not print enroll tokens or private keys.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.datapath-acl.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
IMAGE="orblx-w24acl:w24"
STATE=/var/lib/orblx
AUDIT="$STATE/packet-audit.jsonl"
NODES=(a b c)
TIMEOUT=3

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
proof_lock_take "datapath-acl"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-w24acl-proof" || exit 1

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

resolve_name() {
  dc run --rm --no-deps --entrypoint getent a ahostsv4 "$1" \
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
  docker build -q -t "$IMAGE" "$image_dir"
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

# Wait until the log of a service has a line COUNT times.
wait_log() {
  local service="$1"
  local needle="$2"
  local count="${3:-1}"
  local i got
  for i in $(seq 1 60); do
    got="$(dc logs "$service" 2>&1 | grep -c -- "$needle" || true)"
    if [[ "$got" -ge "$count" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle} (${count})" >&2
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

probe() {
  local from="$1"
  shift
  dc exec -T "$from" python3 /tmp/acl-probe.py "$@"
}

# Expect one probe line. Arguments: node, expected line, probe arguments.
expect_probe() {
  local from="$1"
  local want="$2"
  shift 2
  local got
  got="$(probe "$from" "$@")"
  echo "${from} ${got}"
  if [[ "$got" != "$want" ]]; then
    echo "The probe from ${from} printed: ${got}. The proof wants: ${want}" >&2
    exit 1
  fi
}

expect_ping() {
  local from="$1"
  local ip="$2"
  local want="$3"
  local got=fail
  if dc exec -T "$from" ping -n -c 3 -i 0.3 -W 1 "$ip" >"$WORK/ping.txt" 2>&1; then
    got=ok
  fi
  echo "ping ${from} ${ip} ${got} $(grep -E 'packets transmitted' "$WORK/ping.txt" || true)"
  if [[ "$got" != "$want" ]]; then
    echo "The ping from ${from} to ${ip} is ${got}. The proof wants ${want}." >&2
    exit 1
  fi
}

# Print the line count of a listener log on a node.
log_lines() {
  dc exec -T "$1" sh -c "wc -l <$2" | tr -d ' \r'
}

audit_records() {
  dc exec -T b sh -c "if [ -f $AUDIT ]; then wc -l <$AUDIT; else echo 0; fi" | tr -d ' \r'
}

# Fetch the netmap and the signed grants on each running node.
# A new netmap file makes the nodes dial their peers again.
# The function waits for the paths and for one allowed TCP connect from a to b.
refresh_grants() {
  local name i got
  for name in "${NODES[@]}"; do
    dc exec -T "$name" orblx coord netmap \
      --coord "$COORD_ADDR" --bundle "$STATE/bundle.pem" --state "$STATE" >/dev/null
  done
  sleep 3
  wait_path a b
  wait_path c b
  wait_path b a
  for i in $(seq 1 20); do
    got="$(probe a tcp "${ips[b]}" 8080 1)"
    if [[ "$got" == "tcp ${ips[b]}:8080 connected reply ok" ]]; then
      echo "warm a ${got}"
      return 0
    fi
    sleep 1
  done
  echo "The allowed path from a to b did not come back." >&2
  return 1
}

cp "$ROOT/scripts/proof/datapath-acl.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

echo "=== [C] policy test ==="
dc exec -T coord orblx policy test --file "$STATE/policy.hujson"

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

echo "=== [C] signed grants on b ==="
grants_b="$(dc run --rm --no-deps --entrypoint cat b "$STATE/grants.json")"
printf '%s\n' "$grants_b"
grep -q '"filter":true' <<<"$grants_b"
echo "grants_b filter true"

echo "=== [C] start all nodes ==="
dc up -d "${NODES[@]}"
for name in "${NODES[@]}"; do
  wait_log "$name" 'The TUN device'
  wait_log "$name" 'The packet filter is on.'
done
wait_path a b
wait_path c b
wait_path b a

echo "=== [C] listeners: b on TCP 8080, 8081 and UDP 9000, 9001; a on TCP 8080 ==="
for name in "${NODES[@]}"; do
  dc cp "$ROOT/scripts/proof/acl-probe.py" "${name}:/tmp/acl-probe.py"
done
dc exec -d b python3 /tmp/acl-probe.py listen-tcp "${ips[b]}" 8080 /tmp/tcp-8080.log
dc exec -d b python3 /tmp/acl-probe.py listen-tcp "${ips[b]}" 8081 /tmp/tcp-8081.log
dc exec -d b python3 /tmp/acl-probe.py listen-udp "${ips[b]}" 9000 /tmp/udp-9000.log
dc exec -d b python3 /tmp/acl-probe.py listen-udp "${ips[b]}" 9001 /tmp/udp-9001.log
dc exec -d a python3 /tmp/acl-probe.py listen-tcp "${ips[a]}" 8080 /tmp/tcp-8080.log
sleep 1

echo "=== [C] check 1: allowed ports connect ==="
expect_probe a "tcp ${ips[b]}:8080 connected reply ok" tcp "${ips[b]}" 8080 "$TIMEOUT"
expect_probe c "tcp ${ips[b]}:8080 connected reply ok" tcp "${ips[b]}" 8080 "$TIMEOUT"
expect_probe a "udp ${ips[b]}:9000 reply yes" udp "${ips[b]}" 9000 "$TIMEOUT"

echo "=== [C] check 2: denied ports time out and no app sees the bytes ==="
expect_probe a "tcp ${ips[b]}:8081 timeout" tcp "${ips[b]}" 8081 "$TIMEOUT"
expect_probe c "tcp ${ips[b]}:8081 timeout" tcp "${ips[b]}" 8081 "$TIMEOUT"
expect_probe a "udp ${ips[b]}:9001 reply none" udp "${ips[b]}" 9001 "$TIMEOUT"
expect_probe b "tcp ${ips[a]}:8080 timeout" tcp "${ips[a]}" 8080 "$TIMEOUT"
b_8080="$(log_lines b /tmp/tcp-8080.log)"
b_8081="$(log_lines b /tmp/tcp-8081.log)"
b_9000="$(log_lines b /tmp/udp-9000.log)"
b_9001="$(log_lines b /tmp/udp-9001.log)"
a_8080="$(log_lines a /tmp/tcp-8080.log)"
echo "listener b tcp8080 ${b_8080} tcp8081 ${b_8081} udp9000 ${b_9000} udp9001 ${b_9001}; a tcp8080 ${a_8080}"
dc exec -T b cat /tmp/tcp-8080.log
if [[ "$b_8080" -ne 2 || "$b_8081" -ne 0 || "$b_9000" -ne 1 || "$b_9001" -ne 0 || "$a_8080" -ne 0 ]]; then
  echo "A listener count is not the expected count." >&2
  exit 1
fi
echo "denied_app_bytes 0"

echo "=== [C] check 3: ICMP works as written ==="
expect_ping a "${ips[b]}" ok
expect_ping c "${ips[b]}" fail
expect_ping b "${ips[a]}" fail

echo "=== [C] check 4: sampled and rate limited deny audit ==="
before="$(audit_records)"
echo "audit_records_before_spray ${before}"
probe a spray "${ips[b]}" 9100 9299
sleep 2
expect_probe a "udp ${ips[b]}:9998 reply none" udp "${ips[b]}" 9998 1
sleep 1
after="$(audit_records)"
spray_records=$((after - before))
echo "audit_records_after_spray ${after} spray_records ${spray_records} spray_denied 200"
dc exec -T b cat "$AUDIT" >"$WORK/packet-audit.jsonl"
jq -c '{action, actor, target, detail}' "$WORK/packet-audit.jsonl"
if [[ "$spray_records" -lt 1 || "$spray_records" -gt 12 ]]; then
  echo "The spray wrote ${spray_records} records. The rate limit wants 1 to 12." >&2
  exit 1
fi
jq -e -s 'all(.[]; .action == "packet-deny")' "$WORK/packet-audit.jsonl" >/dev/null
# Each drop has a record or counts in unwritten_before of a later record.
# The spray and the flush probe drop 201 packets. Drops before the spray may add to the sum.
unwritten="$(tail -n "$spray_records" "$WORK/packet-audit.jsonl" \
  | jq -r '.detail' | awk '{sum += $NF} END {print sum + 0}')"
accounted=$((unwritten + spray_records))
echo "spray_unwritten_sum ${unwritten} spray_accounted ${accounted} of 201"
if [[ "$accounted" -lt 201 ]]; then
  echo "The audit chain does not count every dropped packet." >&2
  exit 1
fi
jq -e -s 'any(.[]; .actor == "spiffe://orblx.local/node/a" and .target == "tcp/8081")' "$WORK/packet-audit.jsonl" >/dev/null
jq -e -s 'any(.[]; .actor == "spiffe://orblx.local/node/c" and .target == "icmp/0")' "$WORK/packet-audit.jsonl" >/dev/null
echo "audit_fields ok"
verify="$(dc exec -T b orblx audit verify-config --file "$AUDIT")"
printf '%s\n' "$verify"
grep -qx 'ok' <<<"$verify"

echo "=== [C] check 5: a policy without an ACL list gives the old behavior ==="
printf '%s\n' '{' '  // No ACL list. The datapath does not check the packet port.' '}' >"$POLICY_FILE"
refresh_grants
for name in "${NODES[@]}"; do
  wait_log "$name" 'The packet filter is off.'
done
records_open="$(audit_records)"
expect_probe a "tcp ${ips[b]}:8081 connected reply ok" tcp "${ips[b]}" 8081 "$TIMEOUT"
expect_probe c "tcp ${ips[b]}:8081 connected reply ok" tcp "${ips[b]}" 8081 "$TIMEOUT"
expect_probe a "udp ${ips[b]}:9001 reply yes" udp "${ips[b]}" 9001 "$TIMEOUT"
expect_probe b "tcp ${ips[a]}:8080 connected reply ok" tcp "${ips[a]}" 8080 "$TIMEOUT"
expect_ping c "${ips[b]}" ok
expect_ping b "${ips[a]}" ok
sleep 1
records_open_after="$(audit_records)"
echo "audit_records_no_acl ${records_open} ${records_open_after}"
[[ "$records_open" -eq "$records_open_after" ]]

echo "=== [C] check 6: the ACL list comes back ==="
cp "$ROOT/scripts/proof/datapath-acl.hujson" "$POLICY_FILE"
refresh_grants
for name in "${NODES[@]}"; do
  wait_log "$name" 'The packet filter is on.' 2
done
expect_probe a "tcp ${ips[b]}:8080 connected reply ok" tcp "${ips[b]}" 8080 "$TIMEOUT"
expect_probe a "tcp ${ips[b]}:8081 timeout" tcp "${ips[b]}" 8081 "$TIMEOUT"
expect_ping c "${ips[b]}" fail
final_8081="$(log_lines b /tmp/tcp-8081.log)"
echo "listener b tcp8081 ${final_8081}"
[[ "$final_8081" -eq 2 ]]
verify="$(dc exec -T b orblx audit verify-config --file "$AUDIT")"
grep -qx 'ok' <<<"$verify"
echo "audit_verify_final ok records $(audit_records)"

echo "=== [C] check 7: revoke-all drops the packets of the principal in 1 s or less ==="
# UDP 9500 on b has only a plain logger. The logger has no check of its own.
# Node a sends one datagram each 20 ms for 10 s. Node c (the owner) revokes a after 3 s.
dc exec -d b python3 /tmp/acl-probe.py listen-stamp "${ips[b]}" 9500 /tmp/udp-9500.log
sleep 1
dc exec -d a sh -c "python3 /tmp/acl-probe.py stream ${ips[b]} 9500 10 20 >/tmp/stream.out 2>&1"
sleep 3
rx_before="$(log_lines b /tmp/udp-9500.log)"
echo "stamp_rx_before_revoke ${rx_before}"
[[ "$rx_before" -gt 50 ]]
revoke_out="$(dc exec -T c orblx admin revoke-all a \
  --coord "$COORD_ADDR" --state "$STATE" --bundle "$STATE/bundle.pem")"
printf '%s\n' "$revoke_out" | grep -E '^(revoked_all|svid_denied|deny_version|revoke_start_ms|revoke_done_ms) '
revoke_start="$(awk '$1 == "revoke_start_ms" {print $2; exit}' <<<"$revoke_out")"
revoke_done="$(awk '$1 == "revoke_done_ms" {print $2; exit}' <<<"$revoke_out")"
[[ -n "$revoke_start" && -n "$revoke_done" ]]
sleep 9
stream_out="$(dc exec -T a cat /tmp/stream.out)"
echo "$stream_out"
sent="$(awk '$1 == "stream" {print $4; exit}' <<<"$stream_out")"
[[ -n "$sent" && "$sent" -gt 300 ]]
dc exec -T b cat /tmp/udp-9500.log >"$WORK/udp-9500.log"
last_rx="$(awk -v ip="${ips[a]}" '$1 == "rx_ms" && $3 == ip {last = $2} END {print last + 0}' "$WORK/udp-9500.log")"
rx_total="$(awk -v ip="${ips[a]}" '$1 == "rx_ms" && $3 == ip {n++} END {print n + 0}' "$WORK/udp-9500.log")"
rx_after="$(awk -v ip="${ips[a]}" -v t="$revoke_done" '$1 == "rx_ms" && $3 == ip && $2 > t {n++} END {print n + 0}' "$WORK/udp-9500.log")"
rx_lead="$(awk -v ip="${ips[a]}" -v t="$revoke_start" '$1 == "rx_ms" && $3 == ip && $2 > t - 500 && $2 <= t {n++} END {print n + 0}' "$WORK/udp-9500.log")"
echo "stamp_rx_in_500ms_before_revoke_start ${rx_lead}"
[[ "$rx_lead" -gt 0 ]]
drop_ms=$(( last_rx - revoke_done ))
if (( drop_ms < 0 )); then
  drop_ms=0
fi
echo "stamp_sent ${sent} stamp_rx ${rx_total} stamp_rx_after_revoke_done ${rx_after}"
echo "revoke_drop_ms ${drop_ms} (last datagram from a at b minus revoke_done_ms, limit 1000)"
[[ "$drop_ms" -le 1000 ]]
# The stream ran for 6 s or more after the revoke. Thus most datagrams must be dropped.
[[ $(( sent - rx_total )) -gt 200 ]]
wait_log b 'The peer a is in the deny list. The node closes the session.' 1
dc logs --no-log-prefix b 2>&1 | grep -e 'The peer a is in the deny list.' -e 'The node ended the session with a.' | read_all head -1
expect_probe a "tcp ${ips[b]}:8080 timeout" tcp "${ips[b]}" 8080 "$TIMEOUT"
expect_probe c "tcp ${ips[b]}:8080 connected reply ok" tcp "${ips[b]}" 8080 "$TIMEOUT"

echo "=== [C] logs hold no key or enroll token ==="
{
  dc logs 2>&1
  cat "$WORK/packet-audit.jsonl"
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

echo "summary allowed tcp8080 udp9000 icmp_a_b denied tcp8081 udp9001 icmp_c_b icmp_b_a tcp_b_a denied_app_bytes 0 spray_denied 200 spray_records ${spray_records} spray_accounted ${accounted} audit_verify ok no_acl old_behavior acl_again denied revoke_drop_ms ${drop_ms} limit_ms 1000"
echo "proof_ok"

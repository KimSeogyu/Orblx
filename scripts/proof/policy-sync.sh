#!/usr/bin/env bash
# W25-6 policy sync proof.
# The host is REAL. The coordinator, the subnet router, node a, and 50 load identities are [C]
# containers. Each node runs `orblx up --coord`. After the start, the script does not run
# `orblx coord netmap` for a node, and it does not restart a node.
# Gate 1: remove corp.lan from the policy file. Node a answers db.corp.lan from the system
#         resolver in LIMIT_MS or less (policy_change_to_new_answer_ms). Then add corp.lan again.
# Gate 2: the router (owner) runs `orblx admin revoke-all a`. The router gets the deny list
#         from the same `policy-wait` reply. The last datagram from a reaches the router
#         1000 ms or less after revoke_done_ms (revoke_drop_ms).
# Gate 3: 50 load identities run `orblx coord netmap --watch` (the same `policy-wait` client).
#         Enroll needs an endpoint. Each load identity gives 172.30.126.9 (the load container)
#         and its own port. No datapath runs there.
#         The script measures the coordinator CPU with no change, and with one change each 10 s.
#         Each coordinator CPU value must be less than 5% of one core.
# Gate 4: b enrolls and starts after a and the router run. Node a must reach b (ICMP) in
#         LIMIT_MS or less after b starts (late_peer_reachable_ms). Node a and the router
#         do not restart.
# The script deletes the proof containers at the start and at the end.
# The script does not print enroll tokens or private keys.
# The script takes the box proof lock (proof-lock.sh, W25-5). Proofs run one at a time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.policy-sync.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w256-sync-proof}"
export ORBLX_SYNC_IMAGE="${ORBLX_SYNC_IMAGE:-orblx-w256-sync:local}"
# Gate 3 measures CPU. A debug build is not the build that ships: its TLS handshake and
# Ed25519 signing are slow. Thus the default is release.
PROFILE="${ORBLX_SYNC_PROFILE:-release}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WORK="$(mktemp -d)"
export SYNC_WORK="$WORK"
export SYNC_COORD_STATE="$WORK/coord"
export SYNC_POLICY_DIR="$WORK/policy"
export SYNC_ROUTER_STATE="$WORK/router"
export SYNC_A_STATE="$WORK/a"
export SYNC_B_STATE="$WORK/b"
COORD="172.30.126.2:443"
LIMIT_MS=2000
DROP_LIMIT_MS=1000
CPU_LIMIT_PCT=5
LOAD_NODES="${SYNC_LOAD_NODES:-50}"
LOAD_SECONDS="${SYNC_LOAD_SECONDS:-60}"

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc --profile nodes --profile tool --profile load down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK" >/dev/null 2>&1 || true
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "policy-sync:${PROOF_PROJECT}" "${PROOF_PROJECT}-"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${PROOF_PROJECT:-orblx-w256-sync-proof}" || exit 1

fail() {
  echo "$1" >&2
  dc --profile nodes logs a b router coord >&2 || true
  exit 1
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

# ORBLX_SYNC_BIN uses a built orblx binary (W25-34). Then the script does not build.
build_image() {
  local image_dir bin="${ORBLX_SYNC_BIN:-}"
  if [[ -n "$bin" ]]; then
    echo "binary ${bin} sha256 $(sha256sum "$bin" | awk '{print $1}')"
  elif [[ "$PROFILE" == release ]]; then
    cargo build --release -p orblx-cli --bin orblx --locked
  else
    cargo build -p orblx-cli --bin orblx --locked
  fi
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "${bin:-$TARGET_DIR/$PROFILE/orblx}")"
  docker build -q -t "$ORBLX_SYNC_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  for _ in $(seq 1 90); do
    if [[ -s "$SYNC_COORD_STATE/trust-bundle.pem" ]]; then
      return 0
    fi
    sleep 1
  done
  fail "The coordinator did not write the trust bundle."
}

wait_log() {
  local service="$1" needle="$2" count="${3:-1}" got
  for _ in $(seq 1 60); do
    got="$(dc --profile nodes logs "$service" 2>&1 | grep -c -- "$needle" || true)"
    [[ "$got" -ge "$count" ]] && return 0
    sleep 1
  done
  fail "The service ${service} did not print: ${needle} (${count})"
}

log_count() {
  dc --profile nodes logs "$1" 2>&1 | grep -c -- "$2" || true
}

enroll() {
  local name="$1" endpoint="$2" out
  dc exec -T coord orblx coord token create --state /var/lib/orblx \
    --out "/var/lib/orblx/tokens/${name}" --ttl 3600 >/dev/null
  out="$(dc --profile tool run --rm --no-deps tool coord enroll \
    --name "$name" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "/work/${name}" \
    --endpoint "${endpoint}:443")"
  printf '%s\n' "$out" | grep -E '^(name|overlay_ip) ' || true
}

ask() {
  dc exec -T "$1" python3 /proof/dns-ask.py "$2" "$3"
}

# Write the policy file with a rename, so the coordinator never reads half a file.
# The argument is a Python expression that changes `data`.
set_policy() {
  python3 - "$ROOT/scripts/proof/policy-sync.hujson" "$SYNC_POLICY_DIR/policy.next" "$1" <<'PY'
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
text = re.sub(r",(\s*[}\]])", r"\1", text)
data = json.loads(text)
exec(sys.argv[3])
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(data, indent=2) + "\n")
PY
  mv "$SYNC_POLICY_DIR/policy.next" "$SYNC_POLICY_DIR/policy.hujson"
}

restarts() {
  docker inspect --format '{{.State.StartedAt}} restarts {{.RestartCount}}' "$(dc --profile nodes ps -q "$1")"
}

# Print the CPU ticks (utime + stime) of the coordinator process.
coord_ticks() {
  dc exec -T coord sh -c "cut -d' ' -f14,15 /proc/1/stat" | awk '{print $1 + $2}'
}

# Print the CPU ticks of all orblx processes in the load container.
load_ticks() {
  dc --profile load exec -T load sh -c \
    'for f in /proc/[0-9]*/stat; do read -r line <"$f" 2>/dev/null || continue; case "$line" in *"(orblx)"*) echo "$line";; esac; done' \
    | awk '{t += $14 + $15} END {print t + 0}'
}

load_updates() {
  dc --profile load exec -T load sh -c 'cat /tmp/load/*.log 2>/dev/null' | grep -c '^policy_update ' || true
}

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool --profile load down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward
mkdir -p "$SYNC_COORD_STATE" "$SYNC_POLICY_DIR"
set_policy "pass"

echo "=== [C] build image (${PROFILE}) ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle
dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson

echo "=== [C] enroll router and a ==="
enroll router 172.30.126.3
enroll a 172.30.126.4

echo "=== [C] start sysdns, landns, router ==="
dc --profile nodes up -d sysdns landns router
wait_log router 'approved route 10.88.26.0/24'
wait_log router 'The node forwards 10.88.26.0/24'

echo "=== [C] start a ==="
dc --profile nodes up -d a
wait_log a 'The path to router is direct.'
for _ in $(seq 1 30); do
  dc exec -T a ip route show dev orblx0 2>/dev/null | read_all grep -q '10.88.26.0/24' && break
  sleep 1
done
dc exec -T a ip route show dev orblx0 | read_all grep -q '10.88.26.0/24' || fail "Node a has no route to 10.88.26.0/24."
a_ip="$(jq -r '.self.overlay_ip' "$SYNC_A_STATE/netmap.json")"
router_ip="$(jq -r '.peers[] | select(.name=="router") | .overlay_ip' "$SYNC_A_STATE/netmap.json")"
[[ -n "$a_ip" && -n "$router_ip" ]] || fail "The netmap did not include the overlay addresses."
echo "overlay a ${a_ip} router ${router_ip}"
echo "---- [C] overlay ping a to router ----"
dc exec -T a ping -n -c 20 -i 0.2 -W 1 "$router_ip" | tail -n 2

echo "=== [C] baseline: db.corp.lan through the overlay ==="
out=""
for _ in $(seq 1 20); do
  out="$(ask a db.corp.lan "$a_ip" || true)"
  [[ "$out" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]] && break
  sleep 0.5
done
echo "a: ${out}"
[[ "$out" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]] || fail "Node a did not resolve db.corp.lan through the router."

# Gate 1: one policy change and the time to the new DNS answer on a.
# The argument is the policy change. The second argument is the old address.
measure_dns() {
  local change="$1" old="$2" probe t0 changed_at
  dc exec -T a rm -f /tmp/change.txt
  dc exec -d a sh -c "python3 /proof/dns-ask.py --until-not ${old} db.corp.lan ${a_ip} 8000 > /tmp/change.txt 2>&1"
  sleep 0.3
  t0="$(date +%s%3N)"
  set_policy "$change"
  probe=""
  for _ in $(seq 1 100); do
    probe="$(dc exec -T a cat /tmp/change.txt 2>/dev/null || true)"
    [[ -n "$probe" ]] && break
    sleep 0.1
  done
  echo "probe: ${probe}" >&2
  changed_at="$(printf '%s\n' "$probe" | awk '/changed_at_ms/ {print $2}')"
  [[ -n "$changed_at" ]] || fail "The answer for db.corp.lan did not change after the policy change."
  stage_ms a 'The node applied a new policy from the coordinator.' "$t0" >&2
  stage_ms a 'The DNS answers follow the new netmap.' "$t0" >&2
  echo $((changed_at - t0))
}

# Print the ms from T0 to the last log line of SERVICE with NEEDLE (docker log time).
stage_ms() {
  local service="$1" needle="$2" t0="$3" stamp
  stamp="$(dc --profile nodes logs -t "$service" 2>&1 | grep -F -- "$needle" | tail -n 1 | awk '{print $3}')"
  [[ -n "$stamp" ]] || return 0
  echo "stage ${service} +$(( $(date -d "$stamp" +%s%3N) - t0 )) ms: ${needle}"
}

echo "=== Gate 1 [C]: remove corp.lan from the policy, no restart, no manual fetch ==="
a_start0="$(restarts a)"
applied0="$(log_count a 'The node applied a new policy from the coordinator.')"
remove_ms="$(measure_dns 'data.pop("splitDns")' 10.88.24.20)"
out="$(ask a db.corp.lan "$a_ip")"
echo "a after removal: ${out} (from the system resolver)"
[[ "$out" == "db.corp.lan rcode 0 answers 1 address 192.0.2.1" ]] || fail "Node a did not use the system resolver."
add_ms="$(measure_dns 'pass' 192.0.2.1)"
out="$(ask a db.corp.lan "$a_ip")"
echo "a after the zone came back: ${out}"
[[ "$out" == "db.corp.lan rcode 0 answers 1 address 10.88.24.20" ]] || fail "Node a did not use the zone again."
a_start1="$(restarts a)"
applied1="$(log_count a 'The node applied a new policy from the coordinator.')"
echo "node a container start before [${a_start0}] after [${a_start1}] (orblx is pid 1)"
[[ "$a_start0" == "$a_start1" ]] || fail "Node a restarted."
echo "node a applied_policy_lines before ${applied0} after ${applied1}"
[[ "$applied1" -ge $((applied0 + 2)) ]] || fail "Node a did not apply the two policy changes."
echo "policy_change_to_new_answer_ms remove ${remove_ms} add ${add_ms} (limit ${LIMIT_MS} ms, no manual fetch)"
[[ "$remove_ms" -le "$LIMIT_MS" && "$add_ms" -le "$LIMIT_MS" ]] || fail "A policy change took more than ${LIMIT_MS} ms."
echo "[C] gate1 ok"

echo "=== Gate 4 [C]: b enrolls later, a reaches b with no restart ==="
router_start0="$(restarts router)"
a_start2="$(restarts a)"
enroll_ms="$(date +%s%3N)"
b_out="$(enroll b 172.30.126.5)"
echo "$b_out"
b_ip="$(awk '$1 == "overlay_ip" {print $2; exit}' <<<"$b_out")"
[[ -n "$b_ip" ]] || fail "The enroll of b did not print an overlay address."
# Ping each 100 ms. -D prints the receive time of each reply as UNIX seconds.
dc exec -d a sh -c "ping -D -n -i 0.1 -W 1 -c 100 ${b_ip} >/tmp/ping-b.log 2>&1"
b_up_ms="$(date +%s%3N)"
dc --profile nodes up -d b
b_started_ms="$(date +%s%3N)"
first_reply=""
for _ in $(seq 1 60); do
  first_reply="$(dc exec -T a sh -c 'grep -m1 "bytes from" /tmp/ping-b.log' 2>/dev/null \
    | sed -E 's/^\[([0-9]+)\.([0-9]{3}).*/\1\2/' || true)"
  [[ "$first_reply" =~ ^[0-9]+$ ]] && break
  first_reply=""
  sleep 0.5
done
[[ -n "$first_reply" ]] || fail "Node a did not reach b."
wait_log a 'The node adds the peer b from the new netmap.'
from_enroll=$((first_reply - enroll_ms))
from_up=$((first_reply - b_up_ms))
from_started=$((first_reply - b_started_ms))
(( from_started < 0 )) && from_started=0
router_start1="$(restarts router)"
a_start3="$(restarts a)"
echo "node a container start before [${a_start2}] after [${a_start3}]"
echo "router container start before [${router_start0}] after [${router_start1}]"
[[ "$a_start2" == "$a_start3" && "$router_start0" == "$router_start1" ]] || fail "A node restarted."
sleep 3
dc exec -T a sh -c 'tail -n 2 /tmp/ping-b.log'
echo "late_peer_reachable_ms from_compose_up ${from_up} from_container_started ${from_started} from_enroll_start ${from_enroll} (limit ${LIMIT_MS} ms from compose up)"
[[ "$from_up" -le "$LIMIT_MS" ]] || fail "The late peer took more than ${LIMIT_MS} ms."
echo "[C] gate4 ok"

echo "=== Gate 3 [C]: ${LOAD_NODES} policy-wait clients, coordinator CPU ==="
dc exec -T coord sh -c "for i in \$(seq 1 ${LOAD_NODES}); do orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/load\$i --ttl 3600 >/dev/null || exit 1; done"
dc --profile load up -d load
dc --profile load exec -T load sh -c "mkdir -p /tmp/load; for i in \$(seq 1 ${LOAD_NODES}); do orblx coord enroll --name load\$i --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/load\$i --state /tmp/load/\$i --endpoint 172.30.126.9:\$((20000 + i)) >/dev/null || exit 1; done"
echo "load_enrolled ${LOAD_NODES}"
dc --profile load exec -d load sh -c "for i in \$(seq 1 ${LOAD_NODES}); do orblx coord netmap --coord ${COORD} --bundle /tmp/load/\$i/bundle.pem --state /tmp/load/\$i --watch >/tmp/load/\$i.log 2>&1 & done; wait"
for _ in $(seq 1 60); do
  [[ "$(load_updates)" -ge "$LOAD_NODES" ]] && break
  sleep 1
done
first="$(load_updates)"
echo "load_first_updates ${first}"
[[ "$first" -ge "$LOAD_NODES" ]] || fail "Not all load clients got the first policy."
sleep 3
hz="$(dc exec -T coord getconf CLK_TCK)"
cpu_window() {
  local label="$1" changes="$2" c0 l0 u0 t0 c1 l1 u1 t1 secs coord_pct load_pct each_pct k
  c0="$(coord_ticks)"; l0="$(load_ticks)"; u0="$(load_updates)"; t0="$(date +%s%3N)"
  if [[ "$changes" -eq 0 ]]; then
    sleep "$LOAD_SECONDS"
  else
    for k in $(seq 1 $((LOAD_SECONDS / 10))); do
      sleep 5
      if (( k % 2 == 1 )); then
        set_policy 'data["splitDns"]["load.lan"] = ["10.88.26.53"]'
      else
        set_policy 'pass'
      fi
      sleep 5
    done
  fi
  c1="$(coord_ticks)"; l1="$(load_ticks)"; u1="$(load_updates)"; t1="$(date +%s%3N)"
  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.3f", (b - a) / 1000}')"
  coord_pct="$(awk -v t=$((c1 - c0)) -v h="$hz" -v s="$secs" 'BEGIN {printf "%.2f", 100 * t / h / s}')"
  load_pct="$(awk -v t=$((l1 - l0)) -v h="$hz" -v s="$secs" 'BEGIN {printf "%.2f", 100 * t / h / s}')"
  each_pct="$(awk -v p="$load_pct" -v n="$LOAD_NODES" 'BEGIN {printf "%.3f", p / n}')"
  echo "poll_cpu ${label} nodes ${LOAD_NODES} seconds ${secs} hz ${hz} coord_ticks $((c1 - c0)) coord_cpu_pct ${coord_pct} clients_ticks $((l1 - l0)) clients_cpu_pct_total ${load_pct} client_cpu_pct_each ${each_pct} policy_updates $((u1 - u0))"
  awk -v p="$coord_pct" -v l="$CPU_LIMIT_PCT" 'BEGIN {exit !(p < l)}' \
    || fail "The coordinator used ${coord_pct}% of one core (${label})."
  if [[ "$changes" -ne 0 ]]; then
    [[ $((u1 - u0)) -ge $((LOAD_NODES * (LOAD_SECONDS / 10))) ]] \
      || fail "The load clients did not get each policy change."
  fi
}
cpu_window idle 0
cpu_window change_each_10s 1
echo "[C] gate3 ok"

echo "=== Gate 2 [C]: revoke-all a, the router drops a through policy-wait ==="
dc exec -d router python3 /proof/acl-probe.py listen-stamp "$router_ip" 9500 /tmp/udp-9500.log
sleep 1
dc exec -d a sh -c "python3 /proof/acl-probe.py stream ${router_ip} 9500 10 20 >/tmp/stream.out 2>&1"
sleep 3
rx_before="$(dc exec -T router sh -c 'wc -l </tmp/udp-9500.log' | tr -d ' \r')"
echo "stamp_rx_before_revoke ${rx_before}"
[[ "$rx_before" -gt 50 ]] || fail "The router did not get the stream from a."
router_applied0="$(log_count router 'The node applied a new policy from the coordinator.')"
revoke_out="$(dc exec -T router orblx admin revoke-all a \
  --coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)"
printf '%s\n' "$revoke_out" | grep -E '^(revoked_all|svid_denied|deny_version|revoke_start_ms|revoke_done_ms) '
revoke_start="$(awk '$1 == "revoke_start_ms" {print $2; exit}' <<<"$revoke_out")"
revoke_done="$(awk '$1 == "revoke_done_ms" {print $2; exit}' <<<"$revoke_out")"
[[ -n "$revoke_start" && -n "$revoke_done" ]] || fail "The revoke did not print its times."
sleep 9
stream_out="$(dc exec -T a cat /tmp/stream.out)"
echo "$stream_out"
dc exec -T router cat /tmp/udp-9500.log >"$WORK/udp-9500.log"
last_rx="$(awk -v ip="$a_ip" '$1 == "rx_ms" && $3 == ip {last = $2} END {print last + 0}' "$WORK/udp-9500.log")"
rx_total="$(awk -v ip="$a_ip" '$1 == "rx_ms" && $3 == ip {n++} END {print n + 0}' "$WORK/udp-9500.log")"
rx_after="$(awk -v ip="$a_ip" -v t="$revoke_done" '$1 == "rx_ms" && $3 == ip && $2 > t {n++} END {print n + 0}' "$WORK/udp-9500.log")"
drop_ms=$((last_rx - revoke_done))
(( drop_ms < 0 )) && drop_ms=0
router_applied1="$(log_count router 'The node applied a new policy from the coordinator.')"
echo "router applied_policy_lines before ${router_applied0} after ${router_applied1}"
[[ "$router_applied1" -gt "$router_applied0" ]] || fail "The router did not get the deny list from policy-wait."
echo "stamp_rx ${rx_total} stamp_rx_after_revoke_done ${rx_after}"
echo "revoke_drop_ms ${drop_ms} (last datagram from a at the router minus revoke_done_ms, limit ${DROP_LIMIT_MS})"
[[ "$drop_ms" -le "$DROP_LIMIT_MS" ]] || fail "The drop took ${drop_ms} ms."
echo "[C] gate2 ok"

echo "=== [C] logs hold no key or enroll token ==="
# W25-14: a failed or empty log read fails the scan. Before, "|| true" let the scan pass.
dc --profile nodes --profile load logs >"$WORK/all-logs.out" 2>&1 || fail "docker compose logs failed."
secret_scan "$WORK/all-logs.out" || fail "A log holds a private key or an enroll token, or the log is empty."

echo "summary policy_change_to_new_answer_ms remove ${remove_ms} add ${add_ms} limit_ms ${LIMIT_MS} revoke_drop_ms ${drop_ms} limit_ms ${DROP_LIMIT_MS} late_peer_reachable_ms ${from_up} restarts 0 manual_fetch 0"
echo "proof_ok"

#!/usr/bin/env bash
# W25-16 policy-wait scale proof.
# The host is REAL. The coordinator and the load identities are [C] containers (the compose
# file of the W25-6 policy sync proof). Each load identity runs `orblx coord netmap --watch`,
# the `policy-wait` client of `orblx up`. Enroll needs an endpoint. Each load identity gives
# 172.30.126.9 (the load container) and its own port. No datapath runs there.
# For each count in SCALE_NODES (default "50 200"), the script measures the coordinator CPU
# in two windows of SCALE_SECONDS (default 60):
#   idle:   no change.
#   change: one policy change each 10 s. Each client must get each change.
# Gates:
#   At 50 clients: idle CPU IDLE_LIMIT_PCT (0.5%) of one core or less, change CPU
#   CHANGE_LIMIT_PCT (2%) of one core or less.
#   At the largest count: the change CPU at 500 clients, from a line through the first and
#   the last count, must be PROJECT_LIMIT_PCT (10%) of one core or less.
# The script also prints the UDP sockets of the load clients. With one QUIC connection for
# each client, the count is the client count.
# The script deletes the proof containers at the start and at the end.
# The script does not print enroll tokens or private keys.
# The script takes the box proof lock (proof-lock.sh, W25-5). Proofs run one at a time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.policy-sync.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w25p-scale-proof}"
export ORBLX_SYNC_IMAGE="${ORBLX_SYNC_IMAGE:-orblx-w25p-scale:local}"
# The proof measures CPU, so the default is the release build (the build that ships).
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
IDLE_LIMIT_PCT=0.5
CHANGE_LIMIT_PCT=2
PROJECT_LIMIT_PCT=10
PROJECT_NODES=500
GATE_NODES=50
read -r -a COUNTS <<<"${SCALE_NODES:-50 200}"
SECONDS_EACH="${SCALE_SECONDS:-60}"

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
proof_lock_take "policy-scale:${PROOF_PROJECT}" "${PROOF_PROJECT}-"
# W25-14b (#114): start from a clean state. Old containers, volumes, and networks of the project make the proof fail.
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${PROOF_PROJECT}" || exit 1

fail() {
  echo "$1" >&2
  dc logs coord 2>&1 | tail -n 40 >&2 || true
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

build_image() {
  local image_dir
  if [[ "$PROFILE" == release ]]; then
    cargo build --release -p orblx-cli --bin orblx --locked
  else
    cargo build -p orblx-cli --bin orblx --locked
  fi
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$TARGET_DIR/$PROFILE/orblx")"
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

load_failures() {
  dc --profile load exec -T load sh -c 'cat /tmp/load/*.log 2>/dev/null' | grep -c 'The policy wait failed' || true
}

# Print the count of UDP sockets in the load container (IPv4 and IPv6).
load_sockets() {
  dc --profile load exec -T load sh -c 'cat /proc/net/udp /proc/net/udp6 2>/dev/null' \
    | awk '$1 ~ /^[0-9]+:$/ {n++} END {print n + 0}'
}

# Enroll the load identities FROM to TO and start their watch clients.
add_clients() {
  local from="$1" to="$2"
  dc exec -T coord sh -c "for i in \$(seq ${from} ${to}); do orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/load\$i --ttl 3600 >/dev/null || exit 1; done"
  dc --profile load exec -T load sh -c "mkdir -p /tmp/load; for i in \$(seq ${from} ${to}); do orblx coord enroll --name load\$i --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/load\$i --state /tmp/load/\$i --endpoint 172.30.126.9:\$((20000 + i)) >/dev/null || exit 1; done"
  dc --profile load exec -d load sh -c "for i in \$(seq ${from} ${to}); do orblx coord netmap --coord ${COORD} --bundle /tmp/load/\$i/bundle.pem --state /tmp/load/\$i --watch >/tmp/load/\$i.log 2>&1 & done; wait"
}

# Measure one window. Print the coordinator CPU percent as the last word.
# Arguments: label, node count, changes (0 or 1).
cpu_window() {
  local label="$1" nodes="$2" changes="$3" c0 l0 u0 f0 t0 c1 l1 u1 f1 t1 secs coord_pct load_pct each_pct k
  c0="$(coord_ticks)"; l0="$(load_ticks)"; u0="$(load_updates)"; f0="$(load_failures)"; t0="$(date +%s%3N)"
  if [[ "$changes" -eq 0 ]]; then
    sleep "$SECONDS_EACH"
  else
    for k in $(seq 1 $((SECONDS_EACH / 10))); do
      sleep 5
      if (( k % 2 == 1 )); then
        set_policy 'data["splitDns"]["load.lan"] = ["10.88.26.53"]'
      else
        set_policy 'pass'
      fi
      sleep 5
    done
  fi
  c1="$(coord_ticks)"; l1="$(load_ticks)"; u1="$(load_updates)"; f1="$(load_failures)"; t1="$(date +%s%3N)"
  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.3f", (b - a) / 1000}')"
  coord_pct="$(awk -v t=$((c1 - c0)) -v h="$hz" -v s="$secs" 'BEGIN {printf "%.2f", 100 * t / h / s}')"
  load_pct="$(awk -v t=$((l1 - l0)) -v h="$hz" -v s="$secs" 'BEGIN {printf "%.2f", 100 * t / h / s}')"
  each_pct="$(awk -v p="$load_pct" -v n="$nodes" 'BEGIN {printf "%.4f", p / n}')"
  echo "scale_cpu ${label} nodes ${nodes} seconds ${secs} hz ${hz} coord_ticks $((c1 - c0)) coord_cpu_pct ${coord_pct} clients_ticks $((l1 - l0)) clients_cpu_pct_total ${load_pct} client_cpu_pct_each ${each_pct} policy_updates $((u1 - u0)) wait_failures $((f1 - f0)) load_udp_sockets $(load_sockets)" >&2
  if [[ "$changes" -ne 0 ]]; then
    [[ $((u1 - u0)) -ge $((nodes * (SECONDS_EACH / 10))) ]] \
      || fail "The load clients did not get each policy change (${label})."
  fi
  echo "$coord_pct"
}

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool --profile load down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward
mkdir -p "$SYNC_COORD_STATE" "$SYNC_POLICY_DIR"
set_policy "pass"

echo "=== [C] build image (${PROFILE}) ==="
build_image

echo "=== [C] start coordinator and load container ==="
dc up -d coord
wait_bundle
dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson
dc --profile load up -d load
hz="$(dc exec -T coord getconf CLK_TCK)"

declare -A IDLE CHANGE
have=0
for nodes in "${COUNTS[@]}"; do
  echo "=== [C] ${nodes} policy-wait clients ==="
  add_clients $((have + 1)) "$nodes"
  have="$nodes"
  for _ in $(seq 1 120); do
    [[ "$(load_updates)" -ge "$nodes" ]] && break
    sleep 1
  done
  first="$(load_updates)"
  echo "load_first_updates ${first}"
  [[ "$first" -ge "$nodes" ]] || fail "Not all load clients got the first policy."
  # One hold time, so each client is in a steady wait.
  sleep 25
  IDLE[$nodes]="$(cpu_window idle "$nodes" 0)"
  CHANGE[$nodes]="$(cpu_window change_each_10s "$nodes" 1)"
done

low="${COUNTS[0]}"
high="${COUNTS[${#COUNTS[@]} - 1]}"
ok=1
if [[ -n "${IDLE[$GATE_NODES]:-}" ]]; then
  echo "gate idle nodes ${GATE_NODES} coord_cpu_pct ${IDLE[$GATE_NODES]} limit ${IDLE_LIMIT_PCT}"
  awk -v p="${IDLE[$GATE_NODES]}" -v l="$IDLE_LIMIT_PCT" 'BEGIN {exit !(p <= l)}' || ok=0
  echo "gate change nodes ${GATE_NODES} coord_cpu_pct ${CHANGE[$GATE_NODES]} limit ${CHANGE_LIMIT_PCT}"
  awk -v p="${CHANGE[$GATE_NODES]}" -v l="$CHANGE_LIMIT_PCT" 'BEGIN {exit !(p <= l)}' || ok=0
fi
if [[ "$high" -gt "$low" ]]; then
  for kind in idle change; do
    if [[ "$kind" == idle ]]; then
      a="${IDLE[$low]}"; b="${IDLE[$high]}"
    else
      a="${CHANGE[$low]}"; b="${CHANGE[$high]}"
    fi
    slope="$(awk -v a="$a" -v b="$b" -v n="$low" -v m="$high" 'BEGIN {printf "%.5f", (b - a) / (m - n)}')"
    projected="$(awk -v b="$b" -v s="$slope" -v m="$high" -v p="$PROJECT_NODES" 'BEGIN {printf "%.2f", b + s * (p - m)}')"
    echo "projection ${kind} nodes ${low} ${a} nodes ${high} ${b} pct_per_node ${slope} nodes ${PROJECT_NODES} coord_cpu_pct ${projected}"
    if [[ "$kind" == change ]]; then
      echo "gate projected change nodes ${PROJECT_NODES} coord_cpu_pct ${projected} limit ${PROJECT_LIMIT_PCT}"
      awk -v p="$projected" -v l="$PROJECT_LIMIT_PCT" 'BEGIN {exit !(p <= l)}' || ok=0
    fi
  done
fi

echo "=== [C] logs hold no key or enroll token ==="
dc --profile load logs >"$WORK/all-logs.out" 2>&1 || true
dc --profile load exec -T load sh -c 'cat /tmp/load/*.log 2>/dev/null' >>"$WORK/all-logs.out" || true
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.out" || true)"
echo "secret_grep 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]] || fail "A log holds a private key."

[[ "$ok" -eq 1 ]] || fail "A CPU gate failed."
echo "proof_ok"

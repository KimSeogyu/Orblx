#!/usr/bin/env bash
# W25-34 mixed-version and upgrade proof (PO option A).
# The host is REAL. The coordinator and nodes a, b, c, and d are [C] containers. Each node
# runs `orblx up --coord`. Node a is the owner.
# OLD is the rc.2 binary (MIX_OLD_BIN, built from d9704cfb). NEW is the W25-34 binary
# (MIX_NEW_BIN).
# Phase P (all old): enroll a, b, c, d with old tools. All paths are direct.
# Gate X1 (new coordinator, old nodes):
#   - The coordinator logs `coord rejected: version mismatch, upgrade` for the old nodes
#     (MIX_OLD_POLICY_WAIT=1 only, see below).
#   - The old nodes do not restart and do not exit (same container, same StartedAt).
#   - The script prints what an old node logs and what old `orblx status` shows.
#   - An old `orblx coord enroll` of a new name prints the mismatch text.
#   - The new CLI revokes c with the identity of a. Old a and b drop c: ping fails, and
#     deny.json has c (no traffic to a revoked peer).
# Gate U (upgrade on rc.2 state): nodes a, b, d change to NEW on their rc.2 state directories
#   (no netmap.seq). The coordinator was started on an rc.2 state directory (no netmap-seq).
#   The coordinator log shows `persisted none` and seq == issued_at_ms. The nodes print no
#   `netmap refuse`, write netmap.seq, and get direct paths, with no manual step.
# Gate X2 (old coordinator, new nodes):
#   - The new nodes log `ALERT version mismatch, upgrade`, and `orblx status` shows
#     `coord version mismatch, upgrade ...` (and the JSON key coord).
#   - The new CLI revokes d against the old coordinator. a and b drop d.
#   - The new nodes do not restart and do not exit.
# PO rule: each contention claim gives unknown_samples with contended_samples. A run is valid
# only with samples >= 1 and unknown_samples 0. Else the script prints proof_invalid and stops
# with exit 1. The proof lock prints the full proof_contention line at the end.
# The script does not print enroll tokens or private keys.
# The script takes the box proof lock (proof-lock.sh). Proofs run one at a time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.netmap-mixed.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w2534-mix-proof}"
OLD_BIN="${MIX_OLD_BIN:?set MIX_OLD_BIN (the rc.2 binary)}"
NEW_BIN="${MIX_NEW_BIN:?set MIX_NEW_BIN (the W25-34 binary)}"
# 1: the old node uses `policy-wait` (W25-6 and later, for example d9704cfb). The new
# coordinator refuses it and logs the mismatch. 0: the old node only fetches the deny list
# (the v0.1.0-rc.2 tag, b9cae9c). The new coordinator allows that op, so it logs no mismatch.
OLD_POLICY_WAIT="${MIX_OLD_POLICY_WAIT:-1}"
OLD_LABEL="${MIX_OLD_LABEL:-old}"
OLD_IMAGE="orblx-w2534-mix-old:local"
NEW_IMAGE="orblx-w2534-mix-new:local"
WORK="$(mktemp -d)"
export MIX_WORK="$WORK"
export MIX_COORD_STATE="$WORK/coord"
export MIX_POLICY_DIR="$WORK/policy"
export MIX_A_STATE="$WORK/a" MIX_B_STATE="$WORK/b" MIX_C_STATE="$WORK/c" MIX_D_STATE="$WORK/d"
export MIX_COORD_IMAGE="$OLD_IMAGE" MIX_TOOL_IMAGE="$OLD_IMAGE"
export MIX_A_IMAGE="$OLD_IMAGE" MIX_B_IMAGE="$OLD_IMAGE" MIX_C_IMAGE="$OLD_IMAGE" MIX_D_IMAGE="$OLD_IMAGE"
COORD="172.30.135.2:443"
NODES=(a b c d)

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK" >/dev/null 2>&1 || true
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "netmap-mixed:${PROOF_PROJECT}" "${PROOF_PROJECT}-"
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"
proof_compose_clean "${PROOF_PROJECT}" || exit 1

fail() {
  echo "GATE_FAIL $1" >&2
  dc --profile nodes logs --tail 60 a b c d coord >&2 || true
  exit 1
}

now_ms() {
  date +%s%3N
}

build_images() {
  local image_dir
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$OLD_BIN")"
  docker build -q -t "$OLD_IMAGE" "$image_dir" >/dev/null
  rm -rf "$image_dir"
  image_dir="$(stage_proof_image "$ROOT" "$NEW_BIN")"
  docker build -q -t "$NEW_IMAGE" "$image_dir" >/dev/null
  rm -rf "$image_dir"
  echo "old binary sha256 $(sha256sum "$OLD_BIN" | awk '{print $1}') version $("$OLD_BIN" --version 2>/dev/null || echo unknown)"
  echo "new binary sha256 $(sha256sum "$NEW_BIN" | awk '{print $1}') version $("$NEW_BIN" --version 2>/dev/null || echo unknown)"
}

wait_bundle() {
  for _ in $(seq 1 90); do
    [[ -s "$MIX_COORD_STATE/trust-bundle.pem" ]] && return 0
    sleep 1
  done
  fail "The coordinator did not write the trust bundle."
}

log_count() {
  dc --profile nodes logs "$1" 2>&1 | grep -c -- "$2" || true
}

# Count lines in the log of the current container of a service since it started.
log_count_since() {
  local id
  id="$(dc --profile nodes ps -q "$1")"
  docker logs "$id" 2>&1 | grep -c -- "$2" || true
}

wait_log() {
  local service="$1" needle="$2" count="${3:-1}" limit="${4:-60}"
  for _ in $(seq 1 "$limit"); do
    [[ "$(log_count_since "$service" "$needle")" -ge "$count" ]] && return 0
    sleep 1
  done
  fail "The service ${service} did not print: ${needle} (${count})"
}

token_for() {
  dc exec -T coord orblx coord token create --state /var/lib/orblx \
    --out "/var/lib/orblx/tokens/$1" --ttl 3600 >/dev/null
}

enroll() {
  local name="$1" endpoint="$2" out
  token_for "$name"
  out="$(dc --profile tool run --rm --no-deps tool coord enroll \
    --name "$name" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "/work/${name}" \
    --endpoint "${endpoint}:443")"
  printf '%s\n' "$out" | grep -E '^(name|overlay_ip) ' || true
}

set_policy() {
  python3 - "$ROOT/scripts/proof/netmap-mixed.hujson" "$MIX_POLICY_DIR/policy.hujson" <<'PY'
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
text = re.sub(r",(\s*[}\]])", r"\1", text)
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(json.loads(text), indent=2) + "\n")
PY
}

overlay_of() {
  jq -r --arg n "$2" '.peers[] | select(.name==$n) | .overlay_ip' "$WORK/$1/netmap.json"
}

# The container id and the start time. A restart or a new container changes the value.
run_id() {
  local id
  id="$(dc --profile nodes ps -q "$1")"
  [[ -n "$id" ]] || { echo "none"; return; }
  docker inspect -f '{{.Id}} {{.State.StartedAt}} running={{.State.Running}} restarts={{.RestartCount}}' "$id"
}

wait_paths() {
  local node peer
  for node in "$@"; do
    for peer in "$@"; do
      [[ "$node" == "$peer" ]] && continue
      wait_log "$node" "The path to ${peer} is direct." 1 90
    done
  done
}

# Wait until NODE cannot ping PEER_IP (3 failed pings in a row). Print the wait time.
wait_no_ping() {
  local node="$1" ip="$2" limit="${3:-90}" start
  start="$(now_ms)"
  for _ in $(seq 1 "$limit"); do
    if ! dc exec -T "$node" ping -n -c 3 -W 1 "$ip" >/dev/null 2>&1; then
      echo "$(( $(now_ms) - start ))"
      return 0
    fi
    sleep 1
  done
  return 1
}

contention_check() {
  local line samples unknown
  [[ -n "${PROOF_LOCK_SAMPLES:-}" && -f "$PROOF_LOCK_SAMPLES" ]] || {
    echo "proof_invalid $1 no proof-lock sample file: contention is unknown" >&2
    exit 1
  }
  line="$(awk '{ n++; if ($2 < 0) u++; if ($2 > 0) b++ } END { printf "samples %d contended_samples %d unknown_samples %d", n + 0, b + 0, u + 0 }' "$PROOF_LOCK_SAMPLES")"
  echo "contention_check $1 ${line}"
  samples="$(awk '{print $2}' <<<"$line")"
  unknown="$(awk '{print $6}' <<<"$line")"
  if [[ "$samples" -lt 1 || "$unknown" -gt 0 ]]; then
    echo "proof_invalid $1 samples ${samples} unknown_samples ${unknown}" >&2
    exit 1
  fi
}

echo "=== [C] W25-34 mixed-version proof start $(date '+%F %T %Z') old ${OLD_LABEL} old_policy_wait ${OLD_POLICY_WAIT} ==="
dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
mkdir -p "$MIX_COORD_STATE" "$MIX_POLICY_DIR"
chmod 0700 "$WORK"
set_policy

echo "=== [C] build images ==="
build_images

echo "=== [C] Phase P: all old (rc.2) ==="
dc up -d coord
wait_bundle
enroll a 172.30.135.4
enroll b 172.30.135.5
enroll c 172.30.135.6
enroll d 172.30.135.7
dc --profile nodes up -d a b c d
wait_paths a b c d
echo "All paths are direct (all old)."
[[ ! -e "$MIX_COORD_STATE/netmap-seq" ]] || fail "The rc.2 coordinator wrote netmap-seq."
for node in "${NODES[@]}"; do
  [[ ! -e "$WORK/$node/netmap.seq" ]] || fail "The rc.2 node ${node} wrote netmap.seq."
done
echo "rc.2 state: no coordinator netmap-seq file, no node netmap.seq file"
sleep 20

echo "=== [C] Gate X1: new coordinator, old nodes ==="
declare -A id0
for node in "${NODES[@]}"; do
  id0[$node]="$(run_id "$node")"
done
MIX_COORD_IMAGE="$NEW_IMAGE" dc up -d --no-deps coord
x1_start="$(date +%s)"
if [[ "$OLD_POLICY_WAIT" == 1 ]]; then
  for _ in $(seq 1 90); do
    [[ "$(log_count coord 'coord rejected: version mismatch, upgrade')" -ge 4 ]] && break
    sleep 1
  done
fi
sleep 40
echo "coordinator log (new):"
dc logs coord 2>&1 | grep -E 'coord rejected: version mismatch' | sed -E 's/^[^|]*\| //' | sort | uniq -c | sed 's/^/  /'
for node in "${NODES[@]}"; do
  n="$(dc logs coord 2>&1 | grep -c -- "coord rejected: version mismatch, upgrade node ${node} " || true)"
  echo "coord mismatch lines for old node ${node}: ${n}"
  if [[ "$OLD_POLICY_WAIT" == 1 ]]; then
    [[ "$n" -ge 1 ]] || fail "Gate X1: the coordinator did not log the mismatch for ${node}."
  fi
done
for node in "${NODES[@]}"; do
  now_id="$(run_id "$node")"
  echo "old node ${node} run ${now_id}"
  [[ "$now_id" == "${id0[$node]}" ]] || fail "Gate X1: old node ${node} restarted or exited."
  [[ "$now_id" == *"running=true"* ]] || fail "Gate X1: old node ${node} is not running."
done
echo "old node a log since the coordinator change (last 15 lines):"
dc --profile nodes logs --since "${x1_start}" a 2>&1 | tail -n 15 | sed 's/^/  /'
echo "old node a log lines with 'version mismatch': $(log_count a 'version mismatch')"
echo "old node a: orblx status:"
dc exec -T a orblx status --state-dir /var/lib/orblx 2>&1 | sed 's/^/  /' || true
echo "old enroll of e (old tool, new coordinator):"
token_for e
MIX_TOOL_IMAGE="$OLD_IMAGE" dc --profile tool run --rm --no-deps tool coord enroll \
  --name e --coord "$COORD" --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/e --state /work/e --endpoint 172.30.135.8:443 \
  >"$WORK/enroll-e.out" 2>&1 && enroll_rc=0 || enroll_rc=$?
sed 's/^/  /' "$WORK/enroll-e.out"
echo "old enroll rc ${enroll_rc}"
[[ "$enroll_rc" -ne 0 ]] || fail "Gate X1: the old enroll worked with the new coordinator."
grep -q 'version mismatch, upgrade' "$WORK/enroll-e.out" || fail "Gate X1: the old enroll did not print the mismatch."
c_ip="$(overlay_of a c)"
dc exec -T a ping -n -c 3 -W 1 "$c_ip" >/dev/null || fail "Gate X1: old a cannot ping c before the revoke."
dc exec -T b ping -n -c 3 -W 1 "$c_ip" >/dev/null || fail "Gate X1: old b cannot ping c before the revoke."
echo "revoke c with the new CLI (identity of a):"
MIX_TOOL_IMAGE="$NEW_IMAGE" dc --profile tool run --rm --no-deps tool admin revoke c \
  --coord "$COORD" --state /work/a --bundle /work/a/bundle.pem 2>&1 | grep -E '^(revoked|deny_version|revoke_)' | sed 's/^/  /' \
  || fail "Gate X1: the new CLI did not revoke c."
for node in a b; do
  waited="$(wait_no_ping "$node" "$c_ip" 90)" || fail "Gate X1: old ${node} can still ping revoked c."
  grep -q 'spiffe://orblx.local/node/c' "$WORK/$node/deny.json" || fail "Gate X1: deny.json of old ${node} has no c."
  echo "old ${node}: ping to revoked c fails after ${waited} ms; deny.json has c"
done
sleep 10
for node in a b; do
  if dc exec -T "$node" ping -n -c 5 -W 1 "$c_ip" >/dev/null 2>&1; then
    fail "Gate X1: old ${node} reached revoked c again."
  fi
done
echo "old a and b: 0 of 5 pings to revoked c after 10 s more"
for node in "${NODES[@]}"; do
  [[ "$(run_id "$node")" == "${id0[$node]}" ]] || fail "Gate X1: old node ${node} restarted or exited."
done
echo "old nodes: 0 restarts, 0 exits in Gate X1"
contention_check X1
echo "GATE_PASS X1 new-coordinator-old-nodes"

echo "=== [C] Gate U: nodes a, b, d to new on rc.2 state ==="
dc --profile nodes stop c >/dev/null
first_line="$(dc logs coord 2>&1 | awk '/netmap seq first after start/ && !n { sub(/^[^|]*\| /, ""); print; n = 1 }' || true)"
echo "coordinator (before node upgrade): ${first_line:-no netmap signed yet}"
for node in a b d; do
  [[ ! -e "$WORK/$node/netmap.seq" ]] || fail "Gate U: ${node} has netmap.seq before the upgrade."
done
up_start="$(now_ms)"
MIX_A_IMAGE="$NEW_IMAGE" MIX_B_IMAGE="$NEW_IMAGE" MIX_D_IMAGE="$NEW_IMAGE" \
  dc --profile nodes up -d --no-deps a b d
wait_paths a b d
up_ms=$(( $(now_ms) - up_start ))
first_line="$(dc logs coord 2>&1 | awk '/netmap seq first after start/ && !n { sub(/^[^|]*\| /, ""); print; n = 1 }' || true)"
echo "coordinator: ${first_line}"
[[ "$first_line" =~ persisted\ none\ seq\ ([0-9]+)\ issued_at_ms\ ([0-9]+) ]] \
  || fail "Gate U: no 'persisted none' first-seq line."
[[ "${BASH_REMATCH[1]}" == "${BASH_REMATCH[2]}" ]] || fail "Gate U: the first seq is not issued_at_ms."
echo "first seq ${BASH_REMATCH[1]} == issued_at_ms ${BASH_REMATCH[2]} (max(persisted + 1, issued_at_ms), persisted none)"
for node in a b d; do
  [[ "$(log_count_since "$node" 'netmap refuse')" -eq 0 ]] || fail "Gate U: ${node} printed netmap refuse."
  [[ "$(log_count_since "$node" 'version mismatch')" -eq 0 ]] || fail "Gate U: ${node} printed a mismatch."
  [[ -s "$WORK/$node/netmap.seq" ]] || fail "Gate U: ${node} did not write netmap.seq."
  echo "new node ${node}: netmap.seq $(awk '{print $1}' "$WORK/$node/netmap.seq"), 0 netmap refuse, 0 mismatch"
done
echo "new nodes a, b, d: direct paths in ${up_ms} ms after the start, no manual step"
id_a_up="$(run_id a)"
contention_check U
echo "GATE_PASS U upgrade-on-rc2-state"

echo "=== [C] Gate X2: old coordinator, new nodes ==="
declare -A id1
for node in a b d; do
  id1[$node]="$(run_id "$node")"
done
MIX_COORD_IMAGE="$OLD_IMAGE" dc up -d --no-deps coord
for node in a b d; do
  wait_log "$node" 'ALERT version mismatch, upgrade' 1 90
done
echo "new node a log (mismatch lines):"
dc --profile nodes logs a 2>&1 | grep 'version mismatch' | sed -E 's/^[^|]*\| //' | sed 's/^/  /'
for node in a b d; do
  status="$(dc exec -T "$node" orblx status --state-dir /var/lib/orblx 2>&1 || true)"
  coord_line="$(grep -E '^coord ' <<<"$status" || true)"
  echo "new node ${node} orblx status: ${coord_line}"
  [[ "$coord_line" == "coord version mismatch, upgrade"* ]] || fail "Gate X2: orblx status of ${node} does not show the mismatch."
done
json="$(dc exec -T a orblx status --json --state-dir /var/lib/orblx 2>&1 || true)"
echo "new node a orblx status --json coord: $(jq -r '.coord // "none"' <<<"$json" 2>/dev/null || echo none)"
jq -e '.coord | startswith("version mismatch, upgrade")' <<<"$json" >/dev/null || fail "Gate X2: the JSON status has no coord key."
d_ip="$(overlay_of a d)"
dc exec -T a ping -n -c 3 -W 1 "$d_ip" >/dev/null || fail "Gate X2: a cannot ping d before the revoke."
echo "revoke d with the new CLI against the old coordinator:"
MIX_TOOL_IMAGE="$NEW_IMAGE" dc --profile tool run --rm --no-deps tool admin revoke d \
  --coord "$COORD" --state /work/a --bundle /work/a/bundle.pem 2>&1 | grep -E '^(revoked|deny_version|revoke_)' | sed 's/^/  /' \
  || fail "Gate X2: the new CLI did not revoke d."
for node in a b; do
  waited="$(wait_no_ping "$node" "$d_ip" 90)" || fail "Gate X2: new ${node} can still ping revoked d."
  grep -q 'spiffe://orblx.local/node/d' "$WORK/$node/deny.json" || fail "Gate X2: deny.json of ${node} has no d."
  echo "new ${node}: ping to revoked d fails after ${waited} ms; deny.json has d"
done
sleep 10
for node in a b; do
  if dc exec -T "$node" ping -n -c 5 -W 1 "$d_ip" >/dev/null 2>&1; then
    fail "Gate X2: ${node} reached revoked d again."
  fi
done
echo "new a and b: 0 of 5 pings to revoked d after 10 s more"
for node in a b d; do
  now_id="$(run_id "$node")"
  echo "new node ${node} run ${now_id}"
  [[ "$now_id" == "${id1[$node]}" ]] || fail "Gate X2: new node ${node} restarted or exited."
done
[[ "$id_a_up" == "$(run_id a)" ]] || fail "Gate X2: a restarted."
echo "new nodes: 0 restarts, 0 exits in Gate X2"
contention_check X2
echo "GATE_PASS X2 old-coordinator-new-nodes"
echo "proof_ok $(date '+%F %T %Z')"

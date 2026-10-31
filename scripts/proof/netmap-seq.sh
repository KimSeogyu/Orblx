#!/usr/bin/env bash
# W25-34 netmap seq proof.
# The host is REAL. The coordinator and nodes a, b, and c are [C] containers. Each node runs
# `orblx up --coord`. The script enrolls each node with a coordinator token.
# Gate H (heartbeat): no change for HB_SECONDS (default 600). Each node gets a signed heartbeat
#   (the signed issued_at is 20 s old or less at each sample). No node prints a dial, a path
#   change, a session end, a peer add, a policy apply, or a DNS or grants reload. The session
#   gauge does not change. netmap.json, grants.json, and endpoints.json do not change.
#   The script prints the coordinator interface bytes per node per hour.
# Gate R (replay after revoke): save the signed files of a. Node a (owner) revokes and expires c.
#   A proof tool (crates/orblx-coord/examples/netmap_replay.rs) gives the saved older signed
#   netmap to the node intake path. The node must refuse it (seq-lower). c stays out of the
#   netmap of a, and a cannot ping c.
# Gate O (offline node): stop b for OFFLINE_SECONDS (default 75) and change the policy.
#   Start b. b must take the new netmap and get a direct path to a with no manual step.
# Gate B (backup-restore): copy the coordinator state, wait, put the copy back, and restart
#   the coordinator. The nodes must take the next netmap with no refusal. The seq goes up.
# No node log may have "netmap refuse" in the run.
# PO rule: each contention claim gives unknown_samples with contended_samples. A run is valid
# only with samples >= 1 and unknown_samples 0. Else the script prints proof_invalid and stops
# with exit 1.
# SEQ_MODE=baseline runs only the setup and the heartbeat bytes for an older binary
# (ORBLX_SEQ_BIN), with no seq gate.
# The script does not print enroll tokens or private keys.
# The script takes the box proof lock (proof-lock.sh). Proofs run one at a time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.netmap-seq.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w2534-seq-proof}"
export ORBLX_SEQ_IMAGE="${ORBLX_SEQ_IMAGE:-orblx-w2534-seq:local}"
MODE="${SEQ_MODE:-full}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="${ORBLX_SEQ_BIN:-}"
REPLAY_BIN="${ORBLX_SEQ_REPLAY_BIN:-}"
HB_SECONDS="${HB_SECONDS:-600}"
OFFLINE_SECONDS="${OFFLINE_SECONDS:-75}"
WORK="$(mktemp -d)"
export SEQ_WORK="$WORK"
export SEQ_COORD_STATE="$WORK/coord"
export SEQ_POLICY_DIR="$WORK/policy"
export SEQ_A_STATE="$WORK/a"
export SEQ_B_STATE="$WORK/b"
export SEQ_C_STATE="$WORK/c"
COORD="172.30.134.2:443"
NODES=(a b c)

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
proof_lock_take "netmap-seq:${PROOF_PROJECT}" "${PROOF_PROJECT}-"
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"
proof_compose_clean "${PROOF_PROJECT}" || exit 1

fail() {
  echo "GATE_FAIL $1" >&2
  dc --profile nodes logs --tail 80 a b c coord >&2 || true
  exit 1
}

now_ms() {
  date +%s%3N
}

build_image() {
  local image_dir
  if [[ -z "$BIN" ]]; then
    cargo build --release -p orblx-cli --bin orblx --locked
    BIN="$TARGET_DIR/release/orblx"
  fi
  if [[ "$MODE" == full && -z "$REPLAY_BIN" ]]; then
    cargo build --release -p orblx-coord --example netmap_replay --locked
    REPLAY_BIN="$TARGET_DIR/release/examples/netmap_replay"
  fi
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$BIN")"
  docker build -q -t "$ORBLX_SEQ_IMAGE" "$image_dir" >/dev/null
  rm -rf "$image_dir"
}

wait_bundle() {
  for _ in $(seq 1 90); do
    [[ -s "$SEQ_COORD_STATE/trust-bundle.pem" ]] && return 0
    sleep 1
  done
  fail "The coordinator did not write the trust bundle."
}

log_count() {
  dc --profile nodes logs "$1" 2>&1 | grep -c -- "$2" || true
}

wait_log() {
  local service="$1" needle="$2" count="${3:-1}" limit="${4:-60}"
  for _ in $(seq 1 "$limit"); do
    [[ "$(log_count "$service" "$needle")" -ge "$count" ]] && return 0
    sleep 1
  done
  fail "The service ${service} did not print: ${needle} (${count})"
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

# Write the policy file with a rename. The argument is Python code that changes `data`.
set_policy() {
  python3 - "$ROOT/scripts/proof/netmap-seq.hujson" "$SEQ_POLICY_DIR/policy.next" "$1" <<'PY'
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
text = re.sub(r",(\s*[}\]])", r"\1", text)
data = json.loads(text)
exec(sys.argv[3])
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(data, indent=2) + "\n")
PY
  mv "$SEQ_POLICY_DIR/policy.next" "$SEQ_POLICY_DIR/policy.hujson"
}

node_seq() {
  awk '{print $1}' "$WORK/$1/netmap.seq" 2>/dev/null || echo 0
}

node_issued() {
  jq -r '.netmap.issued_at_ms // 0' "$WORK/$1/netmap.signed.json" 2>/dev/null || echo 0
}

coord_seq() {
  tr -d '[:space:]' <"$SEQ_COORD_STATE/netmap-seq" 2>/dev/null || echo 0
}

file_id() {
  stat -c '%i %Y %s' "$1" 2>/dev/null | tr ' ' ':'
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

overlay_of() {
  jq -r --arg n "$2" '.peers[] | select(.name==$n) | .overlay_ip' "$WORK/$1/netmap.json"
}

sessions() {
  dc exec -T "$1" curl -fsS http://127.0.0.1:9464/metrics 2>/dev/null \
    | awk '$1=="orblx_node_sessions" {print $2}'
}

coord_bytes() {
  dc exec -T coord sh -c 'echo $(( $(cat /sys/class/net/eth0/statistics/rx_bytes) + $(cat /sys/class/net/eth0/statistics/tx_bytes) ))'
}

# The node log lines that show a dial, a path or session change, or a reload.
CHANGE_LINES=(
  "The dial to"
  "The path to"
  "ended the session"
  "The node adds the peer"
  "The node applied a new policy from the coordinator."
  "The DNS answers follow the new netmap."
  "The DNS responder loaded new signed grants"
  "netmap refuse"
)

change_counts() {
  local node="$1" line out=""
  for line in "${CHANGE_LINES[@]}"; do
    out+="$(log_count "$node" "$line") "
  done
  printf '%s\n' "$out"
}

# Read the proof-lock sampler file (one line per sample: time count load1; count -1 = unknown).
# PO rule (W25-35, #132): the run is valid only with samples >= 1 and unknown_samples 0.
# The script reports contended_samples with unknown_samples. It never drops a gap or a sample
# as a host stall.
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

echo "=== [C] W25-34 netmap seq proof mode ${MODE} start $(date '+%F %T %Z') ==="
dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
mkdir -p "$SEQ_COORD_STATE" "$SEQ_POLICY_DIR"
chmod 0700 "$WORK"
set_policy "pass"

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle
dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson

echo "=== [C] enroll a, b, c with coordinator tokens ==="
enroll a 172.30.134.4
enroll b 172.30.134.5
enroll c 172.30.134.6

echo "=== [C] start a, b, c ==="
dc --profile nodes up -d a b c
for node in "${NODES[@]}"; do
  for peer in "${NODES[@]}"; do
    [[ "$node" == "$peer" ]] && continue
    wait_log "$node" "The path to ${peer} is direct." 1 90
  done
done
echo "All paths are direct."
# Let the first policy-wait replies and the keepalives settle.
sleep 30

echo "=== [C] Gate H: heartbeat with no change for ${HB_SECONDS} s ==="
declare -A before_counts before_sessions before_files seqs_seen max_age
for node in "${NODES[@]}"; do
  before_counts[$node]="$(change_counts "$node")"
  before_sessions[$node]="$(sessions "$node")"
  before_files[$node]="$(file_id "$WORK/$node/netmap.json") $(file_id "$WORK/$node/grants.json") $(file_id "$WORK/$node/endpoints.json")"
  seqs_seen[$node]=""
  max_age[$node]=0
done
bytes0="$(coord_bytes)"
t0="$(date +%s)"
samples=0
while [[ $(( $(date +%s) - t0 )) -lt "$HB_SECONDS" ]]; do
  for node in "${NODES[@]}"; do
    if [[ "$MODE" == full ]]; then
      seq_now="$(node_seq "$node")"
      case " ${seqs_seen[$node]} " in *" ${seq_now} "*) ;; *) seqs_seen[$node]+=" ${seq_now}" ;; esac
      age=$(( $(now_ms) - $(node_issued "$node") ))
      [[ "$age" -gt "${max_age[$node]}" ]] && max_age[$node]="$age"
    fi
  done
  samples=$((samples + 1))
  sleep 2
done
bytes1="$(coord_bytes)"
elapsed=$(( $(date +%s) - t0 ))
bytes=$((bytes1 - bytes0))
per_node_hour=$(( bytes * 3600 / elapsed / ${#NODES[@]} ))
echo "heartbeat_window_s ${elapsed} samples ${samples}"
echo "coord_eth0_bytes ${bytes} nodes ${#NODES[@]} bytes_per_node_per_hour ${per_node_hour}"
hb_fail=0
for node in "${NODES[@]}"; do
  after_counts="$(change_counts "$node")"
  after_sessions="$(sessions "$node")"
  after_files="$(file_id "$WORK/$node/netmap.json") $(file_id "$WORK/$node/grants.json") $(file_id "$WORK/$node/endpoints.json")"
  echo "node ${node} change_counts_before [${before_counts[$node]}] after [${after_counts}] (dial path session_end peer_add policy_apply dns_reload grants_reload refuse)"
  echo "node ${node} sessions_before ${before_sessions[$node]} after ${after_sessions}"
  if [[ "${before_counts[$node]}" != "$after_counts" ]]; then
    echo "node ${node}: a change line was printed in the window." >&2
    hb_fail=1
  fi
  if [[ "${before_sessions[$node]}" != "$after_sessions" ]]; then
    echo "node ${node}: the session gauge changed." >&2
    hb_fail=1
  fi
  if [[ "${before_files[$node]}" != "$after_files" ]]; then
    echo "node ${node}: netmap.json, grants.json, or endpoints.json changed." >&2
    hb_fail=1
  fi
  if [[ "$MODE" == full ]]; then
    count="$(wc -w <<<"${seqs_seen[$node]}")"
    echo "node ${node} distinct_seq_seen ${count} max_issued_age_ms ${max_age[$node]}"
    [[ "${max_age[$node]}" -le 20000 ]] || { echo "node ${node}: the signed issued_at was older than 20 s." >&2; hb_fail=1; }
    [[ "$count" -ge $((HB_SECONDS / 20)) ]] || { echo "node ${node}: too few heartbeats." >&2; hb_fail=1; }
  fi
done
[[ "$hb_fail" -eq 0 ]] || fail "Gate H"
contention_check heartbeat
echo "GATE_PASS H heartbeat"

if [[ "$MODE" != full ]]; then
  echo "proof_ok baseline"
  exit 0
fi

echo "=== [C] Gate R: replay after revoke ==="
mkdir -p "$WORK/a/replay-old"
cp "$WORK/a/netmap.signed.json" "$WORK/a/grants.signed.json" "$WORK/a/endpoints.json" "$WORK/a/replay-old/"
saved_seq="$(jq -r '.netmap.seq' "$WORK/a/replay-old/netmap.signed.json")"
jq -e '.netmap.peers[] | select(.name=="c")' "$WORK/a/replay-old/netmap.signed.json" >/dev/null \
  || fail "The saved netmap of a does not have c."
c_ip="$(overlay_of a c)"
echo "saved_seq ${saved_seq} (the saved netmap has peer c)"
dc exec -T a ping -n -c 3 -W 1 "$c_ip" >/dev/null || fail "a cannot ping c before the revoke."
admin=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
dc exec -T a orblx admin revoke c "${admin[@]}" | grep -E '^revoke_(start|done)_ms' || true
dc exec -T a orblx admin expire c "${admin[@]}" | grep -E '^expires_unix_ms' || true
for _ in $(seq 1 60); do
  jq -e '.peers[] | select(.name=="c")' "$WORK/a/netmap.json" >/dev/null 2>&1 || break
  sleep 1
done
jq -e '.peers[] | select(.name=="c")' "$WORK/a/netmap.json" >/dev/null 2>&1 && fail "c is still in the netmap of a."
echo "after revoke: node_seq_a $(node_seq a) (saved ${saved_seq})"
docker cp "$REPLAY_BIN" "$(dc --profile nodes ps -q a):/tmp/netmap_replay" >/dev/null
replay_out="$(dc exec -T a /tmp/netmap_replay /var/lib/orblx /var/lib/orblx/replay-old 2>&1)" && replay_rc=0 || replay_rc=$?
printf '%s\n' "$replay_out"
[[ "$replay_rc" -eq 0 ]] || fail "Gate R: the node did not refuse the replay (rc ${replay_rc})."
grep -q 'netmap refuse seq-lower' <<<"$replay_out" || fail "Gate R: the refusal is not seq-lower."
sleep 20
jq -e '.peers[] | select(.name=="c")' "$WORK/a/netmap.json" >/dev/null 2>&1 && fail "Gate R: c came back in the netmap of a."
if dc exec -T a ping -n -c 3 -W 1 "$c_ip" >/dev/null 2>&1; then
  fail "Gate R: a can ping c after the replay."
fi
echo "after replay: c is not in the netmap of a, and a cannot ping c."
echo "GATE_PASS R replay-after-revoke"

echo "=== [C] Gate O: offline node b for ${OFFLINE_SECONDS} s ==="
b_seq0="$(node_seq b)"
b_direct0="$(log_count b 'The path to a is direct.')"
b_refuse0="$(log_count b 'netmap refuse')"
dc --profile nodes stop b >/dev/null
set_policy "data['acls'].append({'action': 'accept', 'src': ['spiffe://orblx.local/node/a'], 'proto': 'udp', 'dst': ['spiffe://orblx.local/node/b:9500']})"
sleep "$OFFLINE_SECONDS"
echo "offline: b last seq ${b_seq0} coord seq $(coord_seq)"
start_ms="$(now_ms)"
dc --profile nodes start b >/dev/null
wait_log b 'The path to a is direct.' $((b_direct0 + 1)) 90
back_ms=$(( $(now_ms) - start_ms ))
b_seq1="$(node_seq b)"
[[ "$b_seq1" -gt "$b_seq0" ]] || fail "Gate O: b did not take a new netmap."
[[ "$(log_count b 'netmap refuse')" -eq "$b_refuse0" ]] || fail "Gate O: b refused a netmap."
a_ip="$(overlay_of b a)"
dc exec -T b ping -n -c 3 -W 1 "$a_ip" >/dev/null || fail "Gate O: b cannot ping a."
echo "b back: seq ${b_seq0} -> ${b_seq1}, direct path to a in ${back_ms} ms after start, ping ok, no manual step"
echo "GATE_PASS O offline-node"

echo "=== [C] Gate B: coordinator backup and restore ==="
cp -a "$SEQ_COORD_STATE" "$WORK/coord-backup"
backup_seq="$(coord_seq)"
sleep 40
declare -A pre_seq pre_refuse
for node in a b; do
  pre_seq[$node]="$(node_seq "$node")"
  pre_refuse[$node]="$(log_count "$node" 'netmap refuse')"
done
live_seq="$(coord_seq)"
dc stop coord >/dev/null
rm -rf "$SEQ_COORD_STATE"
cp -a "$WORK/coord-backup" "$SEQ_COORD_STATE"
echo "backup_seq ${backup_seq} live_seq_before_restore ${live_seq} restored_seq $(coord_seq)"
dc start coord >/dev/null
for node in a b; do
  ok=0
  for _ in $(seq 1 90); do
    if [[ "$(node_seq "$node")" -gt "${pre_seq[$node]}" ]]; then ok=1; break; fi
    sleep 1
  done
  [[ "$ok" -eq 1 ]] || fail "Gate B: ${node} did not take a netmap after the restore."
  [[ "$(log_count "$node" 'netmap refuse')" -eq "${pre_refuse[$node]}" ]] || fail "Gate B: ${node} refused a netmap."
  echo "node ${node} seq ${pre_seq[$node]} -> $(node_seq "$node") after restore, no refusal"
done
[[ "$(coord_seq)" -gt "$live_seq" ]] || fail "Gate B: the coordinator seq did not go up."
echo "coord seq after restore $(coord_seq) > ${live_seq}"
echo "GATE_PASS B backup-restore"

for node in "${NODES[@]}"; do
  [[ "$(log_count "$node" 'netmap refuse')" -eq 0 ]] || fail "node ${node} printed netmap refuse."
done
echo "No node log has netmap refuse."
contention_check end
echo "proof_ok $(date '+%F %T %Z')"

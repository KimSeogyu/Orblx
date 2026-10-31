#!/usr/bin/env bash
# W25-28 dead peer dial proof.
# The host is REAL. The coordinator, nodes a, b, c, d, and one UDP sink for 50 dead peers are
# [C] containers. Each node runs `orblx up --coord` and gets its tickets from the coordinator.
# Node a has the lowest name, so node a dials each peer.
# The sink records each datagram to a dead peer and never answers (dead-peer-sink.py).
# A dial is one QUIC Initial destination connection ID (DCID). Only datagrams from a count.
# Gate 1: after the fast window (WINDOW_END_S after node a starts), each dead peer gets
#         0 dials, or 1 dial each 60 s or more (DEAD_SECONDS, default 300).
# Gate 4: in the 0-10 s window after node a starts, all 50 dead peers get BURST_LIMIT
#         datagrams or less (100 datagrams/s). The script also prints each second.
#         The live peer b gets its direct path (report only; no delay of the first dial).
# Gate 2: c is dead until it starts, after the fast window. Outbound traffic from a to c
#         (ping) dials c. The first reply comes in WAKE_LIMIT_MS or less.
# Gate 3: d is dead until it starts, after the fast window. A netmap change (e enrolls)
#         dials d. The redial starts, and the path to d is direct, in WAKE_LIMIT_MS or less
#         after node a applies the new netmap.
# The script deletes the proof containers at the start and at the end.
# The script does not print enroll tokens or private keys.
# The script takes the box proof lock (proof-lock.sh, W25-5) for this one run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.dead-peer.yml"
export PROOF_PROJECT="${PROOF_PROJECT:-orblx-w2528-dead-proof}"
export ORBLX_DEAD_IMAGE="${ORBLX_DEAD_IMAGE:-orblx-w2528-dead:local}"
PROFILE="${ORBLX_DEAD_PROFILE:-release}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
export DEAD_WORK="$WORK"
export DEAD_COORD_STATE="$WORK/coord"
COORD="172.30.133.2:443"
DEAD_PEERS=50
DEAD_SECONDS="${ORBLX_DEAD_SECONDS:-300}"
# The fast dial window (10 s) plus the time limit of the last fast dial attempt (3 s).
WINDOW_END_S=13
REDIAL_MIN_S=60
BURST_LIMIT=1000
WAKE_LIMIT_MS=1000

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK" >/dev/null 2>&1 || as_root rm -rf "$WORK" >/dev/null 2>&1 || true
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "dead-peer:${PROOF_PROJECT}" "${PROOF_PROJECT}-"
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${PROOF_PROJECT}" || exit 1

fail() {
  echo "$1" >&2
  dc --profile nodes logs a c d coord >&2 || true
  exit 1
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
  docker build -q -t "$ORBLX_DEAD_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  for _ in $(seq 1 90); do
    [[ -s "$DEAD_COORD_STATE/trust-bundle.pem" ]] && return 0
    sleep 1
  done
  fail "The coordinator did not write the trust bundle."
}

wait_log() {
  local service="$1" needle="$2" got
  for _ in $(seq 1 120); do
    got="$(dc --profile nodes logs "$service" 2>&1 | grep -c -- "$needle" || true)"
    [[ "$got" -ge 1 ]] && return 0
    sleep 0.25
  done
  fail "The service ${service} did not print: ${needle}"
}

# Print the epoch ms of the first docker log line of SERVICE with NEEDLE at or after AFTER_MS.
log_ms() {
  local service="$1" needle="$2" after="$3" stamp ms
  while read -r stamp; do
    ms="$(date -d "$stamp" +%s%3N)"
    if [[ "$ms" -ge "$after" ]]; then
      echo "$ms"
      return 0
    fi
  done < <(dc --profile nodes logs -t "$service" 2>&1 | grep -F -- "$needle" | awk '{print $3}')
  return 0
}

started_ms() {
  date -d "$(docker inspect --format '{{.State.StartedAt}}' "$(dc --profile nodes ps -q "$1")")" +%s%3N
}

enroll() {
  local name="$1" endpoint="$2"
  dc exec -T coord orblx coord token create --state /var/lib/orblx \
    --out "/var/lib/orblx/tokens/${name}" --ttl 3600 >/dev/null
  dc --profile tool run --rm --no-deps tool coord enroll \
    --name "$name" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "/work/${name}" \
    --endpoint "${endpoint}" | grep -E '^(name|overlay_ip) ' || true
}

overlay_of() {
  jq -r --arg n "$1" '.peers[] | select(.name == $n) | .overlay_ip' "$WORK/a/netmap.json"
}

path_of() {
  dc exec -T a orblx status --state-dir /var/lib/orblx 2>/dev/null \
    | awk -v n="$2" '$1 == "peer" && $2 == n {for (i = 3; i < NF; i++) if ($i == "path") print $(i + 1)}'
}

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
mkdir -p "$DEAD_COORD_STATE"

echo "=== [C] build image (${PROFILE}) ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

echo "=== [C] enroll a, b, c, d and ${DEAD_PEERS} dead peers (before a starts) ==="
enroll a 172.30.133.4:443
enroll b 172.30.133.5:443
enroll c 172.30.133.6:443
enroll d 172.30.133.7:443
dc exec -T coord sh -c "for i in \$(seq -w 1 ${DEAD_PEERS}); do orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/dead\$i --ttl 3600 >/dev/null || exit 1; done"
dc --profile tool run --rm --no-deps --entrypoint sh tool -c "for n in \$(seq 1 ${DEAD_PEERS}); do i=\$(printf %02d \$n); orblx coord enroll --name dead\$i --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/dead\$i --state /work/dead/\$i --endpoint 172.30.133.9:\$((20000 + n)) >/dev/null || exit 1; done"
echo "dead_enrolled ${DEAD_PEERS} endpoints 172.30.133.9:20001-200$(printf '%02d' "$DEAD_PEERS")"

echo "=== [C] start the sink and b ==="
dc --profile nodes up -d sink b
for _ in $(seq 1 40); do
  [[ -s "$WORK/sink.log" ]] && break
  sleep 0.25
done
[[ -s "$WORK/sink.log" ]] || fail "The sink did not start."
wait_log b 'The node b listens on UDP'

echo "=== [C] start a (t0) ==="
dc --profile nodes up -d a
a_start="$(started_ms a)"
wait_log a 'The path to b is direct.'
b_direct="$(log_ms a 'The path to b is direct.' "$a_start")"
echo "a_started_ms ${a_start} live_peer_b_direct_after_a_start_ms $((b_direct - a_start))"
c_ip="$(overlay_of c)"; d_ip="$(overlay_of d)"
[[ -n "$c_ip" && -n "$d_ip" ]] || fail "The netmap of a has no overlay address for c or d."

echo "=== Gate 1 and 4 [C]: ${DEAD_PEERS} dead peers for ${DEAD_SECONDS} s, no netmap change ==="
end_ms=$((a_start + DEAD_SECONDS * 1000))
while [[ "$(date +%s%3N)" -lt "$end_ms" ]]; do
  sleep 5
done
cp "$WORK/sink.log" "$WORK/sink-phase1.log"
python3 - "$WORK/sink-phase1.log" "$a_start" "$DEAD_SECONDS" "$WINDOW_END_S" "$REDIAL_MIN_S" "$BURST_LIMIT" "$DEAD_PEERS" <<'PY' || fail "Gate 1 or gate 4 failed."
import sys
from collections import defaultdict
path, t0, secs, win, gap_min, burst_limit, peers = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7])
first = defaultdict(dict)  # port -> dcid -> first ms
per_sec = [0] * 10
total = 0
for line in open(path):
    p = line.split()
    if not p or p[0] != "rx":
        continue
    # Only datagrams from node a count. b, c, and d also dial the dead peers (lower names).
    if p[3] != "172.30.133.4":
        continue
    ms, port, dcid = int(p[1]), int(p[2]), p[5]
    rel = ms - t0
    if rel < 0 or rel >= secs * 1000:
        continue
    total += 1
    if rel < 10000:
        per_sec[rel // 1000] += 1
    if dcid not in ("short", "empty") and dcid not in first[port]:
        first[port][dcid] = rel
burst = sum(per_sec)
print(f"burst_0_10s datagrams {burst} mean_per_s {burst / 10:.1f} limit {burst_limit} per_second {per_sec}")
print(f"phase1 datagrams {total} ports_seen {len(first)} of {peers}")
bad = []
after_counts = []
min_gap = None
window_dials = 0
for port in range(20001, 20001 + peers):
    times = sorted(first.get(port, {}).values())
    window = [t for t in times if t < win * 1000]
    after = [t for t in times if t >= win * 1000]
    window_dials += len(window)
    after_counts.append(len(after))
    prev = None
    for t in after:
        if prev is not None:
            gap = t - prev
            min_gap = gap if min_gap is None else min(min_gap, gap)
            if gap < gap_min * 1000:
                bad.append(f"{port}:{prev}->{t}")
        prev = t
    # At most 1 dial in the first 60 s after the window end.
    if len([t for t in after if t < (win + gap_min) * 1000]) > 1:
        bad.append(f"{port}:two_in_first_60s")
sample = sorted(first.get(20001, {}).values())
print(f"dead_peer_dials window_total {window_dials} after_window_per_peer min {min(after_counts)} max {max(after_counts)} min_gap_after_window_ms {min_gap}")
print(f"dead_peer_20001_dial_ms {sample}")
print(f"dead_peer_violations {len(bad)} {bad[:5]}")
ok = burst <= burst_limit and not bad
sys.exit(0 if ok else 1)
PY
echo "[C] gate1 ok"
echo "[C] gate4 ok"

echo "=== Gate 2 [C]: c starts after the window; traffic from a dials c ==="
[[ "$(path_of a c)" != direct && "$(path_of a c)" != relay ]] || fail "Node a has a path to c before c starts."
c_up="$(date +%s%3N)"
dc --profile nodes up -d c
wait_log c 'The node c listens on UDP'
[[ "$(path_of a c)" != direct ]] || fail "Node a dialed c before the traffic. The gate needs an idle dial task."
t_traffic="$(date +%s%3N)"
dc exec -T a sh -c "ping -D -n -i 0.05 -W 1 -c 60 ${c_ip} >/tmp/ping-c.log 2>&1 || true"
first_reply="$(dc exec -T a sh -c 'grep -m1 "bytes from" /tmp/ping-c.log' | sed -E 's/^\[([0-9]+)\.([0-9]{3}).*/\1\2/' || true)"
[[ "$first_reply" =~ ^[0-9]+$ ]] || fail "Node a did not reach c."
dc exec -T a sh -c 'tail -n 2 /tmp/ping-c.log'
redial_c="$(log_ms a 'The node dials c again. The reason is outbound traffic.' "$c_up")"
echo "c_started_after_a_ms $((c_up - a_start)) traffic_to_first_reply_ms $((first_reply - t_traffic)) traffic_to_redial_log_ms $(( ${redial_c:-0} - t_traffic )) limit ${WAKE_LIMIT_MS}"
[[ -n "$redial_c" ]] || fail "Node a did not log a redial to c on traffic."
[[ $((first_reply - t_traffic)) -le "$WAKE_LIMIT_MS" ]] || fail "The first reply from c took more than ${WAKE_LIMIT_MS} ms."
echo "[C] gate2 ok"

echo "=== Gate 3 [C]: d starts after the window; a netmap change dials d ==="
dc --profile nodes up -d d
wait_log d 'The node d listens on UDP'
sleep 1
[[ "$(path_of a d)" != direct ]] || fail "Node a dialed d before the netmap change. The gate needs an idle dial task."
t_enroll="$(date +%s%3N)"
enroll e 172.30.133.8:443
t_enrolled="$(date +%s%3N)"
wait_log a 'The node adds the peer e from the new netmap.'
wait_log a 'The path to d is direct.'
t_netmap="$(log_ms a 'The node adds the peer e from the new netmap.' "$t_enroll")"
redial_d="$(log_ms a 'The node dials d again. The reason is a netmap change.' "$t_enroll")"
d_direct="$(log_ms a 'The path to d is direct.' "$t_enroll")"
[[ -n "$t_netmap" && -n "$redial_d" && -n "$d_direct" ]] || fail "Node a did not log the netmap redial to d."
echo "enroll_e_ms $((t_enrolled - t_enroll)) enroll_done_to_netmap_applied_ms $((t_netmap - t_enrolled)) netmap_to_redial_log_ms $((redial_d - t_netmap)) netmap_to_d_direct_ms $((d_direct - t_netmap)) limit ${WAKE_LIMIT_MS}"
[[ $((redial_d - t_netmap)) -le "$WAKE_LIMIT_MS" && $((d_direct - t_netmap)) -le "$WAKE_LIMIT_MS" ]] \
  || fail "The redial to d took more than ${WAKE_LIMIT_MS} ms after the netmap change."
echo "[C] gate3 ok"

echo "=== [C] node a dial log lines ==="
dc --profile nodes logs a 2>&1 | grep -cE 'The node dials .* again' | sed 's/^/a_redial_log_lines /'
dc --profile nodes logs a 2>&1 | grep -E 'The node dials (dead01|c|d) again' | sed -E 's/^[^|]*\| //' | sed -n '1,20p'

echo "=== [C] logs hold no key or enroll token ==="
dc --profile nodes logs >"$WORK/all-logs.out" 2>&1 || fail "docker compose logs failed."
secret_scan "$WORK/all-logs.out" || fail "A log holds a private key or an enroll token, or the log is empty."
echo "proof_ok"

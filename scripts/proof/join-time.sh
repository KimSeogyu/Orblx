#!/usr/bin/env bash
# Join-time proof.
# The host is REAL. The coordinator, node a, and node b are [C] containers on one Linux host.
# The script runs N late-peer joins (JOIN_N, default 20) one after the other in one run.
# Each join starts from a clean state: its own compose project (JOIN_PROJECT_BASE-jI), its
# own new state directories, a new coordinator, and proof_compose_clean (W25-14b) before
# the first "up" and after the join. No state goes from one join to the next.
# In each join, node a runs first. Then the tool enrolls b, a pings b each 100 ms, and b starts.
# For each join the script prints:
#   enroll_to_first_packet_ms    from the start of the enroll call of b to the first ICMP
#                                reply from b on a (report only, no limit)
#   listener_to_first_packet_ms  from the listener start that b logs ("The node b listener
#                                started at unix_ms M.") to the same first reply
# All three clocks are the clock of the one host (date, ping -D, and the node log).
# Gate: each join reaches its first packet (a timeout or an error fails the proof), and each
# join has listener_to_first_packet_ms of LIMIT_MS (2000) or less. join-time-summary.py
# prints n, median, p95 and max of both values from all joins (it drops no join).
# Test only: ORBLX_JOIN_BREAK_AT=K removes the trust bundle of b in join K. Then b cannot
# start, and the proof must fail.
# The script does not print enroll tokens or private keys.
# The script takes the box proof lock (proof-lock.sh). Proofs run one at a time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
cd "$ROOT"
FILE="scripts/proof/compose.join-time.yml"
BASE="${JOIN_PROJECT_BASE:-orblx-join-time}"
export ORBLX_JOIN_IMAGE="${ORBLX_JOIN_IMAGE:-orblx-join-time:local}"
PROFILE="${ORBLX_JOIN_PROFILE:-release}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
N="${JOIN_N:-20}"
BREAK_AT="${ORBLX_JOIN_BREAK_AT:-0}"
LIMIT_MS=2000
FIRST_PACKET_WAIT_S=30
COORD="172.30.127.2:443"
WORKROOT="$(mktemp -d "${TMPDIR:-/tmp}/orblx-join-time.XXXXXX")"
JOINS="$WORKROOT/joins.txt"
: >"$JOINS"
export JOIN_PROJECT="${BASE}-j0"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack of ${JOIN_PROJECT} for debug."
    return
  fi
  dc --profile nodes down -v --remove-orphans >/dev/null 2>&1 || true
  # The containers write the state as root.
  as_root rm -rf "$WORKROOT" >/dev/null 2>&1 || true
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "join-time:${BASE}" "${BASE}-"
# W25-14b: each join starts from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"

[[ "$N" =~ ^[1-9][0-9]*$ ]] || { echo "JOIN_N must be a whole number of 1 or more."; exit 2; }
# Clean the compose project of every join of this run before any start. Each join cleans its
# own project again before its first "up" and after it ends.
mapfile -t JOIN_PROJECTS < <(seq -f "${BASE}-j%g" 1 "$N")
proof_compose_clean "${JOIN_PROJECTS[@]}" || exit 1
if [[ "$BREAK_AT" != 0 ]]; then
  echo "TEST ONLY: ORBLX_JOIN_BREAK_AT=${BREAK_AT}. Join ${BREAK_AT} must fail, and the proof must fail."
fi

summary() {
  python3 "$ROOT/scripts/proof/join-time-summary.py" "$JOINS" "$N" "$LIMIT_MS"
}

# Write the fail line of join I, print the logs of the join and the summary, and stop.
join_fail() {
  local i="$1" reason="$2"
  echo "join ${i} fail ${reason}" >>"$JOINS"
  echo "join ${i} fail ${reason}" >&2
  dc --profile nodes logs a b coord >&2 || true
  summary || true
  exit 1
}

wait_bundle() {
  local i="$1"
  for _ in $(seq 1 90); do
    [[ -s "$JOIN_COORD_STATE/trust-bundle.pem" ]] && return 0
    sleep 1
  done
  join_fail "$i" "the coordinator did not write the trust bundle"
}

wait_log() {
  local i="$1" service="$2" needle="$3" got
  for _ in $(seq 1 60); do
    got="$(dc --profile nodes logs "$service" 2>&1 | grep -c -- "$needle" || true)"
    [[ "$got" -ge 1 ]] && return 0
    sleep 1
  done
  join_fail "$i" "the service ${service} did not print: ${needle}"
}

token() {
  dc exec -T coord orblx coord token create --state /var/lib/orblx \
    --out "/var/lib/orblx/tokens/$1" --ttl 3600 >/dev/null
}

enroll() {
  dc exec -T tool orblx coord enroll \
    --name "$1" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/$1" \
    --state "/work/$1" \
    --endpoint "$2:443"
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
  docker build -q -t "$ORBLX_JOIN_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

one_join() {
  local i="$1" jw b_out b_ip t0 first_reply listen_ms enroll_ms listener_ms
  export JOIN_PROJECT="${BASE}-j${i}"
  echo "=== [C] join ${i} of ${N}: project ${JOIN_PROJECT} ==="
  proof_compose_clean "$JOIN_PROJECT" || join_fail "$i" "old compose state is still there"
  jw="$WORKROOT/j${i}"
  mkdir -p "$jw/coord" "$jw/a" "$jw/b"
  export JOIN_WORK="$jw" JOIN_COORD_STATE="$jw/coord" JOIN_A_STATE="$jw/a" JOIN_B_STATE="$jw/b"
  dc up -d coord tool || join_fail "$i" "the coordinator or the tool did not start"
  wait_bundle "$i"
  if [[ "$i" == 1 ]]; then
    dc exec -T coord orblx policy test --file /etc/orblx/policy.hujson || join_fail "$i" "the policy test failed"
  fi
  token a || join_fail "$i" "the token of a failed"
  token b || join_fail "$i" "the token of b failed"
  enroll a 172.30.127.4 >/dev/null || join_fail "$i" "the enroll of a failed"
  dc --profile nodes up -d a || join_fail "$i" "node a did not start"
  wait_log "$i" a 'The node a listener started at unix_ms'

  t0="$(date +%s%3N)"
  b_out="$(enroll b 172.30.127.5)" || join_fail "$i" "the enroll of b failed"
  enroll_ms="$(( $(date +%s%3N) - t0 ))"
  b_ip="$(awk '$1 == "overlay_ip" {print $2}' <<<"$b_out")"
  [[ -n "$b_ip" ]] || join_fail "$i" "the enroll of b did not print an overlay address"
  if [[ "$BREAK_AT" == "$i" ]]; then
    echo "TEST ONLY: join ${i} removes the trust bundle of b."
    as_root rm -f "$JOIN_B_STATE/bundle.pem"
  fi
  # Ping each 100 ms. -D prints the receive time of each reply as UNIX seconds.
  dc exec -d a sh -c "ping -D -n -i 0.1 -W 1 -c $((FIRST_PACKET_WAIT_S * 10)) ${b_ip} >/tmp/ping-b.log 2>&1" \
    || join_fail "$i" "the ping on a did not start"
  dc --profile nodes up -d b || join_fail "$i" "node b did not start"
  first_reply=""
  for _ in $(seq 1 $((FIRST_PACKET_WAIT_S * 2))); do
    # pipe-ok: the grep -m1 runs in the container sh, with no pipefail.
    first_reply="$(dc exec -T a sh -c 'grep -m1 "bytes from" /tmp/ping-b.log' 2>/dev/null \
      | sed -E 's/^\[([0-9]+)\.([0-9]{3}).*/\1\2/' || true)"
    [[ "$first_reply" =~ ^[0-9]+$ ]] && break
    first_reply=""
    sleep 0.5
  done
  [[ -n "$first_reply" ]] || join_fail "$i" "node a got no reply from b in ${FIRST_PACKET_WAIT_S} s (timeout)"
  listen_ms="$(dc --profile nodes logs b 2>&1 | sed -nE 's/.*The node b listener started at unix_ms ([0-9]+)\..*/\1/p' | tail -n 1)"
  [[ "$listen_ms" =~ ^[0-9]+$ ]] || join_fail "$i" "node b did not log its listener start"
  listener_ms=$((first_reply - listen_ms))
  echo "join ${i} enroll_call_ms ${enroll_ms} listener_unix_ms ${listen_ms} first_reply_unix_ms ${first_reply}"
  echo "join ${i} ok enroll_to_first_packet_ms $((first_reply - t0)) listener_to_first_packet_ms ${listener_ms}" | tee -a "$JOINS"

  dc --profile nodes logs >"$jw/logs.out" 2>&1 || join_fail "$i" "docker compose logs failed"
  secret_scan "$jw/logs.out" || join_fail "$i" "a log holds a private key or an enroll token, or the log is empty"
  dc --profile nodes down -v --remove-orphans >/dev/null 2>&1 || true
  proof_compose_clean "$JOIN_PROJECT" || join_fail "$i" "the compose state of the join is still there"
  as_root rm -rf "$jw"
}

echo "=== [C] build image (${PROFILE}) ==="
build_image

for i in $(seq 1 "$N"); do
  one_join "$i"
done

echo "=== [C] summary of ${N} joins ==="
summary || { echo "The join-time gate failed."; exit 1; }
echo "proof_ok"

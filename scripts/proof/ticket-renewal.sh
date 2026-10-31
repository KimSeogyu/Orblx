#!/usr/bin/env bash
# W25-26: ticket renewal proof with real coordinator tickets (no lab tickets).
# Nodes owner, a, b, c run `orblx up --coord`. The coordinator issues the leaf and the
# capability ticket with the life ORBLX_SVID_TTL (TR_SVID_TTL). Each node pings each other
# node every TR_PING_I s on the overlay.
# Gates:
#  1. Each node crosses TR_ENDS or more ticket ends + MAX_SKEW in a row.
#  2. 0 refusals ("capability ticket check rejected", "leaf check failed", "The end time has passed").
#  3. 0 lost peers: each status sample shows all 3 peers with path direct.
#  4. The largest gap between two replies of a pair is TR_GAP_MS or less, in the whole run
#     and in the window [end - 2 s, end + 2 s] of each ticket end. The proof prints one gap
#     line for each ticket end of each node (ticket_end ...), and one line for each reply gap
#     above TR_GAP_MS with its place (renewal, ticket end, or elsewhere).
#  5. No restart: same container start time, restart count 0, same orblxd pid.
#  6. A new handshake (a to b) after the ticket ends passes.
#  7. (TR_REVOKE=1) A revoked node gets no new ticket, and its peers stop it in TR_REVOKE_MS.
#  8. 0 contended samples while the proof held the lock: the proof-lock sampler saw no
#     other orblx container, no unknown sample, and no host load1 above TR_LOAD_MAX
#     (default: the CPU count).
#  9. Host stall check (W25-26 PO rule). scripts/proof/host-sampler.py writes /proc/stat
#     steal and iowait and /proc/pressure (cpu, io, memory) deltas every 100 ms. A sample is a
#     host stall window when steal_ms >= TR_STALL_STEAL_MS, iowait_ms >= TR_STALL_IOWAIT_MS,
#     cpu some >= TR_STALL_CPU_MS, io full >= TR_STALL_IO_FULL_MS or memory some >=
#     TR_STALL_MEM_MS (all per 100 ms sample, over all CPUs). Each reply gap above
#     TR_GAP_MS gets "class host_stall" when a stall window touches the gap, else
#     "class quiet_host". The gap gate does not change: each gap above TR_GAP_MS fails
#     the run. When one gap is host_stall, the run is INVALID (not a PASS): it prints
#     proof_invalid and exits 3. The run gets 1 clean rerun.
# The nodes run with ORBLX_TRACE_RENEW=1. TR_OUT_DIR keeps the host samples, the ping
# files and the node trace lines after the run.
# Gates 3, 4 and 8 do not stop the proof at once. Gates 5, 6 and 7 run first, then the
# proof fails if one of gates 3, 4 or 8 failed.
# The proof reads MAX_SKEW and MAX_USER_TTL from clock.rs.
# The waits are a schedule. The proof does not retry a check.
# The script does not print tokens, keys, tickets, or bundles.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ticket-renewal.yml"
CLOCK="crates/orblx-identity/src/clock.rs"
export TR_PROJECT="${TR_PROJECT:-orblx-w25t-tr}"
export TR_IMAGE="${TR_IMAGE:-orblx-w25t-tr:local}"
export TR_NET="${TR_NET:-172.28.48}"
export TR_SVID_TTL="${TR_SVID_TTL:-60}"
TR_ENDS="${TR_ENDS:-5}"
TR_GAP_MS="${TR_GAP_MS:-200}"
TR_PING_I="${TR_PING_I:-0.05}"
TR_REVOKE="${TR_REVOKE:-1}"
TR_REVOKE_MS="${TR_REVOKE_MS:-1000}"
TR_BIN="${TR_BIN:-}"
TR_OUT_DIR="${TR_OUT_DIR:-}"
# Host stall limits per 100 ms sample. Baseline: 3000 samples (300 s, 15:29:40-15:34:40 KST
# 2026-10-31, load1 0.7-2.0, 8 CPUs, no proof container of this run). Baseline max: steal
# 100 ms, iowait 80 ms (both summed over 8 CPUs, 10 ms steps), cpu some 72.7 ms, io full
# 52.4 ms, memory some 0.8 ms. Limits: steal and iowait 2x the baseline max; cpu some and
# io full 90 ms (a PSI value cannot pass 100 ms in a 100 ms sample, so 2x is not possible);
# memory some 10 ms. No baseline sample is at or above a limit.
TR_STALL_STEAL_MS="${TR_STALL_STEAL_MS:-200}"
TR_STALL_IOWAIT_MS="${TR_STALL_IOWAIT_MS:-160}"
TR_STALL_CPU_MS="${TR_STALL_CPU_MS:-90}"
TR_STALL_IO_FULL_MS="${TR_STALL_IO_FULL_MS:-90}"
TR_STALL_MEM_MS="${TR_STALL_MEM_MS:-10}"
SAMPLER_PID=""
COORD="${TR_NET}.10:443"
NODES=(owner a b c)
declare -A NODE_IP=([owner]="${TR_NET}.20" [a]="${TR_NET}.11" [b]="${TR_NET}.12" [c]="${TR_NET}.13")
WORK="$(mktemp -d /tmp/orblx-tr.XXXXXX)"
export TR_POLICY="$WORK/policy.hujson"
PING_PIDS=()
REFUSAL='capability ticket check rejected|leaf check failed|The end time has passed'

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  local pid
  for pid in "${PING_PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  [[ -z "$SAMPLER_PID" ]] || kill "$SAMPLER_PID" >/dev/null 2>&1 || true
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs, last 80 lines per service (the proof failed) ----"
    dc logs -t --tail 80 2>&1 | sed 's/[A-Za-z0-9_-]\{40,\}/<redacted>/g' || true
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ticket-renewal" "$TR_PROJECT"

# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${TR_PROJECT}" || exit 1

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

clock_secs() {
  local name="$1" expr
  expr="$(sed -n "s/^pub const ${name}: Duration = Duration::from_secs(\([0-9 *]*\));\$/\1/p" "$CLOCK")"
  [[ -n "$expr" ]] || fail "${name} is not in ${CLOCK}."
  echo $(( expr ))
}

now_s() {
  date +%s.%N
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir bin="$TR_BIN"
  if [[ -z "$bin" ]]; then
    cargo build -p orblx-cli --bin orblx --locked
    bin="$ROOT/target/debug/orblx"
  fi
  [[ -x "$bin" ]] || fail "The orblx binary ${bin} is missing."
  echo "orblx_bin_sha256 $(sha256sum "$bin" | awk '{print $1}')"
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t "$TR_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

wait_log() {
  local service="$1" needle="$2" limit="$3" since="${4:-}" i
  for ((i = 0; i < limit * 2; i++)); do
    if dc logs ${since:+--since "$since"} "$service" 2>&1 | read_all grep -q -- "$needle"; then
      return 0
    fi
    sleep 0.5
  done
  fail "The ${service} log has no line '${needle}' after ${limit} s."
}

status_of() {
  dc exec -T "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

direct_peers() {
  status_of "$1" | read_all awk '$1 == "peer" && $6 == "direct" {n++} END {print n + 0}'
}

overlay_of() {
  status_of owner | read_all awk -v p="$1" '$1 == "overlay_ip" && p == "owner" {print $2; exit} $1 == "peer" && $2 == p {print $4; exit}'
}

ticket_sha() {
  dc exec -T "$1" sha256sum /var/lib/orblx/ticket.bin | awk '{print substr($1, 1, 16)}'
}

started_of() {
  docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$(dc ps -q "$1")"
}

pid_of() {
  dc exec -T "$1" cat /var/lib/orblx/orblxd.pid 2>/dev/null | tr -d '\n' || true
}

# Print the first refusal line with its time, and fail.
check_refusals() {
  local hits first
  hits="$(dc logs -t "${NODES[@]}" 2>&1 | read_all grep -cE -- "$REFUSAL" || true)"
  if [[ "${hits:-0}" -ne 0 ]]; then
    first="$(dc logs -t "${NODES[@]}" 2>&1 | read_all grep -E -- "$REFUSAL" | sort -k3,3 | sed -n 1p)"
    echo "refusals ${hits}"
    echo "first_refusal ${first}"
    report_first_refusal "$first"
    fail "A peer refused a node that renews."
  fi
}

report_first_refusal() {
  local line="$1" ts at
  ts="$(printf '%s\n' "$line" | awk '{print $3}')"
  at="$(date -d "$ts" +%s.%N 2>/dev/null || echo "")"
  [[ -n "$at" ]] || return 0
  echo "first_refusal_after_first_enroll_s $(awk -v a="$at" -v e="$FIRST_ENROLL" 'BEGIN {printf "%.1f", a - e}')"
  echo "first_refusal_after_first_ticket_end_s $(awk -v a="$at" -v e="$FIRST_END" 'BEGIN {printf "%.1f", a - e}')"
}

echo "=== [C] constants from ${CLOCK} ==="
SKEW="$(clock_secs MAX_SKEW)"
MAX_USER="$(clock_secs MAX_USER_TTL)"
echo "max_skew_s ${SKEW}"
echo "max_user_ttl_s ${MAX_USER}"
echo "svid_ttl_s ${TR_SVID_TTL} ticket_ends ${TR_ENDS} gap_limit_ms ${TR_GAP_MS} ping_interval_s ${TR_PING_I}"
if (( TR_SVID_TTL < 30 || TR_SVID_TTL > MAX_USER )); then
  fail "TR_SVID_TTL must be from 30 to ${MAX_USER} seconds."
fi
# The node renews at two thirds of the life, so a new ticket comes each PERIOD seconds.
PERIOD=$(( TR_SVID_TTL - TR_SVID_TTL / 3 ))

cp "$ROOT/scripts/proof/ticket-renewal.hujson" "$TR_POLICY"
chmod 644 "$TR_POLICY"

echo "=== [C] remove old proof stack ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward

echo "=== [C] build image ${TR_IMAGE} ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
for ((i = 0; i < 60; i++)); do
  dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem && break
  sleep 0.5
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "The coordinator did not write the trust bundle."

FIRST_ENROLL=""
declare -A ENROLL_SHA
for name in "${NODES[@]}"; do
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 \
    --out "/var/lib/orblx/tokens/${name}" >/dev/null
  echo "=== [C] enroll ${name} ==="
  [[ -n "$FIRST_ENROLL" ]] || FIRST_ENROLL="$(now_s)"
  dc run --rm --no-deps --entrypoint sh "$name" -c \
    "rm -rf /var/lib/orblx/* && orblx coord enroll --name ${name} --coord ${COORD} --coord-name coord --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint ${NODE_IP[$name]}:443" \
    | read_all grep -E '^(enrolled|name|overlay_ip|svid) ' || fail "The enroll of ${name} failed."
done
FIRST_END="$(awk -v e="$FIRST_ENROLL" -v t="$TR_SVID_TTL" 'BEGIN {printf "%.3f", e + t}')"

echo "=== [C] start owner, a, b, c ==="
# Start the nodes one at a time. Each node must list the 3 other peers
# from the coordinator netmap before the next node starts. If a node
# dials a peer that does not have it in its netmap yet, that peer
# refuses the session (a start race that is not part of this proof).
listed_peers() {
  status_of "$1" | read_all awk '$1 == "peer" {n++} END {print n + 0}'
}
for name in "${NODES[@]}"; do
  dc up -d "$name"
  wait_log "$name" "The TUN device" 30 || fail "The node ${name} did not start."
  for ((i = 0; i < 120; i++)); do
    [[ "$(listed_peers "$name")" -eq 3 ]] && break
    sleep 0.5
  done
  n="$(listed_peers "$name")"
  echo "netmap_peers ${name} ${n}"
  [[ "$n" -eq 3 ]] || fail "The node ${name} lists ${n} peers from the netmap after 60 s, not 3."
done
# A path shows "direct" only while packets come in (STALE_AFTER is 2 s in node.rs).
# So each wait step sends one ping to each peer overlay IP.
poke_peers() {
  local name="$1" ip
  for ip in $(status_of "$name" | read_all awk '$1 == "peer" {print $4}'); do
    dc exec -T "$name" ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
  done
}
for name in "${NODES[@]}"; do
  for ((i = 0; i < 30; i++)); do
    poke_peers "$name"
    [[ "$(direct_peers "$name")" -eq 3 ]] && break
    sleep 0.5
  done
  if [[ "$(direct_peers "$name")" -ne 3 ]]; then
    echo "---- status ${name} ----"
    status_of "$name" | read_all awk '$1 == "state" || $1 == "peer" {print $1, $2, $5, $6}'
    fail "The node ${name} has no direct path to 3 peers after 30 tries."
  fi
  ENROLL_SHA[$name]="$(ticket_sha "$name")"
done

declare -A OVERLAY START0 PID0 E0
for name in "${NODES[@]}"; do
  OVERLAY[$name]="$(overlay_of "$name")"
  [[ -n "${OVERLAY[$name]}" ]] || fail "No overlay IP for ${name}."
  START0[$name]="$(started_of "$name")"
  PID0[$name]="$(pid_of "$name")"
  E0[$name]="$(status_of "$name" | read_all awk '$1 == "svid_expiry" && !f {print $2; f = 1}')"
  [[ -n "${E0[$name]}" ]] || fail "No svid_expiry for ${name}."
  echo "node ${name} overlay ${OVERLAY[$name]} pid ${PID0[$name]} svid_expiry ${E0[$name]}"
done

# The run ends TR_ENDS ticket ends + MAX_SKEW + 5 s after the latest first ticket end.
max_e0=0
for name in "${NODES[@]}"; do
  if (( E0[$name] > max_e0 )); then
    max_e0="${E0[$name]}"
  fi
done
RUN_END=$(( max_e0 + (TR_ENDS - 1) * PERIOD + SKEW + 5 ))
PING_SECS=$(( RUN_END - $(date +%s) + 3 ))
echo "renew_period_s ${PERIOD} run_end_unix ${RUN_END} ping_s ${PING_SECS}"

OUTD="${TR_OUT_DIR:-$WORK/out}"
mkdir -p "$OUTD"
echo "=== [C] host sampler every 100 ms to ${OUTD}/host-samples.txt ==="
cg_args=()
for name in "${NODES[@]}"; do
  cid="$(dc ps -q "$name")"
  for d in "/sys/fs/cgroup/docker/${cid}" "/sys/fs/cgroup/system.slice/docker-${cid}.scope"; do
    if [[ -n "$cid" && -d "$d" ]]; then
      cg_args+=("${name}=${d}")
      break
    fi
  done
done
python3 "$ROOT/scripts/proof/host-sampler.py" --out "$OUTD/host-samples.txt" --interval 0.1 "${cg_args[@]}" &
SAMPLER_PID="$!"
echo "host_sampler pid ${SAMPLER_PID} cgroups ${#cg_args[@]}"

echo "=== [C] ping each pair every ${TR_PING_I} s for ${PING_SECS} s ==="
for src in "${NODES[@]}"; do
  for dst in "${NODES[@]}"; do
    [[ "$src" == "$dst" ]] && continue
    dc exec -T "$src" ping -D -n -i "$TR_PING_I" -w "$PING_SECS" "${OVERLAY[$dst]}" \
      > "$WORK/ping-${src}-${dst}.txt" 2>&1 &
    PING_PIDS+=("$!")
  done
done

echo "=== [C] sample the status of each node every 2 s ==="
lost=0
samples=0
declare -A EXPIRIES
tick=0
while (( $(date +%s) < RUN_END )); do
  for name in "${NODES[@]}"; do
    st="$(status_of "$name")"
    e="$(printf '%s\n' "$st" | awk '$1 == "svid_expiry" && !f {print $2; f = 1}')"
    # One entry for each ticket end: the list holds each svid_expiry once.
    if [[ -n "$e" && " ${EXPIRIES[$name]:-} " != *" ${e} "* ]]; then
      EXPIRIES[$name]="${EXPIRIES[$name]:+${EXPIRIES[$name]} }${e}"
    fi
    n="$(printf '%s\n' "$st" | awk '$1 == "peer" && $6 == "direct" {n++} END {print n + 0}')"
    samples=$((samples + 1))
    if [[ "$n" -ne 3 ]]; then
      lost=$((lost + 1))
      echo "lost_peer_sample $(date +%T.%N | cut -c1-12) node ${name} direct ${n}"
      printf '%s\n' "$st" | awk '$1 == "peer" {print "  " $2, $5, $6}'
    fi
  done
  tick=$((tick + 1))
  if (( tick % 5 == 0 )); then
    check_refusals
  fi
  sleep 2
done
echo "=== [C] wait for the ping runs to end ==="
for pid in "${PING_PIDS[@]}"; do
  wait "$pid" || true
done
PING_PIDS=()
kill "$SAMPLER_PID" >/dev/null 2>&1 || true
wait "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""
check_refusals
echo "refusals 0"
echo "status_samples ${samples} lost_peer_samples ${lost}"

echo "=== gate 1: ticket ends crossed ==="
for name in "${NODES[@]}"; do
  crossed=0
  for e in ${EXPIRIES[$name]}; do
    if (( e + SKEW < RUN_END )); then
      crossed=$((crossed + 1))
    fi
  done
  renewed="$(dc logs "$name" 2>&1 | read_all grep -c "The node renewed the SVID" || true)"
  sha_now="$(ticket_sha "$name")"
  echo "node ${name} ticket_ends_crossed ${crossed} renewals ${renewed} svid_expiries ${EXPIRIES[$name]}"
  echo "node ${name} ticket_changed $([[ "$sha_now" != "${ENROLL_SHA[$name]}" ]] && echo yes || echo no)"
  (( crossed >= TR_ENDS )) || fail "The node ${name} crossed ${crossed} ticket ends. The gate is ${TR_ENDS}."
  [[ "$sha_now" != "${ENROLL_SHA[$name]}" ]] || fail "The node ${name} has the ticket from enroll."
done

echo "=== gate 3: lost peers (checked after gate 4b) ==="
echo "lost_peer_samples ${lost}"

echo "=== gate 4: reply gaps ==="
worst=0
for src in "${NODES[@]}"; do
  for dst in "${NODES[@]}"; do
    [[ "$src" == "$dst" ]] && continue
    f="$WORK/ping-${src}-${dst}.txt"
    read -r got gap last < <(awk '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (p != "") {d = (ts - p) * 1000; if (d > m) m = d}; p = ts; n++} END {printf "%d %.0f %.3f\n", n, m, p}' "$f")
    loss="$(awk '/packet loss/ {for (i = 1; i <= NF; i++) if ($i ~ /%$/) print $i}' "$f")"
    echo "pair ${src}->${dst} replies ${got} loss ${loss:-none} max_gap_ms ${gap} last_reply_before_end_s $(awk -v l="$last" -v e="$RUN_END" 'BEGIN {printf "%.1f", e - l}')"
    if (( gap > worst )); then
      worst="$gap"
    fi
    (( got > 0 )) || fail "No reply on ${src}->${dst}."
    awk -v l="$last" -v e="$RUN_END" 'BEGIN {exit !(l + 0 >= e - 3)}' || fail "The pair ${src}->${dst} stopped before the run end."
  done
done
echo "max_gap_ms_all_pairs ${worst} limit_ms ${TR_GAP_MS}"

# W25-26 PO gate: one gap line for each ticket end of each node.
# The window is [end - 2 s, end + 2 s]. The gap is the largest time between two replies
# that touch the window, on a pair that has the node at one end.
echo "=== gate 4b: reply gap at each ticket end, per node ==="
declare -A RENEWS
end_lines=0
end_fail=0
for name in "${NODES[@]}"; do
  renews=""
  for ts in $(dc logs -t --no-log-prefix "$name" 2>&1 | read_all awk '/The node renewed the SVID/ {print $1}'); do
    renews="${renews:+${renews} }$(date -u -d "$ts" +%s.%N)"
  done
  RENEWS[$name]="$renews"
  echo "node ${name} renewals_unix ${renews:-none}"
  files=()
  for other in "${NODES[@]}"; do
    [[ "$other" == "$name" ]] && continue
    files+=("$WORK/ping-${name}-${other}.txt" "$WORK/ping-${other}-${name}.txt")
  done
  for e in ${EXPIRIES[$name]}; do
    if (( e + SKEW >= RUN_END )); then
      continue
    fi
    ws=$(( e - 2 ))
    we=$(( e + 2 ))
    g="$(awk -v a="$ws" -v b="$we" 'FNR == 1 {p = ""} /bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (p != "" && ts + 0 >= a + 0 && p + 0 <= b + 0) {d = (ts - p) * 1000; if (d > m) m = d}; p = ts} END {printf "%.0f", m + 0}' "${files[@]}")"
    echo "ticket_end node ${name} end_unix ${e} window ${ws}-${we} max_gap_ms ${g} limit_ms ${TR_GAP_MS}"
    end_lines=$((end_lines + 1))
    if (( g > TR_GAP_MS )); then
      end_fail=$((end_fail + 1))
    fi
  done
done
echo "ticket_end_lines ${end_lines} ticket_end_gaps_above_limit ${end_fail}"

# Each reply gap above the limit, with its place. "renewal": a renewal of the src or dst
# node is in [gap start - 2 s, gap end + 2 s]. "ticket_end": an end or an end + MAX_SKEW of
# the src or dst node is in that range. "elsewhere": none of them.
echo "=== gate 4c: place of each reply gap above ${TR_GAP_MS} ms ==="
big=0
for src in "${NODES[@]}"; do
  for dst in "${NODES[@]}"; do
    [[ "$src" == "$dst" ]] && continue
    marks="$(for n in "$src" "$dst"; do
      for r in ${RENEWS[$n]}; do echo "renewal $n $r"; done
      for e in ${EXPIRIES[$n]}; do echo "ticket_end $n $e"; echo "ticket_end_skew $n $((e + SKEW))"; done
    done)"
    while read -r p ts d; do
      [[ -n "$p" ]] || continue
      place="$(printf '%s\n' "$marks" | awk -v a="$p" -v b="$ts" 'NF == 3 && $3 + 0 >= a - 2 && $3 + 0 <= b + 2 {printf "%s%s:%s@%s", (n++ ? "," : ""), $1, $2, $3} END {if (!n) printf "elsewhere"}')"
      echo "big_gap pair ${src}->${dst} from ${p} to ${ts} gap_ms ${d} place ${place}"
      echo "${src} ${dst} ${p} ${ts} ${d}" >> "$WORK/big-gaps.txt"
      big=$((big + 1))
    done < <(awk -v l="$TR_GAP_MS" '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (p != "") {d = (ts - p) * 1000; if (d > l) printf "%s %s %.0f\n", p, ts, d}; p = ts}' "$WORK/ping-${src}-${dst}.txt")
  done
done
echo "big_gaps ${big}"

echo "=== gate 9: host stall check for each reply gap above ${TR_GAP_MS} ms ==="
touch "$WORK/big-gaps.txt"
: > "$OUTD/traces.txt"
for name in "${NODES[@]}"; do
  dc logs --no-log-prefix "$name" 2>&1 | read_all awk -v n="$name" '$1 == "trace" {$1 = n; print}' >> "$OUTD/traces.txt" || true
done
cp "$WORK"/ping-*.txt "$WORK/big-gaps.txt" "$OUTD/" 2>/dev/null || true
host_out="$(python3 "$ROOT/scripts/proof/host-sampler.py" analyze --samples "$OUTD/host-samples.txt" \
  --gaps "$WORK/big-gaps.txt" --traces "$OUTD/traces.txt" \
  --steal-ms "$TR_STALL_STEAL_MS" --iowait-ms "$TR_STALL_IOWAIT_MS" --cpu-some-ms "$TR_STALL_CPU_MS" \
  --io-full-ms "$TR_STALL_IO_FULL_MS" --mem-some-ms "$TR_STALL_MEM_MS")"
printf '%s\n' "$host_out"
printf '%s\n' "$host_out" > "$OUTD/host-analysis.txt"
host_gaps="$(printf '%s\n' "$host_out" | awk '$1 == "gap_class" {print $3}')"
unknown_gaps="$(printf '%s\n' "$host_out" | awk '$1 == "gap_host" && $NF == "unknown" {n++} END {print n + 0}')"
[[ -n "$host_gaps" ]] || fail "The host stall check printed no result."

LATE_FAIL=()
(( lost == 0 )) || LATE_FAIL+=("${lost} status samples show a lost peer.")
(( end_fail == 0 )) || LATE_FAIL+=("${end_fail} ticket ends have a reply gap above ${TR_GAP_MS} ms.")
(( worst <= TR_GAP_MS )) || LATE_FAIL+=("A reply gap of ${worst} ms (whole run) is above ${TR_GAP_MS} ms.")

echo "=== gate 5: no restart ==="
for name in "${NODES[@]}"; do
  s="$(started_of "$name")"
  p="$(pid_of "$name")"
  echo "node ${name} started ${s} pid ${p}"
  [[ "$s" == "${START0[$name]}" && "$p" == "${PID0[$name]}" ]] || fail "The node ${name} restarted."
  [[ "${s##* }" == "0" ]] || fail "The node ${name} has a restart count."
done

echo "=== gate 6: a new handshake a->b after the ticket ends ==="
cut_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
dc exec -T a iptables -I OUTPUT -d "${NODE_IP[b]}" -p udp -j DROP
dc exec -T a iptables -I INPUT -s "${NODE_IP[b]}" -p udp -j DROP
wait_log a "The path to b is down" 90 "$cut_at"
heal_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
dc exec -T a iptables -D OUTPUT -d "${NODE_IP[b]}" -p udp -j DROP
dc exec -T a iptables -D INPUT -s "${NODE_IP[b]}" -p udp -j DROP
wait_log a "The path to b is direct" 30 "$heal_at"
hs_out="$(dc exec -T a ping -n -c 5 -i 0.2 "${OVERLAY[b]}" 2>&1 || true)"
printf '%s\n' "$hs_out" | read_all grep "packet loss" | sed 's/^/new_handshake_a_b /'
printf '%s\n' "$hs_out" | read_all grep -q " 0% packet loss" || fail "The new handshake a->b has packet loss."
check_refusals

if [[ "$TR_REVOKE" == "1" ]]; then
  echo "=== gate 7: a revoked node gets no new ticket and loses its peers ==="
  c_sha="$(ticket_sha c)"
  for src in owner a b; do
    dc exec -T "$src" ping -D -n -i "$TR_PING_I" -w 8 "${OVERLAY[c]}" > "$WORK/rv-${src}.txt" 2>&1 &
    PING_PIDS+=("$!")
  done
  sleep 2
  revoked_at_utc="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  revoke_start="$(now_s)"
  dc exec -T owner orblx admin revoke c --coord "$COORD" --coord-name coord \
    --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem | sed 's/^/revoke_c /'
  for pid in "${PING_PIDS[@]}"; do
    wait "$pid" || true
  done
  PING_PIDS=()
  for src in owner a b; do
    before="$(awk -v r="$revoke_start" '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); if (ts + 0 < r + 0) n++} END {print n + 0}' "$WORK/rv-${src}.txt")"
    last="$(awk '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); v = ts} END {print v}' "$WORK/rv-${src}.txt")"
    ms="$(awk -v l="$last" -v r="$revoke_start" 'BEGIN {printf "%.0f", (l - r) * 1000}')"
    echo "revoke ${src}->c replies_before ${before} last_reply_after_revoke_ms ${ms} limit_ms ${TR_REVOKE_MS}"
    (( before > 0 )) || fail "No reply ${src}->c before the revoke."
    (( ms <= TR_REVOKE_MS )) || fail "${src} reached c ${ms} ms after the revoke."
  done
  wait_log c "The SVID renewal failed" "$(( PERIOD + 40 ))" "$revoked_at_utc"
  if dc logs --since "$revoked_at_utc" c 2>&1 | read_all grep -q "The node renewed the SVID"; then
    fail "The revoked node c renewed."
  fi
  [[ "$(ticket_sha c)" == "$c_sha" ]] || fail "The revoked node c has a new ticket."
  echo "revoked_c new_ticket no renew_refused yes"
fi

dc logs > "$WORK/stack.log" 2>&1
secret_scan "$WORK/stack.log"

echo "=== gate 8: contention while the proof held the lock ==="
if [[ -n "${PROOF_LOCK_SAMPLES:-}" && -f "$PROOF_LOCK_SAMPLES" ]]; then
  load_max="${TR_LOAD_MAX:-$(nproc)}"
  read -r cs_n cs_busy cs_unknown cs_maxc cs_maxl cs_load cs_lfirst cs_llast < <(awk -v lm="$load_max" '{n++; if ($2 < 0) u++; if ($2 > 0) b++; if ($2 > c) c = $2; if ($3 > l) l = $3; if ($3 + 0 > lm + 0) {h++; if (!f) f = $1; z = $1}} END {printf "%d %d %d %d %s %d %s %s\n", n, b + 0, u + 0, c + 0, (n ? l : "-"), h + 0, (f ? f : "-"), (z ? z : "-")}' "$PROOF_LOCK_SAMPLES")
  echo "contention samples ${cs_n} contended_samples ${cs_busy} unknown_samples ${cs_unknown} max_other_orblx_containers ${cs_maxc} max_load1 ${cs_maxl} cpus $(nproc)"
  echo "host_load samples_above_load_max ${cs_load} load_max ${load_max} first_ms ${cs_lfirst} last_ms ${cs_llast}"
  (( cs_n > 0 )) || LATE_FAIL+=("The proof-lock sampler has no sample.")
  (( cs_busy == 0 && cs_unknown == 0 )) || LATE_FAIL+=("${cs_busy} contended and ${cs_unknown} unknown samples. The run does not count.")
  (( cs_load == 0 )) || LATE_FAIL+=("${cs_load} samples have host load1 above ${load_max}. The run does not count.")
else
  LATE_FAIL+=("No proof-lock samples. The run does not count.")
fi

(( unknown_gaps == 0 )) || LATE_FAIL+=("${unknown_gaps} reply gaps have no host sample. The run does not count.")
if (( ${#LATE_FAIL[@]} > 0 )); then
  for msg in "${LATE_FAIL[@]}"; do
    echo "late_fail ${msg}"
  done
  if (( host_gaps > 0 )); then
    echo "proof_invalid host_stall_gaps ${host_gaps}: a host stall touches a reply gap. The run is INVALID, not a PASS."
    echo "FAIL: ${LATE_FAIL[0]}" >&2
    exit 3
  fi
  fail "${LATE_FAIL[0]}"
fi
echo "proof_ok"

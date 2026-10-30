#!/usr/bin/env bash
# NAT realism proof (W20).
# The host is REAL. Every extra host is a [C] container.
# router-a and router-b are port-restricted cone NAT (prc).
# router-c and router-d are symmetric NAT.
# Cases: prc to prc, prc to symmetric, symmetric to symmetric,
# and block and unblock switches with ping loss and ping gap.
# The script fails when a switch loses more than 1 of 50 pings,
# when a switch gap is more than 1 second, or when svid_expiry is unknown.
# The script also fails when the direct ping RTT is more than RTT_LIMIT_MS above
# the plain container RTT, or when a renewed SVID does not reach the peer line.
# W21: the script also fails when the relay ping RTT avg is more than RELAY_SLACK_MS
# above the direct ping RTT avg, when a relay ping is lost, or when an idle orblx
# process uses more than IDLE_CPU_PCT percent CPU.
# W23: RELAY_SLACK_MS is 1. The relay gate also prints the median and the slowest pings.
# W24: the direct RTT check prints them too (direct_ping). W24-A: ORBLX_NATR_POLICY sets an ACL policy. ORBLX_NATR_PREFIX, ORBLX_NATR_PROJECT,
# ORBLX_NATR_IMAGE, ORBLX_NATR_PUB and ORBLX_NATR_LAN change the names and the subnets.
# The script measures TCP bulk throughput on the plain, direct and relay paths.
# The script prints proof_ok.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.nat-realism.yml"
# The names and the subnets can change, so that two proof stacks can run on one host.
# The defaults are the W20 names and subnets.
NATR_PREFIX="${ORBLX_NATR_PREFIX:-orblx-natr-}"
PROJECT="${ORBLX_NATR_PROJECT:-orblx-natr-proof}"
IMAGE="${ORBLX_NATR_IMAGE:-orblx-natr:w20}"
PUB="${ORBLX_NATR_PUB:-172.29.20}"
LAN="${ORBLX_NATR_LAN:-10.19}"
export ORBLX_NATR_IMAGE="$IMAGE" ORBLX_NATR_PUB="$PUB" ORBLX_NATR_LAN="$LAN"
COORD="${PUB}.10:443"
STUN="${PUB}.20:3478"
STUN_ALT="${PUB}.20:3479"
RELAY="${PUB}.20:443"
WAN_A="${PUB}.11"
WAN_B="${PUB}.12"
WAN_C="${PUB}.13"
WAN_D="${PUB}.14"
PINGS=50
MAX_LOSS=1
MAX_GAP_MS=1000
SPRAY_MAX=2048
# The direct overlay RTT may be at most this much above the plain container RTT.
RTT_LIMIT_MS="${ORBLX_RTT_LIMIT_MS:-5}"
# The relay overlay RTT avg may be at most this much above the direct overlay RTT avg.
RELAY_SLACK_MS="${ORBLX_RELAY_SLACK_MS:-1}"
# The seconds of each TCP bulk transfer.
BULK_SECS="${ORBLX_BULK_SECS:-5}"
# The seconds of each idle CPU sample.
IDLE_SECS="${ORBLX_IDLE_SECS:-10}"
# The CPU limit in percent of one core for the idle relay server process and the idle node relay thread.
IDLE_CPU_PCT="${ORBLX_IDLE_CPU_PCT:-3}"
# The CPU limit for the whole idle node process. The node sends probes and hellos when idle.
# This limit finds a spin (near 100 percent). It is not a cost target.
NODE_IDLE_CPU_PCT="${ORBLX_NODE_IDLE_CPU_PCT:-25}"
BULK_PORT=5201
DIRECT_AVG=""
# The node leaf life in seconds for the renewal case.
RENEW_TTL=60

dc() {
  docker compose --progress quiet -p "$PROJECT" -f "$FILE" "$@"
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# The REAL host must not filter or route the bridged frames.
# The [C] routers must receive each frame by MAC.
open_legacy_forward() {
  if command -v iptables-legacy >/dev/null 2>&1; then
    if as_root iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
      echo "=== REAL set iptables-legacy FORWARD ACCEPT ==="
      as_root iptables-legacy -P FORWARD ACCEPT
    fi
  fi
  if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
    if [[ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" != "0" ]]; then
      echo "=== REAL set bridge-nf-call-iptables 0 ==="
      as_root sysctl -w net.bridge.bridge-nf-call-iptables=0
      as_root sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null
    fi
    echo "REAL bridge-nf-call-iptables $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
  fi
  local flag
  for flag in /sys/class/net/br-*/bridge/nf_call_iptables; do
    [[ -e "$flag" ]] || continue
    if [[ "$(cat "$flag")" != "0" ]]; then
      echo 0 | as_root tee "$flag" >/dev/null
    fi
  done
}

build_image() {
  local image_dir bin
  # ORBLX_NATR_PROFILE=release builds an optimized binary. The default is the debug binary.
  if [[ "${ORBLX_NATR_PROFILE:-debug}" == "release" ]]; then
    bin="$ROOT/target/release/orblx"
    cargo build --release -p orblx-cli --bin orblx
  else
    bin="$ROOT/target/debug/orblx"
    cargo build -p orblx-cli --bin orblx
  fi
  echo "build profile ${ORBLX_NATR_PROFILE:-debug}"
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t "$IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 60); do
    if dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

gateway_of() {
  case "$1" in
    node-a) echo ${LAN}.21.2 ;;
    node-b) echo ${LAN}.22.2 ;;
    node-c) echo ${LAN}.23.2 ;;
    node-d) echo ${LAN}.24.2 ;;
  esac
}

container_of() {
  echo "${NATR_PREFIX}${1#node-}"
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$name" -c \
    "ip route replace default via $(gateway_of "$name") && orblx coord enroll --name ${name} --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint 127.0.0.1:9"
}

stop_node() {
  docker rm -f "$1" >/dev/null 2>&1 || true
}

start_nat() {
  local name="$1"
  local peer="$2"
  local container
  container="$(container_of "$name")"
  stop_node "$container"
  dc --profile nodes run -d --name "$container" --no-deps "$name" \
    nat run \
    --state /var/lib/orblx \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --stun "$STUN" \
    --stun-alt "$STUN_ALT" \
    --relay "$RELAY" \
    --peer "$peer" \
    --gateway "$(gateway_of "$name")" >/dev/null
}

status_text() {
  docker exec "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

path_of() {
  printf '%s\n' "$1" | awk '/^peer / {print $6; exit}'
}

wait_path() {
  local container="$1"
  local want="$2"
  local peer="$3"
  local tries="${4:-60}"
  local i text kind
  for i in $(seq 1 "$tries"); do
    text="$(status_text "$container")"
    if printf '%s\n' "$text" | grep -q "^peer ${peer} "; then
      kind="$(path_of "$text")"
      if [[ -n "$kind" && "$kind" != "down" && "$kind" != "starting" ]]; then
        if [[ "$want" == "any" || "$kind" == "$want" ]]; then
          printf '%s\n' "$text"
          return 0
        fi
      fi
    fi
    sleep 1
  done
  echo "The path on ${container} did not become ${want}." >&2
  status_text "$container" >&2
  docker logs "$container" >&2 || true
  return 1
}

# Fail when the self line or the peer line has no real SVID expiry.
check_svid() {
  local label="$1"
  local text="$2"
  local own peer
  own="$(printf '%s\n' "$text" | awk '/^svid_expiry / {print $2; exit}')"
  peer="$(printf '%s\n' "$text" | awk '/^peer / {print $10; exit}')"
  echo "${label} svid_expiry self ${own:-none} peer ${peer:-none}"
  if [[ ! "$own" =~ ^[0-9]+$ || ! "$peer" =~ ^[0-9]+$ ]]; then
    echo "${label} has an svid_expiry that is not known." >&2
    printf '%s\n' "$text" >&2
    exit 1
  fi
}

# Wait until the peer line shows a real SVID expiry.
wait_svid() {
  local container="$1"
  local i text
  for i in $(seq 1 30); do
    text="$(status_text "$container")"
    if printf '%s\n' "$text" | awk '/^peer / {print $10}' | grep -Eq '^[0-9]+$'; then
      printf '%s\n' "$text"
      return 0
    fi
    sleep 0.5
  done
  status_text "$container"
}

now_s() {
  date +%s.%N
}

NAT_CONTAINERS="${NATR_PREFIX}a ${NATR_PREFIX}b ${NATR_PREFIX}c ${NATR_PREFIX}d"

cleanup() {
  local name
  for name in $NAT_CONTAINERS; do
    stop_node "$name"
  done
  dc --profile nodes down -v --remove-orphans >/dev/null 2>&1 || true
}

# Block or restore UDP between two router WAN addresses.
udp_rules() {
  local op="$1"
  local router_one="$2"
  local wan_one="$3"
  local router_two="$4"
  local wan_two="$5"
  dc exec -T "$router_one" iptables "$op" FORWARD -d "$wan_two" -p udp -j DROP
  dc exec -T "$router_one" iptables "$op" FORWARD -s "$wan_two" -p udp -j DROP
  dc exec -T "$router_two" iptables "$op" FORWARD -d "$wan_one" -p udp -j DROP
  dc exec -T "$router_two" iptables "$op" FORWARD -s "$wan_one" -p udp -j DROP
}

SUMMARY=()

# Measure one path switch with a separate run of 50 pings.
# Arguments: label, container, peer name, peer overlay IP, want path, action words.
measure_switch() {
  local label="$1"
  local container="$2"
  local peer="$3"
  local ip="$4"
  local want="$5"
  shift 5
  local t_start t_switch text kind i result
  docker exec "$container" sh -c "rm -f /tmp/switch.txt"
  docker exec "$container" sh -c "ping -D -n -i 0.2 -c ${PINGS} -W 1 ${ip} > /tmp/switch.txt 2>&1" &
  local ping_pid=$!
  sleep 2
  t_start="$(now_s)"
  "$@"
  t_switch=""
  for i in $(seq 1 80); do
    text="$(status_text "$container")"
    kind="$(path_of "$text")"
    if [[ "$kind" == "$want" ]]; then
      t_switch="$(now_s)"
      break
    fi
    sleep 0.1
  done
  wait "$ping_pid" || true
  if [[ -z "$t_switch" ]]; then
    echo "${label} did not change the path to ${want}." >&2
    status_text "$container" >&2
    docker logs "$container" >&2 || true
    exit 1
  fi
  printf '%s\n' "$text"
  result="$(docker exec "$container" cat /tmp/switch.txt | python3 -c '
import sys
label, start, switch, pings, max_loss, max_gap_ms = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
times = []
seqs = set()
for line in sys.stdin:
    line = line.strip()
    if line.startswith("[") and "icmp_seq=" in line and "bytes from" in line:
        times.append(float(line.split("]", 1)[0][1:]))
        seqs.add(int(line.split("icmp_seq=", 1)[1].split()[0]))
    if "packets transmitted" in line:
        print("%s ping_summary %s" % (label, line))
lost = pings - len(seqs)
gaps = [b - a for a, b in zip(times, times[1:])]
gap_ms = int(max(gaps) * 1000) if gaps else 999999
print("%s detect_ms %d lost %d/%d max_gap_ms %d" % (label, int((switch - start) * 1000), lost, pings, gap_ms))
if lost > max_loss or gap_ms > max_gap_ms:
    print("%s limits_ok false" % label)
    raise SystemExit(1)
print("%s limits_ok true" % label)
' "$label" "$t_start" "$t_switch" "$PINGS" "$MAX_LOSS" "$MAX_GAP_MS")" || {
    printf '%s\n' "$result"
    echo "${label} did not meet the switch limits." >&2
    docker logs "$container" 2>&1 | tail -40 >&2 || true
    exit 1
  }
  printf '%s\n' "$result"
  SUMMARY+=("$(printf '%s\n' "$result" | grep ' detect_ms ')")
}

# Send 50 pings on a stable path and check the loss.
steady_pings() {
  local label="$1"
  local container="$2"
  local ip="$3"
  local out received
  out="$(docker exec "$container" ping -n -i 0.2 -c "$PINGS" -W 1 "$ip" | tail -2)"
  printf '%s\n' "$out"
  received="$(printf '%s\n' "$out" | awk '/packets transmitted/ {print $4}')"
  echo "${label} steady lost $((PINGS - received))/${PINGS}"
  if (( PINGS - received > MAX_LOSS )); then
    echo "${label} lost too many pings on a stable path." >&2
    exit 1
  fi
}

# Print the avg value of one ping run.
rtt_avg() {
  awk -F'/' '/^rtt / {print $5; exit}'
}

# Print the median and the 3 slowest pings of one ping -D run (read on stdin).
# Also print a ping_rtts line with every RTT and the sent and received counts (a record only).
# Arguments: line kind (relay_ping or direct_ping), label.
ping_detail() {
  python3 -c '
import re, sys
kind, label = sys.argv[1], sys.argv[2]
rows = []
sent = received = None
for text in sys.stdin:
    c = re.match(r"([0-9]+) packets transmitted, ([0-9]+) received", text)
    if c:
        sent, received = c.group(1), c.group(2)
    m = re.match(r"\[([0-9.]+)\].*icmp_seq=([0-9]+).*time=([0-9.]+) ms", text)
    if m:
        rows.append((float(m.group(3)), int(m.group(2)), m.group(1)))
if rows:
    times = sorted(r[0] for r in rows)
    n = len(times)
    mid = times[n // 2] if n % 2 else (times[n // 2 - 1] + times[n // 2]) / 2
    slow = " ".join("seq%d:%.3f@%s" % (r[1], r[0], r[2]) for r in sorted(rows, reverse=True)[:3])
    print("%s %s median_ms %.3f slowest %s" % (kind, label, mid, slow))
# W24-E2: print every RTT in seq order and the sent and received counts. This line is a record only.
# The CI perf watch reads it for the p99, the max and the spike count. No gate of this script reads it.
print("ping_rtts %s %s sent %s received %s ms %s" % (kind, label, sent or "none", received or "none",
      ",".join("%.3f" % r[0] for r in sorted(rows, key=lambda r: r[1])) or "none"))
' "$1" "$2"
}

# Compare the plain container RTT with the direct overlay RTT.
# The plain ping goes node-a -> router-a (NAT) -> router-b WAN address. It does not use orblx.
# The overlay ping goes node-a -> orblx TUN -> router-a -> router-b -> node-b -> orblx TUN.
measure_rtt() {
  local container="$1"
  local wan="$2"
  local ip="$3"
  local plain overlay odd out full
  out="$(docker exec "$container" ping -n -c "$PINGS" -i 0.2 -W 1 "$wan" | tail -2)"
  printf 'plain %s\n' "$out"
  plain="$(printf '%s\n' "$out" | rtt_avg)"
  full="$(docker exec "$container" ping -D -n -c "$PINGS" -i 0.2 -W 1 "$ip")"
  out="$(printf '%s\n' "$full" | tail -2)"
  printf 'overlay %s\n' "$out"
  printf '%s\n' "$full" | ping_detail direct_ping prc_prc
  overlay="$(printf '%s\n' "$out" | rtt_avg)"
  # A second interval that is not a multiple of 50 ms shows a timer phase effect.
  full="$(docker exec "$container" ping -D -n -c "$PINGS" -i 0.23 -W 1 "$ip")"
  out="$(printf '%s\n' "$full" | tail -2)"
  printf 'overlay_i0.23 %s\n' "$out"
  printf '%s\n' "$full" | ping_detail direct_ping prc_prc_i0.23
  odd="$(printf '%s\n' "$out" | rtt_avg)"
  echo "rtt plain_avg_ms ${plain} direct_avg_ms ${overlay} direct_i0.23_avg_ms ${odd}"
  if ! python3 -c 'import sys; p, a, b, lim = map(float, sys.argv[1:5]); sys.exit(0 if max(a, b) - p <= lim else 1)' \
    "$plain" "$overlay" "$odd" "$RTT_LIMIT_MS"; then
    echo "The direct overlay RTT is more than ${RTT_LIMIT_MS} ms above the plain RTT." >&2
    exit 1
  fi
  echo "rtt limit_ms ${RTT_LIMIT_MS} ok"
  RTT_LINE="rtt plain_avg_ms ${plain} direct_avg_ms ${overlay} direct_i0.23_avg_ms ${odd}"
  DIRECT_AVG="$overlay"
}

# Send 50 pings on the relay path. Fail when one ping is lost,
# or when the avg is more than RELAY_SLACK_MS above the direct avg.
# Arguments: label, container, peer overlay IP.
relay_gate() {
  local label="$1"
  local container="$2"
  local ip="$3"
  local full out avg received lost line
  full="$(docker exec "$container" ping -D -n -c "$PINGS" -i 0.2 -W 1 "$ip")"
  out="$(printf '%s\n' "$full" | tail -2)"
  printf '%s relay %s\n' "$label" "$out"
  # Print the median and the 3 slowest pings with their seq and time stamp.
  printf '%s\n' "$full" | ping_detail relay_ping "$label"
  avg="$(printf '%s\n' "$out" | rtt_avg)"
  received="$(printf '%s\n' "$out" | awk '/packets transmitted/ {print $4}')"
  lost=$((PINGS - ${received:-0}))
  line="relay_rtt ${label} relay_avg_ms ${avg:-none} direct_avg_ms ${DIRECT_AVG} slack_ms ${RELAY_SLACK_MS} lost ${lost}/${PINGS}"
  echo "$line"
  if (( lost > 0 )) || [[ -z "$avg" ]]; then
    echo "${label} lost a ping on the relay path." >&2
    exit 1
  fi
  if ! python3 -c 'import sys; r, d, s = map(float, sys.argv[1:4]); sys.exit(0 if r <= d + s else 1)' \
    "$avg" "$DIRECT_AVG" "$RELAY_SLACK_MS"; then
    echo "${label} relay RTT avg ${avg} ms is more than ${RELAY_SLACK_MS} ms above the direct avg ${DIRECT_AVG} ms." >&2
    exit 1
  fi
  echo "${label} relay_gate ok"
  SUMMARY+=("$line relay_gate ok")
}

copy_bulk() {
  docker cp "$ROOT/scripts/proof/tcp-bulk.py" "$1:/tmp/tcp-bulk.py" >/dev/null
}

# Measure the throughput of one TCP bulk transfer of BULK_SECS seconds.
# Arguments: label, client container, server container, target IP.
bulk() {
  local label="$1"
  local client="$2"
  local server="$3"
  local ip="$4"
  local out=""
  copy_bulk "$client"
  copy_bulk "$server"
  docker exec "$server" rm -f /tmp/bulk.txt
  docker exec -d "$server" python3 /tmp/tcp-bulk.py server 0.0.0.0 "$BULK_PORT" /tmp/bulk.txt
  sleep 1
  local tmp name line
  tmp="$(mktemp -d)"
  if [[ "$label" != "plain" ]]; then
    # Sample the CPU of each orblx process and thread during the transfer. This shows where the time goes.
    copy_bulk "$(dc ps -q relay)"
    for name in "$client" "$server"; do
      (sleep 1 && docker exec "$name" python3 /tmp/tcp-bulk.py cpu "orblx nat run" $((BULK_SECS - 2)) >"${tmp}/${name}") &
    done
    (sleep 1 && dc exec -T relay python3 /tmp/tcp-bulk.py cpu "orblx relay" $((BULK_SECS - 2)) >"${tmp}/relay") &
  fi
  if ! docker exec "$client" timeout $((BULK_SECS + 60)) python3 /tmp/tcp-bulk.py client "$ip" "$BULK_PORT" "$BULK_SECS"; then
    echo "The ${label} bulk transfer failed." >&2
    exit 1
  fi
  wait
  if [[ "$label" != "plain" ]]; then
    for name in "$client" "$server" relay; do
      while read -r line; do
        [[ -z "$line" || "$line" == *" ticks 0 "* ]] && continue
        echo "bulk_cpu ${label} ${name} ${line}"
      done <"${tmp}/${name}"
    done
  fi
  rm -rf "$tmp"
  for _ in $(seq 1 20); do
    out="$(docker exec "$server" cat /tmp/bulk.txt 2>/dev/null || true)"
    [[ -n "$out" ]] && break
    sleep 0.5
  done
  if [[ -z "$out" ]]; then
    echo "The ${label} bulk server wrote no result." >&2
    exit 1
  fi
  echo "throughput ${label} ${out}"
  SUMMARY+=("throughput ${label} ${out}")
}

# Sample the CPU of idle orblx processes for IDLE_SECS seconds. No ping or bulk runs.
# Arguments: label, then node containers.
idle_cpu() {
  local label="$1"
  shift
  local tmp name line pct limit what
  tmp="$(mktemp -d)"
  for name in "$@"; do
    copy_bulk "$name"
    docker exec "$name" python3 /tmp/tcp-bulk.py cpu "orblx nat run" "$IDLE_SECS" >"${tmp}/${name}" &
  done
  copy_bulk "$(dc ps -q relay)"
  dc exec -T relay python3 /tmp/tcp-bulk.py cpu "orblx relay" "$IDLE_SECS" >"${tmp}/relay" &
  wait
  for name in "$@" relay; do
    if ! grep -q '^cpu ' "${tmp}/${name}"; then
      echo "The idle CPU sample found no orblx process in ${name}." >&2
      rm -rf "$tmp"
      exit 1
    fi
    while read -r line; do
      [[ -z "$line" ]] && continue
      echo "idle_cpu ${label} ${name} ${line}"
      SUMMARY+=("idle_cpu ${label} ${name} ${line}")
      pct="$(printf '%s\n' "$line" | awk '{for (i = 1; i < NF; i++) if ($i == "cpu_pct") print $(i + 1)}')"
      # The relay server process and the node relay thread must stay near idle.
      # The whole node process has a loose limit. It finds a spin, not the keepalive cost.
      limit=""
      if [[ "$name" == "relay" && "$line" == cpu\ * ]]; then
        limit="$IDLE_CPU_PCT"
        what="relay server process"
      elif [[ "$line" == *" name orblx-nat-relay "* ]]; then
        limit="$IDLE_CPU_PCT"
        what="node relay thread"
      elif [[ "$name" != "relay" && "$line" == cpu\ * ]]; then
        limit="$NODE_IDLE_CPU_PCT"
        what="node process"
      fi
      [[ -z "$limit" ]] && continue
      if ! python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)' "$pct" "$limit"; then
        echo "The idle ${what} in ${name} used ${pct} percent CPU. The limit is ${limit}." >&2
        rm -rf "$tmp"
        exit 1
      fi
    done <"${tmp}/${name}"
  done
  rm -rf "$tmp"
}

# Enroll a new node name into the state volume of a node service.
enroll_as() {
  local service="$1"
  local name="$2"
  echo "=== [C] enroll ${name} in the ${service} LAN ==="
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$service" -c \
    "rm -rf /var/lib/orblx/* && ip route replace default via $(gateway_of "$service") && orblx coord enroll --name ${name} --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint 127.0.0.1:9"
}

self_overlay() {
  status_text "$1" | awk '/^overlay_ip / {print $2; exit}'
}

peer_expiry_of() {
  printf '%s
' "$1" | awk '/^peer / {print $10; exit}'
}

self_expiry_of() {
  printf '%s
' "$1" | awk '/^svid_expiry / {print $2; exit}'
}

# Wait until the peer line on one node shows the renewed expiry of the other node.
# Arguments: label, container, other container, want path, peer expiry before the renewal.
check_renewal() {
  local label="$1"
  local container="$2"
  local other="$3"
  local want="$4"
  local before="$5"
  local text after other_self kind i
  echo "${label} before peer_svid_expiry ${before}"
  for i in $(seq 1 120); do
    text="$(status_text "$container")"
    after="$(peer_expiry_of "$text")"
    other_self="$(self_expiry_of "$(status_text "$other")")"
    kind="$(path_of "$text")"
    if [[ "$after" =~ ^[0-9]+$ && "$before" =~ ^[0-9]+$ ]] \
      && (( after > before )) && [[ "$after" == "$other_self" ]]; then
      printf '%s
' "$text"
      echo "${label} after peer_svid_expiry ${after} peer_self_svid_expiry ${other_self} path ${kind}"
      if [[ "$kind" != "$want" ]]; then
        echo "${label} path is ${kind}, not ${want}." >&2
        exit 1
      fi
      docker logs "$other" 2>&1 | grep -E '^The node renewed the SVID' | sed "s/^/${other}: /"
      SUMMARY+=("renew ${label} path ${kind} peer_svid_expiry ${before} to ${after}")
      return 0
    fi
    sleep 1
  done
  echo "${label} peer svid_expiry did not move forward. It is ${after}." >&2
  status_text "$container" >&2
  docker logs "$other" >&2 || true
  exit 1
}

# Print punch evidence from the node log.
punch_log() {
  local container="$1"
  docker logs "$container" 2>&1 \
    | grep -E '^The (reflexive endpoint|second reflexive endpoint|local NAT mapping|candidate for|punch plan|hole punch reached|birthday|port spray|direct attempt|relay transport|path to|node sent)' \
    | sort -u | sed "s/^/${container}: /"
}

# Check that the probe counts in the log are in the bound.
check_probe_bound() {
  local container="$1"
  local count
  for count in $(docker logs "$container" 2>&1 | grep -E '^The (birthday|port spray)' | grep -oE 'after [0-9]+ probes' | awk '{print $2}'); do
    if (( count > SPRAY_MAX )); then
      echo "${container} sent ${count} probes. The bound is ${SPRAY_MAX}." >&2
      exit 1
    fi
  done
  echo "${container} probe_bound ${SPRAY_MAX} ok"
}

ECHO_PY='
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5001))
while True:
    data, addr = s.recvfrom(64)
    s.sendto(("%s:%d" % addr).encode(), addr)
'

PROBE_PY='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 40000))
s.settimeout(3)
for dest in sys.argv[1:]:
    host, port = dest.split(":")
    seen = b"none"
    for _ in range(3):
        s.sendto(b"probe", (host, int(port)))
        try:
            seen, _ = s.recvfrom(64)
            break
        except socket.timeout:
            seen = b"none"
    print("mapping", "inner:40000", "to", dest, "seen_as", seen.decode())
'

# The filter server gets one datagram on port 5011.
# It answers from port 5012 (same IP, other port).
# It asks the relay host to answer from a third address.
# Last, it answers from port 5011 (the address that the inside host sent to).
FILTER_PY='
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5011))
o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
o.bind(("0.0.0.0", 5012))
t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    data, addr = s.recvfrom(64)
    o.sendto(b"other_port", addr)
    t.sendto(("%s:%d" % addr).encode(), ("'"${PUB}"'.20", 5013))
    time.sleep(0.5)
    s.sendto(b"same_endpoint", addr)
'

THIRD_PY='
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5013))
while True:
    data, _ = s.recvfrom(64)
    host, port = data.decode().split(":")
    s.sendto(b"third_host", (host, int(port)))
'

FILTER_PROBE_PY='
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 40001))
s.settimeout(0.3)
s.sendto(b"probe", ("'"${PUB}"'.10", 5011))
got = []
end = time.time() + 2.5
while time.time() < end:
    try:
        data, addr = s.recvfrom(64)
        got.append("%s@%s:%d" % (data.decode(), addr[0], addr[1]))
    except socket.timeout:
        pass
print("filter received", " ".join(got) if got else "nothing")
'

mapping_ports() {
  local service="$1"
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$service" -c \
    "ip route replace default via $(gateway_of "$service") && python3 -c '${PROBE_PY}' ${PUB}.10:5001 ${PUB}.20:5001" \
    | sed "s/^/${service}: /"
}

port_of_mapping() {
  printf '%s\n' "$1" | awk -v dest="$2" '$2 == "mapping" && $5 == dest {n = split($7, a, ":"); print a[n]; exit}'
}

echo "=== REAL cargo test signed hello and birthday bounds ==="
cargo test -p orblx-edge --lib -- nat_path:: birthday:: 2>&1 | grep -E '^test |test result'

echo "=== [C] remove old proof stack ==="
cleanup
trap cleanup EXIT
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start public network, routers, coordinator, and relay ==="
dc up -d coord relay router-a router-b router-c router-d
open_legacy_forward
wait_bundle
# W24-A: ORBLX_NATR_POLICY sets an ACL policy file. Then the datapath packet filter is on.
if [[ -n "${ORBLX_NATR_POLICY:-}" ]]; then
  docker cp "$ORBLX_NATR_POLICY" "$(dc ps -q coord)":/var/lib/orblx/policy.hujson
  echo "natr_policy $(basename "$ORBLX_NATR_POLICY") $(sha256sum "$ORBLX_NATR_POLICY" | cut -c1-16)"
fi
sleep 1
for router in router-a router-b router-c router-d; do
  echo "=== [C] ${router} rules ==="
  dc logs --no-log-prefix "$router" | sed -n '1,40p'
done

echo "=== [C] no DNAT, no port forward, and no hairpin ==="
for router in router-a router-b router-c router-d; do
  dnat="$(dc exec -T "$router" iptables -t nat -S | grep -c -- '-j DNAT' || true)"
  echo "${router} dnat_rules ${dnat}"
  if [[ "$dnat" != "0" ]]; then
    echo "${router} has a DNAT rule." >&2
    exit 1
  fi
done

echo "=== [C] NAT mapping probe ==="
dc exec -d -T coord python3 -c "$ECHO_PY"
dc exec -d -T relay python3 -c "$ECHO_PY"
dc exec -d -T coord python3 -c "$FILTER_PY"
dc exec -d -T relay python3 -c "$THIRD_PY"
sleep 1
for node in node-a node-b node-c node-d; do
  map="$(mapping_ports "$node")"
  printf '%s\n' "$map"
  one="$(port_of_mapping "$map" ${PUB}.10:5001)"
  two="$(port_of_mapping "$map" ${PUB}.20:5001)"
  if [[ -z "$one" || -z "$two" ]]; then
    echo "The ${node} mapping probe did not get two answers." >&2
    exit 1
  fi
  case "$node" in
    node-a | node-b)
      if [[ "$one" != "$two" ]]; then
        echo "${node} did not keep one external port. The router is not endpoint-independent." >&2
        exit 1
      fi
      echo "${node} mapping endpoint_independent port ${one}"
      ;;
    *)
      if [[ "$one" == "$two" ]]; then
        echo "${node} kept one external port. The router is not symmetric." >&2
        exit 1
      fi
      echo "${node} mapping symmetric ports ${one} ${two}"
      ;;
  esac
done

echo "=== [C] port-restricted filter probe ==="
for node in node-a node-b; do
  filter="$(dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$node" -c \
    "ip route replace default via $(gateway_of "$node") && python3 -c '${FILTER_PROBE_PY}'")"
  echo "${node}: ${filter}"
  if [[ "$filter" != "filter received same_endpoint@${PUB}.10:5011" ]]; then
    echo "${node} did not filter by IP and port." >&2
    exit 1
  fi
  echo "${node} filter port_restricted true"
done

for name in node-a node-b node-c node-d; do
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out "/var/lib/orblx/tokens/${name}" | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
done
for name in node-a node-b node-c node-d; do
  enroll_node "$name"
done

overlay_of() {
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$1" -c \
    "ip route replace default via $(gateway_of "$1") && orblx coord netmap --coord ${COORD} --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx" \
    | awk '/^overlay_ip /{print $2; exit}'
}

echo "=== [C] overlay addresses ==="
IP_A="$(overlay_of node-a)"
IP_B="$(overlay_of node-b)"
IP_C="$(overlay_of node-c)"
IP_D="$(overlay_of node-d)"
echo "overlay node-a ${IP_A}"
echo "overlay node-b ${IP_B}"
echo "overlay node-c ${IP_C}"
echo "overlay node-d ${IP_D}"

echo "=== [C] no LAN shortcut ==="
LAN_REACH="$(dc --profile nodes run --rm --no-deps --entrypoint /bin/sh node-a -c \
  "ip route replace default via ${LAN}.21.2; for ip in ${LAN}.22.10 ${LAN}.23.10 ${LAN}.24.10 ${LAN}.22.2 ${LAN}.23.2; do if ping -c 1 -W 1 \$ip >/dev/null 2>&1; then echo lan_reach \$ip yes; else echo lan_reach \$ip no; fi; done")"
printf '%s\n' "$LAN_REACH"
if printf '%s\n' "$LAN_REACH" | grep -q ' yes$'; then
  echo "node-a can reach another LAN without NAT." >&2
  exit 1
fi
echo "lan_shortcut false"

block_ab() { udp_rules -I router-a "$WAN_A" router-b "$WAN_B"; }
open_ab() { udp_rules -D router-a "$WAN_A" router-b "$WAN_B"; }
block_ac() { udp_rules -I router-a "$WAN_A" router-c "$WAN_C"; }
open_ac() { udp_rules -D router-a "$WAN_A" router-c "$WAN_C"; }

echo "=== [C] case prc_prc node-a to node-b ==="
start_nat node-a node-b
start_nat node-b node-a
wait_path ${NATR_PREFIX}a direct node-b >/dev/null
wait_path ${NATR_PREFIX}b direct node-a >/dev/null
PP_A="$(wait_svid ${NATR_PREFIX}a)"
PP_B="$(wait_svid ${NATR_PREFIX}b)"
printf '%s\n' "$PP_A"
printf '%s\n' "$PP_B"
check_svid "prc_prc node-a" "$PP_A"
check_svid "prc_prc node-b" "$PP_B"
PP_PATH="$(path_of "$PP_A") $(path_of "$PP_B")"
echo "prc_prc path ${PP_PATH}"
punch_log ${NATR_PREFIX}a
punch_log ${NATR_PREFIX}b
for name in ${NATR_PREFIX}a ${NATR_PREFIX}b; do
  echo "natr_filter ${name} on $(docker logs "$name" 2>&1 | grep -c 'The packet filter is on.' || true) off $(docker logs "$name" 2>&1 | grep -c 'The packet filter is off.' || true)"
done
steady_pings prc_prc ${NATR_PREFIX}a "$IP_B"

echo "=== [C] RTT on the prc_prc topology ==="
measure_rtt ${NATR_PREFIX}a "$WAN_B" "$IP_B"

echo "=== [C] throughput plain and direct, idle CPU on direct ==="
# plain: node-a -> router-a (NAT) -> router-b. The server runs on router-b. No orblx.
bulk plain ${NATR_PREFIX}a "$(dc ps -q router-b)" "$WAN_B"
bulk prc_prc_direct ${NATR_PREFIX}a ${NATR_PREFIX}b "$IP_B"
idle_cpu prc_prc_direct ${NATR_PREFIX}a ${NATR_PREFIX}b

echo "=== [C] switch prc_prc direct to relay (block UDP between router-a and router-b) ==="
measure_switch "switch prc_prc direct_to_relay" ${NATR_PREFIX}a node-b "$IP_B" relay block_ab
echo "=== [C] relay gate, throughput and idle CPU on the prc_prc relay path ==="
sleep 2
relay_gate prc_prc ${NATR_PREFIX}a "$IP_B"
bulk prc_prc_relay ${NATR_PREFIX}a ${NATR_PREFIX}b "$IP_B"
idle_cpu prc_prc_relay ${NATR_PREFIX}a ${NATR_PREFIX}b
echo "=== [C] switch prc_prc relay to direct (restore UDP) ==="
measure_switch "switch prc_prc relay_to_direct" ${NATR_PREFIX}a node-b "$IP_B" direct open_ab
docker logs ${NATR_PREFIX}a 2>&1 | grep -E '^The (path to|node sent|relay also)' | sed "s/^/${NATR_PREFIX}a: /"
stop_node ${NATR_PREFIX}a
stop_node ${NATR_PREFIX}b

echo "=== [C] case prc_sym node-a to node-c ==="
start_nat node-a node-c
start_nat node-c node-a
PS_A="$(wait_path ${NATR_PREFIX}a any node-c)"
# The birthday attempt has a window of 15 seconds.
for _ in $(seq 1 20); do
  if [[ "$(path_of "$(status_text ${NATR_PREFIX}a)")" == "direct" && "$(path_of "$(status_text ${NATR_PREFIX}c)")" == "direct" ]]; then
    break
  fi
  sleep 1
done
PS_A="$(wait_svid ${NATR_PREFIX}a)"
PS_C="$(wait_svid ${NATR_PREFIX}c)"
printf '%s\n' "$PS_A"
printf '%s\n' "$PS_C"
check_svid "prc_sym node-a" "$PS_A"
check_svid "prc_sym node-c" "$PS_C"
PS_PATH_A="$(path_of "$PS_A")"
PS_PATH_C="$(path_of "$PS_C")"
echo "prc_sym path ${PS_PATH_A} ${PS_PATH_C}"
punch_log ${NATR_PREFIX}a
punch_log ${NATR_PREFIX}c
check_probe_bound ${NATR_PREFIX}a
check_probe_bound ${NATR_PREFIX}c
if [[ "$PS_PATH_A" == "direct" ]]; then
  REACHED="$(docker logs ${NATR_PREFIX}a 2>&1 | awk '/^The hole punch reached / {sub(/\.$/, "", $5); print $5; exit}')"
  echo "prc_sym node-a punch_peer ${REACHED}"
  if [[ "${REACHED%%:*}" != "$WAN_C" ]]; then
    echo "The prc_sym direct path did not go through the router-c WAN address." >&2
    exit 1
  fi
fi
steady_pings prc_sym ${NATR_PREFIX}a "$IP_C"
if [[ "$PS_PATH_A" == "direct" ]]; then
  echo "=== [C] switch prc_sym direct to relay (block UDP between router-a and router-c) ==="
  measure_switch "switch prc_sym direct_to_relay" ${NATR_PREFIX}a node-c "$IP_C" relay block_ac
  echo "=== [C] switch prc_sym relay to direct (restore UDP) ==="
  measure_switch "switch prc_sym relay_to_direct" ${NATR_PREFIX}a node-c "$IP_C" direct open_ac
fi
stop_node ${NATR_PREFIX}a
stop_node ${NATR_PREFIX}c

echo "=== [C] case sym_sym node-c to node-d ==="
start_nat node-c node-d
start_nat node-d node-c
wait_path ${NATR_PREFIX}c relay node-d >/dev/null
sleep 5
SS_C="$(wait_svid ${NATR_PREFIX}c)"
SS_D="$(wait_svid ${NATR_PREFIX}d)"
printf '%s\n' "$SS_C"
printf '%s\n' "$SS_D"
check_svid "sym_sym node-c" "$SS_C"
check_svid "sym_sym node-d" "$SS_D"
SS_PATH="$(path_of "$SS_C") $(path_of "$SS_D")"
echo "sym_sym path ${SS_PATH}"
punch_log ${NATR_PREFIX}c
punch_log ${NATR_PREFIX}d
if [[ "$SS_PATH" != "relay relay" ]]; then
  echo "The sym_sym case did not use the relay." >&2
  exit 1
fi
if docker logs ${NATR_PREFIX}c 2>&1 | grep -q '^The hole punch reached'; then
  echo "The sym_sym case reported a hole punch." >&2
  exit 1
fi
steady_pings sym_sym ${NATR_PREFIX}c "$IP_D"
relay_gate sym_sym ${NATR_PREFIX}c "$IP_D"
bulk sym_sym_relay ${NATR_PREFIX}c ${NATR_PREFIX}d "$IP_D"
idle_cpu sym_sym_relay ${NATR_PREFIX}c ${NATR_PREFIX}d
stop_node ${NATR_PREFIX}c
stop_node ${NATR_PREFIX}d

echo "=== [C] renewal case: restart the coordinator with a node leaf life of ${RENEW_TTL} s ==="
ORBLX_NATR_SVID_TTL="$RENEW_TTL" dc up -d coord
wait_bundle
TTL_LINE=""
for _ in $(seq 1 30); do
  TTL_LINE="$(dc logs --no-log-prefix coord 2>/dev/null | grep -E '^node svid ttl' | tail -1 || true)"
  [[ -n "$TTL_LINE" ]] && break
  sleep 1
done
if [[ "$TTL_LINE" != "node svid ttl ${RENEW_TTL}" ]]; then
  echo "The coordinator did not start with a node leaf life of ${RENEW_TTL} s." >&2
  dc logs coord >&2 || true
  exit 1
fi
echo "coord ${TTL_LINE}"
sleep 1
for name in node-e node-f node-g node-h; do
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out "/var/lib/orblx/tokens/${name}" | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
done
# node-e and node-f sit behind the prc routers. node-g and node-h sit behind the symmetric routers.
enroll_as node-a node-e
enroll_as node-b node-f
enroll_as node-c node-g
enroll_as node-d node-h
start_nat node-a node-f
start_nat node-b node-e
start_nat node-c node-h
start_nat node-d node-g
wait_path ${NATR_PREFIX}a direct node-f >/dev/null
wait_path ${NATR_PREFIX}c relay node-h >/dev/null
# Read each peer expiry before the first renewal (at two thirds of the leaf life).
BEFORE_A="$(peer_expiry_of "$(wait_svid ${NATR_PREFIX}a)")"
BEFORE_B="$(peer_expiry_of "$(wait_svid ${NATR_PREFIX}b)")"
BEFORE_C="$(peer_expiry_of "$(wait_svid ${NATR_PREFIX}c)")"
BEFORE_D="$(peer_expiry_of "$(wait_svid ${NATR_PREFIX}d)")"
for name in $NAT_CONTAINERS; do
  status_text "$name"
done
check_renewal "direct node-e sees node-f" ${NATR_PREFIX}a ${NATR_PREFIX}b direct "$BEFORE_A"
check_renewal "direct node-f sees node-e" ${NATR_PREFIX}b ${NATR_PREFIX}a direct "$BEFORE_B"
check_renewal "relay node-g sees node-h" ${NATR_PREFIX}c ${NATR_PREFIX}d relay "$BEFORE_C"
check_renewal "relay node-h sees node-g" ${NATR_PREFIX}d ${NATR_PREFIX}c relay "$BEFORE_D"
steady_pings renew_direct ${NATR_PREFIX}a "$(self_overlay ${NATR_PREFIX}b)"
steady_pings renew_relay ${NATR_PREFIX}c "$(self_overlay ${NATR_PREFIX}d)"
for name in $NAT_CONTAINERS; do
  if docker logs "$name" 2>&1 | grep -q "PRIVATE KEY"; then
    echo "The ${name} log contains a private key." >&2
    exit 1
  fi
  stop_node "$name"
done

if dc logs coord relay 2>&1 | grep -q "PRIVATE KEY"; then
  echo "A log contains a private key." >&2
  exit 1
fi

echo "=== summary ==="
echo "prc_prc path ${PP_PATH}"
echo "prc_sym path ${PS_PATH_A} ${PS_PATH_C}"
echo "sym_sym path ${SS_PATH}"
echo "${RTT_LINE}"
for line in "${SUMMARY[@]}"; do
  echo "$line"
done
echo "proof_ok"

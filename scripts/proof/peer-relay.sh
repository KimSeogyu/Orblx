#!/usr/bin/env bash
# Peer relay for two hard NATs and one easy peer.
# The host is REAL. Routers, nodes, the coordinator, the coordinator Relay, and the easy peer are [C].
# Cases, five runs each:
#   far: the coordinator Relay waits 100 ms before the attach reply. The first packet uses that Relay. The path then uses the peer.
#   down: the coordinator Relay does not answer. The path uses the peer.
#   near: the coordinator Relay is near. The path stays on that Relay.
# The script takes the box proof lock and builds the release binary.
# A wait is a bounded poll. The script stops when the poll ends without the expected line.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"

export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
export PATH="${CARGO_HOME}/bin:${PATH}"

FILE="scripts/proof/compose.nat-realism.yml"
PREFIX="${ORBLX_PEER_PREFIX:-orblx-peer-}"
PROJECT="${ORBLX_PEER_PROJECT:-orblx-peer-proof}"
IMAGE="${ORBLX_PEER_IMAGE:-orblx-peer:relay}"
PUB="${ORBLX_PEER_PUB:-172.29.31}"
LAN="${ORBLX_PEER_LAN:-10.31}"
RUNS="${ORBLX_PEER_RUNS:-5}"
export ORBLX_NATR_IMAGE="$IMAGE" ORBLX_NATR_PUB="$PUB" ORBLX_NATR_LAN="$LAN"
export ORBLX_NATR_MODE_C=random ORBLX_NATR_MODE_D=random

COORD="${PUB}.10:443"
STUN="${PUB}.20:3478"
STUN_ALT="${PUB}.20:3479"
RELAY="${PUB}.20:443"
PEER_IP="${PUB}.30"
PEER_ADDR="${PEER_IP}:443"
NEEDLE="4f52424c58504c41494e"
PINGS=50
MAX_LOSS=2

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose --progress quiet -p "$PROJECT" -f "$FILE" "$@"
}

open_legacy_forward() {
  if command -v iptables-legacy >/dev/null 2>&1; then
    if as_root iptables-legacy -S FORWARD 2>/dev/null | has_line '^-P FORWARD DROP$'; then
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
}

build_image() {
  local bin image_dir
  echo "rustc $(rustc -V)"
  echo "build profile release"
  bin="$ROOT/target/release/orblx"
  cargo build --locked --release -p orblx-cli --bin orblx
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  as_root docker build -q -t "$IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

cleanup() {
  dc --profile nodes --profile peer down -v --remove-orphans >/dev/null 2>&1 || true
  proof_lock_end
}
trap 'cleanup' EXIT
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
proof_lock_take "peer-relay:${PROJECT}" "${PROJECT}"
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"
proof_compose_clean "$PROJECT" || exit 1
open_legacy_forward
build_image

wait_log() {
  local name="$1" pattern="$2" tries="${3:-40}" i
  for i in $(seq 1 "$tries"); do
    if as_root docker logs "$name" 2>&1 | has_line "$pattern"; then
      return 0
    fi
    sleep 0.25
  done
  echo "The log on ${name} did not show ${pattern}." >&2
  as_root docker logs "$name" 2>&1 | tail -40 >&2 || true
  return 1
}

service_container() {
  local names
  names="$(dc ps -a --format '{{.Service}} {{.Name}}' | read_all awk -v svc="$1" '$1 == svc { print $2 }')"
  printf '%s\n' "$names" | read_all awk 'NR == 1 { print }'
}

wait_bundle() {
  local i
  for i in $(seq 1 60); do
    if dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

gateway_of() {
  case "$1" in
    node-c) echo "${LAN}.23.2" ;;
    node-d) echo "${LAN}.24.2" ;;
    *) echo "The node ${1} has no gateway." >&2; return 1 ;;
  esac
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$name" -c \
    "ip route replace default via $(gateway_of "$name") && orblx coord enroll --name ${name} --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint 127.0.0.1:9"
}

stop_node() {
  as_root docker rm -f "$1" >/dev/null 2>&1 || true
}

start_nat() {
  local name="$1" peer="$2"
  local container="${PREFIX}${name#node-}"
  stop_node "$container"
  dc --profile nodes run -d --name "$container" --no-deps "$name" \
    nat run \
    --state /var/lib/orblx \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --stun "$STUN" \
    --stun-alt "$STUN_ALT" \
    --relay "$RELAY" \
    --peer-relay "$PEER_ADDR" \
    --port-map off \
    --peer "$peer" \
    --gateway "$(gateway_of "$name")" >/dev/null
}

start_peer() {
  stop_node "${PREFIX}e"
  dc --profile peer run -d --name "${PREFIX}e" --no-deps --entrypoint orblx peer \
    relay \
    --udp 0.0.0.0:443 \
    --tcp 0.0.0.0:443 \
    --sealed-only \
    --metrics 127.0.0.1:9099 \
    --audit-absent "$NEEDLE" \
    --audit-file /tmp/peer-audit.txt >/dev/null
  wait_log "${PREFIX}e" "^relay sealed-only yes$" 40
}

status_text() {
  as_root docker exec "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

path_of() {
  printf '%s\n' "$1" | awk '!found && /^peer / { print $6; found = 1 }'
}

wait_path() {
  local container="$1" want="$2" peer="$3" tries="${4:-80}" i text kind
  for i in $(seq 1 "$tries"); do
    text="$(status_text "$container")"
    if printf '%s\n' "$text" | has_line "^peer ${peer} "; then
      kind="$(path_of "$text")"
      if [[ "$kind" == "$want" ]]; then
        printf '%s\n' "$text"
        return 0
      fi
    fi
    sleep 0.25
  done
  echo "The path on ${container} did not become ${want}." >&2
  status_text "$container" >&2 || true
  as_root docker logs "$container" 2>&1 | tail -50 >&2 || true
  return 1
}

# This kernel has no netem qdisc. The lab waits on the attach reply instead.
# The node records that wait as the coordinator Relay RTT.
relay_up() {
  local delay="$1" name
  export ORBLX_RELAY_DELAY_MS="$delay"
  dc up -d --force-recreate --no-deps relay >/dev/null
  name="$(service_container relay)"
  wait_log "$name" "^relay udp " 40
  wait_log "$name" "^relay attach delay ${delay} ms$" 40
  printf '%s\n' "$name"
}

relay_far() {
  relay_up 100 >/dev/null
  echo "relay_attach_delay 100ms"
}

relay_down() {
  local name show
  name="$(relay_up 0)"
  as_root docker exec "$name" iptables -I INPUT 1 -p udp --dport 443 -j DROP
  as_root docker exec "$name" iptables -I INPUT 1 -p tcp --dport 443 -j DROP
  show="$(as_root docker exec "$name" iptables -S INPUT)"
  printf '%s\n' "$show"
  if ! printf '%s\n' "$show" | has_line '-p udp .*--dport 443 -j DROP'; then
    echo "The relay did not drop udp 443." >&2
    return 1
  fi
  if ! printf '%s\n' "$show" | has_line '-p tcp .*--dport 443 -j DROP'; then
    echo "The relay did not drop tcp 443." >&2
    return 1
  fi
  echo "relay_down udp 443 tcp 443"
}

relay_near() {
  relay_up 0 >/dev/null
  echo "relay_attach_delay 0ms"
}

bring_routers() {
  local rc rd
  dc up -d --force-recreate --no-deps router-c router-d >/dev/null
  rc="$(service_container router-c)"
  rd="$(service_container router-d)"
  wait_log "$rc" "router mode random" 40
  wait_log "$rd" "router mode random" 40
}

reset_endpoints() {
  dc exec -T coord python3 -c '
import json
path = "/var/lib/orblx/nodes.json"
with open(path) as handle:
    data = json.load(handle)
for node in data["nodes"]:
    node["endpoints"] = ["127.0.0.1:9"]
with open(path, "w") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
print("endpoints_reset")
'
  dc restart coord >/dev/null
  wait_bundle
}

start_ping() {
  local container="$1" ip="$2"
  as_root docker exec -d "$container" sh -c "
    i=0
    while [ \"\$i\" -lt 50 ]; do
      if ping -D -n -c 1 -W 1 ${ip} >/tmp/first.txt 2>/dev/null; then
        break
      fi
      i=\$((i + 1))
      sleep 0.1
    done
    ping -D -n -i 0.1 -c ${PINGS} -W 1 ${ip} >/tmp/switch.txt 2>&1
  "
}

wait_ping() {
  local container="$1" i
  for i in $(seq 1 40); do
    if as_root docker exec "$container" test -s /tmp/switch.txt >/dev/null 2>&1; then
      if as_root docker exec "$container" grep -q 'packets transmitted' /tmp/switch.txt; then
        return 0
      fi
    fi
    sleep 0.5
  done
  echo "The ping file on ${container} did not finish." >&2
  return 1
}

inject_plaintext() {
  local session="$1"
  dc exec -T coord python3 -c '
import socket, sys
session = bytes.fromhex(sys.argv[1])
payload = bytes([0x45, 0, 0, 32]) + b"ORBLXPLAIN"
body = bytes([1, 2]) + session + payload
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(body, (sys.argv[2], 443))
print("plaintext_inject")
' "$session" "$PEER_IP"
}

echo "=== [C] stack up ==="
dc up -d coord relay router-c router-d >/dev/null
wait_bundle
bring_routers
for name in node-c node-d peer; do
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out "/var/lib/orblx/tokens/${name}" | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
done
enroll_c="$(enroll_node node-c)"
enroll_d="$(enroll_node node-d)"
echo "=== [C] enroll peer ==="
enroll_peer="$(dc --profile peer run --rm --no-deps --entrypoint orblx peer \
  coord enroll --name peer --coord "$COORD" --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/peer --state /tmp/peer-state --endpoint "${PEER_ADDR}")"
printf '%s\n' "$enroll_c" "$enroll_d" "$enroll_peer"
IP_C="$(printf '%s\n' "$enroll_c" | awk '!found && /^overlay_ip / { print $2; found = 1 }')"
IP_D="$(printf '%s\n' "$enroll_d" | awk '!found && /^overlay_ip / { print $2; found = 1 }')"
IP_E="$(printf '%s\n' "$enroll_peer" | awk '!found && /^overlay_ip / { print $2; found = 1 }')"
echo "overlay node-c ${IP_C} node-d ${IP_D} peer ${IP_E}"
echo "easy_peer_nat none address ${PEER_IP}"
if [[ ! "$IP_C" =~ ^[0-9.]+$ || ! "$IP_D" =~ ^[0-9.]+$ || ! "$IP_E" =~ ^[0-9.]+$ ]]; then
  echo "The overlay addresses are not known." >&2
  exit 1
fi

CA="${PREFIX}c"
CD="${PREFIX}d"
CE="${PREFIX}e"
FAIL=0

summarize_run() {
  local label="$1" expect="$2" first_kind="$3"
  as_root docker logs "$CA" >"/tmp/${label}-a.log" 2>&1 || true
  as_root docker logs "$CD" >"/tmp/${label}-b.log" 2>&1 || true
  as_root docker cp "$CA:/tmp/switch.txt" "/tmp/${label}-switch.txt" >/dev/null 2>&1 || true
  as_root docker cp "$CE:/tmp/peer-audit.txt" "/tmp/${label}-audit.txt" >/dev/null 2>&1 || true
  python3 - "$label" "$expect" "$first_kind" "/tmp/${label}-a.log" "/tmp/${label}-b.log" "/tmp/${label}-switch.txt" "/tmp/${label}-audit.txt" "$PINGS" "$MAX_LOSS" <<'PY'
import re, sys
label, expect, first_kind, log_a, log_b, switch_path, audit_path, pings, max_loss = sys.argv[1:]
pings = int(pings)
max_loss = int(max_loss)

def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except FileNotFoundError:
        return []

a = read(log_a)
b = read(log_b)

def first_ms(lines, kind):
    for line in lines:
        m = re.match(r"first_packet %s ms (\d+)" % re.escape(kind), line)
        if m:
            return int(m.group(1))
    return None

def path_ms(lines, kind):
    for line in lines:
        m = re.match(r"path_up %s ms (\d+)" % re.escape(kind), line)
        if m:
            return int(m.group(1))
    return None

def rtt(lines):
    vals = []
    for line in lines:
        m = re.match(r"The coordinator relay rtt is (\d+) ms\.", line)
        if m:
            vals.append(int(m.group(1)))
    return vals[0] if vals else None

node_first = first_ms(a, first_kind)
node_path = path_ms(a, "peer-relay" if expect == "peer-relay" else "relay")
node_rtt = rtt(a)
relay_path = path_ms(a, "relay")
peer_path = path_ms(a, "peer-relay")
order_ok = True
if expect == "peer-relay" and first_kind == "relay":
    seen_packet = False
    seen_peer = False
    for line in a:
        if line.startswith("first_packet "):
            if not seen_packet and not line.startswith("first_packet relay "):
                order_ok = False
            seen_packet = True
        if line.startswith("The peer relay transport is ") and not seen_packet:
            seen_peer = True
    if seen_peer:
        order_ok = False
hits = 0
forwards = 0
for line in read(audit_path):
    parts = line.split()
    if len(parts) == 4 and parts[0] == "forward":
        forwards += 1
        hits += int(parts[3])
times = []
seqs = set()
for line in read(switch_path):
    m = re.match(r"\[([0-9.]+)\].*icmp_seq=([0-9]+)", line)
    if m:
        times.append(float(m.group(1)))
        seqs.add(int(m.group(2)))
switch_lines = read(switch_path)
lost = pings - len(seqs)
gaps = [b - a for a, b in zip(times, times[1:])]
gap_ms = int(max(gaps) * 1000) if gaps else -1
print("case %s expect %s first_kind %s first_packet_ms %s path_ms %s relay_ms %s peer_ms %s rtt_ms %s forwards %s audit_hits %s switch_lost %s/%s switch_gap_ms %s order_ok %s" % (
    label, expect, first_kind,
    node_first if node_first is not None else "none",
    node_path if node_path is not None else "none",
    relay_path if relay_path is not None else "none",
    peer_path if peer_path is not None else "none",
    node_rtt if node_rtt is not None else "none",
    forwards, hits, lost, pings, gap_ms if gap_ms >= 0 else "none",
    "yes" if order_ok else "no",
))
ok = True
if not any("packets transmitted" in line for line in switch_lines):
    print("case %s ping file is missing" % label)
    ok = False
if node_first is None or not order_ok:
    ok = False
if hits != 0 or forwards < 1:
    ok = False
if lost < 0 or lost > max_loss or (gap_ms >= 0 and gap_ms > 1500):
    ok = False
if expect == "relay" and peer_path is not None:
    ok = False
if expect == "peer-relay" and peer_path is None:
    ok = False
if not ok:
    print("case_ok false")
    sys.exit(1)
print("case_ok true")
PY
}

run_case() {
  local mode="$1" n="$2" label text_c text_d path_c path_d session
  label="${mode}-${n}"
  echo "=== [C] case ${label} ==="
  stop_node "$CA"
  stop_node "$CD"
  stop_node "$CE"
  reset_endpoints
  bring_routers
  case "$mode" in
    far) relay_far || return 1 ;;
    down) relay_down || return 1 ;;
    near) relay_near || return 1 ;;
    *) echo "The mode ${mode} is not valid." >&2; return 1 ;;
  esac
  if [[ "$mode" != "far" ]]; then
    start_peer
  fi
  start_nat node-c node-d
  start_nat node-d node-c
  start_ping "$CA" "$IP_D"
  if [[ "$mode" == "far" ]]; then
    wait_log "$CA" "^first_packet relay ms " 80
    echo "order first_packet_before_peer_relay yes"
    start_peer
    text_c="$(wait_path "$CA" peer-relay node-d 80)"
    text_d="$(wait_path "$CD" peer-relay node-c 80)"
  elif [[ "$mode" == "down" ]]; then
    text_c="$(wait_path "$CA" peer-relay node-d 120)"
    text_d="$(wait_path "$CD" peer-relay node-c 120)"
  else
    text_c="$(wait_path "$CA" relay node-d 80)"
    text_d="$(wait_path "$CD" relay node-c 80)"
    wait_log "$CA" "^The peer relay transport is " 80
    local i kind
    for i in $(seq 1 8); do
      kind="$(path_of "$(status_text "$CA")")"
      if [[ "$kind" == "peer-relay" ]]; then
        echo "The near pair moved to the peer relay." >&2
        FAIL=1
        break
      fi
      sleep 0.5
    done
    text_c="$(status_text "$CA")"
    text_d="$(status_text "$CD")"
  fi
  path_c="$(path_of "$text_c")"
  path_d="$(path_of "$text_d")"
  echo "paths ${path_c} ${path_d}"
  session="$(as_root docker logs "$CA" 2>&1 | awk '!found && /^session / { print $2; found = 1 }')"
  if [[ "$session" =~ ^[0-9a-f]{32}$ ]]; then
    inject_plaintext "$session"
    sleep 0.3
  else
    echo "The session id is not known." >&2
    FAIL=1
  fi
  wait_ping "$CA" || FAIL=1
  local expect first_kind
  if [[ "$mode" == "near" ]]; then
    expect=relay
    first_kind=relay
  elif [[ "$mode" == "far" ]]; then
    expect=peer-relay
    first_kind=relay
  else
    expect=peer-relay
    first_kind=peer-relay
  fi
  summarize_run "$label" "$expect" "$first_kind" || FAIL=1
  local metrics
  metrics="$(as_root docker exec "$CE" curl -fsS http://127.0.0.1:9099/metrics || true)"
  printf '%s\n' "$metrics" | awk '$1 == "orblx_relay_plaintext_rejects" || $1 == "orblx_relay_plaintext_hits" || $1 == "orblx_relay_forwards" { print }'
  if ! printf '%s\n' "$metrics" | has_line '^orblx_relay_plaintext_hits 0$'; then
    echo "The peer relay counted a plaintext hit." >&2
    FAIL=1
  fi
  if ! printf '%s\n' "$metrics" | has_line '^orblx_relay_plaintext_rejects [1-9]'; then
    echo "The peer relay did not drop the plaintext inject." >&2
    FAIL=1
  fi
  if [[ "$path_c" != "$expect" || "$path_d" != "$expect" ]]; then
    echo "Case ${label} path was ${path_c} ${path_d}." >&2
    FAIL=1
  fi
  if ! as_root docker logs "$CA" 2>&1 | has_line '^The peer relay discovery does not delay the first packet\.$'; then
    echo "Case ${label} delayed discovery in the log." >&2
    FAIL=1
  fi
  stop_node "$CA"
  stop_node "$CD"
  stop_node "$CE"
}

for n in $(seq 1 "$RUNS"); do
  run_case far "$n" || FAIL=1
  run_case down "$n" || FAIL=1
  run_case near "$n" || FAIL=1
done

if [[ "$FAIL" -ne 0 ]]; then
  echo "peer_relay_fail"
  exit 1
fi
echo "peer_relay_ok"
echo "proof_ok"

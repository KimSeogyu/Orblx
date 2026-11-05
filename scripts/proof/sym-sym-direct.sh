#!/usr/bin/env bash
# Direct path between two endpoint-dependent NATs when a port allocation is predictable.
# The host is REAL. Routers, nodes, the coordinator, and the relay are [C].
# Cases, five runs each:
#   random to random: relay, no predict spray
#   sequential to random: direct
#   sequential to sequential: direct
#   port-block to random: direct
# One more run blocks the punch, then opens it. The node must reach direct without a restart.
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
PREFIX="${ORBLX_SYM_PREFIX:-orblx-sym-}"
PROJECT="${ORBLX_SYM_PROJECT:-orblx-sym-proof}"
IMAGE="${ORBLX_SYM_IMAGE:-orblx-sym:direct}"
PUB="${ORBLX_SYM_PUB:-172.29.28}"
LAN="${ORBLX_SYM_LAN:-10.28}"
RUNS="${ORBLX_SYM_RUNS:-5}"
export ORBLX_NATR_IMAGE="$IMAGE" ORBLX_NATR_PUB="$PUB" ORBLX_NATR_LAN="$LAN"
export ORBLX_NATR_MODE_C=random ORBLX_NATR_MODE_D=random

COORD="${PUB}.10:443"
STUN="${PUB}.20:3478"
STUN_ALT="${PUB}.20:3479"
RELAY="${PUB}.20:443"
WAN_C="${PUB}.13"
WAN_D="${PUB}.14"
PINGS=50
MAX_LOSS=1

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
  cargo build --release -p orblx-cli --bin orblx
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  as_root docker build -q -t "$IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

cleanup() {
  dc --profile nodes down -v --remove-orphans >/dev/null 2>&1 || true
  proof_lock_end
}
trap cleanup EXIT
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
proof_lock_take "sym-sym-direct:${PROJECT}" "$PREFIX" "${PROJECT}-"
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
  dc ps -a --format '{{.Service}} {{.Name}}' | awk -v svc="$1" '$1 == svc { print $2; exit }'
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
  local name="$1" peer="$2" container
  container="${PREFIX}${name#node-}"
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
      if [[ "$want" == "any" && -n "$kind" && "$kind" != "down" && "$kind" != "starting" ]]; then
        printf '%s\n' "$text"
        return 0
      fi
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

bring_routers() {
  local mode_c="$1" mode_d="$2" rc rd
  export ORBLX_NATR_MODE_C="$mode_c" ORBLX_NATR_MODE_D="$mode_d"
  dc up -d --force-recreate --no-deps router-c router-d >/dev/null
  rc="$(service_container router-c)"
  rd="$(service_container router-d)"
  if [[ "$mode_c" == "sequential" || "$mode_c" == "portblock" || "$mode_c" == "shift" ]]; then
    wait_log "$rc" "router nat ready ${mode_c}" 40
  else
    wait_log "$rc" "router mode ${mode_c}" 40
  fi
  if [[ "$mode_d" == "sequential" || "$mode_d" == "portblock" || "$mode_d" == "shift" ]]; then
    wait_log "$rd" "router nat ready ${mode_d}" 40
  else
    wait_log "$rd" "router mode ${mode_d}" 40
  fi
}

block_punch() {
  local rc rd
  rc="$(service_container router-c)"
  rd="$(service_container router-d)"
  as_root docker exec "$rc" iptables -I OUTPUT 1 -d "$WAN_D" -p udp -j DROP
  as_root docker exec "$rd" iptables -I OUTPUT 1 -d "$WAN_C" -p udp -j DROP
  echo "punch_block output udp ${WAN_C} ${WAN_D}"
}

unblock_punch() {
  local rc rd
  rc="$(service_container router-c)"
  rd="$(service_container router-d)"
  as_root docker exec "$rc" iptables -D OUTPUT -d "$WAN_D" -p udp -j DROP
  as_root docker exec "$rd" iptables -D OUTPUT -d "$WAN_C" -p udp -j DROP
  echo "punch_open output udp ${WAN_C} ${WAN_D}"
}

start_ping() {
  local container="$1" ip="$2"
  # The first ping waits until the overlay answers. The next pings use 0.1 s.
  # The punch can finish during that run. The loss in the file is the switch loss.
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

# Drop the last reflexive list so the next run does not punch at the old ports.
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

summarize_run() {
  local label="$1" expect="$2" ca="$3" cb="$4" t0="$5"
  as_root docker logs "$ca" >"/tmp/${label}-a.log" 2>&1 || true
  as_root docker logs "$cb" >"/tmp/${label}-b.log" 2>&1 || true
  as_root docker cp "$ca:/tmp/first.txt" "/tmp/${label}-first.txt" >/dev/null 2>&1 || true
  as_root docker cp "$ca:/tmp/switch.txt" "/tmp/${label}-switch.txt" >/dev/null 2>&1 || true
  python3 - "$label" "$expect" "$t0" "/tmp/${label}-a.log" "/tmp/${label}-b.log" "/tmp/${label}-first.txt" "/tmp/${label}-switch.txt" "$PINGS" "$MAX_LOSS" <<'PY'
import re, sys
label, expect, t0, log_a, log_b, first_path, switch_path, pings, max_loss = sys.argv[1:]
t0 = float(t0)
pings = int(pings)
max_loss = int(max_loss)

def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except FileNotFoundError:
        return []

a = read(log_a)
b = read(log_b)

def path_ms(lines, kind):
    vals = []
    for line in lines:
        m = re.match(r"path_up %s ms (\d+)" % kind, line)
        if m:
            vals.append(int(m.group(1)))
    return vals[0] if vals else None

def probes(lines):
    vals = [int(line.split()[1]) for line in lines if line.startswith("predict_probes ")]
    return sum(vals)

def has(lines, text):
    return any(text in line for line in lines)

relay_ms = [v for v in (path_ms(a, "relay"), path_ms(b, "relay")) if v is not None]
direct_ms = [v for v in (path_ms(a, "direct"), path_ms(b, "direct")) if v is not None]
probe_n = probes(a) + probes(b)
plans = [line for line in a + b if line.startswith("The punch plan is ")]
allocs = [line for line in a + b if "port allocation is " in line]
drops = [line for line in a + b if line.startswith("punch_drop ")]
budgets = [line for line in a + b if line.startswith("predict_budget ")]

# The node clock. path_up and first_packet use the same process start.
first_ms = None
for line in a:
    m = re.match(r"first_packet relay ms (\d+)", line)
    if m:
        first_ms = int(m.group(1))
        break

times = []
seqs = set()
for line in read(switch_path):
    m = re.match(r"\[([0-9.]+)\].*bytes from.*icmp_seq=([0-9]+)", line)
    if m:
        times.append(float(m.group(1)))
        seqs.add(int(m.group(2)))
switch_lines = read(switch_path)
if not any("packets transmitted" in line for line in switch_lines):
    print("case %s ping file is missing" % label)
    print("switch_limits_ok false")
    sys.exit(1)
if first_ms is None:
    print("case %s has no first relay packet" % label)
    print("switch_limits_ok false")
    sys.exit(1)
node_direct = path_ms(a, "direct")
node_relay = path_ms(a, "relay")
if node_relay is None or first_ms < node_relay:
    print("case %s first packet is before the relay path" % label)
    print("switch_limits_ok false")
    sys.exit(1)
if node_direct is not None and first_ms > node_direct:
    print("case %s first packet %s is after direct %s" % (label, first_ms, node_direct))
    print("switch_limits_ok false")
    sys.exit(1)
lost = pings - len(seqs)
gaps = [b - a for a, b in zip(times, times[1:])]
gap_ms = int(max(gaps) * 1000) if gaps else -1

print("case %s expect %s relay_ms %s direct_ms %s first_packet_ms %s probes %d switch_lost %s/%s switch_gap_ms %s" % (
    label, expect,
    node_relay if node_relay is not None else "none",
    node_direct if node_direct is not None else "none",
    first_ms if first_ms is not None else "none",
    probe_n,
    lost if lost >= 0 else "none",
    pings,
    gap_ms if gap_ms >= 0 else "none",
))
for line in plans:
    print("plan_log " + line)
for line in allocs:
    print("alloc_log " + line)
for line in drops:
    print("drop_log " + line)
for line in budgets:
    print("budget_log " + line)
if expect == "miss":
    cap = None
    for line in budgets:
        parts = line.split()
        # predict_budget attempts N packets_per_attempt M ...
        try:
            attempts = int(parts[2])
            per = int(parts[4])
        except (IndexError, ValueError):
            continue
        cap = attempts * per * 2
        break
    if cap is None:
        print("case %s has no predict budget" % label)
        print("switch_limits_ok false")
        sys.exit(1)
    if probe_n == 0 or probe_n > cap:
        print("case %s probes %s outside 1..%s" % (label, probe_n, cap))
        print("switch_limits_ok false")
        sys.exit(1)
if lost >= 0 and (lost > max_loss or (gap_ms >= 0 and gap_ms > 1000)):
    print("switch_limits_ok false")
    sys.exit(1)
print("switch_limits_ok true")
PY
}

echo "=== [C] stack up ==="
dc up -d coord relay router-c router-d >/dev/null
wait_bundle
bring_routers random random
for name in node-c node-d; do
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out "/var/lib/orblx/tokens/${name}" | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
done
enroll_c="$(enroll_node node-c)"
enroll_d="$(enroll_node node-d)"
printf '%s\n' "$enroll_c" "$enroll_d"
IP_C="$(printf '%s\n' "$enroll_c" | awk '!found && /^overlay_ip / { print $2; found = 1 }')"
IP_D="$(printf '%s\n' "$enroll_d" | awk '!found && /^overlay_ip / { print $2; found = 1 }')"
echo "overlay node-c ${IP_C} node-d ${IP_D}"
if [[ ! "$IP_C" =~ ^[0-9.]+$ || ! "$IP_D" =~ ^[0-9.]+$ ]]; then
  echo "The overlay addresses are not known." >&2
  exit 1
fi

CA="${PREFIX}c"
CD="${PREFIX}d"
FAIL=0

run_case() {
  local mode_c="$1" mode_d="$2" expect="$3" n="$4" label t0 text_c text_d path_c path_d
  label="${mode_c}-${mode_d}-${n}"
  echo "=== [C] case ${label} expect ${expect} ==="
  stop_node "$CA"
  stop_node "$CD"
  reset_endpoints
  bring_routers "$mode_c" "$mode_d"
  t0="$(date +%s.%N)"
  start_nat node-c node-d
  start_nat node-d node-c
  start_ping "$CA" "$IP_D"
  text_c="$(wait_path "$CA" any node-d 80)"
  text_d="$(wait_path "$CD" any node-c 80)"
  if [[ "$expect" == "relay" || "$expect" == "miss" ]]; then
    local i kind tries=16
    if [[ "$expect" == "miss" ]]; then
      tries=160
    fi
    for i in $(seq 1 "$tries"); do
      kind="$(path_of "$(status_text "$CA")")"
      if [[ "$kind" == "direct" ]]; then
        echo "The ${expect} pair moved to direct." >&2
        FAIL=1
        break
      fi
      if [[ "$expect" == "miss" ]] && as_root docker logs "$CA" 2>&1 | has_line '^The predict budget is spent after '; then
        break
      fi
      sleep 0.5
    done
    if [[ "$expect" == "miss" ]] && ! as_root docker logs "$CA" 2>&1 | has_line '^The predict budget is spent after '; then
      echo "The predict budget did not end." >&2
      FAIL=1
    fi
    text_c="$(status_text "$CA")"
    text_d="$(status_text "$CD")"
  elif [[ "$(path_of "$text_c")" != "direct" || "$(path_of "$text_d")" != "direct" ]]; then
    text_c="$(wait_path "$CA" direct node-d 80)"
    text_d="$(wait_path "$CD" direct node-c 80)"
  else
    echo "direct was up at the first status poll"
  fi
  path_c="$(path_of "$text_c")"
  path_d="$(path_of "$text_d")"
  echo "paths ${path_c} ${path_d}"
  # Let the ping file finish. 40 pings at 0.2 s, plus the first-packet wait.
  local i
  for i in $(seq 1 30); do
    if as_root docker exec "$CA" test -s /tmp/switch.txt >/dev/null 2>&1; then
      if as_root docker exec "$CA" grep -q 'packets transmitted' /tmp/switch.txt; then
        break
      fi
    fi
    sleep 0.5
  done
  summarize_run "$label" "$expect" "$CA" "$CD" "$t0" || FAIL=1
  local want="$expect"
  if [[ "$expect" == "miss" ]]; then
    want=relay
  fi
  if [[ "$path_c" != "$want" || "$path_d" != "$want" ]]; then
    echo "Case ${label} path was ${path_c} ${path_d}." >&2
    FAIL=1
  fi
  if [[ "$expect" == "relay" ]]; then
    if as_root docker logs "$CA" 2>&1 | has_line 'predict-spray|predict_probes |^The hole punch reached'; then
      echo "Case ${label} sent a predict spray or a hole punch." >&2
      FAIL=1
    fi
    if as_root docker logs "$CD" 2>&1 | has_line 'predict-spray|predict_probes |^The hole punch reached'; then
      echo "Case ${label} sent a predict spray or a hole punch." >&2
      FAIL=1
    fi
    if ! as_root docker logs "$CA" 2>&1 | has_line '^The punch plan is relay-only\.'; then
      echo "Case ${label} did not log relay-only." >&2
      FAIL=1
    fi
  elif [[ "$expect" == "miss" ]]; then
    if as_root docker logs "$CA" 2>&1 | has_line '^The hole punch reached'; then
      echo "Case ${label} punched with the wrong prediction." >&2
      FAIL=1
    fi
    if ! as_root docker logs "$CA" 2>&1 | has_line '^The punch plan is predict-spray\.'; then
      echo "Case ${label} did not log predict-spray." >&2
      FAIL=1
    fi
  else
    if ! as_root docker logs "$CA" 2>&1 | has_line '^The punch plan is predict-spray\.'; then
      echo "Case ${label} did not log predict-spray." >&2
      FAIL=1
    fi
  fi
  stop_node "$CA"
  stop_node "$CD"
}

show_foreign_punch() {
  local rc session token
  echo "=== [C] foreign punch ==="
  stop_node "$CA"
  stop_node "$CD"
  bring_routers random random
  start_nat node-c node-d
  start_nat node-d node-c
  wait_log "$CA" '^The punch plan is ' 40
  session="$(as_root docker logs "$CA" 2>&1 | awk '!found && /^session / { print $2; found = 1 }')"
  token="${session:0:16}"
  if [[ ! "$token" =~ ^[0-9a-f]{16}$ ]]; then
    echo "The session token is not known." >&2
    FAIL=1
    stop_node "$CA"
    stop_node "$CD"
    return
  fi
  rc="$(service_container router-c)"
  as_root docker exec "$rc" python3 -c '
import socket, sys
token = bytes.fromhex(sys.argv[1])
node = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bad = b"ORBLXPN1" + bytes([1]) + b"\x00" * 8
good = b"ORBLXPN1" + bytes([1]) + token
sock.sendto(bad, (node, 443))
sock.sendto(good, (node, 443))
print("foreign_punch_sent")
' "$token" "${LAN}.23.10"
  wait_log "$CA" '^punch_drop .* token$' 20
  wait_log "$CA" '^punch_drop .* netmap$' 20
  as_root docker logs "$CA" 2>&1 | awk '/^punch_drop / { print }'
  stop_node "$CA"
  stop_node "$CD"
}

show_foreign_punch

for n in $(seq 1 "$RUNS"); do
  run_case random random relay "$n"
  run_case sequential random direct "$n"
  run_case sequential sequential direct "$n"
  run_case portblock random direct "$n"
  run_case shift shift miss "$n"
done

echo "=== [C] retry after a blocked punch ==="
stop_node "$CA"
stop_node "$CD"
reset_endpoints
bring_routers sequential sequential
block_punch
t0="$(date +%s.%N)"
start_nat node-c node-d
start_nat node-d node-c
started_c="$(as_root docker inspect -f '{{.State.StartedAt}}' "$CA")"
wait_path "$CA" relay node-d 40 >/dev/null
wait_path "$CD" relay node-c 40 >/dev/null
echo "retry relay up while the punch is blocked"
found=0
for i in $(seq 1 160); do
  if as_root docker logs "$CA" 2>&1 | has_line '^The predict attempt ended after '; then
    found=1
    break
  fi
  if [[ "$(path_of "$(status_text "$CA")")" == "direct" ]]; then
    echo "The blocked punch reached direct." >&2
    FAIL=1
    break
  fi
  sleep 0.25
done
if [[ "$found" != "1" ]]; then
  echo "The blocked predict attempt did not end." >&2
  FAIL=1
fi
found2=0
for i in $(seq 1 40); do
  if as_root docker logs "$CA" 2>&1 | has_line '^The predict attempt [2-9][0-9]* starts\.'; then
    found2=1
    break
  fi
  if [[ "$(path_of "$(status_text "$CA")")" == "direct" ]]; then
    echo "The blocked punch reached direct before the retry." >&2
    FAIL=1
    break
  fi
  sleep 0.25
done
if [[ "$found2" != "1" ]]; then
  echo "The node did not log a later predict attempt while the punch was blocked." >&2
  FAIL=1
fi
unblock_punch
text_c="$(wait_path "$CA" direct node-d 80)"
text_d="$(wait_path "$CD" direct node-c 80)"
echo "retry paths $(path_of "$text_c") $(path_of "$text_d")"
started_c2="$(as_root docker inspect -f '{{.State.StartedAt}}' "$CA")"
if [[ "$started_c" != "$started_c2" ]]; then
  echo "The node container restarted during the retry." >&2
  FAIL=1
else
  echo "retry restarted false"
fi
stop_node "$CA"
stop_node "$CD"

if [[ "$FAIL" != "0" ]]; then
  echo "sym_sym_direct_fail"
  exit 1
fi
echo "sym_sym_direct_ok"

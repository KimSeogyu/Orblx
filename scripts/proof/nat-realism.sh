#!/usr/bin/env bash
# NAT realism proof (W20).
# The host is REAL. Every extra host is a [C] container.
# router-a and router-b are port-restricted cone NAT (prc).
# router-c and router-d are symmetric NAT.
# Cases: prc to prc, prc to symmetric, symmetric to symmetric,
# and block and unblock switches with ping loss and ping gap.
# The script fails when a switch loses more than 1 of 50 pings,
# when a switch gap is more than 1 second, or when svid_expiry is unknown.
# The script prints proof_ok.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.nat-realism.yml"
IMAGE="orblx-natr:w20"
COORD="172.29.20.10:443"
STUN="172.29.20.20:3478"
STUN_ALT="172.29.20.20:3479"
RELAY="172.29.20.20:443"
WAN_A="172.29.20.11"
WAN_B="172.29.20.12"
WAN_C="172.29.20.13"
WAN_D="172.29.20.14"
PINGS=50
MAX_LOSS=1
MAX_GAP_MS=1000
SPRAY_MAX=2048

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
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
  bin="$ROOT/target/debug/orblx"
  cargo build -p orblx-cli --bin orblx
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
    node-a) echo 10.19.21.2 ;;
    node-b) echo 10.19.22.2 ;;
    node-c) echo 10.19.23.2 ;;
    node-d) echo 10.19.24.2 ;;
  esac
}

container_of() {
  echo "orblx-natr-${1#node-}"
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

NAT_CONTAINERS="orblx-natr-a orblx-natr-b orblx-natr-c orblx-natr-d"

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
    t.sendto(("%s:%d" % addr).encode(), ("172.29.20.20", 5013))
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
s.sendto(b"probe", ("172.29.20.10", 5011))
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
    "ip route replace default via $(gateway_of "$service") && python3 -c '${PROBE_PY}' 172.29.20.10:5001 172.29.20.20:5001" \
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
  one="$(port_of_mapping "$map" 172.29.20.10:5001)"
  two="$(port_of_mapping "$map" 172.29.20.20:5001)"
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
  if [[ "$filter" != "filter received same_endpoint@172.29.20.10:5011" ]]; then
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
  "ip route replace default via 10.19.21.2; for ip in 10.19.22.10 10.19.23.10 10.19.24.10 10.19.22.2 10.19.23.2; do if ping -c 1 -W 1 \$ip >/dev/null 2>&1; then echo lan_reach \$ip yes; else echo lan_reach \$ip no; fi; done")"
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
wait_path orblx-natr-a direct node-b >/dev/null
wait_path orblx-natr-b direct node-a >/dev/null
PP_A="$(wait_svid orblx-natr-a)"
PP_B="$(wait_svid orblx-natr-b)"
printf '%s\n' "$PP_A"
printf '%s\n' "$PP_B"
check_svid "prc_prc node-a" "$PP_A"
check_svid "prc_prc node-b" "$PP_B"
PP_PATH="$(path_of "$PP_A") $(path_of "$PP_B")"
echo "prc_prc path ${PP_PATH}"
punch_log orblx-natr-a
punch_log orblx-natr-b
steady_pings prc_prc orblx-natr-a "$IP_B"

echo "=== [C] switch prc_prc direct to relay (block UDP between router-a and router-b) ==="
measure_switch "switch prc_prc direct_to_relay" orblx-natr-a node-b "$IP_B" relay block_ab
echo "=== [C] switch prc_prc relay to direct (restore UDP) ==="
measure_switch "switch prc_prc relay_to_direct" orblx-natr-a node-b "$IP_B" direct open_ab
docker logs orblx-natr-a 2>&1 | grep -E '^The (path to|node sent|relay also)' | sed 's/^/orblx-natr-a: /'
stop_node orblx-natr-a
stop_node orblx-natr-b

echo "=== [C] case prc_sym node-a to node-c ==="
start_nat node-a node-c
start_nat node-c node-a
PS_A="$(wait_path orblx-natr-a any node-c)"
# The birthday attempt has a window of 15 seconds.
for _ in $(seq 1 20); do
  if [[ "$(path_of "$(status_text orblx-natr-a)")" == "direct" && "$(path_of "$(status_text orblx-natr-c)")" == "direct" ]]; then
    break
  fi
  sleep 1
done
PS_A="$(wait_svid orblx-natr-a)"
PS_C="$(wait_svid orblx-natr-c)"
printf '%s\n' "$PS_A"
printf '%s\n' "$PS_C"
check_svid "prc_sym node-a" "$PS_A"
check_svid "prc_sym node-c" "$PS_C"
PS_PATH_A="$(path_of "$PS_A")"
PS_PATH_C="$(path_of "$PS_C")"
echo "prc_sym path ${PS_PATH_A} ${PS_PATH_C}"
punch_log orblx-natr-a
punch_log orblx-natr-c
check_probe_bound orblx-natr-a
check_probe_bound orblx-natr-c
if [[ "$PS_PATH_A" == "direct" ]]; then
  REACHED="$(docker logs orblx-natr-a 2>&1 | awk '/^The hole punch reached / {sub(/\.$/, "", $5); print $5; exit}')"
  echo "prc_sym node-a punch_peer ${REACHED}"
  if [[ "${REACHED%%:*}" != "$WAN_C" ]]; then
    echo "The prc_sym direct path did not go through the router-c WAN address." >&2
    exit 1
  fi
fi
steady_pings prc_sym orblx-natr-a "$IP_C"
if [[ "$PS_PATH_A" == "direct" ]]; then
  echo "=== [C] switch prc_sym direct to relay (block UDP between router-a and router-c) ==="
  measure_switch "switch prc_sym direct_to_relay" orblx-natr-a node-c "$IP_C" relay block_ac
  echo "=== [C] switch prc_sym relay to direct (restore UDP) ==="
  measure_switch "switch prc_sym relay_to_direct" orblx-natr-a node-c "$IP_C" direct open_ac
fi
stop_node orblx-natr-a
stop_node orblx-natr-c

echo "=== [C] case sym_sym node-c to node-d ==="
start_nat node-c node-d
start_nat node-d node-c
wait_path orblx-natr-c relay node-d >/dev/null
sleep 5
SS_C="$(wait_svid orblx-natr-c)"
SS_D="$(wait_svid orblx-natr-d)"
printf '%s\n' "$SS_C"
printf '%s\n' "$SS_D"
check_svid "sym_sym node-c" "$SS_C"
check_svid "sym_sym node-d" "$SS_D"
SS_PATH="$(path_of "$SS_C") $(path_of "$SS_D")"
echo "sym_sym path ${SS_PATH}"
punch_log orblx-natr-c
punch_log orblx-natr-d
if [[ "$SS_PATH" != "relay relay" ]]; then
  echo "The sym_sym case did not use the relay." >&2
  exit 1
fi
if docker logs orblx-natr-c 2>&1 | grep -q '^The hole punch reached'; then
  echo "The sym_sym case reported a hole punch." >&2
  exit 1
fi
steady_pings sym_sym orblx-natr-c "$IP_D"
stop_node orblx-natr-c
stop_node orblx-natr-d

if dc logs coord relay 2>&1 | grep -q "PRIVATE KEY"; then
  echo "A log contains a private key." >&2
  exit 1
fi

echo "=== summary ==="
echo "prc_prc path ${PP_PATH}"
echo "prc_sym path ${PS_PATH_A} ${PS_PATH_C}"
echo "sym_sym path ${SS_PATH}"
for line in "${SUMMARY[@]}"; do
  echo "$line"
done
echo "proof_ok"

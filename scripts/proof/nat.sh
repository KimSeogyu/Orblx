#!/usr/bin/env bash
# NAT traversal proof.
# The host is REAL. Every extra host is a [C] container.
# The script prints proof_ok and the path kind for each case.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.nat.yml"
COORD="172.29.19.10:443"
STUN="172.29.19.20:3478"
RELAY="172.29.19.20:443"

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

# The REAL host can drop bridged frames in two ways.
# iptables-legacy FORWARD DROP drops frames that br_netfilter sends to iptables.
# br_netfilter also routes a frame by its IP destination and skips the [C] router.
# The NAT routers must receive the frame by MAC.
open_legacy_forward() {
  if command -v iptables-legacy >/dev/null 2>&1; then
    if as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP'; then
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
  docker build -t orblx-nat:w19 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 60); do
    if dc exec -T coord cat /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

enroll_node() {
  local service="$1"
  local name="$2"
  local gateway="$3"
  echo "=== [C] enroll ${name} ==="
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$service" -c \
    "ip route replace default via ${gateway} && orblx coord enroll --name ${name} --coord ${COORD} --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${name} --state /var/lib/orblx --endpoint 127.0.0.1:9"
}

stop_node() {
  local name="$1"
  docker rm -f "$name" >/dev/null 2>&1 || true
}

start_nat() {
  local container="$1"
  local service="$2"
  local peer="$3"
  local gateway="$4"
  stop_node "$container"
  dc --profile nodes run -d --name "$container" --no-deps "$service" \
    nat run \
    --state /var/lib/orblx \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --stun "$STUN" \
    --relay "$RELAY" \
    --peer "$peer" \
    --gateway "$gateway" >/dev/null
}

status_text() {
  docker exec "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

path_of() {
  printf '%s\n' "$1" | read_all awk '/^peer / {print $6; exit}'
}

wait_path() {
  local container="$1"
  local want="$2"
  local peer="$3"
  local i text kind
  for i in $(seq 1 45); do
    text="$(status_text "$container")"
    if printf '%s\n' "$text" | read_all grep -q "^peer ${peer} "; then
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
  printf '%s\n' "$(status_text "$container")" >&2
  docker logs "$container" >&2 || true
  return 1
}

ping_ok() {
  local container="$1"
  local ip="$2"
  docker exec "$container" ping -c 3 -W 2 -i 0.2 "$ip"
}

NAT_CONTAINERS="orblx-nat-x orblx-nat-y orblx-nat-z orblx-nat-w"

cleanup() {
  local name
  for name in $NAT_CONTAINERS; do
    stop_node "$name"
  done
  dc --profile nodes down -v --remove-orphans >/dev/null 2>&1 || true
}

# The mapping probe sends from one LAN port to two public UDP servers.
# Each server answers with the source address that it saw.
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
    for _ in range(3):
        s.sendto(b"probe", (host, int(port)))
        try:
            seen, _ = s.recvfrom(64)
            break
        except socket.timeout:
            seen = b"none"
    print("mapping", "inner:40000", "to", dest, "seen_as", seen.decode())
'

# Print the external port that a router gives one inner port for two destinations.
mapping_ports() {
  local service="$1"
  local gateway="$2"
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$service" -c \
    "ip route replace default via ${gateway} && python3 -c '${PROBE_PY}' 172.29.19.10:5001 172.29.19.20:5001" \
    | sed "s/^/${service}: /"
}

port_of_mapping() {
  printf '%s\n' "$1" | read_all awk -v dest="$2" '$2 == "mapping" && $5 == dest {n = split($7, a, ":"); print a[n]; exit}'
}

ip_of_mapping() {
  printf '%s\n' "$1" | read_all awk -v dest="$2" '$2 == "mapping" && $5 == dest {split($7, a, ":"); print a[1]; exit}'
}

now_s() {
  date +%s.%N
}

# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "nat"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-nat-proof" || exit 1

echo "=== REAL cargo test tampered candidate ==="
cargo test -p orblx-edge --lib signed::tests::tampered_candidate_signature_is_rejected -- --nocapture

echo "=== [C] remove old proof volumes ==="
cleanup
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start public network, routers, coordinator, and relay ==="
dc up -d coord relay router-1 router-2 router-3 router-4
open_legacy_forward
wait_bundle
sleep 1
echo "=== [C] router-1 cone ==="
dc logs --no-log-prefix router-1 | sed -n '1,40p'
echo "=== [C] router-2 symmetric ==="
dc logs --no-log-prefix router-2 | sed -n '1,40p'
echo "=== [C] router-3 cone ==="
dc logs --no-log-prefix router-3 | sed -n '1,40p'
echo "=== [C] router-4 symmetric ==="
dc logs --no-log-prefix router-4 | sed -n '1,40p'

echo "=== [C] no hairpin and no LAN to LAN forward ==="
for router in router-1 router-2 router-3 router-4; do
  wan="$(dc logs --no-log-prefix "$router" | read_all awk '/^router wan / {print $3; exit}')"
  nat_rules="$(dc exec -T "$router" iptables -t nat -S)"
  # A hairpin needs a DNAT rule that matches a packet from the LAN side.
  hairpin="$(printf '%s\n' "$nat_rules" | grep -E -- '-j DNAT' | grep -v -- "-i ${wan} " || true)"
  if [[ -z "$wan" || -n "$hairpin" ]]; then
    echo "${router} has a DNAT rule that is not on the WAN interface ${wan}." >&2
    printf '%s\n' "$nat_rules" >&2
    exit 1
  fi
  echo "${router} wan ${wan} dnat_rules_off_wan 0"
done

echo "=== [C] symmetric NAT mapping probe ==="
dc exec -d -T coord python3 -c "$ECHO_PY"
dc exec -d -T relay python3 -c "$ECHO_PY"
sleep 1
MAP_2="$(mapping_ports node-y 10.19.2.2)"
printf '%s\n' "$MAP_2"
MAP_2_A="$(port_of_mapping "$MAP_2" 172.29.19.10:5001)"
MAP_2_B="$(port_of_mapping "$MAP_2" 172.29.19.20:5001)"
MAP_2_IP="$(ip_of_mapping "$MAP_2" 172.29.19.10:5001)"
echo "router-2 inner_port 40000 external_ip ${MAP_2_IP} port_to_coord ${MAP_2_A} port_to_relay ${MAP_2_B}"
if [[ -z "$MAP_2_A" || -z "$MAP_2_B" || "$MAP_2_IP" != "172.29.19.12" ]]; then
  echo "The router-2 mapping probe did not get two answers through 172.29.19.12." >&2
  exit 1
fi
if [[ "$MAP_2_A" == "$MAP_2_B" ]]; then
  echo "router-2 used the same external port for two destinations. Router-2 is not symmetric." >&2
  exit 1
fi
echo "router-2 symmetric true"
MAP_1="$(mapping_ports node-x 10.19.1.2)"
printf '%s\n' "$MAP_1"
MAP_1_A="$(port_of_mapping "$MAP_1" 172.29.19.10:5001)"
MAP_1_B="$(port_of_mapping "$MAP_1" 172.29.19.20:5001)"
echo "router-1 inner_port 40000 port_to_coord ${MAP_1_A} port_to_relay ${MAP_1_B}"
if [[ -z "$MAP_1_A" || "$MAP_1_A" != "$MAP_1_B" ]]; then
  echo "router-1 did not keep one external port for two destinations." >&2
  exit 1
fi
echo "router-1 endpoint_independent true"
MAP_4="$(mapping_ports node-w 10.19.4.2)"
printf '%s\n' "$MAP_4"
MAP_4_A="$(port_of_mapping "$MAP_4" 172.29.19.10:5001)"
MAP_4_B="$(port_of_mapping "$MAP_4" 172.29.19.20:5001)"
echo "router-4 inner_port 40000 port_to_coord ${MAP_4_A} port_to_relay ${MAP_4_B}"
if [[ -z "$MAP_4_A" || -z "$MAP_4_B" || "$MAP_4_A" == "$MAP_4_B" ]]; then
  echo "router-4 is not symmetric." >&2
  exit 1
fi
echo "router-4 symmetric true"

echo "=== [C] token node-x ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-x
echo "=== [C] token node-y ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-y
echo "=== [C] token node-z ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-z
echo "=== [C] token node-w ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-w

enroll_node node-x node-x 10.19.1.2
enroll_node node-y node-y 10.19.2.2
enroll_node node-z node-z 10.19.3.2
enroll_node node-w node-w 10.19.4.2

overlay_of() {
  local service="$1"
  local gateway="$2"
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$service" -c \
    "ip route replace default via ${gateway} && orblx coord netmap --coord ${COORD} --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx" \
    | read_all awk '/^overlay_ip /{print $2; exit}'
}

echo "=== [C] overlay addresses ==="
IP_X="$(overlay_of node-x 10.19.1.2)"
IP_Y="$(overlay_of node-y 10.19.2.2)"
IP_Z="$(overlay_of node-z 10.19.3.2)"
IP_W="$(overlay_of node-w 10.19.4.2)"
echo "overlay node-x ${IP_X}"
echo "overlay node-y ${IP_Y}"
echo "overlay node-z ${IP_Z}"
echo "overlay node-w ${IP_W}"

echo "=== [C] no shared subnet between nodes ==="
for pair in "node-x 10.19.1.2" "node-y 10.19.2.2" "node-z 10.19.3.2" "node-w 10.19.4.2"; do
  node="${pair% *}"
  gateway="${pair#* }"
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$node" -c \
    "ip route replace default via ${gateway} && ip -4 -o addr show scope global && ip route" \
    | sed "s/^/${node}: /"
done
LAN_REACH="$(dc --profile nodes run --rm --no-deps --entrypoint /bin/sh node-x -c \
  "ip route replace default via 10.19.1.2; for ip in 10.19.2.10 10.19.3.10 10.19.4.10 10.19.2.2 10.19.3.2; do if ping -c 1 -W 1 \$ip >/dev/null 2>&1; then echo lan_reach \$ip yes; else echo lan_reach \$ip no; fi; done")"
printf '%s\n' "$LAN_REACH"
if printf '%s\n' "$LAN_REACH" | read_all grep -q ' yes$'; then
  echo "node-x can reach another LAN without NAT." >&2
  exit 1
fi
echo "lan_shortcut false"

echo "=== [C] case 1 cone to cone ==="
start_nat orblx-nat-x node-x node-z 10.19.1.2
start_nat orblx-nat-z node-z node-x 10.19.3.2
CASE1_X="$(wait_path orblx-nat-x direct node-z)"
CASE1_Z="$(wait_path orblx-nat-z direct node-x)"
printf '%s\n' "$CASE1_X"
ping_ok orblx-nat-x "$IP_Z"
CASE1_PATH="$(path_of "$CASE1_X")"
echo "case1 path ${CASE1_PATH}"
if [[ "$CASE1_PATH" != "direct" ]]; then
  echo "Case 1 did not use a direct path." >&2
  exit 1
fi
stop_node orblx-nat-x
stop_node orblx-nat-z

echo "=== [C] case 2 cone to symmetric ==="
start_nat orblx-nat-x node-x node-y 10.19.1.2
start_nat orblx-nat-y node-y node-x 10.19.2.2
CASE2_X="$(wait_path orblx-nat-x any node-y)"
printf '%s\n' "$CASE2_X"
CASE2_PATH="$(path_of "$CASE2_X")"
ping_ok orblx-nat-x "$IP_Y"
echo "case2 path ${CASE2_PATH}"
if [[ "$CASE2_PATH" != "direct" && "$CASE2_PATH" != "relay" ]]; then
  echo "Case 2 did not report a path." >&2
  exit 1
fi
echo "=== [C] case 2 direct path evidence ==="
docker logs orblx-nat-x 2>&1 | show_matching -E '^The (reflexive endpoint|candidate for|hole punch reached)' | sort -u | sed 's/^/node-x: /'
docker logs orblx-nat-y 2>&1 | show_matching -E '^The (reflexive endpoint|candidate for|hole punch reached)' | sort -u | sed 's/^/node-y: /'
CASE2_X_REACHED="$(docker logs orblx-nat-x 2>&1 | read_all awk '/^The hole punch reached / {sub(/\.$/, "", $5); print $5; exit}')"
CASE2_Y_REACHED="$(docker logs orblx-nat-y 2>&1 | read_all awk '/^The hole punch reached / {sub(/\.$/, "", $5); print $5; exit}')"
echo "case2 node-x punch_peer ${CASE2_X_REACHED:-none}"
echo "case2 node-y punch_peer ${CASE2_Y_REACHED:-none}"
if [[ "$CASE2_PATH" == "direct" ]]; then
  if [[ "${CASE2_X_REACHED%%:*}" != "172.29.19.12" && "${CASE2_Y_REACHED%%:*}" != "172.29.19.11" ]]; then
    echo "The case 2 direct path did not go through the router WAN addresses." >&2
    exit 1
  fi
fi
stop_node orblx-nat-x
stop_node orblx-nat-y

echo "=== [C] case 3 block direct UDP ==="
start_nat orblx-nat-x node-x node-z 10.19.1.2
start_nat orblx-nat-z node-z node-x 10.19.3.2
wait_path orblx-nat-x direct node-z >/dev/null
docker exec orblx-nat-x sh -c "ping -D -n -i 0.2 -c 300 -W 1 ${IP_Z} > /tmp/ping.txt 2>&1" &
PING_PID=$!
sleep 2
echo "=== [C] drop UDP between the cone routers ==="
T_BLOCK="$(now_s)"
dc exec -T router-1 iptables -I FORWARD 1 -d 172.29.19.13 -p udp -j DROP
dc exec -T router-1 iptables -I FORWARD 1 -s 172.29.19.13 -p udp -j DROP
dc exec -T router-3 iptables -I FORWARD 1 -d 172.29.19.11 -p udp -j DROP
dc exec -T router-3 iptables -I FORWARD 1 -s 172.29.19.11 -p udp -j DROP
CASE3_BLOCK="$(wait_path orblx-nat-x relay node-z)"
T_RELAY="$(now_s)"
printf '%s\n' "$CASE3_BLOCK"
CASE3_PATH="$(path_of "$CASE3_BLOCK")"
sleep 3
echo "=== [C] restore UDP between the cone routers ==="
T_RESTORE="$(now_s)"
dc exec -T router-1 iptables -D FORWARD -d 172.29.19.13 -p udp -j DROP
dc exec -T router-1 iptables -D FORWARD -s 172.29.19.13 -p udp -j DROP
dc exec -T router-3 iptables -D FORWARD -d 172.29.19.11 -p udp -j DROP
dc exec -T router-3 iptables -D FORWARD -s 172.29.19.11 -p udp -j DROP
CASE3_RETURN="relay"
T_DIRECT=""
for _ in $(seq 1 100); do
  text="$(status_text orblx-nat-x)"
  kind="$(path_of "$text")"
  if printf '%s\n' "$text" | read_all grep -q "^peer node-z " && [[ "$kind" == "direct" ]]; then
    CASE3_RETURN="direct"
    T_DIRECT="$(now_s)"
    printf '%s\n' "$text"
    break
  fi
  sleep 0.2
done
sleep 3
docker exec orblx-nat-x sh -c 'for p in /proc/[0-9]*; do if [ "$(cat "$p/comm" 2>/dev/null)" = ping ]; then kill -INT "${p#/proc/}"; fi; done' || true
wait "$PING_PID" || true
echo "case3 path ${CASE3_PATH}"
echo "case3 return ${CASE3_RETURN}"
if [[ "$CASE3_PATH" != "relay" ]]; then
  echo "Case 3 did not move to the relay." >&2
  docker logs orblx-nat-x >&2 || true
  exit 1
fi
if [[ "$CASE3_RETURN" != "direct" ]]; then
  echo "Case 3 did not return to direct." >&2
  docker logs orblx-nat-x >&2 || true
  exit 1
fi
echo "=== [C] ping gap at each path switch ==="
docker exec orblx-nat-x cat /tmp/ping.txt | python3 -c '
import sys
t_block, t_relay, t_restore, t_direct = (float(v) for v in sys.argv[1:5])
times = []
for line in sys.stdin:
    line = line.strip()
    if line.startswith("[") and "icmp_seq=" in line:
        times.append(float(line.split("]", 1)[0][1:]))
    if "packets transmitted" in line:
        print("ping_summary", line)
print("ping_replies", len(times))
if len(times) < 20:
    raise SystemExit("The ping did not receive enough replies.")

def max_gap(start, stop):
    # The gap that ends after start and begins before stop.
    gaps = [b - a for a, b in zip(times, times[1:]) if b >= start and a <= stop]
    if not gaps:
        raise SystemExit("No ping reply was near the switch.")
    return max(gaps)

switches = [
    ("direct", "relay", t_block, t_relay),
    ("relay", "direct", t_restore, t_direct),
]
worst = 0.0
for index, (before, after, start, stop) in enumerate(switches, 1):
    gap = max_gap(start, stop + 0.5)
    worst = max(worst, gap)
    print("case3 switch%d from %s to %s detect_ms %d max_gap_ms %d" % (
        index, before, after, int((stop - start) * 1000), int(gap * 1000)))
all_gaps = [b - a for a, b in zip(times, times[1:])]
print("case3 max_gap_ms_all", int(max(all_gaps) * 1000))
if worst > 1.0:
    raise SystemExit("A ping gap at a path switch was longer than 1 second.")
' "$T_BLOCK" "$T_RELAY" "$T_RESTORE" "$T_DIRECT"
stop_node orblx-nat-x
stop_node orblx-nat-z

echo "=== [C] case 5 symmetric to symmetric ==="
start_nat orblx-nat-y node-y node-w 10.19.2.2
start_nat orblx-nat-w node-w node-y 10.19.4.2
CASE5_Y="$(wait_path orblx-nat-y any node-w)"
printf '%s\n' "$CASE5_Y"
sleep 8
CASE5_Y="$(status_text orblx-nat-y)"
CASE5_W="$(status_text orblx-nat-w)"
printf '%s\n' "$CASE5_Y"
printf '%s\n' "$CASE5_W"
CASE5_PATH="$(path_of "$CASE5_Y")"
CASE5_PATH_W="$(path_of "$CASE5_W")"
ping_ok orblx-nat-y "$IP_W"
docker logs orblx-nat-y 2>&1 | show_matching -E '^The (reflexive endpoint|candidate for|hole punch|direct attempt|relay transport)' | sort -u | sed 's/^/node-y: /'
docker logs orblx-nat-w 2>&1 | show_matching -E '^The (reflexive endpoint|candidate for|hole punch|direct attempt|relay transport)' | sort -u | sed 's/^/node-w: /'
echo "case5 path ${CASE5_PATH} ${CASE5_PATH_W}"
if [[ "$CASE5_PATH" != "relay" || "$CASE5_PATH_W" != "relay" ]]; then
  echo "Case 5 did not use the relay." >&2
  exit 1
fi
if docker logs orblx-nat-y 2>&1 | read_all grep -q '^The hole punch reached'; then
  echo "Case 5 reported a hole punch between two symmetric NATs." >&2
  exit 1
fi
stop_node orblx-nat-y
stop_node orblx-nat-w

echo "=== [C] case 4 tampered candidate ==="
set +e
CASE4="$(docker run --rm --entrypoint orblx orblx-nat:w19 nat verify-candidate --name node-a --endpoint 203.0.113.10:443 --public 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --key-id ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --sig AAAA 2>&1)"
CASE4_CODE=$?
set -e
printf '%s\n' "$CASE4"
if [[ "$CASE4_CODE" -eq 0 ]]; then
  echo "The tampered candidate was accepted." >&2
  exit 1
fi
if ! printf '%s\n' "$CASE4" | read_all grep -q "The candidate signature for node-a was rejected."; then
  echo "The rejection log line is missing." >&2
  exit 1
fi
echo "case4 rejected true"

if dc logs coord | read_all grep -q "PRIVATE KEY"; then
  echo "The coordinator log contains a private key." >&2
  exit 1
fi

echo "case1 path ${CASE1_PATH}"
echo "case2 path ${CASE2_PATH}"
echo "case3 path ${CASE3_PATH}"
echo "case3 return ${CASE3_RETURN}"
echo "case4 rejected true"
echo "case5 path ${CASE5_PATH}"
echo "router-2 port_to_coord ${MAP_2_A} port_to_relay ${MAP_2_B}"
echo "proof_ok"

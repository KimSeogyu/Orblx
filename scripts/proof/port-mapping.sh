#!/usr/bin/env bash
# Port mapping proof.
# The host is REAL. Every router, node, coordinator, and relay is a [C] container.
# router-c and router-d start as symmetric NAT.
# The mapped case switches router-c to symmap (symmetric NAT plus miniupnpd).
# Cases, each repeated N times (ORBLX_PORTMAP_N, default 5):
#   baseline: symmetric to symmetric, UDP 5351 and 1900 dropped. Expect relay.
#   mapped: symmap to symmetric, --port-map auto. Expect direct.
#   disabled: symmap to symmetric, --port-map off. Expect relay.
# NAT-PMP only and UPnP only use the same N.
# One crash restart checks that a killed node does not leave an orphan map.
# The script prints rustc -V, the build profile, and the proof_contention line.
set -euo pipefail

# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.nat-realism.yml"
NATR_PREFIX="${ORBLX_NATR_PREFIX:-orblx-pmap-}"
PROJECT="${ORBLX_NATR_PROJECT:-orblx-pmap-proof}"
IMAGE="${ORBLX_NATR_IMAGE:-orblx-pmap:portmap}"
# 23.31.0.0/24 is a public range on this Docker network only.
# miniupnpd refuses a private WAN address, so the lab WAN is not in 172.16.0.0/12.
PUB="${ORBLX_NATR_PUB:-23.31.0}"
LAN="${ORBLX_NATR_LAN:-10.31}"
export ORBLX_NATR_IMAGE="$IMAGE" ORBLX_NATR_PUB="$PUB" ORBLX_NATR_LAN="$LAN"
export ORBLX_ROUTER_C="${ORBLX_ROUTER_C:-symmetric}"
export ORBLX_ROUTER_D="${ORBLX_ROUTER_D:-symmetric}"

# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
PROOF_MIN_FREE_GIB=15
trap proof_lock_end EXIT
proof_lock_take "port-mapping:${PROJECT}" "$NATR_PREFIX" "${PROJECT}-"
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$PROJECT" || exit 1

N="${ORBLX_PORTMAP_N:-5}"
PINGS=50
MAX_LOSS=1
LIFETIME="${ORBLX_PORTMAP_LIFETIME:-40}"
COORD="${PUB}.10:443"
STUN="${PUB}.20:3478"
STUN_ALT="${PUB}.20:3479"
RELAY="${PUB}.20:443"
WAN_C="${PUB}.13"
WAN_D="${PUB}.14"

echo "rustc $(rustc -V)"

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
      as_root sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null
      as_root sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null
    fi
  fi
}

build_image() {
  local image_dir bin
  bin="$ROOT/target/release/orblx"
  cargo build --release -p orblx-cli --bin orblx
  echo "build profile release"
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
    node-c) echo "${LAN}.23.2" ;;
    node-d) echo "${LAN}.24.2" ;;
    *) echo "The node $1 has no gateway." >&2; return 1 ;;
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
  local mode="$3"
  local container
  container="$(container_of "$name")"
  stop_node "$container"
  # Drop the previous status before this process starts. A reader must not see the old path.
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$name" -c \
    'rm -f /var/lib/orblx/status.txt /var/lib/orblx/status.txt.tmp' >/dev/null
  dc --profile nodes run -d --name "$container" --no-deps "$name" \
    nat run \
    --state /var/lib/orblx \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --stun "$STUN" \
    --stun-alt "$STUN_ALT" \
    --relay "$RELAY" \
    --peer "$peer" \
    --gateway "$(gateway_of "$name")" \
    --port-map "$mode" \
    --port-map-lifetime "$LIFETIME" >/dev/null
}

status_text() {
  docker exec "$1" orblx status --state-dir /var/lib/orblx 2>/dev/null || true
}

path_of() {
  printf '%s\n' "$1" | awk '!found && /^peer / {print $6; found = 1}'
}

wait_path() {
  local container="$1"
  local want="$2"
  local peer="$3"
  local i text kind
  for i in $(seq 1 40); do
    text="$(status_text "$container")"
    if printf '%s\n' "$text" | has_line "^peer ${peer} "; then
      kind="$(path_of "$text")"
      # The status file is on the volume. The previous process can leave `relay` there.
      # This container's log line is the proof that this run carried the packet.
      if [[ "$kind" == "$want" ]] && docker logs "$container" 2>&1 | read_all grep -q "The first ${want} packet arrived at"; then
        printf '%s\n' "$text"
        return 0
      fi
    fi
    sleep 1
  done
  echo "The path on ${container} did not become ${want}." >&2
  status_text "$container" >&2 || true
  docker logs "$container" >&2 || true
  return 1
}

set_routers() {
  local mode_c="$1"
  local mode_d="$2"
  export ORBLX_ROUTER_C="$mode_c"
  export ORBLX_ROUTER_D="$mode_d"
  dc up -d --force-recreate --no-deps router-c router-d
}

drop_map_ports() {
  local router
  for router in router-c router-d; do
    dc exec -T "$router" iptables -C INPUT -p udp --dport 5351 -j DROP >/dev/null 2>&1 \
      || dc exec -T "$router" iptables -I INPUT 1 -p udp --dport 5351 -j DROP
    dc exec -T "$router" iptables -C INPUT -p udp --dport 1900 -j DROP >/dev/null 2>&1 \
      || dc exec -T "$router" iptables -I INPUT 1 -p udp --dport 1900 -j DROP
  done
}

log_lines() {
  docker logs "$1" 2>&1 | read_all grep -E 'port map|punch plan|first |hole punch|STUN mapping|local NAT|reflexive endpoint|mapping daemon|deleted|published' || true
}

first_ms() {
  local kind="$1"
  docker logs "$2" 2>&1 | read_all awk -v k="$kind" '
    $0 ~ "The first " k " packet arrived at" { ms = $(NF-1) }
    END { if (ms == "") print "none"; else print ms }
  '
}

ping_loss() {
  local out transmitted received
  out="$(docker exec "$1" ping -n -i 0.2 -c "$PINGS" -W 1 "$2" || true)"
  printf '%s\n' "$out" | tail -2 >&2
  transmitted="$(printf '%s\n' "$out" | awk '/packets transmitted/ {print $1; exit}')"
  received="$(printf '%s\n' "$out" | awk '/packets transmitted/ {print $4; exit}')"
  if [[ ! "$transmitted" =~ ^[0-9]+$ || ! "$received" =~ ^[0-9]+$ ]]; then
    echo "none"
    return 0
  fi
  echo "$((transmitted - received))/${transmitted}"
}

# Print one result line. Append it to the table. Return 1 when the path or the loss is wrong.
ROWS=()
FAILS=0

note_row() {
  local ok="$1"
  shift
  local line="$*"
  echo "$line"
  ROWS+=("$line")
  if [[ "$ok" != "yes" ]]; then
    FAILS=$((FAILS + 1))
  fi
}

run_case() {
  local label="$1"
  local run="$2"
  local mode_c="$3"
  local mode_d="$4"
  local port_map="$5"
  local want="$6"
  local drop_probe="$7"
  local container_c container_d path_c path_d loss direct_ms relay_ms ok
  echo "=== [C] ${label} run ${run} ==="
  set_routers "$mode_c" "$mode_d"
  if [[ "$drop_probe" == "yes" ]]; then
    drop_map_ports
  fi
  start_nat node-c node-d "$port_map"
  start_nat node-d node-c "$port_map"
  container_c="$(container_of node-c)"
  container_d="$(container_of node-d)"
  path_c="down"
  path_d="down"
  if wait_path "$container_c" "$want" node-d >/dev/null; then
    path_c="$want"
  else
    path_c="$(path_of "$(status_text "$container_c")")"
  fi
  if wait_path "$container_d" "$want" node-c >/dev/null; then
    path_d="$want"
  else
    path_d="$(path_of "$(status_text "$container_d")")"
  fi
  echo "--- ${container_c} ---"
  log_lines "$container_c"
  echo "--- ${container_d} ---"
  log_lines "$container_d"
  direct_ms="$(first_ms direct "$container_c")"
  relay_ms="$(first_ms relay "$container_c")"
  # Ping after this run has carried a packet. A stale status file must not start the ping.
  loss="$(ping_loss "$container_c" "$IP_D")"
  ok="no"
  local packet_ms="none"
  if [[ "$want" == "direct" ]]; then
    packet_ms="$direct_ms"
  elif [[ "$want" == "relay" ]]; then
    packet_ms="$relay_ms"
  fi
  if [[ "$path_c" == "$want" && "$path_d" == "$want" && "$packet_ms" =~ ^[0-9]+$ ]]; then
    local lost_n="${loss##*$'\n'}"
    lost_n="${lost_n%%/*}"
    if [[ "$lost_n" =~ ^[0-9]+$ && "$lost_n" -le "$MAX_LOSS" ]]; then
      ok="yes"
    fi
  fi
  if [[ "$label" == "mapped" || "$label" == "nat-pmp" || "$label" == "upnp" ]]; then
    local i renewed=no
    for i in $(seq 1 30); do
      if docker logs "$container_c" 2>&1 | read_all grep -q 'The port map was renewed.'; then
        renewed=yes
        break
      fi
      sleep 1
    done
    echo "${label} run ${run} renewed ${renewed}"
    if [[ "$renewed" != "yes" ]]; then
      ok="no"
    fi
    docker stop -t 15 "$container_c" >/dev/null 2>&1 || true
    if docker logs "$container_c" 2>&1 | read_all grep -q 'The port map was deleted.'; then
      echo "${label} run ${run} deleted yes"
    else
      echo "${label} run ${run} deleted no"
      ok="no"
    fi
    echo "=== [C] map rules after delete ==="
    dc exec -T router-c nft list chain inet filter postrouting_miniupnpd || true
  fi
  if [[ "$label" == "mapped" || "$label" == "nat-pmp" || "$label" == "upnp" ]]; then
    if ! docker logs "$container_c" 2>&1 | read_all grep -q 'The port map is .*[:.]443 lifetime'; then
      echo "${label} run ${run} map port is not 443"
      ok="no"
    fi
  fi
  if [[ "$label" == "disabled" ]]; then
    if docker logs "$container_c" 2>&1 | read_all grep -q 'The port map is off.'; then
      echo "disabled run ${run} off yes"
    else
      echo "disabled run ${run} off no"
      ok="no"
    fi
  fi
  note_row "$ok" "case ${label} run ${run} path ${path_c} ${path_d} direct_ms ${direct_ms} relay_ms ${relay_ms} loss ${loss} ok ${ok}"
  stop_node "$container_c"
  stop_node "$container_d"
}

ECHO_PY='import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5001))
while True:
    data, addr = s.recvfrom(64)
    s.sendto(("%s:%d" % addr).encode(), addr)
'

wait_echo_server() {
  local name="$1"
  local port="$2"
  local i line
  for i in $(seq 1 20); do
    line="$(dc exec -T "$name" ss -H -uln "sport = :${port}" 2>/dev/null || true)"
    if printf '%s\n' "$line" | has_line ":${port}"; then
      echo "echo ${name} udp ${port} ready"
      return 0
    fi
    sleep 1
  done
  echo "The echo server on ${name} did not listen on UDP ${port}." >&2
  dc exec -T "$name" ss -uln >&2 || true
  return 1
}

wait_log() {
  local container="$1"
  local pattern="$2"
  local i
  for i in $(seq 1 30); do
    if docker logs "$container" 2>&1 | read_all grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  echo "The log on ${container} did not show: ${pattern}" >&2
  docker logs "$container" >&2 || true
  return 1
}

map_rule_count() {
  local text count
  text="$(dc exec -T router-c nft list chain inet filter prerouting_miniupnpd 2>/dev/null || true)"
  count="$(printf '%s\n' "$text" | awk '/443/ {n++} END {print n+0}')"
  echo "$count"
}

# Kill the node with SIGKILL so Drop does not delete the map.
# The next start must delete that map. One UDP 443 rule remains, then shutdown removes it.
check_crash_restart() {
  local container count
  echo "=== [C] crash restart ==="
  set_routers symmap symmetric
  start_nat node-c node-d auto
  container="$(container_of node-c)"
  wait_log "$container" "The port map is "
  count="$(map_rule_count)"
  echo "crash map rules before kill ${count}"
  docker kill "$container" >/dev/null
  count="$(map_rule_count)"
  echo "crash map rules after kill ${count}"
  if [[ "$count" -lt 1 ]]; then
    echo "The killed node left no map rule." >&2
    return 1
  fi
  start_nat node-c node-d auto
  container="$(container_of node-c)"
  wait_log "$container" "The previous port map delete was sent."
  wait_log "$container" "The port map was granted at "
  count="$(map_rule_count)"
  echo "crash map rules after restart ${count}"
  if [[ "$count" -ne 1 ]]; then
    echo "The restart left ${count} map rules." >&2
    dc exec -T router-c nft list table inet filter >&2 || true
    return 1
  fi
  docker stop -t 15 "$container" >/dev/null
  if ! docker logs "$container" 2>&1 | read_all grep -q "The port map was deleted."; then
    echo "The restarted node did not delete the map." >&2
    return 1
  fi
  count="$(map_rule_count)"
  echo "crash map rules after delete ${count}"
  if [[ "$count" -ne 0 ]]; then
    echo "A map rule stayed after shutdown." >&2
    return 1
  fi
  echo "crash_restart orphan_cleared yes"
  stop_node "$container"
}

check_unmapped_is_symmetric() {
  local map
  echo "=== [C] unmapped socket on symmap ==="
  set_routers symmap symmetric
  dc exec -d -T coord python3 -c "$ECHO_PY"
  dc exec -d -T relay python3 -c "$ECHO_PY"
  wait_echo_server coord 5001
  wait_echo_server relay 5001
  map="$(dc --profile nodes run --rm --no-deps -T --entrypoint /bin/sh node-c -c \
    "ip route replace default via $(gateway_of node-c) && python3 - ${PUB}" <<'PY'
import socket, sys
pub = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 40000))
s.settimeout(2)
seen = []
for dest in (pub + ".10", pub + ".20"):
    s.sendto(b"probe", (dest, 5001))
    data, _ = s.recvfrom(64)
    seen.append(data.decode())
    print("mapping", dest, data.decode())
print("same", seen[0] == seen[1])
PY
)"
  printf '%s\n' "$map"
  if printf '%s\n' "$map" | has_line '^same True$'; then
    echo "The unmapped socket kept one external port. The router is not symmetric." >&2
    return 1
  fi
  echo "unmapped_socket symmetric true"
}

echo "=== REAL rustc and image ==="
open_legacy_forward
build_image
dc up -d coord relay router-c router-d
wait_bundle
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-c | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-d | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
enroll_node node-c
enroll_node node-d
IP_C="$(dc --profile nodes run --rm --no-deps --entrypoint /bin/sh node-c -c "ip route replace default via $(gateway_of node-c) && orblx coord netmap --coord ${COORD} --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx" | awk '/^overlay_ip / {print $2; exit}')"
IP_D="$(dc --profile nodes run --rm --no-deps --entrypoint /bin/sh node-d -c "ip route replace default via $(gateway_of node-d) && orblx coord netmap --coord ${COORD} --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx" | awk '/^overlay_ip / {print $2; exit}')"
echo "overlay node-c ${IP_C}"
echo "overlay node-d ${IP_D}"
check_unmapped_is_symmetric

for run in $(seq 1 "$N"); do
  run_case baseline "$run" symmetric symmetric auto relay yes
  run_case mapped "$run" symmap symmetric auto direct no
  run_case disabled "$run" symmap symmetric off relay no
  run_case nat-pmp "$run" symmap symmetric nat-pmp direct no
  run_case upnp "$run" symmap symmetric upnp direct no
done
check_crash_restart

echo "=== [C] case table ==="
printf '%s\n' "${ROWS[@]}"
count_ok() {
  local label="$1" ok=0 row
  for row in "${ROWS[@]}"; do
    if [[ "$row" == "case ${label} run "* && "$row" == *" ok yes" ]]; then
      ok=$((ok + 1))
    fi
  done
  echo "$ok"
}
BASE_OK="$(count_ok baseline)"
MAP_OK="$(count_ok mapped)"
OFF_OK="$(count_ok disabled)"
PMP_OK="$(count_ok nat-pmp)"
UPNP_OK="$(count_ok upnp)"
echo "success baseline ${BASE_OK}/${N} mapped ${MAP_OK}/${N} disabled ${OFF_OK}/${N} nat-pmp ${PMP_OK}/${N} upnp ${UPNP_OK}/${N}"
echo "wan_c ${WAN_C} wan_d ${WAN_D}"
if [[ "$FAILS" -ne 0 ]]; then
  echo "proof_failed fails ${FAILS}"
  exit 1
fi
echo "proof_ok"

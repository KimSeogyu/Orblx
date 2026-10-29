#!/usr/bin/env bash
# NAT traversal proof.
# The host is REAL. Every extra host is a [C] container.
# The script prints proof_ok and the path kind for each case.
set -euo pipefail

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
  printf '%s\n' "$1" | awk '/^peer / {print $6; exit}'
}

wait_path() {
  local container="$1"
  local want="$2"
  local peer="$3"
  local i text kind
  for i in $(seq 1 45); do
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
  printf '%s\n' "$(status_text "$container")" >&2
  docker logs "$container" >&2 || true
  return 1
}

ping_ok() {
  local container="$1"
  local ip="$2"
  docker exec "$container" ping -c 3 -W 2 -i 0.2 "$ip"
}

echo "=== REAL cargo test tampered candidate ==="
cargo test -p orblx-edge --lib signed::tests::tampered_candidate_signature_is_rejected -- --nocapture

echo "=== [C] remove old proof volumes ==="
stop_node orblx-nat-x || true
stop_node orblx-nat-y || true
stop_node orblx-nat-z || true
dc --profile nodes down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start public network, routers, coordinator, and relay ==="
dc up -d coord relay router-1 router-2 router-3
open_legacy_forward
wait_bundle
sleep 1
echo "=== [C] router-1 cone ==="
dc logs router-1 | sed -n '1,40p'
echo "=== [C] router-2 symmetric ==="
dc logs router-2 | sed -n '1,40p'

echo "=== [C] token node-x ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-x
echo "=== [C] token node-y ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-y
echo "=== [C] token node-z ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/node-z

enroll_node node-x node-x 10.19.1.2
enroll_node node-y node-y 10.19.2.2
enroll_node node-z node-z 10.19.3.2

overlay_of() {
  local service="$1"
  local gateway="$2"
  dc --profile nodes run --rm --no-deps --entrypoint /bin/sh "$service" -c \
    "ip route replace default via ${gateway} && orblx coord netmap --coord ${COORD} --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx" \
    | awk '/^overlay_ip /{print $2; exit}'
}

echo "=== [C] overlay addresses ==="
IP_X="$(overlay_of node-x 10.19.1.2)"
IP_Y="$(overlay_of node-y 10.19.2.2)"
IP_Z="$(overlay_of node-z 10.19.3.2)"
echo "overlay node-x ${IP_X}"
echo "overlay node-y ${IP_Y}"
echo "overlay node-z ${IP_Z}"

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
stop_node orblx-nat-x
stop_node orblx-nat-y

echo "=== [C] case 3 block direct UDP ==="
start_nat orblx-nat-x node-x node-z 10.19.1.2
start_nat orblx-nat-z node-z node-x 10.19.3.2
wait_path orblx-nat-x direct node-z >/dev/null
docker exec orblx-nat-x sh -c "ping -D -n -i 0.2 -c 40 -W 1 ${IP_Z} > /tmp/ping.txt 2>&1" &
PING_PID=$!
sleep 1.5
echo "=== [C] drop UDP between the cone routers ==="
dc exec -T router-1 iptables -I FORWARD 1 -d 172.29.19.13 -p udp -j DROP
dc exec -T router-1 iptables -I FORWARD 1 -s 172.29.19.13 -p udp -j DROP
dc exec -T router-3 iptables -I FORWARD 1 -d 172.29.19.11 -p udp -j DROP
dc exec -T router-3 iptables -I FORWARD 1 -s 172.29.19.11 -p udp -j DROP
sleep 2
CASE3_BLOCK="$(wait_path orblx-nat-x relay node-z)"
printf '%s\n' "$CASE3_BLOCK"
CASE3_PATH="$(path_of "$CASE3_BLOCK")"
echo "=== [C] restore UDP between the cone routers ==="
dc exec -T router-1 iptables -D FORWARD -d 172.29.19.13 -p udp -j DROP
dc exec -T router-1 iptables -D FORWARD -s 172.29.19.13 -p udp -j DROP
dc exec -T router-3 iptables -D FORWARD -d 172.29.19.11 -p udp -j DROP
dc exec -T router-3 iptables -D FORWARD -s 172.29.19.11 -p udp -j DROP
wait "$PING_PID" || true
echo "=== [C] ping during the path switch ==="
docker exec orblx-nat-x cat /tmp/ping.txt | python3 -c '
import sys
times = []
for line in sys.stdin:
    line = line.strip()
    if line.startswith("[") and "icmp_seq=" in line:
        stamp = line.split("]", 1)[0][1:]
        times.append(float(stamp))
print("ping_replies", len(times))
if len(times) < 8:
    raise SystemExit("The ping did not receive enough replies.")
gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
max_gap = max(gaps)
print("max_gap_ms", int(max_gap * 1000))
if max_gap > 1.0:
    raise SystemExit("A ping gap was longer than 1 second.")
'
CASE3_RETURN="relay"
for _ in $(seq 1 20); do
  text="$(status_text orblx-nat-x)"
  kind="$(path_of "$text")"
  if printf '%s\n' "$text" | grep -q "^peer node-z " && [[ "$kind" == "direct" ]]; then
    CASE3_RETURN="direct"
    printf '%s\n' "$text"
    break
  fi
  sleep 1
done
echo "case3 path ${CASE3_PATH}"
echo "case3 return ${CASE3_RETURN}"
if [[ "$CASE3_PATH" != "relay" ]]; then
  echo "Case 3 did not move to the relay." >&2
  docker logs orblx-nat-x >&2 || true
  exit 1
fi
stop_node orblx-nat-x
stop_node orblx-nat-z

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
if ! printf '%s\n' "$CASE4" | grep -q "The candidate signature for node-a was rejected."; then
  echo "The rejection log line is missing." >&2
  exit 1
fi
echo "case4 rejected true"

if dc logs coord | grep -q "PRIVATE KEY"; then
  echo "The coordinator log contains a private key." >&2
  exit 1
fi

echo "case1 path ${CASE1_PATH}"
echo "case2 path ${CASE2_PATH}"
echo "case3 path ${CASE3_PATH}"
echo "case3 return ${CASE3_RETURN}"
echo "case4 rejected true"
echo "proof_ok"

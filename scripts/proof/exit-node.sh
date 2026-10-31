#!/usr/bin/env bash
# Exit node proof.
# One Linux host runs Docker.
# The client reaches an HTTP echo server only through the exit node.
# The echo body is the exit node address on the internet network.
# The script deletes the orblx-exit-proof containers at the start.
# The script does not print enroll tokens or private keys.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.exit.yml"
WORK="$(mktemp -d)"
export EXIT_COORD_STATE="$WORK/coord"
export EXIT_POLICY="$WORK/policy.hujson"
export EXIT_TOOL_STATE="$WORK/tool"
export EXIT_NODE_STATE="$WORK/exit"
export EXIT_CLIENT_STATE="$WORK/client"
export EXIT_ECHO_PY="$ROOT/scripts/proof/echo-ip.py"
COORD_IP="172.30.19.2"
EXIT_IP="172.30.19.3"
CLIENT_IP="172.30.19.4"
RELAY_IP="172.30.19.5"
WEB_IP="10.77.0.5"
EXIT_INET_IP="10.77.0.2"

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
else
  DOCKER=(sudo docker)
fi

write_env() {
  cat >"$WORK/proof.env" <<EOF
EXIT_COORD_STATE=$EXIT_COORD_STATE
EXIT_POLICY=$EXIT_POLICY
EXIT_TOOL_STATE=$EXIT_TOOL_STATE
EXIT_NODE_STATE=$EXIT_NODE_STATE
EXIT_CLIENT_STATE=$EXIT_CLIENT_STATE
EXIT_ECHO_PY=$EXIT_ECHO_PY
EOF
}

cleanup() {
  dc --profile nodes --profile tool down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$(id -u)" -eq 0 ]]; then
    rm -rf "$WORK"
  else
    sudo -n rm -rf "$WORK" >/dev/null 2>&1 || rm -rf "$WORK" >/dev/null 2>&1 || true
  fi
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "exit-node"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-exit-proof" || exit 1

dc() {
  "${DOCKER[@]}" compose --env-file "$WORK/proof.env" --progress quiet -f "$FILE" "$@"
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir bin
  bin="$ROOT/target/debug/orblx"
  cargo build -p orblx-cli --bin orblx
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  "${DOCKER[@]}" build -t orblx-exit:local "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if [[ -s "$EXIT_COORD_STATE/trust-bundle.pem" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

wait_log() {
  local service="$1"
  local pattern="$2"
  local limit="$3"
  local i
  for i in $(seq 1 "$limit"); do
    if dc logs "$service" 2>/dev/null | read_all grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  echo "The ${service} log did not contain: ${pattern}" >&2
  dc logs "$service" >&2 || true
  return 1
}

tool() {
  local state="$1"
  shift
  EXIT_TOOL_STATE="$state"
  write_env
  dc --profile tool run --rm --no-deps tool "$@"
}

overlay_ip() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["self"]["overlay_ip"])' "$1"
}

merge_node() {
  local enroll="$1"
  local issued="$2"
  local dest="$3"
  local name
  as_root rm -rf "$dest"
  as_root mkdir -p "$dest"
  as_root cp -a "$enroll/." "$dest/"
  for name in cert.pem key.pem bundle.pem ticket.bin ticket.bin.mac \
    ticket-verifier.pem ticket-mac.key svid-ca.pub ticket-not-before ticket-not-after; do
    as_root cp -a "$issued/$name" "$dest/$name"
  done
  as_root chown -R "$(id -u):$(id -g)" "$dest"
}

route_uses_tun() {
  local dest="$1"
  local text
  echo "=== [C] ip route get ${dest} ==="
  text="$(dc exec -T client ip route get "$dest")"
  printf '%s\n' "$text"
  printf '%s\n' "$text" | read_all grep -q 'orblx0'
}

mkdir -p "$EXIT_COORD_STATE" "$WORK/enroll-exit" "$WORK/enroll-client" "$EXIT_NODE_STATE" "$EXIT_CLIENT_STATE"
cp "$ROOT/scripts/proof/exit.hujson" "$EXIT_POLICY"
chmod 644 "$EXIT_POLICY" "$EXIT_ECHO_PY"
write_env

echo "=== [C] bridge-nf-call-iptables ==="
if [[ -r /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
  echo "bridge-nf-call-iptables $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
else
  echo "bridge-nf-call-iptables missing"
fi

echo "=== [C] remove old proof containers ==="
dc --profile nodes --profile tool down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

echo "=== [C] policy test ==="
dc exec -T coord orblx policy test --file /var/lib/orblx/policy.hujson

echo "=== [C] token exit ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/exit --ttl 3600
echo "=== [C] token client ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --out /var/lib/orblx/tokens/client --ttl 3600

echo "=== [C] enroll exit ==="
tool "$WORK/enroll-exit" coord enroll \
  --name exit \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/exit \
  --state /var/lib/orblx \
  --endpoint "${EXIT_IP}:443"

echo "=== [C] enroll client ==="
tool "$WORK/enroll-client" coord enroll \
  --name client \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/client \
  --state /var/lib/orblx \
  --endpoint "${CLIENT_IP}:443"

echo "=== [C] netmap before exit approval ==="
tool "$WORK/enroll-client" coord netmap \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx
tool "$WORK/enroll-exit" coord netmap \
  --coord "${COORD_IP}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx
python3 - <<PY
import json
path = "$WORK/enroll-client/netmap.json"
netmap = json.load(open(path))
for peer in netmap["peers"]:
    if peer["name"] == "exit" and peer.get("exit_node"):
        raise SystemExit("The exit node is approved before it offers the role.")
print("exit_node_before_offer false")
PY

exit_overlay="$(overlay_ip "$WORK/enroll-exit/netmap.json")"
client_overlay="$(overlay_ip "$WORK/enroll-client/netmap.json")"
echo "=== [C] overlay addresses ==="
echo "exit ${exit_overlay}"
echo "client ${client_overlay}"

echo "=== [C] node material ==="
"$ROOT/target/debug/orblx" node-issue \
  --out "$WORK/nodes" \
  --node "exit=${exit_overlay}" \
  --node "client=${client_overlay}"
merge_node "$WORK/enroll-exit" "$WORK/nodes/exit" "$EXIT_NODE_STATE"
merge_node "$WORK/enroll-client" "$WORK/nodes/client" "$EXIT_CLIENT_STATE"

echo "=== [C] orblx set --exit-node exit ==="
"$ROOT/target/debug/orblx" set --exit-node exit --state-dir "$EXIT_CLIENT_STATE"

echo "=== [C] start relay and internet echo ==="
dc --profile nodes up -d relay web

echo "=== [C] client before the exit node is approved ==="
dc --profile nodes up -d client
wait_log client "The exit node exit is not approved" 40
echo "=== [C] route before approval ==="
if route_uses_tun "$WEB_IP"; then
  echo "The client sent internet traffic into the TUN before approval." >&2
  exit 1
fi
echo "=== [C] HTTP before approval ==="
set +e
before_body="$(dc exec -T client curl -sS --max-time 5 "http://${WEB_IP}/" 2>&1)"
before_code=$?
set -e
echo "curl_status ${before_code}"
printf '%s\n' "$before_body"
if [[ "$before_body" == "$EXIT_INET_IP" ]]; then
  echo "The client used the exit node before approval." >&2
  exit 1
fi

echo "=== [C] stop client ==="
dc --profile nodes stop client

echo "=== [C] start exit node ==="
dc --profile nodes up -d exit
wait_log exit "approved exit node" 40
wait_log exit "The node forwards exit traffic" 40

echo "=== [C] start client with the approved exit node ==="
dc --profile nodes start client
wait_log client "The node installs route 0.0.0.0/0 through the exit node exit." 40
wait_log client "The path to exit is direct." 40
wait_log client "The node keeps ${COORD_IP}/32 outside the tunnel." 20
wait_log client "The node keeps ${RELAY_IP}/32 outside the tunnel." 20
wait_log client "The node keeps ${EXIT_IP}/32 outside the tunnel." 20

if ! route_uses_tun "$WEB_IP"; then
  echo "Internet traffic did not enter the TUN device." >&2
  exit 1
fi
for outside in "$COORD_IP" "$RELAY_IP" "$EXIT_IP"; do
  if route_uses_tun "$outside"; then
    echo "The underlay address ${outside} entered the tunnel." >&2
    exit 1
  fi
done

echo "=== [C] HTTP through the exit node ==="
echo_body="$(dc exec -T client curl -sS --max-time 10 "http://${WEB_IP}/")"
printf '%s\n' "$echo_body"
if [[ "$echo_body" != "$EXIT_INET_IP" ]]; then
  echo "The echo server did not see the exit node address." >&2
  exit 1
fi

echo "=== [C] DNS through the exit node ==="
dc exec -T client timeout 8 python3 -c 'import socket; socket.getaddrinfo("example.com", 80)' || true
wait_log client "The node sends a DNS query for example.com through the exit node exit." 20
wait_log exit "The node received a DNS query for example.com from" 20
echo "=== [C] client DNS log ==="
dc logs client 2>/dev/null | grep 'through the exit node' || true
echo "=== [C] exit DNS log ==="
dc logs exit 2>/dev/null | grep 'received a DNS query' || true

echo "=== [C] drop client UDP except loopback ==="
dc exec -T client iptables -I OUTPUT -p udp ! -o lo -j DROP
dc exec -T client iptables -I INPUT -p udp ! -i lo -j DROP
dc exec -T client iptables -S OUTPUT
dc exec -T client iptables -S INPUT

echo "=== [C] wait for the TCP Relay ==="
wait_log client "The path to exit uses the TCP Relay." 120
echo "=== [C] client Relay log ==="
dc logs client 2>/dev/null | grep 'uses the TCP Relay' || true

echo "=== [C] HTTP stays on the exit node for 2 minutes ==="
hold_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hold_start_s="$(date +%s)"
for i in $(seq 1 9); do
  hold_body="$(dc exec -T client curl -sS --max-time 15 "http://${WEB_IP}/")"
  echo "hold ${i} $(date -u +%Y-%m-%dT%H:%M:%SZ) ${hold_body}"
  if [[ "$hold_body" != "$EXIT_INET_IP" ]]; then
    echo "The echo address changed during the TCP Relay hold." >&2
    exit 1
  fi
  if [[ "$i" -lt 9 ]]; then
    sleep 15
  fi
done
hold_end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hold_end_s="$(date +%s)"
hold_seconds="$((hold_end_s - hold_start_s))"
echo "tcp_hold_start ${hold_start}"
echo "tcp_hold_end ${hold_end}"
echo "tcp_hold_seconds ${hold_seconds}"
if [[ "$hold_seconds" -lt 120 ]]; then
  echo "The TCP Relay hold was shorter than 2 minutes." >&2
  exit 1
fi

echo "proof_ok"

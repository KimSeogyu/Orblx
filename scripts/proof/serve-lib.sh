#!/usr/bin/env bash
# Shared setup for the serve proofs (W21-4 serve-funnel.sh, W24-C serve-hardening.sh,
# and W25-4 serve-websocket.sh).
# The caller sets ROOT and sources this file. Then it calls serve_setup.
# Three node containers and one outside container on one Linux host.
# The containers stand in for other hosts. The outside network stands in for a public network.
# The functions do not print private keys, tickets, or SVID proofs.
#
# Optional environment:
#   SERVE_PROJECT  Compose project name (default orblx-serve-proof). The container names start with it.
#   SERVE_IMAGE    Image tag (default orblx-serve:local).
#   SERVE_OVL      First three octets of the overlay network (default 172.30.41).
#   SERVE_OUT      First three octets of the outside network (default 172.30.42).
#   SERVE_BIN      An orblx binary to use. Without it, the setup builds target/debug/orblx.
#   ORBLX_NET_HOOK A root script that the setup runs after the networks start.
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

FILE="scripts/proof/compose.serve.yml"
SERVE_PROJECT="${SERVE_PROJECT:-orblx-serve-proof}"
SERVE_IMAGE="${SERVE_IMAGE:-orblx-serve:local}"
SERVE_OVL="${SERVE_OVL:-172.30.41}"
SERVE_OUT="${SERVE_OUT:-172.30.42}"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/serve.env"
A_OVERLAY=100.64.0.1
B_OVERLAY=100.64.0.2
C_OVERLAY=100.64.0.3
B_OUTSIDE="${SERVE_OUT}.12"
OUTSIDE_IP="${SERVE_OUT}.20"
FUNNEL_PORT=8443
B_URI="spiffe://orblx.local/node/b"
GET=/opt/orblx-proof/serve-get.py
POST=/opt/orblx-proof/serve-post.py
APP=/opt/orblx-proof/serve-app.py
APP_LOG=/tmp/serve-app.log
WS=/opt/orblx-proof/serve-ws.py
WS_APP=/opt/orblx-proof/serve-ws-app.py
WS_APP_LOG=/tmp/serve-ws-app.log
ORBLX=""

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$SERVE_PROJECT" --env-file "$ENV_FILE" --progress quiet -f "$FILE" "$@"
}

serve_cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    dc logs || true
  fi
  dc down --remove-orphans >/dev/null 2>&1 || true
  as_root rm -rf "$WORK"
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

write_netmap() {
  local path=$1 name=$2 ip=$3
  local p1=$4 p1_ip=$5 p1_under=$6 p2=$7 p2_ip=$8 p2_under=$9
  cat >"$path" <<NETMAP
{
  "version": 1,
  "self": {"name": "${name}", "overlay_ip": "${ip}"},
  "peers": [
    {"name": "${p1}", "overlay_ip": "${p1_ip}", "svid": "spiffe://orblx.local/node/${p1}",
     "endpoints": ["${p1_under}:443"], "routes": ["${p1_ip}/32"]},
    {"name": "${p2}", "overlay_ip": "${p2_ip}", "svid": "spiffe://orblx.local/node/${p2}",
     "endpoints": ["${p2_under}:443"], "routes": ["${p2_ip}/32"]}
  ]
}
NETMAP
}

wait_direct() {
  local node=$1 peer=$2 attempt
  for attempt in $(seq 1 40); do
    if dc exec -T "$node" orblx status 2>/dev/null | read_all grep -q "peer ${peer} overlay_ip .* path direct "; then
      return 0
    fi
    sleep 1
  done
  echo "The node ${node} did not reach ${peer}." >&2
  return 1
}

# wait_log NODE PATTERN: wait until the node log has a line that matches PATTERN.
wait_log() {
  local node=$1 pattern=$2 attempt
  for attempt in $(seq 1 40); do
    if dc logs "$node" 2>/dev/null | read_all grep -Eq -- "$pattern"; then
      return 0
    fi
    sleep 0.5
  done
  echo "The node ${node} has no log line ${pattern}." >&2
  return 1
}

# log_count NODE PATTERN: print the number of node log lines that match PATTERN.
log_count() {
  dc logs --no-log-prefix "$1" 2>/dev/null | grep -Ec -- "$2" || true
}

bundle_for() {
  if [[ "$1" == "outside" ]]; then
    echo /etc/orblx-outside/bundle.pem
  else
    echo /var/lib/orblx/bundle.pem
  fi
}

# get FROM HOST PORT: one HTTPS GET. The function prints the result line and returns the client status.
get() {
  local from=$1 host=$2 port=$3
  dc exec -T "$from" python3 "$GET" "$host" "$port" "$(bundle_for "$from")" "$B_URI"
}

# post FROM HOST PORT MODE SIZE: one HTTPS POST with a SIZE-byte body.
# MODE is chunked or length. The function prints the result line.
post() {
  local from=$1 host=$2 port=$3 mode=$4 size=$5
  dc exec -T "$from" python3 "$POST" "$host" "$port" "$(bundle_for "$from")" "$B_URI" "$mode" "$size"
}

expect_get() {
  local out
  out="$(get "$@")"
  printf '%s\n' "$out"
  echo "$out" | read_all grep -q ' status HTTP/1.0 200 '
  echo "$out" | read_all grep -q 'body hello from orblx serve on node b'
}

expect_fail() {
  local label=$1 out
  shift
  if out="$(get "$@")"; then
    printf '%s\n' "$out"
    echo "The GET ${label} worked. It must fail." >&2
    return 1
  fi
  printf '%s\n' "$out"
  echo "blocked ${label}"
}

# serve_setup APP_KIND: build the image, issue SVIDs, start the containers,
# and start the local web app on node b at 127.0.0.1:8080.
# APP_KIND is http.server (W21-4) or serve-app (W24-C, accepts POST).
serve_setup() {
  local app_kind=$1 attempt image_dir
  echo "=== [REAL] one Linux host ==="
  uname -s
  uname -m

  echo "=== [C] build image ${SERVE_IMAGE} (project ${SERVE_PROJECT}) ==="
  if [[ -n "${SERVE_BIN:-}" ]]; then
    ORBLX="$SERVE_BIN"
  else
    cargo build -p orblx-cli --bin orblx
    ORBLX="$ROOT/target/debug/orblx"
  fi
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$ORBLX")"
  as_root docker build -q -t "$SERVE_IMAGE" "$image_dir"
  rm -rf "$image_dir"

  echo "=== [C] issue SVIDs ==="
  "$ORBLX" node-issue \
    --out "$WORK" \
    --node a="$A_OVERLAY" \
    --node b="$B_OVERLAY" \
    --node c="$C_OVERLAY" >/dev/null
  echo "issued a b c"

  echo "=== [C] policy tests ==="
  "$ORBLX" policy test --file "$ROOT/scripts/proof/serve.hujson"
  for name in a b c; do
    cp "$ROOT/scripts/proof/serve.hujson" "$WORK/$name/policy.hujson"
  done
  cp "$WORK/b/bundle.pem" "$WORK/outside-bundle.pem"
  mkdir -p "$WORK/tools"
  cp "$ROOT/scripts/proof/serve-get.py" "$ROOT/scripts/proof/serve-post.py" \
    "$ROOT/scripts/proof/serve-app.py" "$ROOT/scripts/proof/serve-ws.py" \
    "$ROOT/scripts/proof/serve-ws-app.py" "$WORK/tools/"

  write_netmap "$WORK/netmap-a.json" a "$A_OVERLAY" b "$B_OVERLAY" "${SERVE_OVL}.12" c "$C_OVERLAY" "${SERVE_OVL}.13"
  write_netmap "$WORK/netmap-b.json" b "$B_OVERLAY" a "$A_OVERLAY" "${SERVE_OVL}.11" c "$C_OVERLAY" "${SERVE_OVL}.13"
  write_netmap "$WORK/netmap-c.json" c "$C_OVERLAY" a "$A_OVERLAY" "${SERVE_OVL}.11" b "$B_OVERLAY" "${SERVE_OVL}.12"

  cat >"$ENV_FILE" <<ENV
SERVE_STATE_A=$WORK/a
SERVE_STATE_B=$WORK/b
SERVE_STATE_C=$WORK/c
SERVE_NETMAP_A=$WORK/netmap-a.json
SERVE_NETMAP_B=$WORK/netmap-b.json
SERVE_NETMAP_C=$WORK/netmap-c.json
SERVE_BUNDLE=$WORK/outside-bundle.pem
SERVE_TOOLS=$WORK/tools
SERVE_IMAGE=$SERVE_IMAGE
SERVE_OVL=$SERVE_OVL
SERVE_OUT=$SERVE_OUT
ENV

  open_legacy_forward
  echo "=== [C] start nodes and the outside host ==="
  dc up -d --remove-orphans
  if [[ -n "${ORBLX_NET_HOOK:-}" ]]; then
    # The box can need an egress fix for each new bridge. The hook does not change the proof steps.
    as_root "$ORBLX_NET_HOOK" >/dev/null 2>&1 || true
  fi
  wait_direct node-a b
  wait_direct node-c b
  wait_direct node-b a
  wait_direct node-b c

  echo "=== [C] local web app on node b at 127.0.0.1:8080 (${app_kind}) ==="
  dc exec -T node-b sh -c 'mkdir -p /srv/www && printf "hello from orblx serve on node b\n" >/srv/www/index.html'
  if [[ "$app_kind" == "serve-app" ]]; then
    dc exec -d -T node-b python3 "$APP" 8080 /srv/www/index.html "$APP_LOG"
  else
    dc exec -d -T node-b python3 -m http.server 8080 --bind 127.0.0.1 --directory /srv/www
  fi
  for attempt in $(seq 1 20); do
    if dc exec -T node-b curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  dc exec -T node-b curl -fsS http://127.0.0.1:8080/
}

#!/usr/bin/env bash
# serve and funnel proof (W21-4) for three node containers and one outside container on one Linux host.
# The containers stand in for other hosts. The outside network stands in for a public network.
# The script does not print private keys, tickets, or SVID proofs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.serve.yml"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/serve.env"
B_OVERLAY=100.64.0.2
B_OUTSIDE=172.30.42.12
FUNNEL_PORT=8443
B_URI="spiffe://orblx.local/node/b"
GET=/opt/orblx-proof/serve-get.py

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose --env-file "$ENV_FILE" --progress quiet -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs ----"
    dc logs || true
  fi
  dc down --remove-orphans >/dev/null 2>&1 || true
  as_root rm -rf "$WORK"
}
trap cleanup EXIT

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

write_netmap() {
  local path=$1 name=$2 ip=$3
  local p1=$4 p1_ip=$5 p1_under=$6 p2=$7 p2_ip=$8 p2_under=$9
  cat >"$path" <<EOF
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
EOF
}

wait_direct() {
  local node=$1 peer=$2 attempt
  for attempt in $(seq 1 40); do
    if dc exec -T "$node" orblx status 2>/dev/null | grep -q "peer ${peer} overlay_ip .* path direct "; then
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
    if dc logs "$node" 2>/dev/null | grep -Eq -- "$pattern"; then
      return 0
    fi
    sleep 0.5
  done
  echo "The node ${node} has no log line ${pattern}." >&2
  return 1
}

# get FROM HOST PORT: one HTTPS GET. The function prints the result line and returns the client status.
get() {
  local from=$1 host=$2 port=$3 bundle=/var/lib/orblx/bundle.pem
  if [[ "$from" == "outside" ]]; then
    bundle=/etc/orblx-outside/bundle.pem
  fi
  dc exec -T "$from" python3 "$GET" "$host" "$port" "$bundle" "$B_URI"
}

expect_get() {
  local out
  out="$(get "$@")"
  printf '%s\n' "$out"
  echo "$out" | grep -q ' status HTTP/1.0 200 '
  echo "$out" | grep -q 'body hello from orblx serve on node b'
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

echo "=== [REAL] one Linux host ==="
uname -s
uname -m

echo "=== [C] build image ==="
cargo build -p orblx-cli --bin orblx
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
IMAGE_DIR="$(stage_proof_image "$ROOT" "$ROOT/target/debug/orblx")"
as_root docker build -q -t orblx-serve:local "$IMAGE_DIR"
rm -rf "$IMAGE_DIR"

echo "=== [C] issue SVIDs ==="
"$ROOT/target/debug/orblx" node-issue \
  --out "$WORK" \
  --node a=100.64.0.1 \
  --node b=100.64.0.2 \
  --node c=100.64.0.3 >/dev/null
echo "issued a b c"

echo "=== [C] policy tests ==="
"$ROOT/target/debug/orblx" policy test --file "$ROOT/scripts/proof/serve.hujson"
for name in a b c; do
  cp "$ROOT/scripts/proof/serve.hujson" "$WORK/$name/policy.hujson"
done
cp "$WORK/b/bundle.pem" "$WORK/outside-bundle.pem"
mkdir -p "$WORK/tools"
cp "$ROOT/scripts/proof/serve-get.py" "$WORK/tools/serve-get.py"

write_netmap "$WORK/netmap-a.json" a 100.64.0.1 b 100.64.0.2 172.30.41.12 c 100.64.0.3 172.30.41.13
write_netmap "$WORK/netmap-b.json" b 100.64.0.2 a 100.64.0.1 172.30.41.11 c 100.64.0.3 172.30.41.13
write_netmap "$WORK/netmap-c.json" c 100.64.0.3 a 100.64.0.1 172.30.41.11 b 100.64.0.2 172.30.41.12

cat >"$ENV_FILE" <<EOF
SERVE_STATE_A=$WORK/a
SERVE_STATE_B=$WORK/b
SERVE_STATE_C=$WORK/c
SERVE_NETMAP_A=$WORK/netmap-a.json
SERVE_NETMAP_B=$WORK/netmap-b.json
SERVE_NETMAP_C=$WORK/netmap-c.json
SERVE_BUNDLE=$WORK/outside-bundle.pem
SERVE_TOOLS=$WORK/tools
EOF

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

echo "=== [C] local web app on node b at 127.0.0.1:8080 ==="
dc exec -T node-b sh -c 'mkdir -p /srv/www && printf "hello from orblx serve on node b\n" >/srv/www/index.html'
dc exec -d -T node-b python3 -m http.server 8080 --bind 127.0.0.1 --directory /srv/www
for attempt in $(seq 1 20); do
  if dc exec -T node-b curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
dc exec -T node-b curl -fsS http://127.0.0.1:8080/

echo "=== [C] before serve: no HTTPS listener on the overlay ==="
expect_fail before_serve node-a "$B_OVERLAY" 443

echo "=== [C] orblx serve 8080 on node b ==="
dc exec -T node-b orblx serve 8080 --state-dir /var/lib/orblx
wait_log node-b "serve_listen ${B_OVERLAY}:443 "
dc exec -T node-b orblx serve status --state-dir /var/lib/orblx
dc exec -T node-b orblx funnel status --state-dir /var/lib/orblx | tee "$WORK/funnel-default.txt"
grep -q '^funnel off' "$WORK/funnel-default.txt"

echo "=== [C] node a is allowed by the ACL ==="
expect_get node-a "$B_OVERLAY" 443
wait_log node-b "serve_allow spiffe://orblx.local/node/a from 100.64.0.1"

echo "=== [C] node c is denied by the ACL ==="
expect_fail node_c node-c "$B_OVERLAY" 443
wait_log node-b "serve_deny spiffe://orblx.local/node/c from 100.64.0.3"

echo "=== [C] funnel is off by default: the outside host cannot connect ==="
expect_fail funnel_default outside "$B_OUTSIDE" "$FUNNEL_PORT"
echo "=== [C] the outside host sends to the overlay address through node b: the ACL denies an unknown source ==="
dc exec -T outside ip route replace 100.64.0.0/10 via "$B_OUTSIDE"
expect_fail outside_to_overlay outside "$B_OVERLAY" 443
wait_log node-b "serve_deny unknown-source from 172.30.42.20"

echo "=== [C] orblx funnel on ==="
dc exec -T node-b orblx funnel on --listen "${B_OUTSIDE}:${FUNNEL_PORT}" --state-dir /var/lib/orblx
wait_log node-b "funnel_listen ${B_OUTSIDE}:${FUNNEL_PORT}"
expect_get outside "$B_OUTSIDE" "$FUNNEL_PORT"
wait_log node-b "funnel_accept from 172.30.42.20"
echo "=== [C] the ACL still blocks node c on the overlay ==="
expect_fail node_c_funnel_on node-c "$B_OVERLAY" 443

echo "=== [C] orblx funnel off ==="
dc exec -T node-b orblx funnel off --state-dir /var/lib/orblx
wait_log node-b "funnel_closed ${B_OUTSIDE}:${FUNNEL_PORT}"
expect_fail funnel_off outside "$B_OUTSIDE" "$FUNNEL_PORT"
echo "=== [C] serve stays on for node a ==="
expect_get node-a "$B_OVERLAY" 443

echo "=== [C] serve and funnel lines in the node b log ==="
dc logs --no-log-prefix node-b 2>/dev/null | grep -E '^(serve|funnel)_' || true

echo "=== [C] audit chain on node b ==="
audit="$(dc exec -T node-b orblx audit verify-config --file /var/lib/orblx/serve-audit.jsonl)"
printf '%s\n' "$audit"
echo "$audit" | grep -qx 'ok'
echo "$audit" | grep -qx 'serve 1'
echo "$audit" | grep -qx 'funnel-on 1'
echo "$audit" | grep -qx 'funnel-off 1'
echo "$audit" | grep -qx 'records 3'

echo "=== [C] a changed record breaks the chain ==="
as_root cp "$WORK/b/serve-audit.jsonl" "$WORK/tampered.jsonl"
as_root sed -i '2s/funnel-on/funnel-off/' "$WORK/tampered.jsonl"
if "$ROOT/target/debug/orblx" audit verify-config --file "$WORK/tampered.jsonl" >/dev/null 2>&1; then
  echo "The changed chain passed verify." >&2
  exit 1
fi
echo "tampered_chain rejected"

echo "=== [C] no key material in the node logs ==="
if dc logs 2>/dev/null | grep -Eq 'PRIVATE KEY|BEGIN CERTIFICATE'; then
  echo "A node log has PEM data." >&2
  exit 1
fi
echo "logs clean"

echo "proof_ok"

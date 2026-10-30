#!/usr/bin/env bash
# W25-4 serve WebSocket proof: a WebSocket echo through serve, and the W24-C ingress checks for upgrades.
# Three node containers and one outside container on one Linux host. serve-lib.sh has the setup.
# The containers stand in for other hosts. The outside network stands in for a public network.
# The script does not print private keys, tickets, SVID proofs, or WebSocket keys.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"/pipe-lib.sh

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=serve-lib.sh
source "$ROOT/scripts/proof/serve-lib.sh"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'serve_cleanup; proof_lock_end' EXIT
proof_lock_take "serve-websocket" "${SERVE_PROJECT:-orblx-serve-proof}"

WS_PORT=8090
COUNT="${ORBLX_WS_COUNT:-100}"
KEYS=/tmp/serve-ws-keys.txt
A_ALLOW="serve_allow spiffe://orblx.local/node/a from ${A_OVERLAY}"

# ws FROM ARGS...: run the WebSocket client in a container. It prints one result line.
ws() {
  local from=$1
  shift
  dc exec -T "$from" python3 "$WS" "$B_OVERLAY" 443 "$(bundle_for "$from")" "$B_URI" "$@"
}

# expect_ws_fail LABEL FROM: the WebSocket open must fail before the upgrade.
expect_ws_fail() {
  local label=$1 from=$2 out
  if out="$(ws "$from" echo 1 "$KEYS")"; then
    printf '%s\n' "$out"
    echo "The WebSocket ${label} worked. It must fail." >&2
    return 1
  fi
  printf '%s\n' "$out"
  if ! grep -Eq ' (tcp_failed|tls_failed) ' <<<"$out"; then
    echo "The WebSocket ${label} did not fail at TCP or TLS." >&2
    return 1
  fi
  echo "blocked ${label}"
}

# expect_upgrade_501 VALUE: an upgrade to VALUE from node a gets 501.
expect_upgrade_501() {
  local out
  out="$(ws node-a upgrade "$1")"
  printf '%s\n' "$out"
  if ! grep -q ' status HTTP/1.1 501 ' <<<"$out"; then
    echo "The upgrade to $1 did not get 501." >&2
    return 1
  fi
}

serve_setup serve-app

echo "=== [C] WebSocket echo app on node b at 127.0.0.1:${WS_PORT} ==="
dc exec -d -T node-b python3 "$WS_APP" "$WS_PORT" "$WS_APP_LOG"
for attempt in $(seq 1 20); do
  if dc exec -T node-b curl -fsS "http://127.0.0.1:${WS_PORT}/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
dc exec -T node-b curl -fsS "http://127.0.0.1:${WS_PORT}/"

echo "=== [C] orblx serve ${WS_PORT} on node b ==="
dc exec -T node-b orblx serve "$WS_PORT" --state-dir /var/lib/orblx
wait_log node-b "serve_listen ${B_OVERLAY}:443 target 127.0.0.1:${WS_PORT}"
dc exec -T node-b orblx serve status --state-dir /var/lib/orblx

echo "=== [C] funnel is off by default, and serve has one listener ==="
funnel="$(dc exec -T node-b orblx funnel status --state-dir /var/lib/orblx)"
printf '%s\n' "$funnel"
grep -qx 'funnel off' <<<"$funnel"
if dc exec -T node-b grep -q '"funnel": true' /var/lib/orblx/serve.json; then
  echo "serve.json has funnel on." >&2
  exit 1
fi
if [[ "$(log_count node-b '^funnel_listen')" -ne 0 ]]; then
  echo "The funnel listener is open." >&2
  exit 1
fi
expect_fail funnel_default outside "$B_OUTSIDE" "$FUNNEL_PORT"
listeners="$(dc exec -T node-b ss -Htln)"
printf '%s\n' "$listeners"
# Port 22 is orblx ssh. The app ports are on 127.0.0.1. The serve and funnel ports are 443 and ${FUNNEL_PORT}.
serve_listeners="$(awk '$4 ~ /:443$/ { n++ } END { print n + 0 }' <<<"$listeners")"
funnel_listeners="$(awk -v port=":${FUNNEL_PORT}" 'substr($4, length($4) - length(port) + 1) == port { n++ } END { print n + 0 }' <<<"$listeners")"
if [[ "$serve_listeners" -ne 1 || "$funnel_listeners" -ne 0 ]]; then
  echo "node b has ${serve_listeners} TCP 443 and ${funnel_listeners} TCP ${FUNNEL_PORT} listeners. It must have 1 and 0." >&2
  exit 1
fi
echo "funnel_default off tcp_443_listeners ${serve_listeners} tcp_${FUNNEL_PORT}_listeners ${funnel_listeners}"

echo "=== [C] gate 1: WebSocket echo from node a over TUN, ${COUNT} messages ==="
echo_out="$(ws node-a echo "$COUNT" "$KEYS")"
printf '%s\n' "$echo_out"
grep -q " status HTTP/1.1 101 Switching Protocols accept_ok yes sent ${COUNT} received ${COUNT} lost 0 " <<<"$echo_out"
grep -q ' close yes ' <<<"$echo_out"
wait_log node-b "serve_ws_open from ${A_OVERLAY}\$"
wait_log node-b "serve_ws_closed from ${A_OVERLAY} up [0-9]+ down [0-9]+\$"
wait_log node-b "$A_ALLOW"
app_line="$(dc exec -T node-b cat "$WS_APP_LOG")"
printf '%s\n' "$app_line"
grep -Eq "^ws_app messages ${COUNT} bytes [0-9]+ unmasked 0 xff ${A_OVERLAY}\$" <<<"$app_line"
sent_bytes="$(sed -E 's/.* bytes ([0-9]+) .*/\1/' <<<"$echo_out")"
grep -Eq "^ws_app messages ${COUNT} bytes ${sent_bytes} " <<<"$app_line"
echo "ws_echo_ok messages ${COUNT} lost 0 bytes ${sent_bytes}"

echo "=== [C] gate 4: an upgrade that is not WebSocket gets 501 ==="
refused_before="$(log_count node-b "^serve_upgrade_refused from ${A_OVERLAY}\$")"
expect_upgrade_501 h2c
expect_upgrade_501 "websocket, h2c"
wait_log node-b "serve_upgrade_refused from ${A_OVERLAY}\$"
refused_after="$(log_count node-b "^serve_upgrade_refused from ${A_OVERLAY}\$")"
if [[ "$((refused_after - refused_before))" -ne 2 ]]; then
  echo "serve_upgrade_refused lines ${refused_before} -> ${refused_after}. It must be +2." >&2
  exit 1
fi
app_lines="$(dc exec -T node-b grep -c '^ws_app ' "$WS_APP_LOG" || true)"
if [[ "$app_lines" -ne 1 ]]; then
  echo "A refused upgrade reached the app (app lines ${app_lines})." >&2
  exit 1
fi
echo "upgrade_501 h2c websocket,h2c app_lines ${app_lines}"

echo "=== [C] gate 2: forged source upgrade: the outside host uses source ${A_OVERLAY} (node a) ==="
dc exec -T outside ip addr add "${A_OVERLAY}/32" dev eth0
dc exec -T outside ip route replace 100.64.0.0/10 via "$B_OUTSIDE" src "$A_OVERLAY"
tun_route="$(dc exec -T node-b ip route show "${A_OVERLAY}/32")"
tun_route="${tun_route%%$'\n'*}"
echo "node b route before: ${tun_route}"
dc exec -T node-b ip route replace "${A_OVERLAY}/32" via "$OUTSIDE_IP"
allow_before="$(log_count node-b "^${A_ALLOW}\$")"
open_before="$(log_count node-b '^serve_ws_open ')"
tls_before="$(log_count node-b '^serve_tls_failed ')"
expect_ws_fail forged_upgrade outside
wait_log node-b "serve_deny forged-source from ${A_OVERLAY}"
allow_after="$(log_count node-b "^${A_ALLOW}\$")"
open_after="$(log_count node-b '^serve_ws_open ')"
tls_after="$(log_count node-b '^serve_tls_failed ')"
if [[ "$allow_after" -ne "$allow_before" || "$open_after" -ne "$open_before" || "$tls_after" -ne "$tls_before" ]]; then
  echo "The forged upgrade got past the ingress check." >&2
  exit 1
fi
echo "forged_upgrade serve_deny before_tls allow ${allow_before} -> ${allow_after} ws_open ${open_before} -> ${open_after} tls_failed ${tls_before} -> ${tls_after}"
# shellcheck disable=SC2086 # The route words must split.
dc exec -T node-b ip route replace ${tun_route}
dc exec -T outside ip route del 100.64.0.0/10
dc exec -T outside ip addr del "${A_OVERLAY}/32" dev eth0

echo "=== [C] gate 3: an upgrade from node c (ACL deny) is refused ==="
open_before="$(log_count node-b '^serve_ws_open ')"
expect_ws_fail acl_upgrade node-c
wait_log node-b "serve_deny spiffe://orblx.local/node/c from ${C_OVERLAY}"
open_after="$(log_count node-b '^serve_ws_open ')"
if [[ "$open_after" -ne "$open_before" ]]; then
  echo "The node c upgrade opened a WebSocket." >&2
  exit 1
fi
echo "acl_upgrade serve_deny ws_open ${open_before} -> ${open_after}"

echo "=== [C] node a WebSocket still works after the checks ==="
again="$(ws node-a echo 10 "$KEYS")"
printf '%s\n' "$again"
grep -q ' sent 10 received 10 lost 0 ' <<<"$again"

echo "=== [C] serve and funnel lines in the node b log ==="
dc logs --no-log-prefix node-b 2>/dev/null | grep -E '^(serve|funnel)_' || true

echo "=== [C] gate 6: no keys in the logs ==="
logs="$(dc logs 2>/dev/null)"
logs+=$'\n'"$(dc exec -T node-b cat "$WS_APP_LOG")"
if grep -Eq 'PRIVATE KEY|BEGIN CERTIFICATE' <<<"$logs"; then
  echo "A log has PEM data." >&2
  exit 1
fi
keys="$(dc exec -T node-a cat "$KEYS")"
key_count=0
while IFS= read -r key; do
  [[ -n "$key" ]] || continue
  key_count=$((key_count + 1))
  if grep -qF -- "$key" <<<"$logs"; then
    echo "A log has a Sec-WebSocket-Key." >&2
    exit 1
  fi
done <<<"$keys"
if grep -q '/chat' <<<"$logs"; then
  echo "A log has the WebSocket path." >&2
  exit 1
fi
echo "logs clean pem 0 ws_keys_checked ${key_count} ws_keys_found 0"

echo "proof_ok"

#!/usr/bin/env bash
# W24-C serve hardening proof: a forged peer address, chunked bodies, the body limit, and funnel off.
# Three node containers and one outside container on one Linux host. serve-lib.sh has the setup.
# The containers stand in for other hosts. The outside network stands in for a public network.
# The script does not print private keys, tickets, or SVID proofs.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=serve-lib.sh
source "$ROOT/scripts/proof/serve-lib.sh"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'serve_cleanup; proof_lock_end' EXIT
proof_lock_take "serve-hardening" "${SERVE_PROJECT:-orblx-serve-proof}"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${SERVE_PROJECT:-orblx-serve-proof}" || exit 1

LIMIT=10485760
A_ALLOW="serve_allow spiffe://orblx.local/node/a from ${A_OVERLAY}"

# expect_post LABEL WANT_STATUS FROM HOST PORT MODE SIZE: one POST. The status must match.
expect_post() {
  local label=$1 want=$2 out
  shift 2
  out="$(post "$@")"
  printf '%s\n' "$out"
  if ! echo "$out" | read_all grep -q " status HTTP/1.1 ${want} "; then
    echo "The POST ${label} did not get ${want}." >&2
    return 1
  fi
  printf '%s\n' "$out" >"$WORK/last-post.txt"
}

# The app body sum must equal the sum that the client sent, with Content-Length and no Transfer-Encoding.
check_app_line() {
  local size=$1 line sent
  line="$(cat "$WORK/last-post.txt")"
  sent="$(echo "$line" | sed -E 's/.* sent_sum ([0-9]+) .*/\1/')"
  echo "$line" | read_all grep -q "app got ${size} te none cl ${size} sum ${sent}\$"
  echo "app_body_ok size ${size} sum ${sent}"
}

serve_setup serve-app

echo "=== [C] orblx serve 8080 on node b (default body limit) ==="
dc exec -T node-b orblx serve 8080 --state-dir /var/lib/orblx
wait_log node-b "serve_listen ${B_OVERLAY}:443 target 127.0.0.1:8080"
dc exec -T node-b orblx serve status --state-dir /var/lib/orblx

echo "=== [C] funnel is off by default ==="
dc exec -T node-b orblx funnel status --state-dir /var/lib/orblx | tee "$WORK/funnel-default.txt"
grep -qx 'funnel off' "$WORK/funnel-default.txt"
if dc exec -T node-b grep -q '"funnel": true' /var/lib/orblx/serve.json; then
  echo "serve.json has funnel on." >&2
  exit 1
fi
expect_fail funnel_default outside "$B_OUTSIDE" "$FUNNEL_PORT"
if [[ "$(log_count node-b '^funnel_listen')" -ne 0 ]]; then
  echo "The funnel listener is open." >&2
  exit 1
fi
echo "funnel_default off"

echo "=== [C] node a over TUN is allowed ==="
expect_get node-a "$B_OVERLAY" 443
wait_log node-b "$A_ALLOW"

echo "=== [C] forged peer address: the outside host uses source ${A_OVERLAY} (node a) ==="
# The outside host sends from the node a overlay address on the underlay.
# node b gets a host route back to the outside host, so the TCP handshake can finish.
# This is the worst case: the forger also gets the replies. Only the TUN ingress check stops it.
dc exec -T outside ip addr add "${A_OVERLAY}/32" dev eth0
dc exec -T outside ip route replace 100.64.0.0/10 via "$B_OUTSIDE" src "$A_OVERLAY"
tun_route="$(dc exec -T node-b ip route show "${A_OVERLAY}/32" | read_all head -n 1)"
echo "node b route before: ${tun_route}"
dc exec -T node-b ip route replace "${A_OVERLAY}/32" via "$OUTSIDE_IP"
dc exec -T node-b ip route show "${A_OVERLAY}/32"
allow_before="$(log_count node-b "^${A_ALLOW}\$")"
expect_fail forged_peer outside "$B_OVERLAY" 443
wait_log node-b "serve_deny forged-source from ${A_OVERLAY}"
allow_after="$(log_count node-b "^${A_ALLOW}\$")"
if [[ "$allow_after" -ne "$allow_before" ]]; then
  echo "The forged source got serve_allow." >&2
  exit 1
fi
echo "forged_peer rejected allow_lines ${allow_before} -> ${allow_after}"
# shellcheck disable=SC2086 # The route words must split.
dc exec -T node-b ip route replace ${tun_route}
dc exec -T node-b ip route show "${A_OVERLAY}/32"
dc exec -T outside ip route del 100.64.0.0/10
dc exec -T outside ip addr del "${A_OVERLAY}/32" dev eth0

echo "=== [C] node a over TUN is still allowed ==="
expect_get node-a "$B_OVERLAY" 443

echo "=== [C] the serve listener has the default body limit ==="
wait_log node-b "serve_listen ${B_OVERLAY}:443 target 127.0.0.1:8080 max_body ${LIMIT}\$"

echo "=== [C] chunked body, 1 MiB ==="
expect_post chunked_1m 200 node-a "$B_OVERLAY" 443 chunked 1048576
check_app_line 1048576

echo "=== [C] chunked body at the limit (${LIMIT} bytes) ==="
expect_post chunked_limit 200 node-a "$B_OVERLAY" 443 chunked "$LIMIT"
check_app_line "$LIMIT"

echo "=== [C] chunked body one byte above the limit ==="
expect_post chunked_over 413 node-a "$B_OVERLAY" 443 chunked "$((LIMIT + 1))"
wait_log node-b "serve_too_large from ${A_OVERLAY} limit ${LIMIT}"

echo "=== [C] Content-Length above the limit with Expect: 100-continue ==="
expect_post length_over 413 node-a "$B_OVERLAY" 443 length "$((LIMIT + 1))"
grep -q ' continue no ' "$WORK/last-post.txt"
echo "length_over no_100_continue"

echo "=== [C] Content-Length body ==="
expect_post length_small 200 node-a "$B_OVERLAY" 443 length 4096
grep -q ' continue yes ' "$WORK/last-post.txt"
check_app_line 4096

echo "=== [C] the app saw no body above the limit ==="
dc exec -T node-b cat "$APP_LOG" | tee "$WORK/app.log"
if grep -Eq "app got ([0-9]+)" "$WORK/app.log" && \
  awk -v limit="$LIMIT" '$1 == "app" && $2 == "got" && $3 > limit { bad = 1 } END { exit bad ? 0 : 1 }' "$WORK/app.log"; then
  echo "The app got a body above the limit." >&2
  exit 1
fi
echo "app_no_oversize ok"

echo "=== [C] node c is still denied by the ACL ==="
expect_fail node_c node-c "$B_OVERLAY" 443
wait_log node-b "serve_deny spiffe://orblx.local/node/c from ${C_OVERLAY}"

echo "=== [C] serve and funnel lines in the node b log ==="
dc logs --no-log-prefix node-b 2>/dev/null | grep -E '^(serve|funnel)_' || true

echo "=== [C] no key material in the node logs ==="
if dc logs 2>/dev/null | read_all grep -Eq 'PRIVATE KEY|BEGIN CERTIFICATE'; then
  echo "A node log has PEM data." >&2
  exit 1
fi
echo "logs clean"

echo "proof_ok"

#!/usr/bin/env bash
# serve and funnel proof (W21-4) for three node containers and one outside container on one Linux host.
# The containers stand in for other hosts. The outside network stands in for a public network.
# serve-lib.sh has the setup and the optional SERVE_* environment values.
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
proof_lock_take "serve-funnel" "${SERVE_PROJECT:-orblx-serve-proof}"

serve_setup http.server

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
wait_log node-b "serve_allow spiffe://orblx.local/node/a from ${A_OVERLAY}"

echo "=== [C] node c is denied by the ACL ==="
expect_fail node_c node-c "$B_OVERLAY" 443
wait_log node-b "serve_deny spiffe://orblx.local/node/c from ${C_OVERLAY}"

echo "=== [C] funnel is off by default: the outside host cannot connect ==="
expect_fail funnel_default outside "$B_OUTSIDE" "$FUNNEL_PORT"
echo "=== [C] the outside host sends to the overlay address through node b: the ACL denies an unknown source ==="
dc exec -T outside ip route replace 100.64.0.0/10 via "$B_OUTSIDE"
expect_fail outside_to_overlay outside "$B_OVERLAY" 443
wait_log node-b "serve_deny unknown-source from ${OUTSIDE_IP}"

echo "=== [C] orblx funnel on ==="
dc exec -T node-b orblx funnel on --listen "${B_OUTSIDE}:${FUNNEL_PORT}" --state-dir /var/lib/orblx
wait_log node-b "funnel_listen ${B_OUTSIDE}:${FUNNEL_PORT}"
expect_get outside "$B_OUTSIDE" "$FUNNEL_PORT"
wait_log node-b "funnel_accept from ${OUTSIDE_IP}"
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
echo "$audit" | read_all grep -qx 'ok'
echo "$audit" | read_all grep -qx 'serve 1'
echo "$audit" | read_all grep -qx 'funnel-on 1'
echo "$audit" | read_all grep -qx 'funnel-off 1'
echo "$audit" | read_all grep -qx 'records 3'

echo "=== [C] a changed record breaks the chain ==="
as_root cp "$WORK/b/serve-audit.jsonl" "$WORK/tampered.jsonl"
as_root sed -i '2s/funnel-on/funnel-off/' "$WORK/tampered.jsonl"
if "$ORBLX" audit verify-config --file "$WORK/tampered.jsonl" >/dev/null 2>&1; then
  echo "The changed chain passed verify." >&2
  exit 1
fi
echo "tampered_chain rejected"

echo "=== [C] no key material in the node logs ==="
if dc logs 2>/dev/null | read_all grep -Eq 'PRIVATE KEY|BEGIN CERTIFICATE'; then
  echo "A node log has PEM data." >&2
  exit 1
fi
echo "logs clean"

echo "proof_ok"

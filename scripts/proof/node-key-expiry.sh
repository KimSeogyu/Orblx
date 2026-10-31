#!/usr/bin/env bash
# W25-20: node key expiry proof (rc.3 row 28).
# A node that cannot renew keeps its leaf until the leaf expires.
# Peers refuse the node at most MAX_SKEW after the expiry, on a new handshake
# and on an existing session (ticket check per frame). Node a keeps a session; node a2
# (no daemon) makes one-shot new handshakes.
# The coordinator refuses the lapsed leaf. A revoked node cannot renew.
# admin expire writes 1 audit record. A new enroll restores access.
# The coordinator refuses a node SVID life above MAX_USER_TTL and an agent
# grant life above MAX_AGENT_TTL.
# The proof reads MAX_SKEW, MAX_USER_TTL, and MAX_AGENT_TTL from clock.rs.
# The proof waits for clock points (expiry + 30 s, expiry + MAX_SKEW + 2 s).
# It does not retry a check. A failed check stops the proof.
# The script does not print tokens, keys, or bundles.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
require_root "$@"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.node-key-expiry.yml"
CLOCK="crates/orblx-identity/src/clock.rs"
export NKE_PROJECT="${NKE_PROJECT:-orblx-w25t-nke}"
export NKE_IMAGE="${NKE_IMAGE:-orblx-w25t-nke:local}"
export NKE_NET="${NKE_NET:-172.28.47}"
export NKE_SVID_TTL="${NKE_SVID_TTL:-60}"
NKE_BIN="${NKE_BIN:-}"
COORD_IP="${NKE_NET}.10"
COORD="${COORD_IP}:443"
WORK="$(mktemp -d /tmp/orblx-nke.XXXXXX)"
export NKE_POLICY="$WORK/policy.hujson"
PING_PIDS=()

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  local pid
  for pid in "${PING_PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (the proof failed) ----"
    dc logs 2>&1 | sed 's/[A-Za-z0-9_-]\{40,\}/<redacted>/g' || true
  fi
  docker rm -f "${NKE_PROJECT}-ttlmax" >/dev/null 2>&1 || true
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "node-key-expiry" "$NKE_PROJECT"

# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "${NKE_PROJECT}" || exit 1

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Read one Duration constant from clock.rs and print it in seconds.
clock_secs() {
  local name="$1" expr
  expr="$(sed -n "s/^pub const ${name}: Duration = Duration::from_secs(\([0-9 *]*\));\$/\1/p" "$CLOCK")"
  [[ -n "$expr" ]] || fail "${name} is not in ${CLOCK}."
  echo $(( expr ))
}

now_s() {
  date +%s.%N
}

# Wait for a clock point. This is the test schedule, not a retry.
wait_until() {
  local target="$1" left
  left="$(awk -v t="$target" -v n="$(now_s)" 'BEGIN {d = t - n; if (d < 0) d = 0; printf "%.3f", d}')"
  sleep "$left"
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  iptables-legacy -P FORWARD ACCEPT
}

build_image() {
  local image_dir bin="$NKE_BIN"
  if [[ -z "$bin" ]]; then
    cargo build -p orblx-cli --bin orblx --locked
    bin="$ROOT/target/debug/orblx"
  fi
  [[ -x "$bin" ]] || fail "The orblx binary ${bin} is missing."
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t "$NKE_IMAGE" "$image_dir"
  rm -rf "$image_dir"
}

# Wait until a log line shows up. The bound fails the proof closed.
wait_log() {
  local service="$1" needle="$2" limit="$3" since="${4:-}" i
  for ((i = 0; i < limit * 2; i++)); do
    if dc logs ${since:+--since "$since"} "$service" 2>&1 | read_all grep -q -- "$needle"; then
      return 0
    fi
    sleep 0.5
  done
  fail "The ${service} log has no line '${needle}' after ${limit} s."
}

wait_peer() {
  local service="$1" peer="$2" i
  for ((i = 0; i < 60; i++)); do
    if dc exec -T "$service" orblx status --state-dir /var/lib/orblx 2>/dev/null \
      | read_all grep -q "^peer ${peer} overlay_ip "; then
      return 0
    fi
    sleep 0.5
  done
  fail "The node ${service} has no netmap entry for ${peer} after 30 s."
}

status_field() {
  local service="$1" key="$2"
  dc exec -T "$service" orblx status --state-dir /var/lib/orblx | read_all awk -v k="$key" '$1 == k {print $2; exit}'
}

# Print the leaf not_after (Unix seconds) of cert.pem in the state of one service.
cert_expiry() {
  local service="$1"
  dc exec -T "$service" python3 -c \
    "import ssl, sys; print(int(ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(sys.argv[1])['notAfter'])))" \
    /var/lib/orblx/cert.pem
}

peer_overlay() {
  local service="$1" peer="$2"
  dc exec -T "$service" orblx status --state-dir /var/lib/orblx \
    | read_all awk -v p="$peer" '$1 == "peer" && $2 == p {print $4; exit}'
}

token() {
  local name="$1"
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 \
    --out "/var/lib/orblx/tokens/${name}" | sed 's/[A-Za-z0-9_-]\{32,\}/<redacted>/g'
}

enroll() {
  local name="$1" ip="$2" token_name="${3:-$1}"
  echo "=== [C] enroll ${name} ==="
  dc run --rm --no-deps --entrypoint sh "$name" -c \
    "rm -rf /var/lib/orblx/* && orblx coord enroll --name ${name} --coord ${COORD} --coord-name coord --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/${token_name} --state /var/lib/orblx --endpoint ${ip}:443" \
    | sed 's/[A-Za-z0-9_-]\{40,\}/<redacted>/g'
}

admin() {
  dc exec -T owner orblx admin "$@" --coord "$COORD" --coord-name coord \
    --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem
}

# One new hello handshake from a to b. Print the result and the clock times.
hello_ping() {
  local label="$1" service="$2" expiry="$3" out status t0 t1
  t0="$(now_s)"
  set +e
  out="$(dc exec -T "$service" orblx ping b --state /var/lib/orblx --timeout 3 2>&1)"
  status=$?
  set -e
  t1="$(now_s)"
  printf '%s\n' "$out" | sed "s/^/${label} /"
  echo "${label} exit ${status} start_after_expiry_s $(awk -v a="$t0" -v e="$expiry" 'BEGIN {printf "%.3f", a - e}') end_after_expiry_s $(awk -v a="$t1" -v e="$expiry" 'BEGIN {printf "%.3f", a - e}')"
  HELLO_STATUS="$status"
  HELLO_OUT="$out"
  HELLO_T0="$t0"
  HELLO_T1="$t1"
}

# Count ping replies with a -D time in [from, to).
replies_between() {
  local file="$1" from="$2" to="$3"
  awk -v f="$from" -v t="$to" '/bytes from/ {
    ts = $1; gsub(/[\[\]]/, "", ts)
    if (ts + 0 >= f + 0 && ts + 0 < t + 0) n++
  } END {print n + 0}' "$file"
}

last_reply() {
  awk '/bytes from/ {ts = $1; gsub(/[\[\]]/, "", ts); v = ts} END {print v}' "$1"
}

echo "=== [C] constants from ${CLOCK} ==="
SKEW="$(clock_secs MAX_SKEW)"
MAX_USER="$(clock_secs MAX_USER_TTL)"
MAX_AGENT="$(clock_secs MAX_AGENT_TTL)"
echo "max_skew_s ${SKEW}"
echo "max_user_ttl_s ${MAX_USER}"
echo "max_agent_ttl_s ${MAX_AGENT}"
echo "svid_ttl_s ${NKE_SVID_TTL} (test setting ORBLX_SVID_TTL)"
if (( NKE_SVID_TTL < 45 || NKE_SVID_TTL > MAX_USER )); then
  fail "NKE_SVID_TTL must be from 45 to ${MAX_USER} seconds."
fi

cp "$ROOT/scripts/proof/node-key-expiry.hujson" "$NKE_POLICY"
chmod 644 "$NKE_POLICY"

echo "=== [C] remove old proof stack ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
open_legacy_forward

echo "=== [C] build image ${NKE_IMAGE} ==="
build_image

echo "=== [C] gate 7: the coordinator refuses a node SVID life of MAX_USER_TTL + 1 s ==="
set +e
ttl_out="$(timeout 20 docker run --rm --network none -e ORBLX_OIDC_MODE=mock \
  -e "ORBLX_SVID_TTL=$((MAX_USER + 1))" "$NKE_IMAGE" \
  coord serve --state /tmp/nke-coord --listen 127.0.0.1:443 --name coord 2>&1)"
ttl_status=$?
set -e
printf '%s\n' "$ttl_out" | sed 's/^/ttl_over /'
echo "ttl_over exit ${ttl_status}"
[[ "$ttl_status" -ne 0 && "$ttl_status" -ne 124 ]] || fail "The coordinator did not refuse ORBLX_SVID_TTL=$((MAX_USER + 1))."
printf '%s\n' "$ttl_out" | read_all grep -q "ORBLX_SVID_TTL must be from 1 to ${MAX_USER} seconds." \
  || fail "The refusal does not name the limit ${MAX_USER}."

echo "=== [C] gate 7 control: the coordinator starts with MAX_USER_TTL ==="
docker rm -f "${NKE_PROJECT}-ttlmax" >/dev/null 2>&1 || true
docker run -d --name "${NKE_PROJECT}-ttlmax" --network none -e ORBLX_OIDC_MODE=mock \
  -e "ORBLX_SVID_TTL=${MAX_USER}" "$NKE_IMAGE" \
  coord serve --state /tmp/nke-coord --listen 127.0.0.1:443 --name coord >/dev/null
sleep 5
ttl_running="$(docker inspect -f '{{.State.Running}}' "${NKE_PROJECT}-ttlmax")"
ttl_out="$(docker logs "${NKE_PROJECT}-ttlmax" 2>&1)"
docker rm -f "${NKE_PROJECT}-ttlmax" >/dev/null
echo "ttl_max running_after_5s ${ttl_running}"
[[ "$ttl_running" == "true" ]] || { printf '%s\n' "$ttl_out" | sed 's/^/ttl_max /'; fail "The coordinator did not run with ORBLX_SVID_TTL=${MAX_USER}."; }
if printf '%s\n' "$ttl_out" | read_all grep -q "ORBLX_SVID_TTL must be"; then
  fail "The coordinator refused ORBLX_SVID_TTL=${MAX_USER}."
fi

echo "=== [C] start coordinator ==="
dc up -d coord
for ((i = 0; i < 60; i++)); do
  if dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem; then
    break
  fi
  sleep 0.5
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "The coordinator did not write the trust bundle."

for name in owner a a2 b c; do
  token "$name"
done
enroll owner "${NKE_NET}.20"
enroll b "${NKE_NET}.12"
enroll c "${NKE_NET}.13"

echo "=== [C] start owner, b, c ==="
dc up -d owner b c
wait_log b "The TUN device" 30
wait_log c "The TUN device" 30
wait_log owner "The TUN device" 30

echo "=== [C] enroll and start a, then cut a off from the coordinator ==="
enroll a "${NKE_NET}.11"
enroll a2 "${NKE_NET}.14"
dc up -d a a2
wait_log a "The TUN device" 30
dc exec -T a iptables -I OUTPUT -d "$COORD_IP" -j REJECT
cut_at="$(now_s)"
dc exec -T a iptables -S OUTPUT | sed 's/^/a_iptables /'
EXPIRY="$(status_field a svid_expiry)"
[[ "$EXPIRY" =~ ^[0-9]+$ ]] || fail "The node a status has no svid_expiry."
renew_due="$(( EXPIRY - NKE_SVID_TTL / 3 ))"
A_CERT_EXPIRY="$(cert_expiry a)"
D_EXPIRY="$(cert_expiry a2)"
echo "a_svid_expiry ${EXPIRY} a_cert_not_after ${A_CERT_EXPIRY}"
echo "a2_cert_not_after ${D_EXPIRY} (a2 runs no daemon and does not renew)"
[[ "$A_CERT_EXPIRY" == "$EXPIRY" ]] || fail "The a status expiry is not the a leaf not_after."
[[ "$D_EXPIRY" =~ ^[0-9]+$ ]] || fail "The a2 leaf has no not_after."
echo "a_cut_off_before_expiry_s $(awk -v e="$EXPIRY" -v c="$cut_at" 'BEGIN {printf "%.3f", e - c}')"
if awk -v c="$cut_at" -v d="$renew_due" 'BEGIN {exit !(c + 0 >= d + 0)}'; then
  fail "The cut-off came after the renewal time. The setup was too slow."
fi
if dc logs a 2>&1 | read_all grep -q "The node renewed the SVID"; then
  fail "The node a renewed before the cut-off."
fi

wait_peer a b
wait_peer c b
wait_log a "The path to b is direct" 30
wait_log c "The path to b is direct" 30
B_OVERLAY="$(peer_overlay a b)"
[[ -n "$B_OVERLAY" ]] || fail "The overlay address of b is missing."
echo "b_overlay ${B_OVERLAY}"
wait_log b "The node adds the peer a2 " 30

echo "=== [C] control: a new handshake from a2 before the expiry ==="
hello_ping "hello_a2_before" a2 "$D_EXPIRY"
[[ "$HELLO_STATUS" -eq 0 ]] || fail "A new handshake from a2 before the expiry did not pass."

ping_end="$(( EXPIRY + SKEW + 15 ))"
ping_secs="$(awk -v e="$ping_end" -v n="$(now_s)" 'BEGIN {printf "%d", e - n}')"
echo "=== [C] ping a->b and c->b every 0.2 s for ${ping_secs} s (until expiry + $((SKEW + 15)) s) ==="
dc exec -T a ping -D -n -i 0.2 -w "$ping_secs" "$B_OVERLAY" >"$WORK/a-ping.txt" 2>&1 &
PING_PIDS+=("$!")
dc exec -T c ping -D -n -i 0.2 -w "$ping_secs" "$B_OVERLAY" >"$WORK/c-ping.txt" 2>&1 &
PING_PIDS+=("$!")

echo "=== [C] new handshake from a2 at expiry + 30 s (inside the skew) ==="
wait_until "$(( D_EXPIRY + 30 ))"
hello_ping "hello_a2_plus30" a2 "$D_EXPIRY"
[[ "$HELLO_STATUS" -eq 0 ]] || fail "A new handshake at expiry + 30 s did not pass."
printf '%s\n' "$HELLO_OUT" | read_all grep -qx 'path direct' || fail "The handshake at expiry + 30 s did not use the direct path."
if awk -v t="$HELLO_T1" -v e="$D_EXPIRY" -v s="$SKEW" 'BEGIN {exit !(t + 0 > e + s)}'; then
  fail "The handshake at expiry + 30 s ended after expiry + MAX_SKEW."
fi

echo "=== [C] new handshake from a2 at expiry + MAX_SKEW + 2 s ==="
wait_until "$(( D_EXPIRY + SKEW + 2 ))"
reject_before="$(dc logs b 2>&1 | awk '/The node did not accept a peer.*The end time has passed/ {n++} END {print n + 0}')"
hello_ping "hello_a2_after_skew" a2 "$D_EXPIRY"
[[ "$HELLO_STATUS" -ne 0 ]] || fail "A new handshake after expiry + MAX_SKEW passed."
if awk -v t="$HELLO_T0" -v e="$D_EXPIRY" -v s="$SKEW" 'BEGIN {exit !(t + 0 < e + s + 1)}'; then
  fail "The refused handshake started before expiry + MAX_SKEW + 1 s."
fi

echo "=== [C] wait for the ping runs to end ==="
for pid in "${PING_PIDS[@]}"; do
  wait "$pid" || true
done
PING_PIDS=()
tail -n 3 "$WORK/a-ping.txt" | sed 's/^/a_ping /'
tail -n 3 "$WORK/c-ping.txt" | sed 's/^/c_ping /'

reject_after="$(dc logs b 2>&1 | awk '/The node did not accept a peer.*The end time has passed/ {n++} END {print n + 0}')"
echo "b_handshake_rejects_expired before ${reject_before} after ${reject_after}"
dc logs b 2>&1 | read_all grep "The node did not accept a peer" | sort | uniq -c | sed 's/^/b_reject_line /'
(( reject_after > reject_before )) || fail "The node b log has no expiry reason for the refused handshake."

a_before="$(replies_between "$WORK/a-ping.txt" 0 "$EXPIRY")"
a_plus30="$(replies_between "$WORK/a-ping.txt" "$(( EXPIRY + 29 ))" "$(( EXPIRY + 31 ))")"
a_after="$(replies_between "$WORK/a-ping.txt" "$(( EXPIRY + SKEW + 1 ))" 99999999999)"
c_after="$(replies_between "$WORK/c-ping.txt" "$(( EXPIRY + SKEW + 1 ))" 99999999999)"
a_last="$(last_reply "$WORK/a-ping.txt")"
echo "a_replies_before_expiry ${a_before}"
echo "a_replies_expiry_plus_29_to_31 ${a_plus30}"
echo "a_replies_after_expiry_plus_skew_plus_1 ${a_after}"
echo "a_last_reply_after_expiry_s $(awk -v l="${a_last:-0}" -v e="$EXPIRY" 'BEGIN {printf "%.3f", l - e}')"
echo "c_replies_after_expiry_plus_skew_plus_1 ${c_after} (control node that renews)"
(( a_before > 0 )) || fail "The session a->b did not carry bytes before the expiry."
(( a_plus30 > 0 )) || fail "The session a->b did not carry bytes at expiry + 30 s."
(( a_after == 0 )) || fail "The session a->b carried bytes after expiry + MAX_SKEW + 1 s."
(( c_after > 0 )) || fail "The control node c lost its session. The cut-off is not specific to a."
if dc logs a 2>&1 | read_all grep -q "The node renewed the SVID"; then
  fail "The node a renewed while it was cut off."
fi

echo "=== [C] status of the lapsed node ==="
a_status_expiry="$(status_field a svid_expiry)"
echo "a_status_svid_expiry ${a_status_expiry} lapsed_by_s $(awk -v e="$a_status_expiry" -v n="$(now_s)" 'BEGIN {printf "%.0f", n - e}')"
admin nodes | sed 's/^/admin_nodes /'
echo "coord_status_shows_lapsed no (the coordinator has no lapsed state; see docs/w25-node-key-expiry.md)"

echo "=== [C] the coordinator refuses the lapsed leaf (the node is online again) ==="
online_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dc exec -T a iptables -D OUTPUT -d "$COORD_IP" -j REJECT
set +e
netmap_out="$(dc exec -T a orblx coord netmap --coord "$COORD" --coord-name coord \
  --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx 2>&1)"
netmap_status=$?
set -e
printf '%s\n' "$netmap_out" | sed 's/[A-Za-z0-9_-]\{40,\}/<redacted>/g; s/^/lapsed_netmap /'
echo "lapsed_netmap exit ${netmap_status}"
[[ "$netmap_status" -ne 0 ]] || fail "The coordinator accepted the lapsed leaf."
wait_log a "The SVID renewal failed" 40 "$online_at"
dc logs --since "$online_at" a 2>&1 | read_all grep "The SVID renewal failed" | sort | uniq -c | sed 's/^/a_renew_refused /'
if dc logs a 2>&1 | read_all grep -q "The node renewed the SVID"; then
  fail "The coordinator renewed the lapsed leaf."
fi

echo "=== [C] gate 7: the coordinator refuses an agent grant life of MAX_AGENT_TTL + 1 s ==="
set +e
agent_out="$(dc exec -T owner orblx agent grant request --agent bot --node b --service web \
  --port 80 --ttl "$((MAX_AGENT + 1))" --coord "$COORD" --coord-name coord \
  --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem 2>&1)"
agent_status=$?
set -e
printf '%s\n' "$agent_out" | sed 's/^/agent_ttl_over /'
echo "agent_ttl_over exit ${agent_status}"
[[ "$agent_status" -ne 0 ]] || fail "The coordinator accepted an agent grant life of $((MAX_AGENT + 1)) s."
printf '%s\n' "$agent_out" | read_all grep -q "The grant life must be 1 to ${MAX_AGENT} seconds." \
  || fail "The agent refusal does not name the limit ${MAX_AGENT}."

echo "=== [C] a revoked node cannot renew ==="
admin revoke c | sed 's/^/revoke_c /'
revoked_at="$(date -u -d '+1 second' +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
c_expiry="$(status_field c svid_expiry)"
echo "c_svid_expiry_at_revoke ${c_expiry}"
wait_log c "The SVID renewal failed" "$(( NKE_SVID_TTL + 10 ))" "$revoked_at"
dc logs --since "$revoked_at" c 2>&1 | read_all grep "The SVID renewal failed" | sort | uniq -c | sed 's/^/c_renew_refused /'
if dc logs --since "$revoked_at" c 2>&1 | read_all grep -q "The node renewed the SVID"; then
  fail "The revoked node c renewed."
fi
c_expiry_now="$(status_field c svid_expiry)"
echo "c_svid_expiry_after_refusal ${c_expiry_now}"
[[ "$c_expiry_now" == "$c_expiry" ]] || fail "The revoked node c has a new leaf."

echo "=== [C] admin expire writes 1 audit record ==="
admin expire a | sed 's/^/expire_a /'
audit_out="$(admin audit)"
printf '%s\n' "$audit_out" | sed 's/^/audit /'
expire_records="$(printf '%s\n' "$audit_out" | awk '$1 == "record" && $4 == "expire" && ($5 == "a" || $5 ~ /\/node\/a$/) {n++} END {print n + 0}')"
echo "audit_expire_records_a ${expire_records}"
[[ "$expire_records" -eq 1 ]] || fail "admin expire a wrote ${expire_records} audit records, not 1."
printf '%s\n' "$audit_out" | read_all grep -q '^verify ok ' || fail "The audit chain check failed."

echo "=== [C] a new enroll restores access ==="
token a-new
dc rm -sf a >/dev/null
enroll a "${NKE_NET}.11" a-new
dc up -d a
wait_log a "The TUN device" 30
wait_peer a b
EXPIRY="$(status_field a svid_expiry)"
echo "a_new_svid_expiry ${EXPIRY} life_left_s $(awk -v e="$EXPIRY" -v n="$(now_s)" 'BEGIN {printf "%.0f", e - n}')"
wait_log a "The path to b is direct" 30
dc exec -T a ping -n -c 5 -i 0.2 -W 2 "$B_OVERLAY" | sed 's/^/a_ping_reenroll /'
dc exec -T a ping -n -c 5 -i 0.2 -W 2 "$B_OVERLAY" | read_all grep -q ' 0% packet loss' \
  || fail "The node a has no access to b after a new enroll."
admin nodes | sed 's/^/admin_nodes_after /'

echo "=== [C] secret scan of the stack logs ==="
dc logs >"$WORK/stack.log" 2>&1
secret_scan "$WORK/stack.log"

echo "proof_ok"

#!/usr/bin/env bash
# W25-38 deny damage proof. Run it on the merge commit.
# Node a is a revoked peer. Node allowed is a peer that is not revoked. Its name sorts
# before b, so node b accepts its new QUIC sessions (the node with the lower name dials).
# Node b runs `orblx up`
# with the SSH server and the datapath. The proof damages deny.json on b.
#
# Gate 0: with a valid deny.json on b, allowed can SSH to b and ping b (the traffic does not
#   change), and a is refused after `admin revoke-all a`.
# Gate 3 (W25-38 merge blocker): the coordinator stops for OFFLINE_SECS (default 600 s)
#   and deny.json on b stays valid. A valid list never goes stale with age. During the
#   whole time, allowed sends ICMP to b over the mesh with no loss, and each probe (orblx ping,
#   a new QUIC session, and an SSH login) from allowed to b is accepted. The counter
#   orblx_node_refused of b does not change (0 refused sessions and frames).
#   Node a (revoked) stops during gate 3, so its dial attempts do not change the counter.
# Gate 1: the coordinator stays stopped, so b cannot get a new deny list. For each damage kind
#   (corrupt, truncated, missing, unreadable), the proof takes SAMPLES samples. Each sample
#   is one SSH login and one ping (a new QUIC session) from a to b. Each must be refused.
#   The file on b must still be damaged after the samples.
#   With a fallback to an empty deny list, a would be accepted.
# Gate 2: the coordinator starts again. b gets a valid deny.json again. allowed can SSH to b
#   again, and a is still refused.
# Gate 4: the refuse-all window after enroll. The enroll reply has no deny list, and the
#   node fetches its first deny list over mutual TLS right after enroll. `orblx coord
#   enroll` prints `deny_list ready_ms N`. WINDOW_ENROLLS (default 10) more enrolls run,
#   and each window must be 2000 ms or less.
#
# Result rules: accepted 0, unknown 0, and samples >= 1 for each kind.
# The proof takes the box proof lock (proof-lock.sh). The proof_contention line must
# show unknown_samples 0.
# The script does not print enroll tokens, private keys, or SVID material.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.w25-38-deny-damage.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROFILE="${ORBLX_PROOF_PROFILE:-release}"
SAMPLES="${ORBLX_DENY_SAMPLES:-3}"
OFFLINE_SECS="${ORBLX_DENY_OFFLINE_SECS:-600}"
WINDOW_ENROLLS="${ORBLX_DENY_WINDOW_ENROLLS:-10}"
WINDOW_MAX_MS=2000
STATE=/var/lib/orblx
DENY="$STATE/deny.json"
KINDS="corrupt truncated missing unreadable"

if ! [[ "$SAMPLES" =~ ^[0-9]+$ ]] || [[ "$SAMPLES" -lt 1 ]]; then
  echo "ORBLX_DENY_SAMPLES must be 1 or more." >&2
  exit 2
fi
if ! [[ "$OFFLINE_SECS" =~ ^[0-9]+$ ]] || [[ "$OFFLINE_SECS" -lt 60 ]]; then
  echo "ORBLX_DENY_OFFLINE_SECS must be 60 or more." >&2
  exit 2
fi
if ! [[ "$WINDOW_ENROLLS" =~ ^[0-9]+$ ]] || [[ "$WINDOW_ENROLLS" -lt 1 ]]; then
  echo "ORBLX_DENY_WINDOW_ENROLLS must be 1 or more." >&2
  exit 2
fi

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  # sudo drops the environment, so pass the Compose variables with env.
  as_root env POLICY_FILE="$POLICY_FILE" COORD_ADDR="$COORD_ADDR" \
    docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (tail) ----"
    dc logs --tail 40 2>&1 | grep -v 'PRIVATE KEY' || true
  fi
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "w25-38-deny-damage" "orblx-w25-38-deny-damage"
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-w25-38-deny-damage" || exit 1

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
  local image_dir flag=()
  if [[ "$PROFILE" == release ]]; then
    flag=(--release)
  fi
  cargo build "${flag[@]}" -p orblx-cli --bin orblx --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$TARGET_DIR/$PROFILE/orblx")"
  as_root docker build -q -t orblx-w25-38-deny:w25 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat "$STATE/trust-bundle.pem" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

wait_log() {
  local service="$1"
  local needle="$2"
  local i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | read_all grep -q "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

owner() {
  run_node owner admin "$@" --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

# Print the refuse-all window of one enroll output file, or "pending".
window_of() {
  local out="$1"
  if grep -q '^deny_list pending' "$out"; then
    echo pending
    return
  fi
  read_all awk '/^deny_list ready_ms /{print $3; exit}' <"$out"
}

enroll_node() {
  local name="$1"
  local out="$WORK/enroll-${name}.out"
  echo "=== [C] enroll ${name} ==="
  run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" \
    --endpoint "${name}:443" >"$out" 2>&1
  grep -E '^(enrolled|name |overlay_ip |deny_list )' "$out"
  echo "enroll ${name} deny_window_ms $(window_of "$out")"
}

# Print the orblx_node_refused counter of node b.
refused_count() {
  dc exec -T b curl -fsS "http://127.0.0.1:9464/metrics" \
    | read_all awk '/^orblx_node_refused /{print $2; exit}' | tr -d '\r\n '
}

# Print the count of deny file error lines in the log of node b.
deny_error_lines() {
  { dc logs b 2>&1 || true; } | read_all grep -c 'The deny file' || true
}

ssh_cmd() {
  printf '%s' "orblx ssh root@b --identity /tmp/sshid --netmap $STATE/netmap.json --peer-cert /tmp/b-cert.pem"
}

# Print accepted, refused, or unknown for one SSH login from FROM to b.
# The SSH client connects over the mesh. When the datapath of b refuses the QUIC session
# of FROM, the TCP connect gets no reply and the client stops at the 20 s limit (status
# 124). That result is refused only when the orblx_node_refused counter of b increased
# during the attempt. Then b refused a session or a frame in that time. Other timeouts are
# unknown.
ssh_try() {
  local from="$1"
  local out="$WORK/ssh-${from}.out"
  local status=0
  local before after
  before="$(refused_count)"
  dc exec -T "$from" sh -c "timeout 20 $(ssh_cmd) --command 'echo ssh_ok'" >"$out" 2>&1 || status=$?
  after="$(refused_count)"
  if [[ "$status" -eq 0 ]] && grep -q '^ssh_ok' "$out"; then
    echo accepted
  elif grep -q '^ssh_ok' "$out"; then
    echo unknown
  elif [[ "$status" -ne 0 && "$status" -ne 124 ]]; then
    echo refused
  elif [[ "$status" -eq 124 && "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]] \
    && (( after > before )); then
    echo refused
  else
    echo unknown
  fi
}

# Print accepted, refused, or unknown for one `orblx ping` (a new QUIC session) from FROM to b.
# The ping uses the netmap of FROM and does not use the coordinator.
ping_try() {
  local from="$1"
  local out="$WORK/ping-${from}.out"
  local status=0
  run_node "$from" ping b --state "$STATE" --timeout 5 >"$out" 2>&1 || status=$?
  if [[ "$status" -eq 0 ]] && grep -q '^rtt_ms ' "$out"; then
    echo accepted
  elif [[ "$status" -ne 0 ]] && ! grep -q '^rtt_ms ' "$out"; then
    echo refused
  else
    echo unknown
  fi
}

expect() {
  local label="$1"
  local want="$2"
  local got="$3"
  echo "check ${label} want ${want} got ${got}"
  if [[ "$got" != "$want" ]]; then
    echo "The check ${label} did not give ${want}." >&2
    exit 1
  fi
}

# Print the state of deny.json on b: valid, invalid, missing, or dir.
deny_state() {
  dc exec -T b sh -c "
    if [ -d $DENY ]; then echo dir
    elif [ ! -e $DENY ]; then echo missing
    elif jq -e '.version' $DENY >/dev/null 2>&1; then echo valid
    else echo invalid
    fi" | tr -d '\r\n '
}

damage() {
  local kind="$1"
  case "$kind" in
    corrupt) dc exec -T b sh -c "printf 'not json {' >$DENY" ;;
    truncated) dc exec -T b sh -c "head -c \$((\$(wc -c <$DENY) / 2)) $DENY >$DENY.half && mv $DENY.half $DENY" ;;
    missing) dc exec -T b rm -f "$DENY" ;;
    unreadable) dc exec -T b sh -c "rm -f $DENY && mkdir $DENY" ;;
    *) echo "unknown damage kind ${kind}" >&2; exit 2 ;;
  esac
}

restore() {
  dc exec -T b sh -c "rm -rf $DENY && cp /tmp/deny.good $DENY"
}

cp "$ROOT/scripts/proof/w25-38-deny-damage.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image (${PROFILE}) ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

for name in owner a b allowed; do
  dc exec -T coord orblx coord token create \
    --state "$STATE" \
    --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done

coord_ip="$(dc run --rm --no-deps --entrypoint getent owner ahostsv4 coord \
  | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}')"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"

for name in owner a b allowed; do
  enroll_node "$name"
done
for name in a b allowed; do
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE" >/dev/null
  echo "netmap ${name} written"
done
dc run --rm --no-deps --entrypoint sh -T b -c "cat > $STATE/policy.hujson" <"$POLICY_FILE"
echo "policy b written"

echo "=== [C] start nodes a, b, and allowed ==="
dc up -d a b allowed
for name in a b allowed; do
  wait_log "$name" 'The TUN device'
done
wait_log b 'ssh_listen '

echo "=== [C] SSH identity and peer certificate on a and allowed ==="
dc exec -T b cat "$STATE/cert.pem" >"$WORK/b-cert.pem"
for name in a allowed; do
  dc exec -T "$name" sh -c "cat > /tmp/b-cert.pem" <"$WORK/b-cert.pem"
  dc exec -T "$name" sh -c "rm -rf /tmp/sshid && mkdir -p /tmp/sshid && cp $STATE/cert.pem $STATE/key.pem $STATE/bundle.pem /tmp/sshid/"
done

echo "=== [C] gate 0: valid deny.json on b, before the revoke ==="
expect "b deny.json" valid "$(deny_state)"
expect "ssh a before revoke" accepted "$(ssh_try a)"
expect "ping a before revoke" accepted "$(ping_try a)"
expect "ssh allowed before revoke" accepted "$(ssh_try allowed)"
expect "ping allowed before revoke" accepted "$(ping_try allowed)"

echo "=== [C] gate 0: revoke a ==="
owner revoke-all a | read_all grep -x 'revoked_all spiffe://orblx.local/node/a'
revoked=""
for _ in $(seq 1 100); do
  if dc exec -T b sh -c "jq -e '.revoked_uris | index(\"spiffe://orblx.local/node/a\")' $DENY" >/dev/null 2>&1; then
    revoked=yes
    break
  fi
  sleep 0.2
done
if [[ -z "$revoked" ]]; then
  echo "The deny.json of b does not revoke a." >&2
  exit 1
fi
echo "b deny.json revokes a, version $(dc exec -T b jq -r .version "$DENY" | tr -d '\r\n')"
sleep 1
expect "ssh a after revoke (valid file)" refused "$(ssh_try a)"
expect "ping a after revoke (valid file)" refused "$(ping_try a)"
expect "ssh allowed after revoke (valid file)" accepted "$(ssh_try allowed)"
expect "ping allowed after revoke (valid file)" accepted "$(ping_try allowed)"
dc exec -T b cp "$DENY" /tmp/deny.good

echo "=== [C] gate 3: coordinator offline ${OFFLINE_SECS} s, valid deny.json, mesh traffic ==="
b_overlay="$(read_all awk '/^overlay_ip /{print $2; exit}' <"$WORK/enroll-b.out")"
if [[ -z "$b_overlay" ]]; then
  echo "The overlay IP of b is not known." >&2
  exit 1
fi
echo "b overlay_ip ${b_overlay}"
dc stop a >/dev/null
sleep 2
refused_before="$(refused_count)"
errors_before="$(deny_error_lines)"
version_before="$(dc exec -T b jq -r .version "$DENY" | tr -d '\r\n')"
echo "gate3 b refused_before ${refused_before} deny_error_lines_before ${errors_before} deny_version ${version_before}"
[[ -n "$refused_before" ]]
dc stop coord >/dev/null
offline_start="$(date +%s)"
icmp_count=$(( OFFLINE_SECS * 2 ))
dc exec -T allowed ping -n -i 0.5 -W 2 -c "$icmp_count" "$b_overlay" >"$WORK/gate3-icmp.out" 2>&1 &
icmp_pid=$!
g3_probes=0
g3_accepted=0
g3_unknown=0
while (( $(date +%s) - offline_start < OFFLINE_SECS - 20 )); do
  for probe in ssh ping; do
    if [[ "$probe" == ssh ]]; then
      got="$(ssh_try allowed)"
    else
      got="$(ping_try allowed)"
    fi
    g3_probes=$(( g3_probes + 1 ))
    case "$got" in
      accepted) g3_accepted=$(( g3_accepted + 1 )) ;;
      refused) ;;
      *) g3_unknown=$(( g3_unknown + 1 )) ;;
    esac
    echo "gate3 t $(( $(date +%s) - offline_start )) s probe ${probe} peer allowed result ${got}"
  done
  sleep 30
done
icmp_status=0
wait "$icmp_pid" || icmp_status=$?
while (( $(date +%s) - offline_start < OFFLINE_SECS )); do
  sleep 1
done
offline_secs_done=$(( $(date +%s) - offline_start ))
icmp_line="$(grep -E 'packets transmitted' "$WORK/gate3-icmp.out" || true)"
echo "gate3 icmp ${icmp_line} status ${icmp_status}"
icmp_tx="$(printf '%s\n' "$icmp_line" | read_all awk '{print $1}')"
icmp_rx="$(printf '%s\n' "$icmp_line" | read_all awk '{print $4}')"
refused_after="$(refused_count)"
errors_after="$(deny_error_lines)"
g3_state="$(deny_state)"
version_after="$(dc exec -T b jq -r .version "$DENY" | tr -d '\r\n')"
g3_refused=$(( refused_after - refused_before ))
echo "summary w25_38_gate3 offline_s ${offline_secs_done} icmp_tx ${icmp_tx} icmp_rx ${icmp_rx} probes ${g3_probes} accepted ${g3_accepted} unknown ${g3_unknown} refused_frames ${g3_refused} deny_error_lines ${errors_before}->${errors_after} deny_state ${g3_state} deny_version ${version_before}->${version_after}"
if [[ "$offline_secs_done" -lt "$OFFLINE_SECS" || -z "$icmp_tx" || "$icmp_tx" -lt 1 \
  || "$icmp_rx" != "$icmp_tx" || "$g3_probes" -lt 2 || "$g3_accepted" -ne "$g3_probes" \
  || "$g3_unknown" -ne 0 || "$g3_refused" -ne 0 || "$errors_after" != "$errors_before" \
  || "$g3_state" != valid || "$version_after" != "$version_before" ]]; then
  echo "The gate 3 (coordinator offline, valid deny.json) failed." >&2
  exit 1
fi
dc start a >/dev/null
wait_log a 'The TUN device'

echo "=== [C] gate 1: the coordinator stays stopped, so b cannot get a new deny list ==="
accepted=0
unknown=0
total=0
rows=()
for kind in $KINDS; do
  damage "$kind"
  state="$(deny_state)"
  echo "damage ${kind} deny_state ${state}"
  [[ "$state" != valid ]]
  # The SSH deny watch reads each 100 ms. The datapath reload reads each 100 ms.
  sleep 1
  k_samples=0
  k_accepted=0
  k_unknown=0
  for i in $(seq 1 "$SAMPLES"); do
    for probe in ssh ping; do
      if [[ "$probe" == ssh ]]; then
        got="$(ssh_try a)"
      else
        got="$(ping_try a)"
      fi
      echo "sample kind ${kind} n ${i} probe ${probe} peer a result ${got}"
      k_samples=$(( k_samples + 1 ))
      case "$got" in
        accepted) k_accepted=$(( k_accepted + 1 )) ;;
        refused) ;;
        *) k_unknown=$(( k_unknown + 1 )) ;;
      esac
    done
  done
  # A peer that is not revoked is also refused: the node fails closed, it does not use
  # the old list without a check.
  c_ssh="$(ssh_try allowed)"
  echo "sample kind ${kind} probe ssh peer allowed result ${c_ssh}"
  after="$(deny_state)"
  echo "damage ${kind} deny_state_after ${after}"
  # The refusals must come from the running node b, not from a stopped node.
  if ! dc ps --services --status running | read_all grep -qx b; then
    echo "Node b does not run during the ${kind} samples." >&2
    exit 1
  fi
  if [[ "$after" == valid ]]; then
    echo "The deny.json of b became valid during the ${kind} samples." >&2
    exit 1
  fi
  echo "kind ${kind} samples ${k_samples} accepted ${k_accepted} unknown ${k_unknown} peer_allowed_ssh ${c_ssh}"
  rows+=("${kind}:${k_samples}/${k_accepted}/${k_unknown}")
  total=$(( total + k_samples ))
  accepted=$(( accepted + k_accepted ))
  unknown=$(( unknown + k_unknown ))
  if [[ "$k_samples" -lt 1 ]]; then
    echo "The kind ${kind} has no sample." >&2
    exit 1
  fi
  restore
  expect "b deny.json restored after ${kind}" valid "$(deny_state)"
  sleep 1
done
dc logs b 2>&1 | grep -E 'deny|Deny' | grep -v 'PRIVATE KEY' | tail -20 || true

echo "=== [C] gate 2: start the coordinator, b gets a valid list again ==="
dc start coord >/dev/null
wait_bundle
sleep 3
expect "b deny.json after coord start" valid "$(deny_state)"
expect "ssh a after restore" refused "$(ssh_try a)"
expect "ping a after restore" refused "$(ping_try a)"
expect "ssh allowed after restore" accepted "$(ssh_try allowed)"
expect "ping allowed after restore" accepted "$(ping_try allowed)"

echo "=== [C] gate 4: refuse-all window after enroll, ${WINDOW_ENROLLS} enrolls ==="
windows=()
for i in $(seq 1 "$WINDOW_ENROLLS"); do
  name="w${i}"
  dc exec -T coord orblx coord token create \
    --state "$STATE" \
    --ttl 600 \
    --out "$STATE/tokens/${name}" >/dev/null
  # The owner service enrolls into a temp state directory of a new container.
  run_node owner \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "/tmp/${name}" \
    --endpoint "${name}:443" >"$WORK/enroll-${name}.out" 2>&1
  w="$(window_of "$WORK/enroll-${name}.out")"
  echo "window enroll ${name} deny_window_ms ${w}"
  windows+=("$w")
done
window_bad=0
for w in "${windows[@]}"; do
  if ! [[ "$w" =~ ^[0-9]+$ ]] || [[ "$w" -gt "$WINDOW_MAX_MS" ]]; then
    window_bad=$(( window_bad + 1 ))
  fi
done
echo "summary w25_38_window enrolls ${WINDOW_ENROLLS} ms ${windows[*]} max_ms ${WINDOW_MAX_MS} over ${window_bad}"
if [[ "$window_bad" -ne 0 ]]; then
  echo "The refuse-all window gate failed." >&2
  exit 1
fi

echo "=== [C] logs hold no key or enroll token ==="
{
  dc logs 2>&1
  cat "$WORK"/*.out 2>/dev/null
} >"$WORK/all-logs.log"
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.log" || true)"
echo "secret_grep 'PRIVATE KEY' ${hits}"
[[ "$hits" -eq 0 ]]

echo "summary w25_38_deny_damage revoked_peer a kinds ${rows[*]} (samples/accepted/unknown) samples ${total} accepted ${accepted} unknown ${unknown}"
if [[ "$total" -lt 1 || "$accepted" -ne 0 || "$unknown" -ne 0 ]]; then
  echo "The deny damage gate failed: samples ${total} accepted ${accepted} unknown ${unknown}." >&2
  exit 1
fi
echo "proof_ok"

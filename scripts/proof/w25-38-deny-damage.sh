#!/usr/bin/env bash
# W25-38 deny damage proof. Run it on the merge commit.
# Node a is a revoked peer. Node c is a peer that is not revoked. Node b runs `orblx up`
# with the SSH server and the datapath. The proof damages deny.json on b.
#
# Gate 0: with a valid deny.json on b, c can SSH to b and ping b (the traffic does not
#   change), and a is refused after `admin revoke-all a`.
# Gate 1: the coordinator stops, so b cannot get a new deny list. For each damage kind
#   (corrupt, truncated, missing, unreadable), the proof takes SAMPLES samples. Each sample
#   is one SSH login and one ping (a new QUIC session) from a to b. Each must be refused.
#   The file on b must still be damaged after the samples.
#   With a fallback to an empty deny list, a would be accepted.
# Gate 2: the coordinator starts again. b gets a valid deny.json again. c can SSH to b
#   again, and a is still refused.
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
STATE=/var/lib/orblx
DENY="$STATE/deny.json"
KINDS="corrupt truncated missing unreadable"

if ! [[ "$SAMPLES" =~ ^[0-9]+$ ]] || [[ "$SAMPLES" -lt 1 ]]; then
  echo "ORBLX_DENY_SAMPLES must be 1 or more." >&2
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

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" \
    --endpoint "${name}:443"
}

ssh_cmd() {
  printf '%s' "orblx ssh root@b --identity /tmp/sshid --netmap $STATE/netmap.json --peer-cert /tmp/b-cert.pem"
}

# Print accepted, refused, or unknown for one SSH login from FROM to b.
ssh_try() {
  local from="$1"
  local out="$WORK/ssh-${from}.out"
  local status=0
  dc exec -T "$from" sh -c "timeout 20 $(ssh_cmd) --command 'echo ssh_ok'" >"$out" 2>&1 || status=$?
  if [[ "$status" -eq 0 ]] && grep -q '^ssh_ok' "$out"; then
    echo accepted
  elif [[ "$status" -ne 0 && "$status" -ne 124 ]] && ! grep -q '^ssh_ok' "$out"; then
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

for name in owner a b c; do
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

for name in owner a b c; do
  enroll_node "$name"
done
for name in a b c; do
  run_node "$name" coord netmap \
    --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE" >/dev/null
  echo "netmap ${name} written"
done
dc run --rm --no-deps --entrypoint sh -T b -c "cat > $STATE/policy.hujson" <"$POLICY_FILE"
echo "policy b written"

echo "=== [C] start nodes a, b, and c ==="
dc up -d a b c
for name in a b c; do
  wait_log "$name" 'The TUN device'
done
wait_log b 'ssh_listen '

echo "=== [C] SSH identity and peer certificate on a and c ==="
dc exec -T b cat "$STATE/cert.pem" >"$WORK/b-cert.pem"
for name in a c; do
  dc exec -T "$name" sh -c "cat > /tmp/b-cert.pem" <"$WORK/b-cert.pem"
  dc exec -T "$name" sh -c "rm -rf /tmp/sshid && mkdir -p /tmp/sshid && cp $STATE/cert.pem $STATE/key.pem $STATE/bundle.pem /tmp/sshid/"
done

echo "=== [C] gate 0: valid deny.json on b, before the revoke ==="
expect "b deny.json" valid "$(deny_state)"
expect "ssh a before revoke" accepted "$(ssh_try a)"
expect "ping a before revoke" accepted "$(ping_try a)"
expect "ssh c before revoke" accepted "$(ssh_try c)"
expect "ping c before revoke" accepted "$(ping_try c)"

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
expect "ssh c after revoke (valid file)" accepted "$(ssh_try c)"
expect "ping c after revoke (valid file)" accepted "$(ping_try c)"
dc exec -T b cp "$DENY" /tmp/deny.good

echo "=== [C] gate 1: stop the coordinator, so b cannot get a new deny list ==="
dc stop coord >/dev/null
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
  c_ssh="$(ssh_try c)"
  echo "sample kind ${kind} probe ssh peer c result ${c_ssh}"
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
  echo "kind ${kind} samples ${k_samples} accepted ${k_accepted} unknown ${k_unknown} peer_c_ssh ${c_ssh}"
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
expect "ssh c after restore" accepted "$(ssh_try c)"
expect "ping c after restore" accepted "$(ping_try c)"

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

#!/usr/bin/env bash
# Custom OIDC issuer proof.
# A [C] test issuer serves discovery and the JWKS over HTTPS.
# The coordinator trusts the issuer from the [oidc] config section.
# A laptop node enrolls with an ID token and pings node srv.
# The coordinator rejects a wrong issuer, a wrong audience, an expired token,
# a bad signature, and an unknown kid.
# The script does not print an ID token, an enroll token, or a private key.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.oidc.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export CONFIG_FILE="$WORK/coord.toml"
export IDP_CA_FILE="$WORK/idp-ca.pem"
export COORD_ADDR="127.0.0.1:443"
ISSUER="https://idp:8443"
CLIENT="orblx-proof"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "custom-oidc"
: > "$IDP_CA_FILE"

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "=== [C] failure: coordinator and issuer log tail ===" >&2
    dc logs --tail 40 coord idp srv >&2 || true
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
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

build_image() {
  local image_dir bin target
  target="${CARGO_TARGET_DIR:-$ROOT/target}"
  bin="$target/debug/orblx"
  cargo build -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  cp "$target/debug/orblx-test-idp" "$image_dir/orblx-test-idp"
  printf '%s\n' 'COPY orblx-test-idp /usr/local/bin/orblx-test-idp' >> "$image_dir/Dockerfile"
  docker build -q -t orblx-oidc:w20 "$image_dir" >/dev/null
  rm -rf "$image_dir"
}

resolve_name() {
  dc run --rm --no-deps --entrypoint getent laptop ahostsv4 "$1" \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

idp() {
  dc run --rm --no-deps --entrypoint orblx-test-idp idp "$@"
}

wait_log() {
  local service="$1" needle="$2" i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | read_all grep -q -- "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The ${service} log does not contain: ${needle}" >&2
  dc logs "$service" >&2 || true
  return 1
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

# mint NAME KID [flags...]: write one ID token to /tokens/NAME.
mint() {
  local name="$1" kid="$2"
  shift 2
  idp mint --dir /idp --kid "$kid" --issuer "$ISSUER" --aud "$CLIENT" \
    --out "/tokens/${name}" "$@"
}

enroll_oidc() {
  local node="$1" token="$2"
  shift 2
  dc run --rm --no-deps laptop coord enroll \
    --name "$node" \
    --coord "${coord_ip}:443" \
    --bundle "/var/lib/orblx/coord-bundle.pem" \
    --id-token-file "/tokens/${token}" \
    --state "/var/lib/orblx/${node}" \
    --endpoint "${node}:443" "$@"
}

reject_count() {
  dc logs coord 2>&1 | grep -c "oidc reject $1" || true
}

expect_reject() {
  local label="$1" reason="$2" token="$3" before out status
  echo "=== [C] reject ${label} ==="
  before="$(reject_count "$reason")"
  set +e
  out="$(enroll_oidc "bad-${token}" "$token" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$out"
  if [[ "$status" -eq 0 ]]; then
    echo "The coordinator accepted the ${label} token." >&2
    exit 1
  fi
  printf '%s\n' "$out" | read_all grep -q 'The OIDC check failed.'
  sleep 1
  if [[ "$(reject_count "$reason")" -le "$before" ]]; then
    echo "The coordinator log does not show oidc reject ${reason}." >&2
    dc logs coord >&2 || true
    exit 1
  fi
  dc logs coord 2>&1 | show_matching "oidc reject ${reason}" | tail -1 | sed 's/^[^|]*| //'
}

cp "$ROOT/scripts/proof/oidc.hujson" "$POLICY_FILE"
cat > "$CONFIG_FILE" <<CONF
# [C] coordinator config for the custom OIDC proof.
[oidc]
issuer = "${ISSUER}"
client_id = "${CLIENT}"
allowed_domains = ["example.test"]
allowed_emails = []
ca_file = "/etc/orblx/idp-ca.pem"
CONF

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build image ==="
build_image

echo "=== [C] init test issuer ==="
idp init --dir /idp --host idp
dc run --rm --no-deps --entrypoint cat idp /idp/ca.pem > "$IDP_CA_FILE"
grep -q 'BEGIN CERTIFICATE' "$IDP_CA_FILE"
echo "idp_ca $(openssl x509 -in "$IDP_CA_FILE" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || echo saved)"

echo "=== [C] start test issuer and coordinator ==="
dc up -d idp
wait_log idp "idp serve"
dc up -d coord
wait_bundle
wait_log coord "oidc issuer"
dc logs coord 2>&1 | show_matching "oidc issuer" | sed 's/^[^|]*| //'

coord_ip="$(resolve_name coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"
dc exec -T coord cat /var/lib/orblx/trust-bundle.pem \
  | dc run --rm --no-deps -T --entrypoint sh laptop -c 'cat > /var/lib/orblx/coord-bundle.pem'

# The peer with the lower name dials. The name laptop is lower than srv.
# Thus the one-shot laptop container dials the srv daemon.
echo "=== [C] enroll srv with a token ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/srv
dc run --rm --no-deps --entrypoint orblx srv coord enroll \
  --name srv \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/srv \
  --state /var/lib/orblx \
  --endpoint srv:443

echo "=== [C] enroll laptop with an RS256 ID token ==="
nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
mint laptop rs1 --sub alice --email alice@example.test --nonce "$nonce"
enroll_oidc laptop laptop --nonce "$nonce"
wait_log coord "oidc accept sub alice"
dc logs coord 2>&1 | show_matching -E "oidc (jwks|accept)" | sed 's/^[^|]*| //'

echo "=== [C] netmap on srv ==="
dc run --rm --no-deps --entrypoint orblx srv coord netmap \
  --coord "${coord_ip}:443" \
  --bundle /var/lib/orblx/bundle.pem \
  --state /var/lib/orblx

echo "=== [C] start node srv ==="
dc up -d srv
wait_log srv "The TUN device"

echo "=== [C] laptop pings srv ==="
ping_ok="$(dc run --rm --no-deps laptop ping srv \
  --state /var/lib/orblx/laptop \
  --coord "${coord_ip}:443" \
  --bundle /var/lib/orblx/laptop/bundle.pem \
  --timeout 5)"
printf '%s\n' "$ping_ok"
printf '%s\n' "$ping_ok" | read_all grep -qx 'path direct'
printf '%s\n' "$ping_ok" | read_all grep -q '^rtt_ms '

echo "=== [C] enroll desk with an ES256 ID token ==="
mint desk es1 --sub bob --email bob@example.test
enroll_oidc desk desk
wait_log coord "oidc accept sub bob"

mint wrong-issuer es1 --sub carol --email carol@example.test --issuer https://evil.test
mint wrong-audience rs1 --sub carol --email carol@example.test --aud other-client
mint expired es1 --sub carol --email carol@example.test --ttl 60 --age 3600
mint bad-signature rs1 --sub carol --email carol@example.test --tamper
mint unknown-kid es1 --sub carol --email carol@example.test --header-kid ghost
mint wrong-domain es1 --sub carol --email carol@other.test

expect_reject "wrong issuer" wrong-issuer wrong-issuer
expect_reject "wrong audience" wrong-audience wrong-audience
expect_reject "expired" expired expired
expect_reject "bad signature" bad-signature bad-signature
expect_reject "unknown kid" unknown-kid unknown-kid
expect_reject "email domain" email-not-allowed wrong-domain

echo "=== [C] rotate issuer keys: add es2, drop rs1 ==="
# Mint one token with rs1 before the issuer drops rs1.
mint old-key rs1 --sub carol --email carol@example.test
sleep 11
idp rotate --dir /idp --kid es2 --alg ES256 --drop rs1
mint rotated es2 --sub dave --email dave@example.test
enroll_oidc rotated rotated
wait_log coord "oidc accept sub dave"
dc logs coord 2>&1 | show_matching "oidc jwks loaded unknown-kid" | tail -1 | sed 's/^[^|]*| //'
dc logs coord 2>&1 | show_matching "oidc jwks loaded unknown-kid" | tail -1 | read_all grep -q "kids es1 es2"
expect_reject "dropped key rs1" unknown-kid old-key

echo "=== [C] coordinator OIDC log lines ==="
dc logs coord 2>&1 | show_matching -E "oidc |enrolled " | sed 's/^[^|]*| //'

echo "=== [C] no token text in logs or the node store ==="
for name in laptop desk rotated wrong-issuer; do
  head_part="$(dc run --rm --no-deps --entrypoint cut idp -d. -f1 "/tokens/${name}")"
  sig_part="$(dc run --rm --no-deps --entrypoint cut idp -d. -f3 "/tokens/${name}")"
  if dc logs 2>&1 | read_all grep -qF -- "$sig_part"; then
    echo "A log contains ID token text." >&2
    exit 1
  fi
  if dc exec -T coord cat /var/lib/orblx/nodes.json | read_all grep -qF -- "$sig_part"; then
    echo "The node store contains ID token text." >&2
    exit 1
  fi
  : "$head_part"
done
if dc logs 2>&1 | read_all grep -q 'PRIVATE KEY'; then
  echo "A log contains a private key." >&2
  exit 1
fi
echo "token_text_in_logs none"
dc exec -T coord cat /var/lib/orblx/nodes.json | jq -r '.nodes[] | "\(.name) \(.owner)"' 2>/dev/null \
  || dc exec -T coord cat /var/lib/orblx/nodes.json | grep -o '"owner":"[^"]*"'

echo "proof_ok"

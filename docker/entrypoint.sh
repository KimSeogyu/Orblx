#!/bin/sh
# Entrypoint for the official Orblx node image (W25-8).
#
# "node" (the default command) does these steps:
#   1. If the state directory has no SVID, the node enrolls one time with the enroll token.
#   2. The node gets the netmap from the coordinator.
#   3. The node runs "orblx up" in the foreground. "orblx up" renews the SVID from the coordinator.
# All other commands go to the orblx binary, for example "coord serve" or "status".
#
# Environment:
#   ORBLX_COORD              The coordinator address, HOST_IP:PORT. Required.
#   ORBLX_NAME               The node name. Required for the first enroll.
#   ORBLX_BUNDLE_FILE        The public coordinator trust bundle (PEM). Required for the first enroll.
#   ORBLX_ENROLL_TOKEN_FILE  A file with the enroll token. Use this, or ORBLX_ENROLL_TOKEN.
#   ORBLX_ENROLL_TOKEN       The enroll token as a value.
#   ORBLX_ENDPOINT           The underlay endpoint for peers. The default is the container IPv4:443.
#   ORBLX_LISTEN             The QUIC listen address. The default is 0.0.0.0:443.
#   ORBLX_COORD_NAME         The coordinator TLS name. The default is coord.
#   ORBLX_STATE_DIR          The state directory. The default is /var/lib/orblx. Mount a volume here.
#
# This script does not print the token, keys, or certificates.

set -eu

if [ "${1:-node}" != node ]; then
  exec /usr/local/bin/orblx "$@"
fi
shift 2>/dev/null || true

STATE="${ORBLX_STATE_DIR:-/var/lib/orblx}"
LISTEN="${ORBLX_LISTEN:-0.0.0.0:443}"
COORD_NAME="${ORBLX_COORD_NAME:-coord}"

fail() {
  echo "orblx-entrypoint: $*" >&2
  exit 64
}

[ -n "${ORBLX_COORD:-}" ] || fail "Set ORBLX_COORD to the coordinator address."

umask 077
mkdir -p "$STATE"

if [ -s "$STATE/cert.pem" ] && [ -s "$STATE/key.pem" ] && [ -s "$STATE/bundle.pem" ]; then
  echo "orblx-entrypoint: state found, no enroll."
else
  [ -n "${ORBLX_NAME:-}" ] || fail "Set ORBLX_NAME for the first enroll."
  [ -n "${ORBLX_BUNDLE_FILE:-}" ] || fail "Set ORBLX_BUNDLE_FILE for the first enroll."
  [ -s "$ORBLX_BUNDLE_FILE" ] || fail "The file ORBLX_BUNDLE_FILE is empty or missing."
  token_file="${ORBLX_ENROLL_TOKEN_FILE:-}"
  temp_token=""
  if [ -z "$token_file" ]; then
    [ -n "${ORBLX_ENROLL_TOKEN:-}" ] || fail "Set ORBLX_ENROLL_TOKEN_FILE or ORBLX_ENROLL_TOKEN for the first enroll."
    temp_token="$(mktemp /tmp/orblx-token.XXXXXX)"
    printf '%s\n' "$ORBLX_ENROLL_TOKEN" >"$temp_token"
    token_file="$temp_token"
  fi
  [ -s "$token_file" ] || fail "The enroll token file is empty or missing."
  endpoint="${ORBLX_ENDPOINT:-}"
  if [ -z "$endpoint" ]; then
    ip4="$(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')"
    [ -n "$ip4" ] || fail "The container has no IPv4 address. Set ORBLX_ENDPOINT."
    endpoint="${ip4}:443"
  fi
  status=0
  /usr/local/bin/orblx coord enroll \
    --name "$ORBLX_NAME" \
    --coord "$ORBLX_COORD" \
    --bundle "$ORBLX_BUNDLE_FILE" \
    --token-file "$token_file" \
    --state "$STATE" \
    --endpoint "$endpoint" || status=$?
  if [ -n "$temp_token" ]; then
    rm -f "$temp_token"
  fi
  [ "$status" -eq 0 ] || fail "The enroll failed."
  echo "orblx-entrypoint: enrolled ${ORBLX_NAME}."
fi

# The token is not necessary after the enroll. Do not give it to the node process.
unset ORBLX_ENROLL_TOKEN ORBLX_ENROLL_TOKEN_FILE

/usr/local/bin/orblx coord netmap \
  --coord "$ORBLX_COORD" \
  --bundle "$STATE/bundle.pem" \
  --state "$STATE" \
  || echo "orblx-entrypoint: the netmap fetch failed. The node uses the netmap in the state directory." >&2

exec /usr/local/bin/orblx up \
  --state-dir "$STATE" \
  --listen "$LISTEN" \
  --coord "$ORBLX_COORD" \
  --bundle "$STATE/bundle.pem" \
  --coord-name "$COORD_NAME" \
  "$@"

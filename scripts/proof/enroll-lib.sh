# shellcheck shell=bash
# W25-27: enroll one proof node at the coordinator through the normal enroll path (enroll-lib.sh).
# Source this file after pipe-lib.sh.
#
# proof_coord_wait_bundle COORD_STATE_DIR
#   Wait up to 90 s for the coordinator trust bundle. Fail after that.
# proof_coord_enroll BIN COORD_ADDR COORD_STATE_DIR TOKEN_FILE NAME STATE_DIR ENDPOINT WANT_IP
#   Run "orblx coord enroll" on the host into STATE_DIR. The node gets its SVID, its
#   ticket, and the signed netmap and grants from the coordinator. The function fails
#   when the coordinator gives an overlay IP other than WANT_IP (the proof netmaps and
#   gates use fixed addresses; the coordinator gives them in enroll order).
#   It prints the enroll lines. It does not print the token, the key, or the ticket.

proof_coord_wait_bundle() {
  local dir="$1"
  for _ in $(seq 1 90); do
    if [[ -s "$dir/trust-bundle.pem" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle in 90 s." >&2
  return 1
}

proof_coord_enroll() {
  local bin="$1" coord="$2" coord_state="$3" token="$4" name="$5" state="$6" endpoint="$7" want_ip="$8"
  local got
  echo "=== [C] enroll ${name} at the coordinator ${coord} ==="
  mkdir -p "$state"
  "$bin" coord enroll \
    --name "$name" \
    --coord "$coord" \
    --coord-name coord \
    --bundle "$coord_state/trust-bundle.pem" \
    --token-file "$token" \
    --state "$state" \
    --endpoint "$endpoint"
  got="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["self"]["overlay_ip"])' "$state/netmap.json")"
  if [[ "$got" != "$want_ip" ]]; then
    echo "The coordinator gave ${name} the overlay IP ${got}, not ${want_ip}." >&2
    return 1
  fi
  echo "enroll ${name} overlay_ip ${got} ok"
}

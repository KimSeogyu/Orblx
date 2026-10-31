# shellcheck shell=bash
# W25-27 lab-ticket guard.
# proof-lock.sh sources this file, so every proof that takes the box proof lock gets it.
#
# 1. proof_lab_ticket_static_guard (proof_lock_take calls it):
#    a manifest proof (a proof| line in sweep-manifest.txt) fails at once when its
#    script text makes lab material: "node-issue", "direct-issue", or "connector issue".
# 2. proof_ticket_guard COORD_NAME STATE_DIR...: a proof calls it after the coordinator
#    enroll and before the nodes start. It reads STATE_DIR/ticket.bin and fails unless
#    the issuer is spiffe://orblx.local/coord/COORD_NAME, the subject is the node in
#    STATE_DIR/node-name, and the ticket life is 900 s or less.
#    The guard reads the ticket claims only. It does not print the ticket.
# Env:
#   ORBLX_PROOF_MANIFEST  manifest file for the static guard (tests set it).
#                         Default: sweep-manifest.txt next to this file.

PROOF_TICKET_GUARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOF_LAB_TICKET_RE='node-issue|direct-issue|connector issue'

# Print the manifest proof name for the script PATH, or nothing.
proof_manifest_name_for() {
  local path="$1" manifest root real kind name script rest
  manifest="${ORBLX_PROOF_MANIFEST:-$PROOF_TICKET_GUARD_DIR/sweep-manifest.txt}"
  [[ -f "$manifest" && -f "$path" ]] || return 0
  real="$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
  root="$(cd "$(dirname "$manifest")/../.." && pwd)"
  while IFS='|' read -r kind name script rest; do
    [[ "$kind" == "proof" ]] || continue
    if [[ "$real" == "$root/$script" ]]; then
      printf '%s\n' "$name"
      return 0
    fi
  done <"$manifest"
  return 0
}

# Fail when the running script is a manifest proof that makes lab material.
proof_lab_ticket_static_guard() {
  local path="${1:-$0}" name hits
  name="$(proof_manifest_name_for "$path")"
  [[ -n "$name" ]] || return 0
  hits="$(grep -nE -- "$PROOF_LAB_TICKET_RE" "$path" || true)"
  if [[ -n "$hits" ]]; then
    echo "proof_ticket_guard FAIL ${name}: the manifest proof makes lab tickets (${path}):" >&2
    printf '%s\n' "$hits" >&2
    echo "A manifest proof must use tickets from the coordinator enroll path." >&2
    return 1
  fi
  echo "proof_ticket_guard ${name} static ok"
}

# proof_ticket_guard COORD_NAME STATE_DIR...
proof_ticket_guard() {
  local coord_name="$1"
  shift
  [[ "$#" -ge 1 ]] || { echo "proof_ticket_guard FAIL: no state directory" >&2; return 1; }
  python3 - "$coord_name" "$@" <<'PY'
import os
import struct
import sys

MAX_LIFE = 900
coord_name = sys.argv[1]
want_issuer = "spiffe://orblx.local/coord/" + coord_name
bad = 0


def counted(data, at):
    (size,) = struct.unpack_from(">H", data, at)
    at += 2
    return data[at:at + size].decode("utf-8"), at + size


for state in sys.argv[2:]:
    path = os.path.join(state, "ticket.bin")
    try:
        data = open(path, "rb").read()
        if not data or data[0] != 1:
            raise ValueError("version")
        issuer, at = counted(data, 1)
        subject, at = counted(data, at)
        not_before, expires = struct.unpack_from(">QQ", data, at)
    except (OSError, ValueError, struct.error, UnicodeDecodeError) as err:
        print("proof_ticket_guard FAIL %s: ticket.bin is missing or not valid (%s)" % (state, type(err).__name__), file=sys.stderr)
        bad += 1
        continue
    life = expires - not_before
    name_path = os.path.join(state, "node-name")
    node = open(name_path).read().strip() if os.path.exists(name_path) else ""
    want_subject = "spiffe://orblx.local/node/" + node
    problems = []
    if issuer != want_issuer:
        problems.append("issuer %s is not %s" % (issuer, want_issuer))
    if not node:
        problems.append("node-name is missing (the coordinator enroll writes it)")
    elif subject != want_subject:
        problems.append("subject %s is not %s" % (subject, want_subject))
    if life <= 0 or life > MAX_LIFE:
        problems.append("ticket life %d s is not 1 to %d s" % (life, MAX_LIFE))
    if problems:
        print("proof_ticket_guard FAIL %s: %s" % (state, "; ".join(problems)), file=sys.stderr)
        bad += 1
    else:
        print("proof_ticket_guard node %s issuer %s life_s %d expires %d ok" % (node, issuer, life, expires))
sys.exit(1 if bad else 0)
PY
}

# proof_ticket_expires STATE_DIR: print the expires time (unix s) of STATE_DIR/ticket.bin.
proof_ticket_expires() {
  python3 - "$1" <<'PY'
import struct
import sys

data = open(sys.argv[1] + "/ticket.bin", "rb").read()
at = 1
for _ in range(2):
    (size,) = struct.unpack_from(">H", data, at)
    at += 2 + size
print(struct.unpack_from(">QQ", data, at)[1])
PY
}

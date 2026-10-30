#!/usr/bin/env bash
# The steps of the policy GitOps example workflow (W25-9).
# The workflow and the local proof run this same script.
#
# Usage:
#   steps.sh test  FILE   Run the policy tests. No coordinator call.
#   steps.sh plan  FILE   Run the tests, then diff the file with the live policy.
#   steps.sh apply FILE   Run the tests, diff, then apply with the sha that the diff saw.
#
# Environment:
#   ORBLX_BIN             The orblx binary (default orblx).
#   ORBLX_COORD           The coordinator address host:port (plan and apply).
#   ORBLX_COORD_NAME      The coordinator name (default coord).
#   ORBLX_BUNDLE          The coordinator trust bundle file (plan and apply).
#   ORBLX_READ_TOKEN_FILE A file with a policy:read token (plan and apply diff).
#   ORBLX_WRITE_TOKEN_FILE A file with a policy:write token (apply).
#   ORBLX_EXPECT_SHA      Optional. apply uses this sha and does not diff again.
#                         Use the sha that a reviewed plan printed.
#   GITHUB_OUTPUT         Optional. The script writes live_sha256 and changed here.
#
# The script never prints a token. It reads token files only through orblx.
# Exit codes: 0 ok, 1 the check failed or the apply was refused, 2 usage or setup error.
set -euo pipefail

ORBLX_BIN="${ORBLX_BIN:-orblx}"
mode="${1:-}"
file="${2:-}"
if [[ -z "$mode" || -z "$file" ]]; then
  echo "usage: steps.sh test|plan|apply FILE" >&2
  exit 2
fi
if [[ ! -f "$file" ]]; then
  echo "steps: the file $file is missing" >&2
  exit 2
fi

output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

need() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "steps: set $name" >&2
    exit 2
  fi
}

remote() {
  need ORBLX_COORD
  need ORBLX_BUNDLE
  REMOTE=(--coord "$ORBLX_COORD" --coord-name "${ORBLX_COORD_NAME:-coord}" --bundle "$ORBLX_BUNDLE")
}

run_test() {
  echo "== step: policy test"
  if ! "$ORBLX_BIN" policy test --file "$file"; then
    echo "steps: the policy test failed. Nothing is applied." >&2
    exit 1
  fi
}

# run_diff: diff the file with the live policy. Set LIVE_SHA and SAME (true or false).
run_diff() {
  remote
  need ORBLX_READ_TOKEN_FILE
  echo "== step: policy diff"
  local sha_file rc
  sha_file="$(mktemp)"
  set +e
  "$ORBLX_BIN" policy diff --file "$file" "${REMOTE[@]}" \
    --token-file "$ORBLX_READ_TOKEN_FILE" --sha-out "$sha_file"
  rc=$?
  set -e
  case "$rc" in
    0) SAME=true ;;
    1) SAME=false ;;
    *)
      rm -f "$sha_file"
      echo "steps: the policy diff did not run (exit $rc)." >&2
      exit 2
      ;;
  esac
  LIVE_SHA="$(tr -d '[:space:]' < "$sha_file")"
  rm -f "$sha_file"
  output live_sha256 "$LIVE_SHA"
  output changed "$([[ "$SAME" == true ]] && echo false || echo true)"
}

run_apply() {
  remote
  need ORBLX_WRITE_TOKEN_FILE
  local expect="$1"
  echo "== step: policy apply (expect ${expect})"
  if ! "$ORBLX_BIN" policy apply --file "$file" "${REMOTE[@]}" \
    --token-file "$ORBLX_WRITE_TOKEN_FILE" --expect-sha "$expect"; then
    echo "steps: the policy apply was refused. The live policy is not changed by this run." >&2
    exit 1
  fi
}

case "$mode" in
  test)
    run_test
    ;;
  plan)
    run_test
    run_diff
    echo "plan live_sha256 ${LIVE_SHA} same ${SAME}"
    ;;
  apply)
    run_test
    if [[ -n "${ORBLX_EXPECT_SHA:-}" ]]; then
      expect="$ORBLX_EXPECT_SHA"
    else
      run_diff
      expect="$LIVE_SHA"
    fi
    run_apply "$expect"
    ;;
  *)
    echo "usage: steps.sh test|plan|apply FILE" >&2
    exit 2
    ;;
esac

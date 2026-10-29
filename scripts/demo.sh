#!/usr/bin/env bash
# Run City Breeze, Agent JIT, and Radioactive NAT on the live harness.
# City Breeze signs in through the mock IdP page.
# The script follows that sign-in with curl.
# The later actions match the browser smash buttons.
# The script checks the event kinds from those actions.
# The script checks that the default page is the game.
# The script rejects a canned keyframe animation.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

addr="${GYEOL_DEMO_ADDR:-127.0.0.1:8787}"
base="http://${addr}"
log=$(mktemp)
work=$(mktemp -d)
pid=""

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && -s "$log" ]]; then
    echo "The harness log follows."
    cat "$log"
  fi
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
  rm -f "$log"
}
trap cleanup EXIT

echo "The demo starts the harness at ${base}."
setsid cargo run -q -p gyeol-sim -- --listen "$addr" >"$log" 2>&1 &
pid=$!

ready=0
for _ in $(seq 1 600); do
  if curl --fail --silent "${base}/api/state" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "The harness stopped before it was ready."
    exit 1
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "The harness did not open ${base}."
  exit 1
fi

echo "The harness is ready at ${base}."

python3 - "$base" <<'PY'
import sys
import urllib.request

base = sys.argv[1]
files = {}
for path in ("/", "/style.css", "/app.js"):
    with urllib.request.urlopen(base + path, timeout=10) as response:
        files[path] = response.read().decode("utf-8", "replace")
    if "@keyframes" in files[path] or "requestAnimationFrame" in files[path]:
        raise SystemExit(f"The file {path} contains a canned animation.")
page = files["/"]
script = files["/app.js"]
if 'id="game"' not in page:
    raise SystemExit("The default page is not the game.")
if 'id="eng" hidden' not in page:
    raise SystemExit("The engineering view is not hidden.")
if 'Play City Breeze' not in page or 'UDP block' not in page:
    raise SystemExit("The game controls are missing.")
if 'new EventSource("/events")' not in script or "applyFeed" not in script:
    raise SystemExit("The game does not read the feed.")
for needle in (
    'id="curve"',
    'id="runbar"',
    'id="inspector"',
    'id="toolbox"',
    'id="endcard"',
    "Next Level",
    "data-state=\"up\"",
    "data-state=\"degraded\"",
    "data-state=\"down\"",
    "data-state=\"revoked\"",
):
    if needle not in page:
        raise SystemExit("The game page is missing " + needle + ".")
if "RUN_MS = 35000" not in script or "Soft win" not in script:
    raise SystemExit("The timed run or the end card is missing.")
print("The default page is the game. The game reads the feed. The page has no canned keyframe animation.")
PY

seqfile="${work}/seq"
printf '0\n' >"$seqfile"

oidc_easy() {
  local state
  state=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
  local page="${work}/login.html"
  local login_code
  login_code=$(curl --silent --show-error --output "$page" --write-out '%{http_code}' \
    "${base}/oidc/authorize?client_id=gyeol-sim&response_type=code&redirect_uri=%2Foidc%2Fcallback&state=${state}&scope=openid")
  if [[ "$login_code" != "200" ]]; then
    echo "The mock IdP login page returned ${login_code}."
    exit 1
  fi
  python3 - "$page" "$state" <<'PY'
import sys
page, state = sys.argv[1:3]
text = open(page, encoding="utf-8").read()
for needle in (
    "Sign in",
    "https://oidc.gyeol.local",
    "gyeol-issue",
    "Subject: ada",
    f'value="{state}"',
):
    if needle not in text:
        raise SystemExit("The mock IdP login page is missing " + needle + ".")
if "@keyframes" in text:
    raise SystemExit("The mock IdP login page contains an animation.")
print("The mock IdP login page is ready.")
PY
  local headers="${work}/login.headers"
  local posted="${work}/login.body"
  local post_code
  post_code=$(curl --silent --show-error --dump-header "$headers" --output "$posted" --write-out '%{http_code}' \
    --data-urlencode "subject=ada" \
    --data-urlencode "client_id=gyeol-sim" \
    --data-urlencode "response_type=code" \
    --data-urlencode "redirect_uri=/oidc/callback" \
    --data-urlencode "state=${state}" \
    --data-urlencode "scope=openid" \
    "${base}/oidc/authorize")
  if [[ "$post_code" != "303" ]]; then
    echo "The mock IdP sign-in returned ${post_code}."
    cat "$posted"
    exit 1
  fi
  local location
  location=$(python3 - "$headers" "$state" <<'PY'
import sys
path, state = sys.argv[1:3]
location = ""
for line in open(path, encoding="utf-8", errors="replace"):
    if line.lower().startswith("location:"):
        location = line.split(":", 1)[1].strip()
if not location.startswith("/oidc/callback?"):
    raise SystemExit("The mock IdP redirect is not the callback.")
if "state=" + state not in location:
    raise SystemExit("The mock IdP redirect state differs.")
print(location)
PY
)
  local callback_headers="${work}/callback.headers"
  local callback_body="${work}/callback.body"
  local callback_code
  callback_code=$(curl --silent --show-error --dump-header "$callback_headers" --output "$callback_body" --write-out '%{http_code}' \
    "${base}${location}")
  if [[ "$callback_code" != "303" ]]; then
    echo "The mock IdP callback returned ${callback_code}."
    cat "$callback_body"
    exit 1
  fi
  python3 - "$callback_headers" <<'PY'
import sys
location = ""
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if line.lower().startswith("location:"):
        location = line.split(":", 1)[1].strip()
if location != "/":
    raise SystemExit("The callback did not return to the harness page.")
print("The mock IdP callback issued the City Breeze session.")
PY
  local body="${work}/easy.json"
  curl --fail --silent --show-error "${base}/api/state" --output "$body"
  check_snapshot easy "$body"
}

check_snapshot() {
  local name=$1
  local body=$2
  local prev
  prev=$(cat "$seqfile")
  python3 - "$body" "$name" "$prev" "$seqfile" <<'PY'
import json
import sys

path, name, prev_text, seqfile = sys.argv[1:5]
prev = int(prev_text)
state = json.load(open(path, encoding="utf-8"))

def fail(message):
    raise SystemExit(message)

if state.get("skeleton") is not False:
    fail("The harness skeleton flag is not false.")
if state.get("audit", {}).get("ok") is not True:
    fail("The audit check in the snapshot is not ok.")

raw = open(path, encoding="utf-8").read()
if "BEGIN " in raw or "PRIVATE" in raw:
    fail("The snapshot contains PEM text.")

events = state["events"]
new = []
last = prev
for event in events:
    seq = int(event["seq"])
    if seq > last:
        last = seq
    if seq <= prev:
        continue
    try:
        body = json.loads(event["detail"])
    except json.JSONDecodeError:
        fail(f"Event {seq} is not JSON.")
    new.append(body)

if not new:
    fail(f"{name} produced no events.")

kinds = [body["kind"] for body in new]
print(name + " kinds " + " ".join(kinds))

expected = {
    "easy": [
        "difficulty_selected",
        "svid.issued",
        "ticket.verified",
        "quic_hello",
        "frame_tx",
        "frame_rx",
        "frame_tx",
        "connector_https",
        "frame_tx",
        "connector_https",
        "session_up",
    ],
    "revoke": [
        "smash_revoke",
        "svid.revoked",
        "session.dropped",
        "session_down",
    ],
    "medium": [
        "difficulty_selected",
        "agent.spawned",
        "ticket.verified",
        "jit.allow",
        "jit.deny",
        "svid.expired",
        "frame_tx",
        "session_up",
        "session_down",
        "session_down",
    ],
    "agent": [
        "smash_agent_spawn",
        "agent.spawned",
        "ticket.verified",
        "jit.allow",
        "jit.deny",
        "svid.expired",
        "frame_tx",
        "session_up",
        "session_down",
        "session_down",
    ],
    "hard": [
        "difficulty_selected",
        "svid.issued",
        "svid.revoked",
        "session.dropped",
        "nat.inject",
        "path.allocate",
        "path.direct",
        "nat.probe",
        "path.down",
        "path.switch",
        "relay.hop",
        "path.relay",
        "path.up",
        "path.down",
        "session_down",
    ],
    "udp": [
        "smash_udp_block",
        "svid.issued",
        "nat.inject",
        "path.allocate",
        "path.direct",
        "nat.probe",
        "path.down",
        "path.switch",
        "relay.hop",
        "path.relay",
        "path.up",
    ],
}
if kinds != expected[name]:
    fail(name + " kinds differ from the expected list.")

selected = [level for level in state["levels"] if level.get("selected")]
if len(selected) != 1:
    fail("The snapshot does not show one selected level.")
level = selected[0]
statuses = [step["status"] for step in level["steps"]]

def need(body, key, value):
    if body.get(key) != value:
        fail(name + " " + body.get("kind", "") + " " + key + " differs.")

if name == "easy":
    if level["id"] != "city_breeze":
        fail("Easy did not select City Breeze.")
    if statuses != ["pass", "pass", "pass", "pass"]:
        fail("Easy steps are not all pass.")
    if state["session"]["svid"]["state"] != "up":
        fail("The Easy SVID is not up.")
    if state["session"]["quic"]["state"] != "up":
        fail("The Easy QUIC path is not up.")
    https = [body for body in new if body["kind"] == "connector_https"]
    need(https[0], "host", "app-a.orblx.test")
    need(https[1], "host", "app-b.orblx.test")
    need(https[0], "status", 200)
    need(https[1], "status", 200)
    print("easy pass")

if name == "revoke":
    if level["id"] != "city_breeze":
        fail("Revoke left City Breeze.")
    dropped = next(body for body in new if body["kind"] == "session.dropped")
    within = dropped.get("within_s")
    if not isinstance(within, int) or within > 60:
        fail("within_s is missing or above 60.")
    if state["session"]["svid"]["state"] != "revoked":
        fail("The SVID state is not revoked.")
    if state["session"]["quic"]["state"] != "down":
        fail("The QUIC path is not down after revoke.")
    print("revoke pass within_s " + str(within))

if name in ("medium", "agent"):
    if level["id"] != "agent_jit":
        fail("The agent run did not select Agent JIT.")
    if statuses != ["pass", "pass", "pass", "pass"]:
        fail("Agent JIT steps are not all pass.")
    if state["session"]["svid"]["state"] != "expired":
        fail("The agent SVID is not expired.")
    if state["audit"]["deny"] != 2:
        fail("The agent audit deny count is not 2.")
    allow = next(body for body in new if body["kind"] == "jit.allow")
    deny = next(body for body in new if body["kind"] == "jit.deny")
    if "app-a.orblx.test" not in allow.get("detail", ""):
        fail("jit.allow does not name application A.")
    if "app-b.orblx.test" not in deny.get("detail", ""):
        fail("jit.deny does not name application B.")
    print(name + " pass")

if name in ("hard", "udp"):
    if level["id"] != "radioactive_nat":
        fail("The NAT run did not select Radioactive NAT.")
    direct_at = kinds.index("path.direct")
    switch_at = kinds.index("path.switch")
    if direct_at >= switch_at:
        fail("path.direct is not before path.switch.")
    direct = new[direct_at]
    need(direct, "ok", False)
    allocate = next(body for body in new if body["kind"] == "path.allocate")
    need(allocate, "overlay_ip", "10.8.0.1")
    relay = next(body for body in new if body["kind"] == "path.relay")
    need(relay, "hop", "tcp")
    up = next(body for body in new if body["kind"] == "path.up")
    need(up, "path", "relay")
    inject = next(body for body in new if body["kind"] == "nat.inject")
    need(inject, "mode", "udp_block")
    blob = json.dumps(new)
    if "stick" in blob or "upgrade" in blob:
        fail("The NAT feed names stick or upgrade.")
    if name == "hard":
        if statuses != ["pass", "not_run", "pass", "pass", "pass", "pass"]:
            fail("Hard step status differs.")
        dropped = next(body for body in new if body["kind"] == "session.dropped")
        within = dropped.get("within_s")
        if not isinstance(within, int) or within > 60:
            fail("Hard within_s is missing or above 60.")
        if state["session"]["svid"]["state"] != "revoked":
            fail("The Hard SVID is not revoked.")
        print("hard pass within_s " + str(within))
    else:
        if statuses != ["pass", "not_run", "pass", "pass", "pass", "not_run"]:
            fail("UDP block step status differs.")
        if state["session"]["quic"]["state"] != "up":
            fail("The Relay path is not up after UDP block.")
        print("udp pass")

open(seqfile, "w", encoding="utf-8").write(str(last) + "\n")
PY
}

post() {
  local name=$1
  local path=$2
  local id=$3
  local body="${work}/${name}.json"
  curl --fail --silent --show-error \
    --header 'content-type: application/json' \
    --data "{\"id\":\"${id}\"}" \
    "${base}${path}" \
    --output "$body"
  check_snapshot "$name" "$body"
}

oidc_easy
post revoke /api/smash revoke
post medium /api/difficulty medium
post agent /api/smash agent_spawn
post hard /api/difficulty hard
post udp /api/smash udp_block

echo "demo pass"

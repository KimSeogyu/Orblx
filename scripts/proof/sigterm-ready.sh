#!/usr/bin/env bash
# Root proof: SIGTERM during node start prints "The node is down." within 5 s.
# The script uses a netns, throwaway identities from `orblx node-issue`, and a static netmap.
# It does not use a coordinator. It does not print a key, a ticket, or a token.
# Usage: scripts/proof/sigterm-ready.sh [LOG]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
LOG="${1:-$ROOT/target/sigterm-ready.log}"
mkdir -p "$(dirname "$LOG")"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "not run: this proof needs root and a netns"
  exit 2
fi
if ! command -v ip >/dev/null 2>&1; then
  echo "not run: ip is missing"
  exit 2
fi

NS="orblx-sigterm-$$"
WORK="$(mktemp -d /tmp/orblx-sigterm.XXXXXX)"
cleanup() {
  ip netns delete "$NS" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "profile release" | tee "$LOG"
rustc -V | tee -a "$LOG"
cargo -V | tee -a "$LOG"
echo "commit $(git rev-parse HEAD)" | tee -a "$LOG"

cargo build --release --locked -p orblx-cli --bin orblx
BIN="$ROOT/target/release/orblx"
sha256sum "$BIN" | awk '{print "binary_sha256 " $1}' | tee -a "$LOG"

ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

"$BIN" node-issue --out "$WORK/id" --node a=100.64.0.1 --node b=100.64.0.2 >/dev/null
STATE="$WORK/id/a"
cat >"$STATE/netmap.json" <<'EOF'
{
  "version": 1,
  "self": {"name": "a", "overlay_ip": "100.64.0.1"},
  "peers": [{
    "name": "b",
    "overlay_ip": "100.64.0.2",
    "svid": "spiffe://orblx.local/node/b",
    "endpoints": ["127.0.0.1:51821"],
    "routes": []
  }]
}
EOF
chmod 0644 "$STATE/netmap.json"

cat >"$WORK/shim.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
static int (*real_sa)(int, const struct sigaction*, struct sigaction*);
int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
  if (!real_sa) real_sa = dlsym(RTLD_NEXT, "sigaction");
  int r = real_sa(sig, act, old);
  if (act && (sig == SIGTERM || sig == SIGINT)) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    char b[160];
    int n = snprintf(b, sizeof b, "SHIM sigaction sig=%d tid=%ld mono_ns=%lld\n",
      sig, (long)syscall(SYS_gettid), (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    write(2, b, (size_t)n);
    const char *s = getenv("SHIM_SLEEP_MS");
    if (sig == SIGTERM && s && atoi(s) > 0) {
      struct timespec d = {0, atoi(s) * 1000000L};
      nanosleep(&d, 0);
    }
  }
  return r;
}
EOF
gcc -shared -fPIC -o "$WORK/shim.so" "$WORK/shim.c" -ldl

export ORBLX_SIGTERM_BIN="$BIN"
export ORBLX_SIGTERM_NS="$NS"
export ORBLX_SIGTERM_STATE="$STATE"
export ORBLX_SIGTERM_SHIM="$WORK/shim.so"
export ORBLX_SIGTERM_LOG="$LOG"

python3 - <<'PY'
import os, signal, subprocess, sys, threading, time

BIN = os.environ["ORBLX_SIGTERM_BIN"]
NS = os.environ["ORBLX_SIGTERM_NS"]
STATE = os.environ["ORBLX_SIGTERM_STATE"]
SHIM = os.environ["ORBLX_SIGTERM_SHIM"]
LOG = os.environ["ORBLX_SIGTERM_LOG"]
PID_FILE = os.path.join(STATE, "orblxd.pid")
READY = "The node is ready. SIGTERM stops the node."
TUN = "The TUN device is"
DOWN = "The node is down."

fails = []
counts = {}

def record(case, ok, reason):
    row = counts.setdefault(case, {"runs": 0, "pass": 0, "fail": 0})
    row["runs"] += 1
    if ok:
        row["pass"] += 1
    else:
        row["fail"] += 1
        fails.append(f"FAIL {case} i={row['runs']} reason={reason}")

def one(case, trigger, delay_ms, shim):
    env = dict(os.environ)
    if shim:
        env["LD_PRELOAD"] = SHIM
        env["SHIM_SLEEP_MS"] = "200"
    cmd = [
        "ip", "netns", "exec", NS, BIN, "up",
        "--netmap", os.path.join(STATE, "netmap.json"),
        "--state-dir", STATE,
        "--listen", "127.0.0.1:51820",
        "--metrics", "off",
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, text=True, bufsize=1,
    )
    lines = []
    marks = {}
    ready = threading.Event()
    tun = threading.Event()
    shim_ev = threading.Event()

    def reader():
        for line in proc.stdout:
            now = time.monotonic()
            text = line.rstrip("\n")
            lines.append((now, text))
            if READY in text:
                marks["ready"] = now
                ready.set()
            if TUN in text:
                marks["tun"] = now
                tun.set()
            if "SHIM sigaction sig=15" in text:
                marks["shim"] = now
                shim_ev.set()

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    trigger_ev = {"ready": ready, "tun": tun, "shim": shim_ev}[trigger]
    if not trigger_ev.wait(20):
        proc.kill()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGKILL)
            proc.wait()
        record(case, False, "no_trigger")
        return
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    killed = time.monotonic()
    try:
        os.kill(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        record(case, False, "gone_before_term")
        proc.wait()
        return
    deadline = time.monotonic() + 20
    rc = None
    while time.monotonic() < deadline:
        rc = proc.poll()
        if rc is not None:
            break
        time.sleep(0.05)
    if rc is None:
        proc.send_signal(signal.SIGKILL)
        proc.wait()
        record(case, False, "not_stopped_20s")
        return
    thread.join(2)
    down_at = None
    for stamp, text in lines:
        if DOWN in text and "PRIVATE KEY" not in text:
            down_at = stamp
            break
    if rc != 0:
        record(case, False, f"rc_{rc}")
        return
    if down_at is None:
        record(case, False, "no_down_line")
        return
    if down_at - killed > 5:
        record(case, False, "down_after_5s")
        return
    if os.path.exists(PID_FILE):
        record(case, False, "pid_file_left")
        return
    record(case, True, "")

cases = [("ready_line", "ready", 0, False, 200), ("tun_line", "tun", 0, False, 200)]
for delay in (0, 10, 25, 50, 100, 200, 300, 500):
    cases.append((f"ready_delay_{delay}", "ready", delay, False, 25))
cases.append(("shim_sleep_200", "shim", 0, True, 25))

for name, trigger, delay, shim, count in cases:
    for _ in range(count):
        one(name, trigger, delay, shim)
        time.sleep(0.05)

lines_out = ["case runs pass fail"]
all_ok = True
for name, *_rest in cases:
    row = counts.get(name, {"runs": 0, "pass": 0, "fail": 0})
    lines_out.append(f"{name} {row['runs']} {row['pass']} {row['fail']}")
    if row["fail"] or row["runs"] != row["pass"]:
        all_ok = False
for item in fails:
    lines_out.append(item)
lines_out.append("PASS" if all_ok and not fails else "FAIL")
text = "\n".join(lines_out) + "\n"
sys.stdout.write(text)
with open(LOG, "a", encoding="utf-8") as handle:
    handle.write(text)
sys.exit(0 if all_ok and not fails else 1)
PY

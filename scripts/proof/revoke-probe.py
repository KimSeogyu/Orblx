#!/usr/bin/env python3
"""Run one command again and again and print the times in Unix ms (W24-D proof).

until-deny LABEL SECS EVERY_MS CMD...: stop at the first failure. Print the end time
  of the last success and of the first failure.
hold LABEL SECS EVERY_MS CMD...: run for SECS. Every run must succeed.

"{n}" in CMD becomes the run number. The commands print no secrets.
"""
import subprocess
import sys
import time


def now_ms():
    return int(time.time() * 1000)


def run(cmd, n):
    args = [part.replace("{n}", str(n)) for part in cmd]
    start = now_ms()
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=10)
        code, out = done.returncode, (done.stdout + done.stderr)
    except subprocess.TimeoutExpired:
        code, out = 124, "timeout"
    return start, now_ms(), code, out


def main():
    mode, label, secs, every = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
    cmd = sys.argv[5:]
    stop_at = time.time() + secs
    ok = 0
    fails = 0
    last_ok = 0
    n = 0
    while time.time() < stop_at:
        n += 1
        start, end, code, out = run(cmd, n)
        if code == 0:
            ok += 1
            last_ok = end
        elif mode == "until-deny":
            print(f"probe {label} ok {ok} last_ok_ms {last_ok} "
                  f"deny_run_start_ms {start} first_deny_ms {end} exit {code}")
            for line in out.strip().splitlines()[-4:]:
                print(f"probe {label} deny_output {line}")
            sys.exit(0 if ok > 0 else 1)
        else:
            fails += 1
            print(f"probe {label} fail_ms {end} exit {code}")
            for line in out.strip().splitlines()[-4:]:
                print(f"probe {label} fail_output {line}")
        time.sleep(every / 1000.0)
    if mode == "until-deny":
        print(f"probe {label} ok {ok} last_ok_ms {last_ok} no_deny_in_s {secs}")
        sys.exit(1)
    print(f"probe {label} hold ok {ok} fail {fails}")
    sys.exit(0 if fails == 0 and ok > 0 else 1)


if __name__ == "__main__":
    main()

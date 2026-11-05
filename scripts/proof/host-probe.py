#!/usr/bin/env python3
"""W25-16: in-window host probe for RTT and throughput proofs.

Usage: host-probe.py [INTERVAL_S]   (default ORBLX_HOST_PROBE_INTERVAL or 0.5)

Prints one TSV row per interval until it gets SIGTERM or SIGINT. Every value is for the
interval that ends at the row time. The data lets a reader check a ping spike against the
W25-26 host-stall rule. The probe does not classify anything and no gate reads it.

Columns:
  kst                 row time, ISO 8601 with +09:00 (KST)
  epoch               row time, epoch seconds (the ping samples use the same clock)
  interval_s          the measured interval
  cpu_user_pct cpu_sys_pct cpu_iowait_pct cpu_steal_pct cpu_idle_pct
                      /proc/stat, all CPUs, percent of the interval
  psi_{cpu,io,mem}_{some,full}_ms
                      /proc/pressure stall time in the interval (total delta), ms
  psi_io_full_avg10   /proc/pressure/io full avg10 at the row time
  load1               /proc/loadavg
  disk_busy_pct       the busiest whole disk: io_ticks delta / interval (/proc/diskstats)
  disk_busy_dev       the name of that disk
  disk_inflight       requests in flight on all whole disks at the row time
  disk_wait_ms        weighted I/O time delta of all whole disks (field 14), ms
A missing source prints "-".
"""

import datetime
import os
import signal
import sys
import time

KST = datetime.timezone(datetime.timedelta(hours=9))
COLUMNS = [
    "kst", "epoch", "interval_s",
    "cpu_user_pct", "cpu_sys_pct", "cpu_iowait_pct", "cpu_steal_pct", "cpu_idle_pct",
    "psi_cpu_some_ms", "psi_cpu_full_ms", "psi_io_some_ms", "psi_io_full_ms",
    "psi_mem_some_ms", "psi_mem_full_ms", "psi_io_full_avg10", "load1",
    "disk_busy_pct", "disk_busy_dev", "disk_inflight", "disk_wait_ms",
]


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def cpu():
    text = read("/proc/stat")
    if not text:
        return None
    v = [int(x) for x in text.splitlines()[0].split()[1:]]
    v += [0] * (8 - len(v))
    user, nice, system, idle, iowait, irq, softirq, steal = v[:8]
    return {"user": user + nice, "sys": system + irq + softirq, "idle": idle,
            "iowait": iowait, "steal": steal, "all": sum(v[:8])}


def psi():
    out = {}
    for res in ("cpu", "io", "memory"):
        text = read("/proc/pressure/" + res) or ""
        for line in text.splitlines():
            kind, *fields = line.split()
            kv = dict(f.split("=") for f in fields)
            out[(res, kind)] = (int(kv["total"]), float(kv["avg10"]))
    return out


def whole_disks():
    try:
        names = os.listdir("/sys/block")
    except OSError:
        return set()
    return {n for n in names if not n.startswith(("loop", "ram", "zram", "dm-", "md", "sr"))}


def disks(names):
    text = read("/proc/diskstats") or ""
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 14 and p[2] in names:
            out[p[2]] = (int(p[11]), int(p[12]), int(p[13]))  # in flight, io_ticks ms, weighted ms
    return out


def snapshot(names):
    return time.time(), time.monotonic(), cpu(), psi(), disks(names)


def row(prev, cur):
    _, m0, c0, p0, d0 = prev
    epoch, m1, c1, p1, d1 = cur
    dt = m1 - m0
    r = {"kst": datetime.datetime.fromtimestamp(epoch, KST).isoformat(timespec="milliseconds"),
         "epoch": "%.3f" % epoch, "interval_s": "%.3f" % dt}
    if c0 and c1 and c1["all"] > c0["all"]:
        tot = c1["all"] - c0["all"]
        for key, col in (("user", "cpu_user_pct"), ("sys", "cpu_sys_pct"), ("iowait", "cpu_iowait_pct"),
                         ("steal", "cpu_steal_pct"), ("idle", "cpu_idle_pct")):
            r[col] = "%.1f" % (100.0 * (c1[key] - c0[key]) / tot)
    for res, short in (("cpu", "cpu"), ("io", "io"), ("memory", "mem")):
        for kind in ("some", "full"):
            k = (res, kind)
            if k in p0 and k in p1:
                r["psi_%s_%s_ms" % (short, kind)] = "%.1f" % ((p1[k][0] - p0[k][0]) / 1000.0)
    if ("io", "full") in p1:
        r["psi_io_full_avg10"] = "%.2f" % p1[("io", "full")][1]
    load = read("/proc/loadavg")
    if load:
        r["load1"] = load.split()[0]
    if d1:
        busy = [((d1[n][1] - d0[n][1]) / (dt * 10.0), n) for n in d1 if n in d0 and dt > 0]
        if busy:
            pct, dev = max(busy)
            r["disk_busy_pct"] = "%.1f" % min(pct, 100.0)
            r["disk_busy_dev"] = dev
        r["disk_inflight"] = str(sum(v[0] for v in d1.values()))
        r["disk_wait_ms"] = str(sum(d1[n][2] - d0[n][2] for n in d1 if n in d0))
    return "\t".join(r.get(c, "-") for c in COLUMNS)


def main(argv):
    interval = float(argv[1]) if len(argv) > 1 else float(os.environ.get("ORBLX_HOST_PROBE_INTERVAL", "0.5"))
    if not 0 < interval <= 1:
        print("host-probe: the interval must be above 0 and at most 1 s.", file=sys.stderr)
        return 2
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    names = whole_disks()
    print("\t".join(COLUMNS), flush=True)
    prev = snapshot(names)
    nxt = prev[1] + interval
    while not stop:
        time.sleep(max(0.0, nxt - time.monotonic()))
        nxt += interval
        cur = snapshot(names)
        print(row(prev, cur), flush=True)
        prev = cur
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        sys.exit(0)

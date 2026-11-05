#!/usr/bin/env python3
"""W25-42 step 2 diagnostic sampler (not a gate). Run it on the HOST as root.

It needs no tool beyond python3 and tracefs. It writes to --dir:

sched-threads.txt.gz, one "T" line each --tick (10 ms):
  T <unix_ns> <mono_ns> <tid>:<state><cpu>:<run_us>:<wait_us> ...
  per tracked thread: state (R/S/D/...) and CPU (field 39 'processor') from
  /proc/<pid>/task/<tid>/stat, and the run and run-queue wait time deltas since the last
  tick from /proc/<pid>/task/<tid>/schedstat. A thread that waits runnable shows wait_us.
  "M <mono_ns> <tid> <role> <node> <comm>" maps a tid when it is first seen.
  "N <unix_ns> <mono_ns> <node>:<rx_pkts>:<tx_pkts> ..." are the KERNEL counters of the TUN
  device (orblx0) of each node, read each tick from /proc/<node pid>/net/dev. They do not
  depend on any node thread. tx = kernel to the node (node TUN read), rx = node to kernel
  (node TUN write).
cpu-stat.txt: one "C" line each --cpu-every ticks (100 ms) with the per-CPU /proc/stat
  deltas in USER_HZ ticks: cpuN:user,nice,system,idle,iowait,irq,softirq,steal.
cpu-heartbeat.txt: one process pinned to each CPU wakes each 5 ms. "L cpu unix_ns mono_ns
  late_us" when a wake is 20 ms or more late; "H cpu unix_ns max_late_us" each second. A
  frozen vCPU stalls its own heartbeat, and steal does not have to show it.
sched-trace.txt.gz (with --trace): tracefs instance "orblx-w2542" with sched_switch,
  sched_wakeup and sched_migrate_task, trace_clock mono, filtered by COMM (ping, orblx-*,
  tokio-runtime-w, the host prober "orblx-hprobe"). The box runs in a pid namespace, so
  tracefs pids are kernel-global and do not match /proc pids; the tid to CPU map per
  10 ms comes from sched-threads. The instance is removed at exit.

Tracked threads (re-scanned each second): each --prober NAME=PID; each process named "ping"
in the net namespace of a --node (role ping, with its destination); every other process in
that net namespace (role node: the orblx node and short "orblx status" execs). --node PID
can be any process in the node's net namespace.
"""
import argparse
import gzip
import os
import signal
import resource
import threading
import time

TRACEFS = "/sys/kernel/tracing"
INSTANCE = TRACEFS + "/instances/orblx-w2542"
STOP = threading.Event()


def readf(path):
    with open(path) as f:
        return f.read()


def netns(pid):
    try:
        return os.readlink(f"/proc/{pid}/ns/net")
    except OSError:
        return None


class Thread:
    __slots__ = ("tid", "stat_fd", "sched_fd", "run", "wait")

    def __init__(self, pid, tid):
        self.tid = tid
        self.stat_fd = os.open(f"/proc/{pid}/task/{tid}/stat", os.O_RDONLY)
        self.sched_fd = os.open(f"/proc/{pid}/task/{tid}/schedstat", os.O_RDONLY)
        self.run = None
        self.wait = None

    def sample(self):
        st = os.pread(self.stat_fd, 1024, 0)
        ss = os.pread(self.sched_fd, 128, 0).split()
        rest = st[st.rindex(b")") + 2:].split()
        state = rest[0].decode()
        cpu = rest[36].decode()
        run, wait = int(ss[0]), int(ss[1])
        dr = 0 if self.run is None else (run - self.run) // 1000
        dw = 0 if self.wait is None else (wait - self.wait) // 1000
        self.run, self.wait = run, wait
        return f"{self.tid}:{state}{cpu}:{dr}:{dw}"

    def close(self):
        for fd in (self.stat_fd, self.sched_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def write_trace(path, text):
    with open(path, "w") as f:
        f.write(text)


def trace_setup(buffer_kb):
    if not os.path.isdir(INSTANCE):
        os.mkdir(INSTANCE)
    write_trace(INSTANCE + "/trace_clock", "mono")
    write_trace(INSTANCE + "/buffer_size_kb", str(buffer_kb))
    trace_filter()
    for ev in ("sched_switch", "sched_wakeup", "sched_migrate_task"):
        write_trace(f"{INSTANCE}/events/sched/{ev}/enable", "1")
    write_trace(INSTANCE + "/tracing_on", "1")


COMMS = ['"ping"', '"orblx*"', '"tokio-runtime-w"']


def trace_filter():
    sw = " || ".join(f"prev_comm ~ {c} || next_comm ~ {c}" for c in COMMS)
    one = " || ".join(f"comm ~ {c}" for c in COMMS)
    write_trace(f"{INSTANCE}/events/sched/sched_switch/filter", sw)
    write_trace(f"{INSTANCE}/events/sched/sched_wakeup/filter", one)
    write_trace(f"{INSTANCE}/events/sched/sched_migrate_task/filter", one)


def trace_teardown():
    try:
        write_trace(INSTANCE + "/tracing_on", "0")
        for ev in ("sched_switch", "sched_wakeup", "sched_migrate_task"):
            write_trace(f"{INSTANCE}/events/sched/{ev}/enable", "0")
        os.rmdir(INSTANCE)
    except OSError:
        pass


def trace_child(path):
    """Child process: copy trace_pipe to gzip; on SIGTERM drain and close the file cleanly."""
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    fd = os.open(INSTANCE + "/trace_pipe", os.O_RDONLY | os.O_NONBLOCK)
    with gzip.open(path, "wb", compresslevel=1) as out:
        while True:
            try:
                data = os.read(fd, 1 << 16)
            except BlockingIOError:
                data = b""
            if data:
                out.write(data)
                continue
            if stop:
                break
            time.sleep(0.05)
    os.close(fd)
    os._exit(0)


def heartbeat(cpu, path, secs):
    """Child process pinned to one CPU. No GIL is shared with other CPUs."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.sched_setaffinity(0, {cpu})
    try:
        with open(f"/proc/{os.getpid()}/comm", "w") as f:
            f.write(f"w2542-hb{cpu}")
    except OSError:
        pass
    out = open(path, "a", buffering=1 << 14)
    end = time.monotonic() + secs
    step = 0.005
    worst = 0
    last_h = time.monotonic()
    while time.monotonic() < end:
        before = time.monotonic_ns()
        time.sleep(step)
        late = (time.monotonic_ns() - before) // 1000 - 5000
        if late >= 20000:
            out.write(f"L {cpu} {time.time_ns()} {time.monotonic_ns()} {late}\n")
        worst = max(worst, late)
        if time.monotonic() - last_h >= 1.0:
            out.write(f"H {cpu} {time.time_ns()} {worst}\n")
            out.flush()
            worst = 0
            last_h = time.monotonic()
    out.close()
    os._exit(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--secs", type=float, required=True)
    ap.add_argument("--tick", type=float, default=0.01)
    ap.add_argument("--cpu-every", type=int, default=10)
    ap.add_argument("--node", action="append", default=[])
    ap.add_argument("--prober", action="append", default=[])
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--trace-buffer-kb", type=int, default=8192)
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    nodes = dict(x.split("=", 1) for x in a.node)
    probers = dict(x.split("=", 1) for x in a.prober)
    ns_of = {netns(pid): name for name, pid in nodes.items()}
    dev_fd = {name: os.open(f"/proc/{pid}/net/dev", os.O_RDONLY) for name, pid in nodes.items()}
    out = gzip.open(os.path.join(a.dir, "sched-threads.txt.gz"), "wt", compresslevel=1)
    cpu_out = open(os.path.join(a.dir, "cpu-stat.txt"), "w", buffering=1 << 16)
    cpu_out.write("# C unix_ns mono_ns cpuN:user,nice,system,idle,iowait,irq,softirq,steal (USER_HZ tick deltas)\n")
    threads = {}
    trace_proc = None
    if a.trace:
        trace_setup(a.trace_buffer_kb)
        trace_proc = os.fork()
        if trace_proc == 0:
            trace_child(os.path.join(a.dir, "sched-trace.txt.gz"))
    hb_path = os.path.join(a.dir, "cpu-heartbeat.txt")
    hb_pids = []
    ru0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    for cpu in sorted(os.sched_getaffinity(0)):
        pid = os.fork()
        if pid == 0:
            heartbeat(cpu, hb_path, a.secs)
        hb_pids.append(pid)

    def scan():
        changed = False
        prober_pids = set(probers.values())
        roles = [(pid, "prober", name) for name, pid in probers.items()]
        for p in os.listdir("/proc"):
            if not p.isdigit() or p in prober_pids:
                continue
            n = ns_of.get(netns(p))
            if not n:
                continue
            try:
                comm = readf(f"/proc/{p}/comm").strip()
            except OSError:
                continue
            if comm == "ping":
                try:
                    dst = readf(f"/proc/{p}/cmdline").split("\0")[-2]
                except (OSError, IndexError):
                    dst = "?"
                roles.append((p, "ping", f"{n}->{dst}"))
            else:
                roles.append((p, "node", n))
        live = set()
        for pid, role, name in roles:
            try:
                tids = os.listdir(f"/proc/{pid}/task")
            except OSError:
                continue
            for tid in tids:
                live.add(tid)
                if tid in threads:
                    continue
                try:
                    comm = readf(f"/proc/{pid}/task/{tid}/comm").strip().replace(" ", "_")
                    threads[tid] = Thread(pid, tid)
                except OSError:
                    continue
                out.write(f"M {time.monotonic_ns()} {tid} {role} {name} {comm}\n")
                changed = True
        for tid in list(threads):
            if tid not in live:
                threads.pop(tid).close()
                out.write(f"X {time.monotonic_ns()} {tid}\n")
                changed = True
        return changed

    def cpu_sample():
        res = {}
        for line in readf("/proc/stat").splitlines():
            if line.startswith("cpu") and line[3:4].isdigit():
                f = line.split()
                res[f[0]] = [int(x) for x in f[1:9]]
        return res

    start = time.monotonic()
    nxt = start
    last_scan = 0.0
    last_cpu = cpu_sample()
    tick_n = 0
    self_stat = f"/proc/{os.getpid()}/stat"
    while not STOP.is_set() and time.monotonic() - start < a.secs:
        now = time.monotonic()
        if now - last_scan >= 1.0:
            last_scan = now
            scan()
        unix_ns, mono_ns = time.time_ns(), time.monotonic_ns()
        parts = []
        for tid, th in list(threads.items()):
            try:
                parts.append(th.sample())
            except (OSError, ValueError, IndexError):
                threads.pop(tid).close()
                out.write(f"X {mono_ns} {tid}\n")
        out.write(f"T {unix_ns} {mono_ns} {' '.join(parts)}\n")
        dev = []
        for name, fd in dev_fd.items():
            try:
                for line in os.pread(fd, 8192, 0).decode().splitlines():
                    if line.strip().startswith("orblx0:"):
                        f = line.split(":", 1)[1].split()
                        dev.append(f"{name}:{f[1]}:{f[9]}")
            except OSError:
                pass
        out.write(f"N {unix_ns} {mono_ns} {' '.join(dev)}\n")
        tick_n += 1
        if tick_n % a.cpu_every == 0:
            cur = cpu_sample()
            cpu_out.write("C {} {} {}\n".format(unix_ns, mono_ns, " ".join(
                "{}:{}".format(k, ",".join(str(x - y) for x, y in zip(v, last_cpu.get(k, v))))
                for k, v in cur.items())))
            last_cpu = cur
        nxt += a.tick
        delay = nxt - time.monotonic()
        if delay > 0:
            STOP.wait(delay)
        else:
            nxt = time.monotonic()
    f = readf(self_stat)
    rest = f[f.rindex(")") + 2:].split()
    cpu_s = (int(rest[11]) + int(rest[12])) / os.sysconf("SC_CLK_TCK")
    wall = time.monotonic() - start
    STOP.set()
    for pid in hb_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        except OSError:
            pass
    if trace_proc:
        write_trace(INSTANCE + "/tracing_on", "0")
        time.sleep(0.5)
        os.kill(trace_proc, signal.SIGTERM)
        os.waitpid(trace_proc, 0)
        trace_teardown()
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    child_cpu_s = (ru.ru_utime + ru.ru_stime) - (ru0.ru_utime + ru0.ru_stime)
    out.write(f"# sampler ticks {tick_n} wall_s {wall:.1f} cpu_s {cpu_s:.2f} threads {len(threads)}\n")
    out.close()
    cpu_out.close()
    print(f"sched_sampler ticks {tick_n} wall_s {wall:.1f} cpu_s {cpu_s:.2f} cpu_pct {100 * cpu_s / max(wall, 0.001):.1f} "
          f"children_cpu_s {child_cpu_s:.2f} children_cpu_pct {100 * child_cpu_s / max(wall, 0.001):.1f} threads {len(threads)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""W25-39: split the agent request time into client, datapath, and guard parts.

Inputs (all hold times only, no key, ticket, or proof byte):
  trace  the agent loop trace (one "trace attempt" line per attempt)
  guard  the guard log (the "agent timing" lines)
  dp_a   the TUN packet trace of node a (the agent side)
  dp_b   the TUN packet trace of node b (the guard side)
  probe  the plain TCP RTT probe output on node a
All containers use the same host clock, so the times of a and b compare directly.
The output has one line per attempt and one percentile line per part (ms).
"""
import sys
from bisect import bisect_left
from collections import defaultdict

GUARD_PORT = 8080
PROBE_PORT = 9090


def fields(line):
    parts = line.split()
    return {parts[i]: parts[i + 1] for i in range(len(parts) - 1)}


def load_dp(path):
    """Return {client_port: [(at_us, dir, from_client, flags, len)]} sorted by time."""
    out = defaultdict(list)
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("dp "):
                continue
            f = fields(line)
            src_port = int(f["src"].rsplit(":", 1)[1])
            dst_port = int(f["dst"].rsplit(":", 1)[1])
            if dst_port in (GUARD_PORT, PROBE_PORT):
                server, client, from_client = dst_port, src_port, True
            elif src_port in (GUARD_PORT, PROBE_PORT):
                server, client, from_client = src_port, dst_port, False
            else:
                continue
            out[(server, client)].append(
                (int(f["at_us"]), line.split()[1], from_client, int(f["flags"], 16), int(f["len"]))
            )
    for key in out:
        out[key].sort()
    return out


def window(packets, lo, hi):
    times = [p[0] for p in packets]
    return packets[bisect_left(times, lo):bisect_left(times, hi)]


def dp_parts(dp_a, dp_b, server, port, lo, hi):
    """One-way datapath times (ms) of the packets of one connection, TUN read to TUN write."""
    a = window(dp_a.get((server, port), []), lo, hi)
    b = window(dp_b.get((server, port), []), lo, hi)

    def first(pkts, direction, from_client, test):
        for p in pkts:
            if p[1] == direction and p[2] == from_client and test(p[3], p[4]):
                return p[0]
        return None

    def all_of(pkts, direction, from_client, test):
        return [p[0] for p in pkts if p[1] == direction and p[2] == from_client and test(p[3], p[4])]

    syn = lambda flags, _len: flags & 0x12 == 0x02
    synack = lambda flags, _len: flags & 0x12 == 0x12
    data = lambda _flags, size: size > 0
    out = {}
    s_a, s_b = first(a, "read", True, syn), first(b, "write", True, syn)
    out["dp_syn"] = (s_b - s_a) / 1000 if s_a and s_b else None
    k_b, k_a = first(b, "read", False, synack), first(a, "write", False, synack)
    out["dp_synack"] = (k_a - k_b) / 1000 if k_a and k_b else None
    c_a, c_b = all_of(a, "read", True, data), all_of(b, "write", True, data)
    pairs = list(zip(c_a, c_b))
    out["dp_req_max"] = max((y - x) / 1000 for x, y in pairs) if pairs else None
    out["req_pkts"] = len(c_a)
    # Time on node a from the first to the last request data packet (a held segment shows here).
    out["req_spread"] = (c_a[-1] - c_a[0]) / 1000 if c_a else None
    r_b, r_a = first(b, "read", False, data), first(a, "write", False, data)
    out["dp_reply"] = (r_a - r_b) / 1000 if r_a and r_b else None
    parts = [out["dp_syn"], out["dp_synack"], out["dp_req_max"], out["dp_reply"]]
    out["dp_crit"] = sum(parts) if all(v is not None for v in parts) else None
    return out


def pct(values, q):
    values = sorted(values)
    if not values:
        return None
    return values[min(len(values) - 1, int(len(values) * q))]


def summary(name, values):
    values = [v for v in values if v is not None]
    if not values:
        print(f"split {name}_ms n 0")
        return
    print(
        f"split {name}_ms p50 {pct(values, .5):.1f} p90 {pct(values, .9):.1f} "
        f"p99 {pct(values, .99):.1f} max {max(values):.1f} n {len(values)}"
    )


def fmt(value):
    return "na" if value is None else f"{value:.1f}"


def main():
    trace_path, guard_path, dp_a_path, dp_b_path, probe_path = sys.argv[1:6]
    dp_a, dp_b = load_dp(dp_a_path), load_dp(dp_b_path)
    guard = defaultdict(list)
    with open(guard_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("agent timing "):
                f = fields(line)
                guard[int(f["peer_port"])].append({k: int(v) for k, v in f.items() if k.endswith("_us")})
    rows = []
    with open(trace_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("trace attempt ") or " result ok " not in line:
                continue
            f = fields(line)
            if "reply_us" not in f:
                continue
            t = {k: int(f[k]) for k in ("send_us", "seal_us", "tcp_us", "sent_us", "reply_us")}
            port = int(f["port"])
            row = {
                "attempt": f["attempt"],
                "port": port,
                "request": (t["reply_us"] - t["send_us"]) / 1000,
                "seal": (t["seal_us"] - t["send_us"]) / 1000,
                "tcp_connect": (t["tcp_us"] - t["seal_us"]) / 1000,
                "write": (t["sent_us"] - t["tcp_us"]) / 1000,
                "wait_reply": (t["reply_us"] - t["sent_us"]) / 1000,
            }
            g = next(
                (x for x in guard.get(port, []) if t["seal_us"] <= x["accept_us"] <= t["reply_us"]),
                None,
            )
            if g:
                row["g_wait_line"] = (g["line_us"] - g["accept_us"]) / 1000
                row["g_admit"] = (g["admit_us"] - g["line_us"]) / 1000
                row["g_upstream"] = (g["upstream_us"] - g["admit_us"]) / 1000
                row["g_reply_write"] = (g["reply_us"] - g["upstream_us"]) / 1000
                row["sent_to_line"] = (g["line_us"] - t["sent_us"]) / 1000
                row["reply_back"] = (t["reply_us"] - g["reply_us"]) / 1000
                row["guard_code"] = row["g_admit"] + row["g_upstream"] + row["g_reply_write"]
            row.update(dp_parts(dp_a, dp_b, GUARD_PORT, port, t["seal_us"] - 1000, t["reply_us"] + 1000))
            if row.get("dp_crit") is not None:
                row["non_dp"] = row["request"] - row["dp_crit"]
            rows.append(row)
    names = [
        "request", "seal", "tcp_connect", "write", "wait_reply", "g_wait_line", "g_admit",
        "g_upstream", "g_reply_write", "guard_code", "sent_to_line", "reply_back", "dp_syn",
        "dp_synack", "dp_req_max", "dp_reply", "dp_crit", "non_dp", "req_spread",
    ]
    for row in rows:
        print(
            f"split_attempt {row['attempt']} port {row['port']} req_pkts {row.get('req_pkts', 0)} "
            + " ".join(f"{n} {fmt(row.get(n))}" for n in names)
        )
    probes = []
    with open(probe_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("probe n "):
                continue
            f = fields(line)
            if f.get("result") != "ok":
                print(line.strip())
                continue
            t = {k: int(f[k]) for k in ("start_us", "connect_us", "reply_us")}
            row = {
                "n": f["n"],
                "probe_total": (t["reply_us"] - t["start_us"]) / 1000,
                "probe_connect": (t["connect_us"] - t["start_us"]) / 1000,
                "probe_rtt": (t["reply_us"] - t["connect_us"]) / 1000,
            }
            row.update(dp_parts(dp_a, dp_b, PROBE_PORT, int(f["port"]), t["start_us"] - 1000, t["reply_us"] + 1000))
            probes.append(row)
    for row in probes:
        print(
            f"probe_attempt {row['n']} total {fmt(row['probe_total'])} connect {fmt(row['probe_connect'])} "
            f"rtt {fmt(row['probe_rtt'])} dp_syn {fmt(row.get('dp_syn'))} dp_synack {fmt(row.get('dp_synack'))} "
            f"dp_req {fmt(row.get('dp_req_max'))} dp_reply {fmt(row.get('dp_reply'))} dp_crit {fmt(row.get('dp_crit'))}"
        )
    print(f"split_rows agent {len(rows)} probe {len(probes)} req_pkts_2plus {sum(1 for r in rows if r.get('req_pkts', 0) >= 2)}")
    for n in names:
        summary(n, [r.get(n) for r in rows])
    # The gate value: the p99 of the request time (W25-39). The shell reads this line by name.
    request = [r["request"] for r in rows]
    print(f"split_gate request_p99_ms {'na' if not request else f'{pct(request, .99):.1f}'}")
    for n in ("probe_total", "probe_connect", "probe_rtt"):
        summary(n, [r[n] for r in probes])
    for n in ("dp_syn", "dp_synack", "dp_req_max", "dp_reply", "dp_crit"):
        summary("probe_" + n, [r.get(n) for r in probes])


if __name__ == "__main__":
    main()

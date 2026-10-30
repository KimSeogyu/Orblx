# W25-22: join-time proof

Status: the script, the gate, and the negative tests are in this change. A full N=20 box run
needs W25-14b (#114, `scripts/proof/compose-clean.sh`) on main first. The script sources
that helper, and it fails if the helper is not there.

## 1. What the proof measures

`scripts/proof/join-time.sh` runs N late-peer joins (default 20) one after the other in one
run, under the box proof lock. The host is REAL. The coordinator, node a, and node b are [C]
containers on one Linux host.

Each join starts from a clean state:
- its own compose project, `JOIN_PROJECT_BASE-jI` (default `orblx-w2522-join-jI`),
- new state directories for the coordinator, a, and b,
- a new coordinator,
- `proof_compose_clean` (W25-14b) before the first `up` of the join and after the join.

No state goes from one join to the next. Only the image is the same.

In each join:
1. The coordinator and the tool container start. The tool creates the tokens and enrolls a.
2. Node a starts and logs its listener start.
3. T0: the tool starts the enroll call of b (`docker compose exec`, so there is no container
   start in the enroll time).
4. Node a pings the overlay address of b each 100 ms (`ping -D`). Node b starts.
5. The first ICMP reply from b on a is the first packet.

| Value | From | To | Gate |
|---|---|---|---|
| `enroll_to_first_packet_ms` | T0, the start of the enroll call of b | the first reply on a | report only |
| `listener_to_first_packet_ms` | "The node b listener started at unix_ms M." (#112) | the first reply on a | 2000 ms or less, each join |

All the times come from the clock of the one host (`date`, `ping -D`, and the node log).

## 2. Gate

`scripts/proof/join-time-summary.py` reads one line for each join that the proof started. It
fails the proof when:
- a join failed (a timeout of 30 s to the first packet, or an error in any step),
- the run does not have exactly N joins, 1 to N (a partial run never passes),
- a join has `listener_to_first_packet_ms` more than 2000.

It drops no join. It prints n, median, p95, and max of both values. The median of an even n
is the mean of the two middle values. The p95 is the nearest rank (rank ceil(0.95 n)).
The proof prints `proof_ok` only after `join_gate ok`.

The sweep runs the proof as the gate `W25-22` (`scripts/proof/sweep-manifest.txt`).

## 3. Negative tests

- `scripts/proof/tests/test_join_time.py`: a failed join, a missing join, a duplicate join,
  and a join with 2001 ms from the listener each fail the gate. A slow enroll alone does not.
  A slow join stays in the median, p95, and max.
- Live: `ORBLX_JOIN_BREAK_AT=K` (test only) removes the trust bundle of b in join K. Node b
  cannot start, node a gets no reply, and the proof must fail with `join K fail`.

## 4. How to run

```
./scripts/proof/join-time.sh                       # N=20, release build
JOIN_N=2 ORBLX_JOIN_BREAK_AT=2 ./scripts/proof/join-time.sh   # must fail
```

## 5. Release note rule

The only join-time number for a release note is enroll to first packet (median and p95) from
this proof in the real rc.3 sweep, labeled "[C] Linux lab, one host", with n. Do not make a
join-time claim from enroll to listener. Do not compare with Tailscale.

## 6. Limits

- One host, containers on one Docker bridge. There is no NAT and no relay in the path.
- The coordinator has 2 nodes. It does not show the join time with many nodes.
- The enroll time includes the cost of `docker compose exec`. The proof does not measure that cost.

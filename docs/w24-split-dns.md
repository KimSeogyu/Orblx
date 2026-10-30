# W24-F split DNS

Gap matrix row 17.
The policy maps a DNS domain (for example `corp.lan`) to nameserver IPs behind a subnet router.
A node that has an overlay route to a nameserver resolves names in that domain through the overlay.
A node without such a route answers REFUSED. The query does not go to the system resolver.

Marks: **REAL** is a real network or a real host. **[C]** is Docker containers on one Linux host.
All results in this document are [C]. No REAL result exists for W24-F.

## Scope

- Changed: the node DNS resolver (`crates/orblx-datapath/src/dns.rs`), the netmap names data
  (`crates/orblx-datapath/src/netmap.rs`), the policy schema (`crates/orblx-identity/src/policy.rs`),
  and the coordinator netmap payload (`crates/orblx-coord/src/state.rs`).
- Not changed: the datapath packet path (`node.rs`, the TUN, the NAT and relay paths, the port ACL). Track A owns it.
- No new crypto. The split DNS list is part of the signed netmap. The existing netmap signature covers it.

## Policy field

```hujson
"splitDns": {
  "corp.lan": ["10.88.24.53"],
},
```

Rules (the coordinator rejects the policy file if a rule fails):

- At most 32 domains. Each domain has 1 to 4 nameservers.
- A domain is lowercase letters, digits and hyphens in labels of 1 to 63 characters, at most 253 characters.
- A domain cannot be `orblx` or end in `.orblx`. The `.orblx` names stay with W18-4.
- A nameserver is a canonical IPv4 address. It cannot be in 100.64.0.0/10 (the overlay) or 127.0.0.0/8.
- The node checks the same rules again when it reads the netmap (`Netmap::check`).

## Design

1. The coordinator reloads the policy file on each request (hash check, no restart).
2. The coordinator puts `split_dns: [{domain, nameservers}]` into the signed netmap of each visible node.
3. The node builds `DnsTable` from the netmap. For each zone it keeps only the nameservers that an
   approved peer route covers (`routed`).
4. The node adds `~corp.lan` to the routing domains of `orblx0` (resolvectl on Linux).
   The OS then sends `corp.lan` names to the node resolver.
5. For a name in a split zone (longest domain match), the node resolver:
   - sends the query over UDP from its overlay address to a routed nameserver that has a kernel route on the overlay interface;
   - answers REFUSED when no such nameserver exists, and counts `split_refused`;
   - answers SERVFAIL when the exchange fails.
   It never sends a split zone query to the system resolver.
6. `.orblx` names and other names keep the W18-4 behavior.

The kernel route check reads `/proc/net/route` on Linux (longest prefix, then lowest metric).
On macOS it uses `route -n get`. On other systems the check is false, so the answer is REFUSED.

## Proof

Script: `scripts/proof/split-dns.sh` (compose `compose.split-dns.yml`, project `orblx-w24f-proof`).

- `router` advertises 10.88.24.0/24 (auto-approved).
- `landns` (10.88.24.53) answers `db.corp.lan` with 10.88.24.20. `db` (10.88.24.20) serves `db-ok` on port 80.
- `sysdns` (172.30.124.53) is the system resolver of `a` and `c`. It answers every name with 192.0.2.1.
- `a` accepts routes. `c` does not accept routes.
- Leak counter: an iptables rule on each node counts UDP to port 53 out of `eth0`.
  The `sysdns` log is a second check.

### [C] Results on the branch head `8c3d44d` (3 runs)

Logs: `w24f-branch-8c3d44d-split-dns-run{1,2,3}.log`. All 3 runs printed `proof_ok`.

| Gate | Check | run1 | run2 | run3 |
|---|---|---|---|---|
| 1 | a direct query `db.corp.lan` | rcode 0, 10.88.24.20 | rcode 0, 10.88.24.20 | rcode 0, 10.88.24.20 |
| 1 | a `resolvectl query db.corp.lan` | 58.0 ms | 58.6 ms | 75.9 ms |
| 1 | a `curl http://db.corp.lan/` | db-ok | db-ok | db-ok |
| 1 | landns queries from the router LAN address 10.88.24.2 / from other addresses | 6 / 0 | 6 / 0 | 6 / 0 |
| 1 | a leak counter delta, sysdns `corp.lan` queries from a | 0, 0 | 0, 0 | 0, 0 |
| 2 | c `db.corp.lan`, `corp.lan`, `x.y.corp.lan` | rcode 5 (REFUSED) | rcode 5 | rcode 5 |
| 2 | c `resolvectl query db.corp.lan` | REFUSED | REFUSED | REFUSED |
| 2 | c leak counter delta, sysdns `corp.lan` queries from c | 0, 0 | 0, 0 | 0, 0 |
| 2 | c `split_refused` | 7 | 7 | 7 |
| 2 | control: c `example.test` leak counter | 0 -> 1 | 0 -> 1 | 0 -> 1 |
| 3 | a and c: `router` / `missing.orblx` / `db.corp.lan.orblx` / `www.example.test` | 100.64.0.1 / NXDOMAIN / NXDOMAIN / 192.0.2.1 | same | same |
| 4 | `policy_change_to_new_answer_ms` (limit 2000) | 1191 | 1126 | 1153 |
| 4 | of which: fetch and write netmap / netmap file to new answer | 387 / 804 | 359 / 767 | 464 / 689 |
| 4 | node a container restart | no | no | no |

The control check shows that the leak counter counts: a normal name goes to the system resolver and the counter goes up by 1.

Gate 4 timing starts when the new policy file is in place on the coordinator.
It stops when a query for `db.corp.lan` on node a gets a different answer (the `sysdns` address 192.0.2.1).
The proof starts the netmap fetch itself (see the limits).

## Gate 5 [C]: W23-4 RTT gate and throughput

W24-F does not change the packet path. This gate checks that the W23-4 numbers did not move.

Harness: `nat-realism.sh` and `compose.nat-realism.yml` from PR #72 (W24-E) at `ee286ea`, copied into the
worktree for the run only and not committed. They take `ORBLX_NATR_PREFIX` and the subnets, so the stack ran as
`orblx-w24f-natr-*` on 172.29.124.0/24 and 10.124.21-24.0/24. Release profile (`ORBLX_NATR_PROFILE=release`).
The gate is: relay avg <= direct avg + 1 ms, and 0/50 lost.

The host was shared. Other workers ran their own `nat-realism.sh` stacks (`orblx-w25a-natr-*`, `orblx-w24acl-natr-*`)
during some of these runs. The load was not measured per run.

### [C] RTT (ms, 50 pings at 0.2 s)

| Run | Code | direct avg | prc relay avg | prc relay median | sym relay avg | Lost | RTT gate | Script |
|---|---|---|---|---|---|---|---|---|
| base1 | main `8972192` | 1.094 | 0.780 | 0.823 | 0.889 | 0/50 | ok | proof_ok |
| base2 | main `8972192` | 0.440 | 0.539 | 0.338 | 0.573 | 0/50 | ok | proof_ok |
| run1 | branch | 0.548 | 1.946 | 0.308 | (stopped) | 0/50 | **fail** | exit 1 |
| run2 | branch | 0.555 | 0.756 | 0.633 | 0.278 | 0/50 | ok | proof_ok |
| run3 | branch | 0.460 | 0.866 | 0.903 | 0.389 | 0/50 | ok | proof_ok |
| run4 | branch | 0.334 | 0.916 | 0.970 | 0.890 | 0/50 | ok | proof_ok |
| run5 | branch | 0.162 | 0.936 | 0.933 | (stopped) | 0/50 | ok | exit 1 (switch limit) |

- run1 failed on one ping: seq48 was 67.100 ms. The median was 0.308 ms. Without that ping the avg is below the gate.
  This is the same single slow ping outlier that `docs/w23-receive-path.md` records (22.1 ms in W23-4 run1). The cause is still not known.
- run5 passed the RTT gate. It then failed the relay-to-direct switch limit (`max_gap_ms 2016`, `detect_ms 511`, 0/50 lost)
  while the `orblx-w24acl-natr` stack ran at the same time. The switch check is not part of gate 5. It is recorded here because the script stopped.

### [C] TCP bulk throughput (Mbit/s, 5 s)

| Run | plain | prc direct | prc relay | sym relay |
|---|---|---|---|---|
| base1 | 33579.50 | 1413.70 | 960.55 | 1050.48 |
| base2 | 37263.25 | 1219.12 | 1059.39 | 1108.83 |
| run1 | 31356.18 | 917.06 | - | - |
| run2 | 33899.77 | 1103.53 | 915.48 | 723.68 |
| run3 | 36245.19 | 1053.23 | 382.61 | 442.35 |
| run4 | 34551.26 | 1161.69 | 1053.35 | 1201.15 |
| run5 | 40975.22 | 593.76 | 1108.45 | - |

The script has no throughput floor. The W22 medians are 1094 (prc direct), 1128 (prc relay) and 1113 (sym relay).
run4 is in the base range on all paths. run3 and run5 have low values on some paths. Both ran while another stack used the host.
The spread is host noise, not a code effect: the branch does not change any file on the packet path.

Logs: `w24f-base-8972192-run{1,2}-release-nat-realism.log`, `w24f-branch-run{1,2,3,4,5}-release-nat-realism.log`.
Runs 1 to 3 ran on the working tree before the commit; the code is the same as `8c3d44d` except the proof script text.

## Known limits

- **No automatic netmap poll on the node.** The node reads its netmap file every 1 s. It does not fetch a new netmap
  from the coordinator by itself (W24-D added only a deny refresh). In gate 4 the proof runs `orblx coord netmap`
  and writes the file. The measured time includes that fetch. A node poller is in `node.rs`/`up.rs`, which this
  task must not change. It needs a separate task that keeps the node lock check of `locked_netmap`.
- **macOS.** The node adds the routing domains for resolvectl only. It does not write `/etc/resolver/<domain>` files
  on macOS. A query that reaches the node resolver on macOS works, but the OS does not send `corp.lan` names to it yet.
- **Port ACL.** Today the subnet route traffic to the nameserver needs no ACL rule (the proof policy allows only TCP 80).
  When the W24-A port ACL covers subnet routes, the policy must allow UDP 53 to the nameserver.
- **IPv4 only.** Nameservers are IPv4. AAAA queries in a split zone go to the nameserver like other types.
- **No REAL proof.** All results are [C].

## Merge and main rerun

See the PR #73 description for the merge sha, the main CI run and the main rerun logs.

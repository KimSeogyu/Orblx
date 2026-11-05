# W25-18 Ephemeral nodes

The coordinator removes an ephemeral node when the node stays offline longer than a limit `T` (gap matrix row 34).
A node that is not ephemeral never changes.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the nodes, the load clients, and the Docker network are [C].

The change has no datapath change, no handshake change, no new crypto, and no new crate.
It uses the node store, the deny file, and the config audit chain that the coordinator already has.
Out of scope: a web UI, and an ephemeral flag on a node that already exists.

## 1. Use

```sh
# The token makes an ephemeral node. Without --ephemeral, the node is not ephemeral (default off).
orblx coord token create --state DIR --out FILE --ttl SECS --ephemeral

# The offline limit T. The default is 600 s (10 minutes). The range is 2 s to 30 days.
orblx coord serve --state DIR --ephemeral-offline SECS
```

- Ephemeral is a property of the enroll token. `token create` prints `ephemeral true` or `ephemeral false`.
  The node record keeps the flag. `orblx coord nodes` shows `"ephemeral": true` or `false`.
- **OIDC enroll always makes a node that is not ephemeral.** Only a token can make an ephemeral node.
- A node store or a token file from an older release reads as not ephemeral (`serde(default)`).
- You cannot set the flag on a node that already exists.

## 2. Online and offline

- A node is online while it has an open request to the coordinator.
  A node is offline from the end of its last request.
- A running node always holds one `policy-wait` request (up to 20 s, `DENY_WAIT_HOLD`) and opens the next request
  at most 100 ms after a reply. Thus a running node is always online.
- **Detection latency.** When a node stops without a clean close, the coordinator can see the open request
  for up to 20 s more. The removal comes up to 20 s + `T` after the stop. The removal is late, never early,
  relative to the time `T` after the last request.
- A tick each 500 ms removes each ephemeral node that is offline for longer than `T`.
  The tick never removes a node that is not ephemeral. The node store also refuses to remove it.

## 3. Removal

One tick (each 500 ms) removes all due nodes in one batch. The batch does these steps:

1. The coordinator adds the SVIDs of all nodes in the batch to the deny file in one write (one new deny
   version, the same deny file as `orblx coord revoke`). The SVIDs cannot renew, and peers drop the nodes.
2. The coordinator deletes the node records under one lock, so a reader sees one change of the node list.
   The overlay addresses become free.
   The next enroll gets the lowest free address, so a new node can get the address of the removed node.
3. The coordinator writes **1** `node-remove` config audit record (code 37) for each node: actor `coord`,
   detail `reason ephemeral offline_ms X limit_secs T deny_version V svid ... overlay_ip ...`.
   `orblx audit verify-config` and `scripts/siem/orblx-siem-verify.py` accept the new action.
4. The deny change wakes each `policy-wait` request. Peers get the new netmap without the node.

The coordinator prints `ephemeral removed NAME overlay_ip IP offline_ms X deny_version V batch N` for each node. It prints no key or token.

**Name reuse.** The name of a removed node stays on the deny list. An enroll with the same name gets
`The node name is revoked. Use a new name.` The token is not used up. Enroll the node with a new name.

## 4. Restart

- The file `ephemeral.json` in the state directory keeps `saved_ms` and the `last_seen_ms` of each node.
  The coordinator writes it at most each 1000 ms when it changes.
- At start the coordinator keeps the offline time that each node had at the last save:
  `last_seen = now - (saved_ms - last_seen_ms)`. The time that the coordinator was down does not count.
  Thus a restart does not remove a node early, and it does not lose a removal.
- A node that had an open request at the last save (the `online` list in the file) was online when
  the coordinator stopped. Its request to the stopped coordinator can take up to `DENY_WAIT_HOLD` + 10 s = 30 s
  to fail before it connects again. Thus after a start that node gets 30 s (`RECONNECT_GRACE`) before its offline
  time starts. A short request in the grace (for example a renew) does not end the grace.
  A node that never comes back is removed 30 s + `T` after the start. Late, never early.
- A file without the `online` list (an older file of this change) reads with an empty list.
- A node that the file does not have starts as online at coordinator start.
- The coordinator prints `ephemeral offline_secs T loaded N` at start.

## 5. Proof

Unit tests (REAL, `cargo test -p orblx-coord`): `store::ephemeral_tests` and `ephemeral::tests`.
Docker proof [C]: `scripts/proof/ephemeral-nodes.sh` with `T` = 6 s. The script takes the W25-5 proof lock.
Gate 6 also uses `scripts/proof/nat-realism.sh` (W23-4).

Head `4bc71f5`. Rust 1.99.1 (`RUSTUP_TOOLCHAIN=stable`). `T` = 6 s, SVID life 120 s. Each proof starts with `proof_compose_clean` and takes the FIFO proof lock for its run only.
The proof enrolls every node with a ticket that the coordinator issues (`orblx coord token create`, then `orblx coord enroll`). It uses no lab tickets.

### 5.1 Ephemeral proof [C]

Log: `/workspace/orblx-w18-proof/w25-q-ephemeral-branch-4bc71f5.log` (full, unfiltered).

**Gate 1 Ephemeral flag through the token, default off** [C]

```
store a false 100.64.0.1
store b false 100.64.0.2
store n1 false 100.64.0.3
store e1 true 100.64.0.4
store e2 true 100.64.0.5
store e3 true 100.64.0.6
store e4 true 100.64.0.7
[C] gate1 ok
```

**Gate 2 Removal after T, netmap <= 2 s, no renew, 0 bytes, IP reuse, 1 audit record** [C]

```
e1 stop_to_removal_ms 17079 (T 6000 ms, a stopped node holds a poll for up to 20000 ms)
e1 removal_to_netmap_ms a 514 b 611 (limit 2000)
e1 node-remove records 1: reason ephemeral offline_ms 6062 limit_secs 6 deny_version 1 svid spiffe://orblx.local/node/e1 overlay_ip 100.64.0.4
e1 renew_ok_after_removal 0
e1 rx_bytes_after_removal 0
re-enroll e1: The node name is revoked. Use a new name.
e1_ip 100.64.0.4 r1_ip 100.64.0.4
[C] gate2 ok
```

**Gate 3 A node that comes back before T stays** [C]

```
e2 offline_ms_at_restart 3278 (T 6000) stop_to_restart_ms 22823
e2 in_store yes node-remove 0 max_offline_ms 3278
[C] gate3 ok
```

**Gate 4 A non-ephemeral node offline > 10 x T stays** [C]

```
n1 stopped_ms 243920 (10 x T is 60000 ms) in_store yes node-remove 0
node_remove_total 22 unique 22
[C] gate4 ok
```

**Gate 5 Coordinator restart keeps the timers** [C]

```
coord down_ms 12435
e3 start_to_removal_ms 4102 expected_ms 3921 late_limit_ms 1500
e3 node-remove records 1: reason ephemeral offline_ms 6178 limit_secs 6 deny_version 2 svid spiffe://orblx.local/node/e3 overlay_ip 100.64.0.6
e4 in_store yes node-remove 0
[C] gate5 ok
```

**Gate 6 20 ephemeral removals, 0 lost packets between the others** [C]

```
load_first_updates 20
load_enroll_failed 0
load_ephemeral_in_store 20
load_left_in_store 0
load_removed 20 stop_to_first_ms -8506 stop_to_last_ms 8890 spread_ms 17396
netmap_load_peers_before c 20 d 20
netmap_load_peers a 0 b 0 c 0 d 0
c->d during the removal of 20 nodes steady lost 0/600 max_ms 121.676 limit_ms 1000
[C] gate6 ok
```

**Gate 7 0 secrets in logs; audit chain verifies** [C]

```
ok
tip 72d302ef657e125165af74fbdd2c47a0aed1c00b26e5f57bce43f07cc02eb539
node-remove 22
records 55
log_lines 6060
secret_grep 'PRIVATE KEY' 0
secret_grep 'ge1\.' 0
secret_grep 'PRIVATE KEY' 0
secret_grep 'ge1\.' 0
```

```
summary T_ms 6000 e1_stop_to_removal_ms 17079 removal_to_netmap_ms a 514 b 611 e1_renew_after_removal 0 e1_replies 0 e2_kept 1 n1_kept 1 e3_restart_delay_ms 4102 expected_ms 3921 load_removed 20 c_d_lost 0
proof_ok
proof_contention ephemeral-nodes:orblx-w25q-eph-proof samples 137 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 7.85
```

### 5.2 W23-4 nat-realism on the same head [C]

Log: `/workspace/orblx-w18-proof/w25-q-nat-realism-branch-4bc71f5.log` (full, unfiltered).

```
prc_prc steady lost 0/50 max_ms 1.661 limit_ms 200
prc_sym steady lost 0/50 max_ms 2.368 limit_ms 200
sym_sym steady lost 0/50 max_ms 2.363 limit_ms 200
renew_direct steady lost 0/50 max_ms 1.518 limit_ms 200
renew_relay steady lost 0/50 max_ms 4.037 limit_ms 200
switch prc_prc direct_to_relay detect_ms 387 lost 0/50 max_gap_ms 283
switch prc_prc relay_to_direct detect_ms 505 lost 0/50 max_gap_ms 210
switch prc_sym direct_to_relay detect_ms 553 lost 0/50 max_gap_ms 546
switch prc_sym relay_to_direct detect_ms 366 lost 0/50 max_gap_ms 208
relay_rtt prc_prc relay_avg_ms 1.480 direct_avg_ms 1.116 slack_ms 1 lost 0/50 relay_gate ok
relay_rtt sym_sym relay_avg_ms 1.603 direct_avg_ms 1.116 slack_ms 1 lost 0/50 relay_gate ok
proof_ok
proof_contention nat-realism:orblx-w25q-natr-proof samples 176 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 4.03
```

A `max_gap_ms` value in a `switch` line is the largest gap in the ping replies during a planned path switch. It is not a steady-path value, and this document does not exclude any gap as a host stall. Each switch had 0 lost packets, and the script limits passed (`limits_ok true`).

### 5.3 Notes

- **Ticket life.** A node capability ticket has the SVID life. An SVID renew does not refresh the ticket. After the SVID life, a new handshake with that ticket fails with "The end time has passed". This is product behavior that this change does not touch (no datapath or handshake change). Thus gate 6 uses the new nodes `c` and `d`, which enroll just before the gate. The nodes `a` and `b` enroll at the start of the run, and their tickets end during the run.
- **Gate 6 load clients.** Each load client starts its netmap watch immediately after its enroll. Thus no client is removed before its watch starts.
- **Secret scan.** The scan of the proof log ignores only the lines that the scan itself writes (`secret_grep 'PATTERN' N`). The scan of the container logs has no filter.
- **Contention.** The proof runs as root (`sudo -n`), so that the lock sampler can read `docker ps`. Each `proof_contention` line above has `unknown_samples 0` and `contended_samples 0`.

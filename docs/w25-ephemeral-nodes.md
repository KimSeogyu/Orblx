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

One removal does these steps:

1. The coordinator adds the SVID of the node to the deny file (the same path as `orblx coord revoke`).
   The SVID cannot renew, and peers drop the node.
2. The coordinator deletes the node record. The overlay address becomes free.
   The next enroll gets the lowest free address, so a new node can get the address of the removed node.
3. The coordinator writes **1** `node-remove` config audit record (code 35): actor `coord`,
   detail `reason ephemeral offline_ms X limit_secs T deny_version V svid ... overlay_ip ...`.
   `orblx audit verify-config` and `scripts/siem/orblx-siem-verify.py` accept the new action.
4. The deny change wakes each `policy-wait` request. Peers get the new netmap without the node.

The coordinator prints `ephemeral removed NAME overlay_ip IP offline_ms X deny_version V`. It prints no key or token.

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
  time starts. A node that never comes back is removed 30 s + `T` after the start. Late, never early.
- A file without the `online` list (an older file of this change) reads with an empty list.
- A node that the file does not have starts as online at coordinator start.
- The coordinator prints `ephemeral offline_secs T loaded N` at start.

## 5. Proof

Unit tests (REAL, `cargo test -p orblx-coord`): `store::ephemeral_tests` and `ephemeral::tests`.
Docker proof [C]: `scripts/proof/ephemeral-nodes.sh` with `T` = 6 s. The script takes the W25-5 proof lock.
Gate 6 also uses `scripts/proof/nat-realism.sh` (W23-4).

RESULTS_PLACEHOLDER

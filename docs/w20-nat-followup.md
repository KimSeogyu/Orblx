# W20 NAT follow-up: SVID renewal hello and direct RTT

This change has two parts:

1. After an SVID renewal, `orblx nat run` sends a new signed hello on the direct path and on the relay path. The peer line in `orblx status` then shows the new `svid_expiry`.
2. The direct-path ping RTT moves from about 50 ms to about 1.6 ms. The cause was a timer in the TUN thread.

`scripts/proof/nat-realism.sh` proves both parts. It prints `proof_ok`.
All extra hosts are [C] containers on the same host. The topology is the W20 topology (see [w20-nat-realism.md](w20-nat-realism.md)).

## Part 1: renewed SVID in the signed hello

### Change

- `NatConfig` has a new `renew` hook. The CLI hook calls the coordinator renew API with the current leaf. The API also writes the new state files. The hook does not log the key.
- A renew thread in the NAT runtime waits until 2/3 of the leaf life, then renews. A failure retries after 1 s. The retry time doubles to a maximum of 30 s.
- After a renewal, the node signs the next hello frames with the new leaf. For 5 s it sends the hello on each path every 500 ms, also to a confirmed peer. The X25519 session key and the frame counters do not change.
- The receiver skips the check only for a hello with the same X25519 key and the same leaf DER as the last checked hello. A new leaf gets the full check: trust bundle, SPIFFE ID of the peer, and the Ed25519 signature over the session and the X25519 key.
- For the same X25519 key, an older leaf does not move the expiry back. This stops a replay of an old hello.
- Unit tests: `a_renewed_hello_moves_the_peer_expiry_forward` (also checks the replay of the old hello and that data still opens) and `a_renewed_hello_from_another_ca_is_rejected`.

### Proof

The renewal case is the last case in `nat-realism.sh`.
The script restarts the coordinator with `ORBLX_SVID_TTL=60`, so a node leaf lives 60 s.
The coordinator does not allow a second enrollment of a name, so four new names enroll in the LANs of the four routers:

- node-e (behind prc router-a) and node-f (behind prc router-b) use the direct path.
- node-g (behind symmetric router-c) and node-h (behind symmetric router-d) use the relay path.

The script reads each peer expiry before the first renewal.
It then waits until the peer line shows a later expiry that is equal to the `svid_expiry` on the self line of the peer.

Real output (dev run on this branch):

```text
coord node svid ttl 60
direct node-e sees node-f before peer_svid_expiry 1793320675
state up
name node-e
overlay_ip 100.64.0.5
svid spiffe://orblx.local/node/node-e
svid_expiry 1793320714
peer node-f overlay_ip 100.64.0.6 path direct svid spiffe://orblx.local/node/node-f svid_expiry 1793320715
direct node-e sees node-f after peer_svid_expiry 1793320715 peer_self_svid_expiry 1793320715 path direct
orblx-natr-b: The node renewed the SVID. The new expiry is 1793320715.
direct node-f sees node-e before peer_svid_expiry 1793320674
direct node-f sees node-e after peer_svid_expiry 1793320714 peer_self_svid_expiry 1793320714 path direct
orblx-natr-a: The node renewed the SVID. The new expiry is 1793320714.
relay node-g sees node-h before peer_svid_expiry 1793320677
state up
name node-g
overlay_ip 100.64.0.7
svid spiffe://orblx.local/node/node-g
svid_expiry 1793320716
peer node-h overlay_ip 100.64.0.8 path relay svid spiffe://orblx.local/node/node-h svid_expiry 1793320717
relay node-g sees node-h after peer_svid_expiry 1793320717 peer_self_svid_expiry 1793320717 path relay
orblx-natr-d: The node renewed the SVID. The new expiry is 1793320717.
relay node-h sees node-g before peer_svid_expiry 1793320676
relay node-h sees node-g after peer_svid_expiry 1793320716 peer_self_svid_expiry 1793320716 path relay
orblx-natr-c: The node renewed the SVID. The new expiry is 1793320716.
renew_direct steady lost 0/50
renew_relay steady lost 0/50
```

Each peer expiry moves forward by 40 s: one renewal at 2/3 of a 60 s life.

## Part 2: direct-path RTT

### Measurement

The script measures on the prc_prc topology (node-a to node-b, direct path), with 50 pings for each line:

- plain: node-a pings the WAN address of router-b (172.29.20.12) through router-a. This is the container network without orblx.
- direct: node-a pings the overlay address of node-b with `-i 0.2`.
- direct `-i 0.23`: the same with an interval that is not a multiple of 50 ms.

The script fails when the direct average is more than 5 ms above the plain average (`ORBLX_RTT_LIMIT_MS`).

Before (main at 69c5bc4, the same script with the limit set to 1000 ms):

```text
plain   rtt min/avg/max/mdev = 0.024/0.033/0.078/0.007 ms
overlay rtt min/avg/max/mdev = 50.129/57.277/100.475/17.392 ms
overlay_i0.23 rtt min/avg/max/mdev = 50.154/64.323/100.594/22.498 ms
rtt plain_avg_ms 0.033 direct_avg_ms 57.277 direct_i0.23_avg_ms 64.323
```

After (this branch):

```text
plain   rtt min/avg/max/mdev = 0.019/0.041/0.140/0.018 ms
overlay rtt min/avg/max/mdev = 0.746/1.591/2.318/0.426 ms
overlay_i0.23 rtt min/avg/max/mdev = 0.793/1.956/2.593/0.409 ms
rtt plain_avg_ms 0.041 direct_avg_ms 1.591 direct_i0.23_avg_ms 1.956
rtt limit_ms 5 ok
```

### Where the 50 ms went

The Linux TUN thread (`tun_dev.rs`) did one loop: read with a 50 ms timeout, then write the queued packets.
A packet for the TUN device waited until the read returned: a read packet or the 50 ms timeout.

- On the node that sends the ping, the reply arrives just after the TUN thread read the request. No other packet comes, so the reply waits for the full timeout. This is the 50 ms minimum.
- On the peer node, the wait depends on the phase of the ping interval and the timeout. With `-i 0.2` (a multiple of 50 ms) the phase stays near 0. With `-i 0.23` the phase moves, so the average goes up from 57 ms to 64 ms. Some pings wait two timeouts. This is the 100 ms maximum.

The macOS utun thread (`tun_macos.rs`) had the same read-then-write loop.

### Fix

- Linux and macOS: one thread reads the TUN device, and a second thread writes to it. The write thread blocks on the channel and writes each packet at once. The read timeout is now only a stop check.
- The NAT router thread now sends a direct data frame at once. Before, the frame waited in a queue for the direct thread, which reads its socket with a 5 ms timeout.

### The remaining 1.5 ms

The direct RTT is 1.55 ms above the plain RTT. The proof uses a debug build.

- Crypto: one seal and one open of an 84-byte ping take 125 us in the debug build (6 us in a release build). Measured with a loop of 1000 frames in a unit test. One RTT has two seals and two opens, so about 0.25 ms.
- Thread handoffs: each direction has four handoffs. On the sender: TUN read thread to bridge thread, bridge thread to router thread. On the receiver: direct thread to bridge thread, bridge thread to TUN write thread. The rest, about 1.3 ms for 8 handoffs in one RTT, is the wake-up time of these threads in the containers. This part is an estimate. It was not measured one by one.

## Caveats

- The macOS utun change compiles in CI. It was not run on a Mac.
- The renewal proof uses new node names (node-e to node-h), because the coordinator does not allow a second enrollment of a name.
- The relay path and the hold logic did not change. The relay loop still sleeps 2 ms for each round.
- In the renewal case, the steady pings had one slow ping on each path (41 ms direct, 185 ms relay) and no loss. The cause was not measured.
- The resend window after a renewal is 5 s. A peer that loses all hello frames in this window keeps the old expiry until the next renewal.

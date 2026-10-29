# SVID renewal

The node daemon renews its SVID before the leaf expires.
The coordinator issues the new leaf.
The node keeps the same name and the same overlay IP.
The node does not restart.
Open sessions reconnect with the new leaf before the old leaf expires.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator. UDP 443. Address `172.28.19.10` |
| `node-a` container | [C] | Node `a`. Overlay `100.64.0.1`. Address `172.28.19.11` |
| `node-b` container | [C] | Node `b`. Overlay `100.64.0.2`. Address `172.28.19.12` |

The image is `orblx-svid:local`.
The proof script builds it from `scripts/proof/Dockerfile`.
The Compose file is `scripts/proof/compose.svid.yml`.
The Compose project name is `orblx-svid`.
The bridge subnet is `172.28.19.0/24`.
The gateway is `172.28.19.1`.

`ORBLX_SVID_TTL=120` sets the node leaf life to 2 minutes.
The coordinator SVID life stays 15 minutes.
The proof runs for 370 seconds.
That is longer than 6 minutes and longer than three leaf lives.
`node-a` pings `100.64.0.2` once per second.

The node renews when two thirds of the leaf life has passed.
A failed renewal retries after 1 second.
Each later failure doubles the wait.
The wait stops at 30 seconds.
The log line is `The SVID renewal failed. The node will retry.`
A success line is `The node renewed the SVID. The new expiry is` followed by the Unix expiry.
The log does not contain keys or tokens.

`orblx status` prints `path direct` when the session received a frame in the last 2 seconds.
The path is `stale` when the session is up and that frame is older.
The path is `down` when the session is down.
A keepalive counts as a received frame.
A quiet session does not stay `path direct`.

## Container proof

Run this command on the REAL Linux host:

```bash
sudo ./scripts/proof/svid-renew.sh
```

The script uses `cargo` and `rustc` from `PATH`.
The script stops when `rustc` is older than the crate MSRV in `Cargo.toml`.
The script exits 0 when the user is not root.
The script exits 0 when Docker is absent.
The script does not print enroll tokens or private keys.

The script writes an env file and prints `env_file`.
A new shell passes that file to Compose.

```bash
docker compose --env-file ENV_FILE -f scripts/proof/compose.svid.yml exec node-a orblx status
docker compose --env-file ENV_FILE -f scripts/proof/compose.svid.yml down
```

`ENV_FILE` is the printed path.
Copy the file to `/etc/orblx/svid.env` when the temp directory is gone.

```bash
sudo install -d -m 755 /etc/orblx
sudo cp ENV_FILE /etc/orblx/svid.env
docker compose --env-file /etc/orblx/svid.env -f scripts/proof/compose.svid.yml exec node-a orblx status
docker compose --env-file /etc/orblx/svid.env -f scripts/proof/compose.svid.yml down
```

Without the env file, Compose has no `SVID_*` values.
`exec` and `down` then fail.

The script fails when two or more pings in a row have no answer.
The script fails when the node log has fewer than two renewal lines.
Two lines cover the first leaf and one renewal inside 6 minutes.
A 2 minute leaf renews at 80 seconds, then again at 160 seconds, and again later.

## Unit test

`session_stays_up_for_three_svid_lifetimes` uses a 60 second leaf.
The test runs for 188 seconds.
Both nodes send packets for that whole time.
The test fails when the gap between packets is over 2 seconds.
The test fails when `orblx status` never prints `path direct`.
The test fails when the status file shows fewer than three SVID expiries.

## Result

This host ran `sudo ./scripts/proof/svid-renew.sh`.
The REAL Linux host built the image `orblx-svid:local`.
The [C] coordinator issued 2 minute leaves.
The [C] nodes `a` and `b` kept the session up.
The script printed these lines:

```
ping_seconds 370
sent 370
received 370
loss_percent 0
max_consecutive_loss 0
svid_expiry_end 1793280923
renew_lines 4
loss_window_ok true
proof_ok
```

`node-a` renewed the SVID four times in 370 seconds.
No ping was lost.
The longest RTT in the run was 113 ms.
That is under the 2 second loss limit.

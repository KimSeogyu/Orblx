# Week 12 TUN bench

## Command

```bash
./scripts/tun-bench.sh
```

Datapath owns this script.
Datapath owns the measured rate.
This change does not add the script.

## Method

The bench uses a Linux TUN device.
The bench sends packets and receives packets.
Each packet uses one ADR-0002 frame.
The script computes Mbps from the byte count and the wall-clock time.
The gate is at least 100 Mbps.
A pass or a fail uses the measured number only.

## Host with no TUN device

On a host that is not Linux, the script exits clean.
When the TUN device is absent, the script exits clean.
The script prints the K3 note.
That exit is not a pass of the 100 Mbps gate.
Datapath owns that clean-exit behavior.

## Record

| Field | Value |
| --- | --- |
| Command | `./scripts/tun-bench.sh` |
| Method | Linux TUN send and receive. ADR-0002 frame loop. Mbps from wall-clock bytes. |
| Gate | at least 100 Mbps |
| Measured Mbps | pending Datapath measurement |
| Result | pending Datapath measurement |
| Script in this tree | absent |
| Supporting PR | pending |
| Datapath agent | `bc-551a2bb3` |

## Checks on 2026-10-28

This tree is base `f4ce5c86d18108ffe71d70325a8f958230d60147`.
`scripts/tun-bench.sh` is absent.
`gh pr list` shows no open pull request for this repository.
`gh search prs` for `tun-bench` shows no pull request.
The GitHub branch list shows `main` only.
Cloud agent `bc-551a2bb3` was not available to this run.

When Datapath opens the supporting pull request, record the URL in this table.
Copy the measured Mbps from that pull request into this table.
Leave the measured Mbps as `pending Datapath measurement` until that number exists.

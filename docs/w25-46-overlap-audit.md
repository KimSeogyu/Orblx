# W25-46 overlap audit

`scripts/proof/w25_46_overlap_audit.py` reads proof logs and writes one record.

## Rules

1. A holder with a pid is one pair of acquire time and pid. A holder with no pid on the acquire line takes the pid from a waiter `holder:` line or from a release line. A second log with the same label and the same acquire time is a copy.
2. The audit counts acquires after 2026-10-31T17:23:11+09:00 (commit 393f7df). Pass `--cutoff` to use another time. `--until` counts acquires at or before that time. The record prints `until=` with no time when the option is absent.
3. The end of a hold is the earliest of the release time, the `proof_cancel` time, and, for `coord-cert-soak`, the next holder's acquire time. The cancel line `<time> proof_cancel reason=... holder_pid=...` is a cancel record. A `proof_plan_end` line is a nominal end. The audit records it and does not use it as the end.
4. A `lock_released` line in the cancel log is cancel-script latency. It is later than the next acquire. It is not a second flock holder.
5. A run whose acquire time is in 2026-11-05 09:10-09:15 +0900 is `INVALID` when `other_orblx_containers` at phase start is greater than 0, or when `contended_samples` is greater than 0. The other runs in that window are `VALID_for_container_overlap`.

## Re-judge input

`docs/w25-46-overlap-audit.txt` is the audit of the real logs in `scripts/proof/tests/fixtures/w25-46-raw/`. Those files are the redacted logs from `/workspace/orblx-w18-proof/`. Each timeline path is `filename:line` in that directory. The scan reads subdirectories. A path in `log=` or `path=` is relative to the log directory. The attached set has 7 acquires after the cutoff and one ssh-renew copy, so the count is 7 to 6. On the full proof directory, recursive scan with no `--until` is 54 to 52, and `--until 2026-11-05T10:05:23+09:00` is 46 to 45.

## Use

```bash
python3 scripts/proof/w25_46_overlap_audit.py /workspace/orblx-w18-proof/ --source-dir /workspace/orblx-w18-proof --until 2026-11-05T10:05:23+09:00
```

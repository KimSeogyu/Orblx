# W25-46 overlap audit

`scripts/proof/w25_46_overlap_audit.py` reads proof logs and writes one record.

## Rules

1. A lock holder is one pair of acquire time and pid. A second log with the same acquire time and the same pid is a copy. The copy is not a second holder.
2. The end of a hold is the release time or the `proof_cancel` time. When both times exist, the end is the earlier time. A `proof_plan_end` line is a nominal end. The audit records that line and does not use it as the end. A hold with no release and no `proof_cancel` has no end.
3. A run whose acquire time is in 2026-11-05 09:10-09:15 +0900 is `INVALID` when `other_orblx_containers` at phase start is greater than 0, or when `contended_samples` is greater than 0. The other runs in that window are `VALID_for_container_overlap`.

## Re-judge input

The box logs for 2026-11-05 09:10-09:15 KST are not in this repository. The fixture `scripts/proof/tests/fixtures/w25-46-0910/` is the structured record from the W25-46 comment on pull request 149. `docs/w25-46-overlap-audit.txt` is the verdict of this audit on that fixture.

## Use

```bash
python3 scripts/proof/w25_46_overlap_audit.py scripts/proof/tests/fixtures/w25-46-0910
```

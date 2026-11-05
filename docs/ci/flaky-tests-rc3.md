# Flaky CI tests for 0.1.0-rc.3

This note lists tests that failed and then passed on the same commit, or that failed on some commits and passed on other commits, in the last 30 runs of the main CI workflow.

## Evidence

Command:

```bash
gh run list --workflow ci.yml --branch main --limit 30
```

The workflow file is `.github/workflows/ci.yml`. The workflow name is `ci`.

| Item | Value |
| --- | --- |
| Runs | 30 |
| Branch | `main` |
| Oldest run | 2026-10-30, run 41096115042, commit `c32d46f` |
| Newest run | 2026-11-05, run 41940783765, commit `d3f4ef7` |
| Success | 28 |
| Failure | 2 |
| Attempt | 1 on every run |

No run in this set has a second attempt. No commit in this set has one failed run and one successful run.

Two tests failed one time each. Each failure is on a commit that does not change that test. The same test passed on other commits in this set. That is the flaky pattern in this set.

## Tests

| Job | Test | Failures / 30 | Example run | Failure signature |
| --- | --- | --- | --- | --- |
| format, clippy, and test | `test_proof_lock.ProofLockTest.test_two_proofs_run_one_after_the_other` | 1 / 30 | https://github.com/KimSeogyu/Orblx/actions/runs/41940783765 | `AssertionError: overlap: one (1793838574524, 1793838577321) two (1793838577117, 1793838577325)` |
| format, clippy, and test | `renew_test::a_peer_that_enrolls_later_is_reachable_in_two_seconds` | 1 / 30 | https://github.com/KimSeogyu/Orblx/actions/runs/41125469053 | `the late peer took 3823 ms` |

### Lock overlap

Run 41940783765 failed on commit `d3f4ef7` (pull request 143). That commit does not change `scripts/proof/tests/test_proof_lock.py`. The previous main run 41939426156 on commit `b82c949` passed. The job `format, clippy, and test` passed on the other 27 successful runs in this set. The failed assertion says the second proof started before the first proof ended.

### Late peer time

Run 41125469053 failed on commit `015f930` (pull request 110). That commit changes the sweep disk check. It does not change `crates/orblx-coord/src/renew_test.rs`. The previous main run 41121552818 on commit `37fdba6` passed. The test log says the late peer took 3823 ms. The test limit is 2000 ms. Later commits change this test. Those later runs are not a second pass of the same test body.

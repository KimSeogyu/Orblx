# Release version on main (W25-44)

A build from main must never print a release version. A dev build prints a `-dev` version,
for example `0.1.0-rc.3-dev`.

## Release step

After each tag, bump to the next -dev version on main.

1. Push the release tag (for example `v0.1.0-rc.2`).
2. In a PR to main, set `[workspace.package] version` in `Cargo.toml` to the next `-dev`
   version (for example `0.1.0-rc.3-dev`), and update `Cargo.lock`.
3. Before the next tag, set the release version (for example `0.1.0-rc.3`) in the release PR.

## Check

`scripts/check-version-not-tagged.sh` fails when the workspace version is the version of an
existing release tag (`git tag`). CI runs it in the "format, clippy, and test" job after it
fetches the tags. `scripts/proof/tests/test_version_not_tagged.py` tests the check.

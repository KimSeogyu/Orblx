# v0.1.0-rc.3 release notes (draft)

This is the draft of the rc.3 release notes. The release workflow does not read this file; the
release owner copies the lines into the GitHub release.

## Known limits

- SSH: partial. Coordinator-issued SSH certificates come later.

## Known issues in v0.1.0-rc.1 and v0.1.0-rc.2

- SSH logins can fail after the node certificate renews (W25-40). Fixed in rc.3.

## Known issues in v0.1.0-rc.2

- With --coord, the coordinator cert is not renewed; nodes lose all peers about 26 min after coordinator start. (from code and a main run, not reproduced on the rc.2 tag)
- On renewal, a node does not load the new capability ticket; peers refuse it after the first ticket ends. (from code and a main run, not reproduced on the rc.2 tag)

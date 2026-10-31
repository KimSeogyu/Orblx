# v0.1.0-rc.3 release notes (draft)

This is the draft of the rc.3 release notes. The release workflow does not read this file; the
release owner copies the lines into the GitHub release.

## Known limits

- SSH: partial. The coordinator issues SSH user certificates (W25-31, `docs/w25-ssh-user-certs.md`).
  SSH identity = the user who owns the client node. Do not enroll a multi-user host as a personal node.
  There is no OIDC step-up at login yet (W25-32).

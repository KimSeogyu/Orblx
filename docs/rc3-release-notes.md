# v0.1.0-rc.3 release notes (draft)

This is the draft of the rc.3 release notes. The release workflow does not read this file; the
release owner copies the lines into the GitHub release.

## BREAKING: SSH password / SVID-proof login removed

SSH accepts only a user certificate from the coordinator SSH user CA (W25-31).

Exact cert login command:

```bash
sudo orblx ssh alice@b --state /var/lib/orblx --peer-cert B.pem --command 'id'
sudo orblx ssh alice@b --state /var/lib/orblx --peer-cert B.pem --shell
```

The client asks the coordinator for a short user certificate (`ssh-cert-request`) with the node SVID. Root is required. See `docs/w25-ssh-user-certs.md`.

## Known limits

- SSH: partial. The coordinator issues SSH user certificates (W25-31, `docs/w25-ssh-user-certs.md`).
  SSH identity = the user who owns the client node. Do not enroll a multi-user host as a personal node.
  There is no OIDC step-up at login yet (W25-32).
  SSH certificate logins need a coordinator reachable within the last 60 s. Mesh traffic does not.

## Known issues in v0.1.0-rc.1 and v0.1.0-rc.2

- SSH logins can fail after the node certificate renews (W25-40). A fix is merged (#137) but is not yet proven on a real host. Open in rc.3.
- rc.1/rc.2: about 1 min after a node's capability ticket ends (the ticket life is the SVID life, about 16 min by default), its peers refuse it (end time has passed). New connections and existing sessions with traffic both stop. Workaround: restart the node (orblx up).
- rc.1/rc.2: A node that sleeps or pauses longer than its SVID life plus 1 min (about 16 min by default) cannot reconnect, and a restart does not help. Enroll it again under a new node name with a new enroll token or pre-auth key (orblx admin preauth-create, then orblx coord enroll). The old node name cannot be enrolled again in this release. Policy rules and grants for the old name do not apply to the new name: update them, and revoke the old node.
- rc.1/rc.2 SSH login has no netmap age check and no cert serial; a node removed from the netmap but not on the deny list can still log in until its SVID expires. Upgrade to rc.3.

## rc.3 long pause

- Automatic recovery after a long sleep is not supported.
- The owner runs `orblx login` for the same name, or `orblx coord enroll` with a pre-auth key whose `nodes` list contains that name.
- The node keeps its name and its overlay address.
- The coordinator issues a new leaf and a new ticket, and denies the previous leaf key id and ticket nonce.
- An expired leaf is not accepted.

## Known issues in v0.1.0-rc.2

- With --coord, the coordinator cert is not renewed; nodes lose all peers about 26 min after coordinator start. (from code and a main run, not reproduced on the rc.2 tag)
- On renewal, a node does not load the new capability ticket; peers refuse it after the first ticket ends. (from code and a main run, not reproduced on the rc.2 tag)

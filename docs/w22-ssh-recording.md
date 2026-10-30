# W22-3 SSH session recording

A policy `ssh` rule can require a session recording.
When the rule requires it, the orblx SSH server records the SVID SSH session to a file.
When the session ends, the server writes the SHA-256 of the file into the SSH audit chain.
`orblx audit verify` hashes the file again and fails when one byte changes.
When the server cannot record, it refuses the session and audits the deny.

Labels:

- **REAL**: the Linux host and `cargo test`.
- **[C]**: a container. The nodes and the coordinator in `scripts/proof/ssh.sh` are [C].

## Policy

An `ssh` rule has an optional `recording` field. The values are `"required"` and `"off"`.
No field is the same as `"off"`. Other values are a policy error: "The SSH recording value is required or off."

```hujson
{
  "src": ["spiffe://orblx.local/user/alice"],
  "dst": ["spiffe://orblx.local/node/b"],
  "users": ["rec"],
  "checkPeriod": "30s",
  "recording": "required"
}
```

When more than one rule matches the source, the destination, and the login user, the session needs a recording if one of the rules requires it.
A rule without `recording` works as before. It writes no file and no `record` line.

## Recording file

- Directory: `<state dir>/recordings/`. The server makes the directory when it does not exist.
- Name: `ssh-<unix nanoseconds>-<frame>.cast`. The server opens the file with `create_new` and mode `0600`. It does not write over an old file.
- Format: asciicast version 2.
  - Line 1: `{"version":2,"width":80,"height":24,"timestamp":<unix seconds>,"env":{"ORBLX_SSH_USER":"<login user>"}}`.
  - `[0.0,"i","<command>"]`: the command of this session.
  - `[<seconds>,"o","<text>"]`: each stdout chunk of this session, with the time from the start of the command.
- One file holds one session. The server writes only the command and the output of that session. It does not record the input or the output of other users or other sessions.
- The file does not hold the SVID proof, the ticket, the key, or the environment of the session.
- The largest file is 16 MiB. A session that writes more fails closed.

## Audit chain

The `record` event (kind code 4) has the session IDs, the time, the file path relative to the chain file directory, and the SHA-256 of the file.

- The hash input of a `record` line adds the path length (u16), the path bytes, and the 32 hash bytes.
  The hash input of the other kinds does not change. Old chains verify as before.
- The JSONL line has `"recording"` and `"recording_sha256"`. Other kinds must not have these fields.
- `orblx audit verify` checks the link hashes. Then, for each `record` line, it reads the file and compares its SHA-256.
  A changed byte or a missing file gives "The recording check failed at index N."
- The path must be relative and must not have `..`. A path that goes out of the chain directory is refused.
- `verify` prints `record N`.

The order for one recorded session is `start`, `record`, `end`.
If the server cannot write the `record` line, the session fails.

This work adds no new crypto and no handshake. It uses SHA-256 from the existing `sha2` crate.

## Fail closed

The server refuses a session that needs a recording when:

- the recording directory or file does not open (read-only directory, a file in place of the directory, disk error),
- a write to the file fails during the session (the server stops the command),
- the file does not close (`sync_all`), or
- the file gets larger than 16 MiB.

The server prints "The SSH session recording did not open. The session is refused." or the "did not close" line.
It writes a `deny` line with `"reason":"recording"` in the audit chain. These lines do not have secrets.

## Proof

REAL `cargo test`:

- `orblx-audit` `tests/w22_record.rs`: a record line verifies; one changed byte in the file fails at that index; a missing file fails; a changed hash in the chain fails the link check; paths with `..` or `/` at the start are refused.
- `orblx-identity` `an_ssh_rule_can_require_a_recording`: the parse of `required`, `off`, no value, and a bad value.
- `orblx-ssh` `record` tests: the header, the command, and the output are in the file; a file in place of the directory makes `create` fail.
- `orblx-ssh` `a_rule_with_recording_writes_the_file_and_fails_closed`: a full SSH session through the server with a recorded user, verify, a byte change, a plain user with no new file, and a deny when the directory cannot open.

[C] `scripts/proof/ssh.sh` (log `w22-3-dev1-ssh.log`, and the PR head log `pr<N>-<sha8>-ssh.log`):

| Step | Result |
| --- | --- |
| `rec` on node b (rule needs a recording) | session runs, 1 file, `recording_sha256` is in the chain `record` line, verify `ok`, `record 1` |
| change 1 byte (offset 1) in the file | verify fails: "The recording check failed at index 10." |
| restore the byte | verify `ok` |
| node c has a read-only (`:ro`) recording directory | `touch` fails, `rec` is denied, the c chain has `deny` with `recording` |
| `alice` on node b (rule without recording) | session runs as before, no new file |
| end | both chains verify, `proof_ok` |

The proof prints the recording of the test session. That session runs `printf` and has no secrets.

## Caveats

- The server records exec sessions only. The orblx SSH server has no interactive shell or PTY. There is no keystroke stream to record.
- The file holds stdout. The server does not send stderr to the client, and the file does not hold it.
- The command text is in the file. A user who puts a secret in the command puts it in the file. The file has mode `0600`.
- The text is UTF-8. Bytes that are not UTF-8 become U+FFFD in the file. The hash is of the file, so verify still works.
- The file is not encrypted. The chain proves that the file did not change. It does not hide the file.
- If a child process of the command keeps stdout open after the command ends, the server waits for it.
- In the [C] proof the containers run as root, so the proof uses a read-only bind mount to force a write error.

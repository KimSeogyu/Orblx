# W23-2 SSH PTY session recording

The orblx SSH server can now run an interactive shell on a PTY.
When the policy rule requires a recording, the server records the input and the output of the shell in time order.
When the shell ends, the server writes the SHA-256 of the file into the SSH audit chain, as for the W22-3 exec recording.
`orblx audit verify` hashes the file again and fails when one byte changes.
When the server cannot record, it refuses the shell and audits the deny.
The W22-3 exec recording path is unchanged.

Labels:

- **REAL**: the Linux host (`Linux x86_64`) and `cargo test`.
- **[C]**: a container. The nodes in `scripts/proof/ssh.sh` are [C]. The containers stand in for other hosts.

## Client

```
orblx ssh rec@b --identity <dir> --netmap <netmap.json> --peer-cert <cert.pem> --shell
```

- `--shell` takes no value. `--shell` with `--command` is an error.
- The client sends a `pty-req` with `TERM` (default `xterm`) and the local terminal size (default 80x24 when stdout is not a terminal), then a `shell` request.
- When stdin is a terminal, the client puts it in raw mode and restores it at the end.
- When the server refuses the PTY or the shell, the client prints "The SSH shell was refused." and exits with an error.

## Server

- The server accepts `pty-req` only on an admitted session. The terminal type keeps only `A-Z a-z 0-9 - . _` and at most 32 characters, else it is `xterm`. A size of 0 becomes 80x24. The maximum is 1000.
- A `shell` request without a `pty-req` is refused and audited as a `destination` deny.
- The server runs the policy recheck before the shell starts, and then each `checkPeriod` while the shell runs.
- The shell is `/bin/sh -i` on a new PTY, in a new session, with a clean environment: `PATH=/usr/bin:/bin`, `TERM`, `HOME=/`, `ORBLX_SSH_USER`.
- `window-change` resizes the PTY.
- When the shell exits, the server sends the exit status, EOF and close. It sends SIGKILL to the process group 500 ms after the shell exits, so background processes do not stay.

## Recording file

The directory, the name, the mode `0600`, `create_new`, and the 16 MiB cap are the same as for W22-3.
The format is asciicast version 2:

- Line 1: `{"version":2,"width":<cols>,"height":<rows>,"timestamp":<unix seconds>,"env":{"ORBLX_SSH_USER":"<login user>","TERM":"<term>"}}`.
- `[<seconds>,"i","<text>"]`: input from the client.
- `[<seconds>,"o","<text>"]`: output from the PTY.
- `[<seconds>,"r","<cols>x<rows>"]`: a window change.
- `[<seconds>,"m","input hidden"]`: a marker. See "Hidden input".

The time is in seconds from the start of the shell, with microsecond steps.
One lock writes all events, and each event takes its time under the lock, so the times do not go down.
The server records the input before it writes the input to the PTY, so an input event comes before the output that it causes.
A UTF-8 character that one read cuts in two is joined before the event is written. A byte that is not UTF-8 becomes U+FFFD.

The exec header is unchanged: `width` 80, `height` 24, and no `TERM`.

## Hidden input

When the PTY has echo off (for example `read -s`, `stty -echo`, or a password prompt), the server does not record the input bytes.
It writes one `m` marker at the start of each hidden input and no `i` events until echo is on again.
This keeps passwords out of the recording.

## Fail closed

- The recording file does not open (for example, a read-only directory): the server prints "The SSH session recording did not open. The session is refused.", refuses the shell, and audits a deny with the reason `recording`. The shell does not start.
- A recording write fails while the shell runs: the server does not write that input to the PTY, kills the process group, and audits a deny with the reason `recording`. It writes no `record` line for that file.
- The recording finish fails: the server audits a deny with the reason `recording`.
- A policy revoke while the shell runs: the server kills the process group, writes the `record` line, and audits a deny with the reason `revoked`.

## Results

`cargo test --workspace`: pass (REAL). New tests:

- `record::tests::the_carry_joins_a_character_that_a_read_cut_in_two`
- `record::tests::a_pty_header_holds_the_size_and_the_terminal_type`
- `pty::tests::a_bad_terminal_type_and_size_become_safe_values`
- `pty::tests::a_shell_on_the_pty_runs_input_and_echo_off_is_seen`
- `server::tests::a_pty_shell_records_input_and_output_in_time_order`: input and output in time order, the hidden input marker, 1-byte change fails verify, a rule without recording writes no file, a recording directory that cannot open refuses the shell with a `recording` deny.
- `server::tests::a_shell_stops_when_a_recording_write_fails` (a recording file that is open only for read): the shell stops and the failure is `recording`.
- `ssh::tests::the_shell_flag_takes_no_value_and_refuses_a_command` (orblx-cli).

`scripts/proof/ssh.sh` ([C], log `/workspace/orblx-w18-proof/w23-2-dev2-ssh.log`) reruns all W22-3 exec steps and then:

| Step | Result |
|------|--------|
| W22-3 exec recording on b | `recording_files 1`, `record 1`, 1-byte change `verify_failed The recording check failed at index 10.`, restore `ok` |
| W22-3 exec on c, read-only directory | `denied recording`, `deny_recording 1` |
| PTY shell `rec@b` | output `pty-42` and `got-10` |
| PTY recording | 10 events: 3 `i`, 6 `o`, 1 `m`. Times in order. Input before its output. `hidden-w23` is not in the file. Header 80x24, `TERM` `xterm-256color` |
| Audit chain on b | `chain_has_pty_recording_sha256 yes`, `record 2` |
| 1-byte change in the PTY recording | `verify_failed The recording check failed at index 15.`, restore `ok` |
| PTY shell `rec@c`, read-only directory | "The SSH shell was refused.", no input ran, `deny_recording 2` |
| PTY shell `alice@b` (no recording) | `plain-alice`, `recording_files 2` (no new file) |
| Final chains | b: `ok`, `record 2`, `deny 4`; c: `ok`, `deny 3` |

The PTY recording from that run (no secrets; the hidden line is only a marker):

```
{"version":2,"width":80,"height":24,"timestamp":1793339248,"env":{"ORBLX_SSH_USER":"rec","TERM":"xterm-256color"}}
[0.002305,"o","# "]
[1.681734,"i","echo pty-$((6*7))\n"]
[1.682176,"o","echo pty-$((6*7))\r\n"]
[1.682238,"o","pty-42\r\n# "]
[3.68208,"i","stty -echo; read -r s; stty echo; echo got-${#s}\n"]
[3.682596,"o","stty -echo; read -r s; stty echo; echo got-${#s}\r\n"]
[5.683345,"m","input hidden"]
[5.684966,"o","got-10\r\n# "]
[7.685895,"i","exit\n"]
[7.686115,"o","exit\r\n"]
```

## Limits

- The shell runs as the user of the orblx daemon, as the exec path does. The login user is in `ORBLX_SSH_USER` only.
- The shell has no maximum time. The recheck runs each `checkPeriod`.
- The server writes input to the PTY in the SSH handler. When the PTY buffer is full, that write can block.
- The 16 MiB cap applies. At the cap, the recording write fails and the shell stops (fail closed).
- Hidden input depends on the PTY echo flag. A program that turns echo off and draws its own echo is not hidden.
- No new crypto. The SHA-256 and the `record` chain line are the W22-3 format.
- The proof uses containers on one Linux host. It does not use other hosts.

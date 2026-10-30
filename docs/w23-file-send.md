# W23-3 file send between nodes

`orblx file send` sends one file from one node to another node in the same mesh.
The receiver stores the file only when the coordinator-signed grants for the receiver allow the sender.
The receiver checks the size and the SHA-256 digest before the file gets its name.
The receiver writes one audit record for each file. The record has the sender, the size, and the digest.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result.

## Parts

| Part | Where | What it does |
|---|---|---|
| Receiver | `orblx file receive --dir DIR` | Listens on the overlay address, TCP port 4243. Stores files in DIR. |
| Sender | `orblx file send FILE --to NODE` | Finds NODE in the local netmap and sends to its overlay address. |
| Offer | first bytes on the connection | Sender SVID leaf, time stamp, name, size, SHA-256, and an ed25519 signature with the SVID key. |
| Gate | receiver | Trust bundle, deny list, and `grants.signed.json` (checked with `netmap.pub`). The grants must be for this node. |
| Audit | `file-audit.jsonl` in the state directory | Config audit chain. Actions `file-receive` (code 24) and `file-deny` (code 25). |

The signature covers the domain `orblx-file-send-v1`, the receiver SPIFFE ID, the name, the size, the SHA-256 digest, and the time stamp.
The change adds no new crypto design. It uses the ed25519 SVID key that the node already has.

## Rules on the receiver

1. The receiver reads the offer header. The header limit is 10 s.
2. The receiver checks, in this order: the leaf against the trust bundle and the deny list,
   the signature (it must cover the SPIFFE ID of this receiver), the time stamp (60 s window), the signed grants (`permits(sender, tcp, 4243)`),
   the name, the size limit (default 1 GiB), and an existing file with the same name.
3. A refusal replies `deny REASON` and writes a `file-deny` record. The receiver makes no file for a refusal.
4. After `ok`, the receiver writes the body to a part file `.orblx-part-*` with mode 0600.
   When the size and the SHA-256 match, a hard link gives the file its name. A hard link does not replace a file.
   The receiver always removes the part file. It replies `done SHA256` or `fail REASON`.
5. At start, the receiver removes part files that a stopped receiver left.
6. A name has only `A-Z a-z 0-9 . _ -`, has at most 255 bytes, and does not start with a dot.
7. The receiver reads the gate files again for each connection. A new grants file applies to the next file.
8. The limit is 16 files at the same time.

Refusal reasons: `format`, `identity`, `signature`, `stale`, `acl`, `name`, `size`, `exists`, `busy`, `short`, `digest`, `io`.

## Commands

| Command | Use |
|---|---|
| `orblx file receive --dir DIR [--state DIR] [--listen IP:PORT] [--max-bytes N]` | Run the receiver. |
| `orblx file send FILE --to NODE [--name NAME] [--state DIR] [--addr IP:PORT] [--timeout SECS]` | Send one file. |
| `orblx audit verify-config --file STATE/file-audit.jsonl` | Check the receiver audit chain. |

To allow a sender, add an ACL rule for TCP port 4243 on the receiver. Example:

```hujson
{"action": "accept", "src": ["spiffe://orblx.local/node/a"], "proto": "tcp", "dst": ["spiffe://orblx.local/node/b:4243"]}
```

The commands print the sender, the receiver, the name, the size, and the SHA-256 digest. They do not print keys or signatures.

## Proof

Script: `scripts/proof/file-send.sh`. Compose project `orblx-w23a-file-send`. Policy: `scripts/proof/file-send.hujson`.
It prints `proof_ok` at the end.

The ACL lets `a` reach `b` on TCP 4243 and 8080. The ACL lets `c` reach `b` on TCP 8080 only.

| Check | Result | Mark |
|---|---|---|
| `c` reaches `b` on TCP 8080 over the overlay | `HTTP/1.0 200` | [C] |
| `a` sends 8388608 random bytes to `b` | the receiver SHA-256 and size are the same as on `a` | [C] |
| `a` sends the same name again | `deny exists`. The first file stays (same SHA-256). | [C] |
| `c` sends to `b` over the overlay | `deny acl`. No new file. No dot file in the inbox. | [C] |
| `b` sends to its own receiver (not in the grants) | `deny acl`. No new file. No dot file in the inbox. | [C] |
| Inbox on `b` at the end | 1 file (`payload.bin`, mode 0600), 0 dot files | [C] |
| Receiver audit chain | 4 records: `file-receive` 1 (actor `a`, size, SHA-256), `file-deny` 3 (`exists` from `a`, `acl` from `c`, `acl` from `b`). `verify-config` prints `ok`. | [C] |
| Logs | 0 enroll tokens, 0 `PRIVATE KEY` | [C] |

Logs:

- Branch: `/workspace/orblx-w18-proof/w23-3-file-send-branch.log`
- Main: `/workspace/orblx-w18-proof/w23-3-file-send-main.log`

## Finding

In this proof, the TCP connection from `c` to `b` port 4243 got to the receiver socket.
The `orblx up` datapath hides peers that the grants do not let a node reach, but it does not check the TCP port of each packet between two nodes that can reach each other.
Thus the file receiver does its own grant check, and the proof shows that check.
A per-port check in the datapath is a separate change. This change does not make it.

## Limits

- No REAL result. The proof uses containers.
- One file for each connection. There is no resume. A broken send leaves no part file and the sender must send again.
- The receiver does not replace a file. Delete or rename the old file first.
- The receiver must run as a separate process. `orblx up` does not start it.

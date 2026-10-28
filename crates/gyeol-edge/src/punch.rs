use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::io_error;
use crate::{EdgeError, EndpointCandidate};

/// The punch datagram magic.
///
/// The first byte is not a QUIC long-header byte.
/// The first two bits are not a STUN header.
pub const PUNCH_MAGIC: [u8; 8] = *b"GYEOLPN1";

const PUNCH_LEN: usize = 17;
const KIND_CHECK: u8 = 1;
const KIND_ACK: u8 = 2;
const RECV_SLICE: Duration = Duration::from_millis(50);

/// A shared punch token.
///
/// The token is not a signature.
/// ADR 0003 does not name the sign or verify owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchToken([u8; 8]);

impl PunchToken {
    /// Build a token from eight bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Draw a random token.
    pub fn generate() -> Result<Self, EdgeError> {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|err| EdgeError::Io(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Parse 16 hex characters.
    pub fn parse_hex(text: &str) -> Result<Self, EdgeError> {
        let text = text.trim();
        if text.len() != 16 {
            return Err(EdgeError::BadToken);
        }
        let mut bytes = [0u8; 8];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *byte =
                u8::from_str_radix(&text[start..start + 2], 16).map_err(|_| EdgeError::BadToken)?;
        }
        Ok(Self(bytes))
    }

    /// Return lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(16);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn bytes(self) -> [u8; 8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchKind {
    Check,
    Ack,
}

/// The peer address to nominate, then the send list.
///
/// Peers with the same reflexive IP share one NAT.
/// The host candidate is first in that case.
/// The function does not verify a signature.
#[must_use]
pub fn punch_plan(
    local: EndpointCandidate,
    remote: EndpointCandidate,
) -> (SocketAddr, Vec<SocketAddr>) {
    let same_nat = local.reflexive.ip() == remote.reflexive.ip();
    let preferred = if same_nat {
        remote.local
    } else {
        remote.reflexive
    };
    let extra = if same_nat {
        remote.reflexive
    } else {
        remote.local
    };
    let mut targets = vec![preferred];
    if extra != preferred {
        targets.push(extra);
    }
    (preferred, targets)
}

/// Counts from one punch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchCounts {
    /// Datagrams this peer sent.
    pub packets_sent: u32,
    /// Datagrams this peer accepted.
    pub packets_received: u32,
}

/// A successful punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchOutcome {
    /// The send and receive counts.
    pub counts: PunchCounts,
    /// The peer socket that answered on the nominated path.
    pub peer: SocketAddr,
}

/// A punch that stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchFailure {
    /// The send and receive counts.
    pub counts: PunchCounts,
    /// The cause.
    pub error: EdgeError,
}

/// Send hole-punch datagrams until `preferred` answers or `deadline` elapses.
///
/// A check or an ack from `preferred` completes the punch.
/// The function sends an ack when it receives a check.
pub fn exchange(
    socket: &UdpSocket,
    targets: &[SocketAddr],
    preferred: SocketAddr,
    token: PunchToken,
    deadline: Instant,
) -> Result<PunchOutcome, PunchFailure> {
    let check = encode_punch(PunchKind::Check, token);
    let ack = encode_punch(PunchKind::Ack, token);
    let mut counts = PunchCounts {
        packets_sent: 0,
        packets_received: 0,
    };
    while Instant::now() < deadline {
        for target in targets {
            if Instant::now() >= deadline {
                break;
            }
            match send_packet(socket, &check, *target) {
                Ok(()) => counts.packets_sent = counts.packets_sent.saturating_add(1),
                Err(error) => return Err(PunchFailure { counts, error }),
            }
        }
        let slice_end = Instant::now() + RECV_SLICE;
        while Instant::now() < slice_end && Instant::now() < deadline {
            match recv_packet(socket, token, &deadline, &slice_end) {
                Recv::Empty => break,
                Recv::Soft | Recv::Ignore => continue,
                Recv::Fatal(error) => return Err(PunchFailure { counts, error }),
                Recv::Punch { kind, from } => {
                    counts.packets_received = counts.packets_received.saturating_add(1);
                    if kind == PunchKind::Check {
                        match send_packet(socket, &ack, from) {
                            Ok(()) => counts.packets_sent = counts.packets_sent.saturating_add(1),
                            Err(error) => return Err(PunchFailure { counts, error }),
                        }
                    }
                    if from == preferred {
                        return Ok(PunchOutcome { counts, peer: from });
                    }
                }
            }
        }
    }
    Err(PunchFailure {
        counts,
        error: EdgeError::DirectBudget,
    })
}

fn encode_punch(kind: PunchKind, token: PunchToken) -> [u8; PUNCH_LEN] {
    let mut packet = [0u8; PUNCH_LEN];
    packet[..8].copy_from_slice(&PUNCH_MAGIC);
    packet[8] = match kind {
        PunchKind::Check => KIND_CHECK,
        PunchKind::Ack => KIND_ACK,
    };
    packet[9..].copy_from_slice(&token.bytes());
    packet
}

fn decode_punch(buf: &[u8], token: PunchToken) -> Option<PunchKind> {
    if buf.len() != PUNCH_LEN || buf[..8] != PUNCH_MAGIC || buf[9..] != token.bytes() {
        return None;
    }
    match buf[8] {
        KIND_CHECK => Some(PunchKind::Check),
        KIND_ACK => Some(PunchKind::Ack),
        _ => None,
    }
}

fn send_packet(socket: &UdpSocket, packet: &[u8], target: SocketAddr) -> Result<(), EdgeError> {
    loop {
        match socket.send_to(packet, target) {
            Ok(size) if size == packet.len() => return Ok(()),
            Ok(_) => {
                return Err(EdgeError::Io(
                    "The punch datagram was shorter than the buffer.".to_string(),
                ))
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(io_error(err)),
        }
    }
}

enum Recv {
    Punch { kind: PunchKind, from: SocketAddr },
    Ignore,
    Empty,
    Soft,
    Fatal(EdgeError),
}

fn recv_packet(
    socket: &UdpSocket,
    token: PunchToken,
    deadline: &Instant,
    slice_end: &Instant,
) -> Recv {
    let limit = (*slice_end).min(*deadline);
    let remaining = limit.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Recv::Empty;
    }
    if let Err(err) = socket.set_read_timeout(Some(remaining)) {
        return Recv::Fatal(io_error(err));
    }
    let mut buf = [0u8; 2048];
    match socket.recv_from(&mut buf) {
        Ok((len, from)) => match decode_punch(&buf[..len], token) {
            Some(kind) => Recv::Punch { kind, from },
            None => Recv::Ignore,
        },
        Err(err) if is_empty(&err) => Recv::Empty,
        Err(err) if is_soft(&err) => Recv::Soft,
        Err(err) => Recv::Fatal(io_error(err)),
    }
}

fn is_empty(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

fn is_soft(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Interrupted | ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::{decode_punch, encode_punch, punch_plan, PunchKind, PunchToken, PUNCH_MAGIC};
    use crate::EndpointCandidate;

    #[test]
    fn punch_magic_is_not_stun_or_quic() {
        assert_eq!(&PUNCH_MAGIC, b"GYEOLPN1");
        assert_ne!(PUNCH_MAGIC[0] & 0xc0, 0);
        assert_eq!(PUNCH_MAGIC[0] & 0x80, 0);
    }

    #[test]
    fn punch_round_trip_checks_the_token() {
        let token = PunchToken::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let packet = encode_punch(PunchKind::Check, token);
        assert_eq!(decode_punch(&packet, token), Some(PunchKind::Check));
        let other = PunchToken::from_bytes([8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(decode_punch(&packet, other), None);
        assert_eq!(token.to_hex(), "0102030405060708");
        assert_eq!(PunchToken::parse_hex("0102030405060708").unwrap(), token);
        assert_eq!(
            PunchToken::parse_hex("zz").unwrap_err(),
            crate::EdgeError::BadToken
        );
    }

    #[test]
    fn same_nat_prefers_the_host_candidate() {
        let local = candidate(10, 443, 20);
        let remote = candidate(11, 443, 21);
        let (preferred, targets) = punch_plan(local, remote);
        assert_eq!(preferred, remote.local);
        assert_eq!(targets[0], remote.local);
        assert_eq!(targets[1], remote.reflexive);
    }

    fn candidate(host: u8, host_port: u16, mapped: u16) -> EndpointCandidate {
        EndpointCandidate {
            local: SocketAddr::from((Ipv4Addr::new(10, 20, 0, host), host_port)),
            reflexive: SocketAddr::from((Ipv4Addr::new(10, 30, 0, 2), mapped)),
        }
    }
}

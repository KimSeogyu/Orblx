use std::fmt;

mod acl;
mod connector;
mod dns;
mod error;
mod exit_route;
mod filter;
mod framing;
mod gate;
mod ipv4;
mod netmap;
mod node;
mod quic;
mod relay_path;
mod router;
mod run;
mod subnet;
mod tun_bench;
mod tun_dev;
mod tun_macos;

pub use acl::enforce_receiver_tcp;
pub use connector::{
    issue_connector_lab, prove_lab_directory, prove_two_https_apps, run_hub_dir, run_spoke_dir,
    serve_apps_dir, serve_userspace, AppFetch, TwoAppProof, APP_A_BODY, APP_A_HOST, APP_A_OVERLAY,
    APP_B_BODY, APP_B_HOST, APP_B_OVERLAY, APP_OVERLAY_PORT, SPOKE_OVERLAY,
};
pub use dns::{
    install_link_resolver, is_visible, remove_link_resolver, AllowPeers, DnsTable, GrantPeers,
    PeerVisibility, MACOS_RESOLVER_PATH,
};

pub use error::HelloError;
pub use exit_route::{plan_exit_routes, underlay_addresses, ExitRoutePlan};
pub use filter::{FilterStats, PacketFilter, PACKET_AUDIT_FILE};
pub use framing::{decode_length_prefixed, encode_length_prefixed, MAX_FRAME_LEN};
pub use gate::PeerGate;
pub use ipv4::{ipv4_destination, ipv4_packet, is_icmp_echo_reply, is_ipv4_packet};
pub use netmap::{
    ssh_key_id, ssh_key_id_node, valid_split_domain, valid_split_nameserver, LockUpdate, Netmap,
    NetmapError, NetmapPeer, NetmapSelf, NodeLockSig, SplitDns, SshRevoked, MAX_SPLIT_DNS_SERVERS,
    MAX_SPLIT_DNS_ZONES, MAX_SSH_REVOKED, MAX_SSH_USER_CA, NODE_LOCK_FILE,
};
pub use node::{
    format_node_status, read_status_text, run_memory_node, run_node, running_pid, ListenEvent,
    MemoryDevice, NodeRequest, NodeStatus, RenewedLeaf, StatusPeer, SvidRenewer, NODE_PID_FILE,
    NODE_RECORD_FILE, NODE_STATUS_FILE,
};
pub use quic::{
    measure_hello_rtt, prove_hello_socket, HelloConfig, HelloEndpoint, HelloReceiver, HelloSender,
    HelloSession, HelloSocketRole,
};
pub use router::{route_packet, RouterError, RouterTable};
pub use run::{run_hello, HelloRequest, HelloRole};
pub use tun_bench::{run_local_tun_bench, TunBenchOutcome, TunBenchReport};
pub use tun_dev::{
    open_tun, open_tun_port, tun_capability_note, TunBridge, TunConfig, TunPort, DEFAULT_UDP_PORT,
    LINUX_TUN_NAME,
};

#[cfg(test)]
mod golden;
#[cfg(test)]
mod hello_tests;

/// Header size in bytes before the payload.
///
/// The header is `ver|type`, flags, `session_id`, `seq`, and `ticket_hash`.
pub const HEADER_LEN: usize = 30;

/// Frame version in the high nibble of byte 0.
pub const FRAME_VERSION: u8 = 1;

/// Flag bit 0. The sender requests a rekey.
pub const FLAG_REKEY_REQ: u8 = 1 << 0;

/// Flag bit 1. The sender marks the end of the stream.
pub const FLAG_EOS: u8 = 1 << 1;

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-datapath"
}

/// The frame type in the low nibble of byte 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// An IPv4 packet payload.
    Data = 1,
    /// A control payload.
    Ctrl = 2,
    /// A ticket payload.
    Ticket = 3,
}

impl FrameType {
    fn from_nibble(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Ctrl),
            3 => Ok(Self::Ticket),
            other => Err(FrameError::BadType { frame_type: other }),
        }
    }

    fn as_nibble(self) -> u8 {
        match self {
            Self::Data => 1,
            Self::Ctrl => 2,
            Self::Ticket => 3,
        }
    }
}

/// One app frame on a QUIC stream.
///
/// The layout is ADR-0002 version 1.
/// This type does not encrypt the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame type.
    pub frame_type: FrameType,
    /// Flag bits. Use `FLAG_REKEY_REQ` and `FLAG_EOS`.
    pub flags: u8,
    /// Local session handle.
    pub session_id: u32,
    /// Per-direction frame sequence number.
    pub seq: u64,
    /// Capability ticket fingerprint.
    pub ticket_hash: [u8; 16],
    /// Frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Encode this frame to bytes.
    ///
    /// The header is big-endian.
    /// Byte 0 stores the version in the high nibble and the type in the low nibble.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        let ver_type = (FRAME_VERSION << 4) | self.frame_type.as_nibble();
        out.push(ver_type);
        out.push(self.flags);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ticket_hash);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode one frame from bytes.
    ///
    /// The function returns an error when the buffer is shorter than the header.
    /// The function returns an error when the version is not 1.
    pub fn decode(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < HEADER_LEN {
            return Err(FrameError::ShortBuffer {
                len: buf.len(),
                need: HEADER_LEN,
            });
        }

        let version = buf[0] >> 4;
        if version != FRAME_VERSION {
            return Err(FrameError::BadVersion { version });
        }

        let frame_type = FrameType::from_nibble(buf[0] & 0x0f)?;
        let flags = buf[1];
        let mut session_bytes = [0u8; 4];
        session_bytes.copy_from_slice(&buf[2..6]);
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[6..14]);
        let mut ticket_hash = [0u8; 16];
        ticket_hash.copy_from_slice(&buf[14..30]);

        Ok(Self {
            frame_type,
            flags,
            session_id: u32::from_be_bytes(session_bytes),
            seq: u64::from_be_bytes(seq_bytes),
            ticket_hash,
            payload: buf[HEADER_LEN..].to_vec(),
        })
    }
}

/// A frame decode error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The buffer is shorter than the 30-byte header.
    ShortBuffer {
        /// The buffer length in bytes.
        len: usize,
        /// The required header length in bytes.
        need: usize,
    },
    /// The version nibble is not 1.
    BadVersion {
        /// The version nibble from byte 0.
        version: u8,
    },
    /// The type nibble is not 1, 2, or 3.
    BadType {
        /// The type nibble from byte 0.
        frame_type: u8,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortBuffer { len, need } => write!(
                f,
                "the buffer is short: the buffer has {len} bytes and the header needs {need} bytes"
            ),
            Self::BadVersion { version } => write!(
                f,
                "the frame version is {version} and the decoder accepts version {FRAME_VERSION}"
            ),
            Self::BadType { frame_type } => write!(
                f,
                "the frame type is {frame_type} and the decoder accepts types 1, 2, and 3"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::{
        crate_name, Frame, FrameError, FrameType, FLAG_EOS, FLAG_REKEY_REQ, FRAME_VERSION,
        HEADER_LEN,
    };

    fn sample(frame_type: FrameType) -> Frame {
        Frame {
            frame_type,
            flags: FLAG_REKEY_REQ | FLAG_EOS,
            session_id: 0x0000_002a,
            seq: 7,
            ticket_hash: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            payload: b"ping".to_vec(),
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "orblx-datapath");
    }

    #[test]
    fn encode_decode_golden_round_trip() {
        let frame = sample(FrameType::Data);
        let bytes = frame.encode();
        let golden: [u8; 34] = [
            0x11, 0x03, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, b'p', b'i', b'n', b'g',
        ];
        assert_eq!(bytes, golden);
        assert_eq!(Frame::decode(&bytes).unwrap(), frame);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let err = Frame::decode(&[0u8; HEADER_LEN - 1]).unwrap_err();
        assert_eq!(
            err,
            FrameError::ShortBuffer {
                len: HEADER_LEN - 1,
                need: HEADER_LEN,
            }
        );
        assert!(err.to_string().contains("short"));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes = sample(FrameType::Data).encode();
        bytes[0] = (2 << 4) | 1;
        let err = Frame::decode(&bytes).unwrap_err();
        assert_eq!(err, FrameError::BadVersion { version: 2 });
        assert_ne!(FRAME_VERSION, 2);
    }

    #[test]
    fn encode_sets_each_type_nibble() {
        let cases = [
            (FrameType::Data, 1u8),
            (FrameType::Ctrl, 2),
            (FrameType::Ticket, 3),
        ];
        for (frame_type, nibble) in cases {
            let frame = sample(frame_type);
            let bytes = frame.encode();
            assert_eq!(bytes[0] >> 4, FRAME_VERSION);
            assert_eq!(bytes[0] & 0x0f, nibble);
            assert_eq!(Frame::decode(&bytes).unwrap().frame_type, frame_type);
        }
    }
}

//! Frozen on-wire vectors for ADR-0002.
//!
//! W4 locks the 30-byte header and the `ticket_hash` bytes.
//! CTRL payload layout stays open.
//! TICKET payload layout stays open.

use orblx_identity::ticket_hash;

use crate::{Frame, FrameType, FLAG_EOS, FLAG_REKEY_REQ, HEADER_LEN};

/// First 16 bytes of SHA-256 over `ticket-valid.bin`.
const TICKET_VALID_HASH: [u8; 16] = [
    0x44, 0xf6, 0x27, 0x76, 0xf5, 0xdd, 0xb2, 0xc2, 0xa2, 0x59, 0x53, 0x9c, 0x36, 0xdb, 0x2c, 0xc4,
];

const TICKET_VALID: &[u8] = include_bytes!("../../orblx-identity/fixtures/ticket-valid.bin");

fn decode_hex(text: &str) -> Vec<u8> {
    let hex: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    assert_eq!(
        hex.len() % 2,
        0,
        "the hex fixture has an odd number of digits"
    );
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn assert_encode_decode(frame: &Frame, fixture: &str) {
    let bytes = decode_hex(fixture);
    assert_eq!(frame.encode(), bytes);
    assert_eq!(Frame::decode(&bytes).unwrap(), *frame);
}

#[test]
fn data_ping_matches_the_frozen_header_and_payload() {
    let frame = Frame {
        frame_type: FrameType::Data,
        flags: FLAG_REKEY_REQ | FLAG_EOS,
        session_id: 0x0000_002a,
        seq: 7,
        ticket_hash: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        payload: b"ping".to_vec(),
    };
    let bytes = decode_hex(include_str!("../testdata/frame-data-ping.hex"));
    assert_eq!(bytes.len(), HEADER_LEN + 4);
    assert_eq!(bytes[0], 0x11);
    assert_eq!(bytes[1], FLAG_REKEY_REQ | FLAG_EOS);
    assert_eq!(&bytes[2..6], &0x0000_002au32.to_be_bytes());
    assert_eq!(&bytes[6..14], &7u64.to_be_bytes());
    assert_eq!(&bytes[14..30], &frame.ticket_hash);
    assert_eq!(&bytes[30..], b"ping");
    assert_encode_decode(&frame, include_str!("../testdata/frame-data-ping.hex"));
}

#[test]
fn frame_type_goldens_lock_each_header_nibble() {
    let cases = [
        (
            FrameType::Data,
            1u8,
            0x01u8,
            include_str!("../testdata/frame-type-data.hex"),
        ),
        (
            FrameType::Ctrl,
            2,
            0x02,
            include_str!("../testdata/frame-type-ctrl.hex"),
        ),
        (
            FrameType::Ticket,
            3,
            0x03,
            include_str!("../testdata/frame-type-ticket.hex"),
        ),
    ];
    let mut seen = Vec::new();
    for (frame_type, nibble, payload_byte, fixture) in cases {
        let frame = Frame {
            frame_type,
            flags: 0,
            session_id: 0,
            seq: 0,
            ticket_hash: [0; 16],
            payload: vec![payload_byte],
        };
        let bytes = decode_hex(fixture);
        assert_eq!(bytes.len(), HEADER_LEN + 1);
        assert_eq!(bytes[0] >> 4, 1);
        assert_eq!(bytes[0] & 0x0f, nibble);
        assert_eq!(*bytes.last().unwrap(), payload_byte);
        assert_encode_decode(&frame, fixture);
        seen.push(bytes);
    }
    assert_ne!(seen[0], seen[1]);
    assert_ne!(seen[1], seen[2]);
    assert_ne!(seen[0], seen[2]);
}

#[test]
fn flag_bit_goldens_lock_rekey_req_and_eos() {
    let rekey = Frame {
        frame_type: FrameType::Data,
        flags: FLAG_REKEY_REQ,
        session_id: 0,
        seq: 0,
        ticket_hash: [0; 16],
        payload: Vec::new(),
    };
    let eos = Frame {
        frame_type: FrameType::Data,
        flags: FLAG_EOS,
        session_id: 0,
        seq: 0,
        ticket_hash: [0; 16],
        payload: Vec::new(),
    };
    let rekey_bytes = decode_hex(include_str!("../testdata/frame-flag-rekey-req.hex"));
    let eos_bytes = decode_hex(include_str!("../testdata/frame-flag-eos.hex"));
    assert_eq!(rekey_bytes.len(), HEADER_LEN);
    assert_eq!(eos_bytes.len(), HEADER_LEN);
    assert_eq!(rekey_bytes[1], FLAG_REKEY_REQ);
    assert_eq!(rekey_bytes[1] & FLAG_EOS, 0);
    assert_eq!(eos_bytes[1], FLAG_EOS);
    assert_eq!(eos_bytes[1] & FLAG_REKEY_REQ, 0);
    assert_ne!(rekey_bytes, eos_bytes);
    assert_encode_decode(&rekey, include_str!("../testdata/frame-flag-rekey-req.hex"));
    assert_encode_decode(&eos, include_str!("../testdata/frame-flag-eos.hex"));
}

#[test]
fn ticket_valid_hash_matches_the_frozen_prefix() {
    assert_eq!(ticket_hash(TICKET_VALID), TICKET_VALID_HASH);
    let listed = decode_hex(include_str!("../testdata/ticket-valid-hash.hex"));
    assert_eq!(listed.as_slice(), &TICKET_VALID_HASH);

    let frame = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        session_id: 1,
        seq: 1,
        ticket_hash: TICKET_VALID_HASH,
        payload: b"ok".to_vec(),
    };
    let bytes = decode_hex(include_str!("../testdata/frame-data-ticket-hash.hex"));
    assert_eq!(bytes.len(), HEADER_LEN + 2);
    assert_eq!(&bytes[14..30], &TICKET_VALID_HASH);
    assert_encode_decode(
        &frame,
        include_str!("../testdata/frame-data-ticket-hash.hex"),
    );
}

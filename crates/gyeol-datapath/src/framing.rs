use crate::{Frame, FrameError, HelloError, HEADER_LEN};

/// The largest encoded frame that the stream reader accepts.
pub const MAX_FRAME_LEN: usize = 65_535 + HEADER_LEN;

const LENGTH_PREFIX_LEN: usize = 4;

/// Encode one frame with a big-endian `u32` length prefix.
pub fn encode_length_prefixed(frame: &Frame) -> Result<Vec<u8>, HelloError> {
    let body = frame.encode();
    let len = u32::try_from(body.len()).map_err(|_| HelloError::BadFrameLength)?;
    if !(HEADER_LEN..=MAX_FRAME_LEN).contains(&body.len()) {
        return Err(HelloError::BadFrameLength);
    }
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode one length-prefixed frame.
///
/// The function returns the frame and the number of bytes that it consumed.
pub fn decode_length_prefixed(buf: &[u8]) -> Result<(Frame, usize), HelloError> {
    if buf.len() < LENGTH_PREFIX_LEN {
        return Err(HelloError::Frame(FrameError::ShortBuffer {
            len: buf.len(),
            need: LENGTH_PREFIX_LEN,
        }));
    }
    let len = usize::try_from(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
        .map_err(|_| HelloError::BadFrameLength)?;
    if !(HEADER_LEN..=MAX_FRAME_LEN).contains(&len) {
        return Err(HelloError::BadFrameLength);
    }
    let end = LENGTH_PREFIX_LEN + len;
    if buf.len() < end {
        return Err(HelloError::Frame(FrameError::ShortBuffer {
            len: buf.len(),
            need: end,
        }));
    }
    let frame = Frame::decode(&buf[LENGTH_PREFIX_LEN..end]).map_err(HelloError::Frame)?;
    Ok((frame, end))
}

/// Return the next sequence number when `actual` matches `expected`.
pub(crate) fn expect_seq(expected: u64, actual: u64) -> Result<u64, HelloError> {
    if actual != expected {
        return Err(HelloError::BadSeq);
    }
    expected.checked_add(1).ok_or(HelloError::BadSeq)
}

#[cfg(test)]
mod tests {
    use super::{decode_length_prefixed, encode_length_prefixed, expect_seq};
    use crate::{Frame, FrameType, HelloError};

    fn sample() -> Frame {
        Frame {
            frame_type: FrameType::Data,
            flags: 0,
            session_id: 9,
            seq: 1,
            ticket_hash: [0x11; 16],
            payload: b"abc".to_vec(),
        }
    }

    #[test]
    fn length_prefix_round_trip() {
        let frame = sample();
        let bytes = encode_length_prefixed(&frame).unwrap();
        let (decoded, used) = decode_length_prefixed(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, frame);
    }

    #[test]
    fn length_prefix_rejects_a_short_declared_length() {
        let mut bytes = encode_length_prefixed(&sample()).unwrap();
        bytes[0] = 0;
        bytes[1] = 0;
        bytes[2] = 0;
        bytes[3] = 1;
        let err = decode_length_prefixed(&bytes).unwrap_err();
        assert!(matches!(err, HelloError::BadFrameLength));
    }

    #[test]
    fn expect_seq_accepts_the_next_value() {
        assert_eq!(expect_seq(0, 0).unwrap(), 1);
        assert!(matches!(expect_seq(0, 1), Err(HelloError::BadSeq)));
    }
}

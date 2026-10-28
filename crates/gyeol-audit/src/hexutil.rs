use crate::AuditError;

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

pub(crate) fn decode_hex_array<const N: usize>(text: &str) -> Result<[u8; N], AuditError> {
    let expected = N.checked_mul(2).ok_or(AuditError::BadTicketHash)?;
    if text.len() != expected {
        return Err(AuditError::BadTicketHash);
    }
    if !text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(AuditError::BadTicketHash);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index * 2;
        let pair = &text[start..start + 2];
        *slot = u8::from_str_radix(pair, 16).map_err(|_| AuditError::BadTicketHash)?;
    }
    Ok(out)
}

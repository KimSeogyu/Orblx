use crate::RelayError;

/// The routing key for one Relay session.
///
/// The Relay header carries this value and no other route key.
/// The Relay does not mint this value.
/// The peers learn it from the control path.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelaySessionId([u8; 16]);

impl RelaySessionId {
    /// Build an id from 16 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Draw a random id.
    ///
    /// A lab harness may call this function.
    /// The Relay server does not call this function.
    pub fn generate() -> Result<Self, RelayError> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|err| RelayError::Io(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Return the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Return lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// Parse 32 hex characters.
    pub fn parse_hex(text: &str) -> Result<Self, RelayError> {
        let text = text.trim();
        if text.len() != 32 {
            return Err(RelayError::BadSession);
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&text[start..start + 2], 16)
                .map_err(|_| RelayError::BadSession)?;
        }
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for RelaySessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "RelaySessionId({})", self.to_hex())
    }
}

impl std::fmt::Display for RelaySessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

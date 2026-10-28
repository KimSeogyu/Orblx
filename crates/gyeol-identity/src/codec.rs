use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::IdentityError;

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

pub(crate) fn decode_hex_array<const N: usize>(text: &str) -> Result<[u8; N], IdentityError> {
    let expected = N.checked_mul(2).ok_or(IdentityError::Encoding)?;
    if text.len() != expected {
        return Err(IdentityError::Encoding);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index * 2;
        let pair = text.get(start..start + 2).ok_or(IdentityError::Encoding)?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| IdentityError::Encoding)?;
    }
    Ok(out)
}

pub(crate) fn pem_encode(tag: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut text = String::new();
    text.push_str("-----BEGIN ");
    text.push_str(tag);
    text.push_str("-----\n");
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + 64).min(body.len());
        text.push_str(&body[offset..end]);
        text.push('\n');
        offset = end;
    }
    text.push_str("-----END ");
    text.push_str(tag);
    text.push_str("-----\n");
    text
}

pub(crate) fn pem_blocks(text: &str, tag: &str) -> Result<Vec<Vec<u8>>, IdentityError> {
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let mut blocks = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("-----BEGIN ") {
            if inside || line != begin {
                return Err(IdentityError::Encoding);
            }
            inside = true;
            body.clear();
            continue;
        }
        if line.starts_with("-----END ") {
            if !inside || line != end {
                return Err(IdentityError::Encoding);
            }
            let der = STANDARD
                .decode(body.as_bytes())
                .map_err(|_| IdentityError::Encoding)?;
            if der.is_empty() {
                return Err(IdentityError::Encoding);
            }
            blocks.push(der);
            inside = false;
            continue;
        }
        if !inside {
            return Err(IdentityError::Encoding);
        }
        body.push_str(line);
    }
    if inside || blocks.is_empty() {
        return Err(IdentityError::Encoding);
    }
    Ok(blocks)
}

/// The fixed SubjectPublicKeyInfo prefix for an Ed25519 key.
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub(crate) fn ed25519_spki(public_key: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(ED25519_SPKI_PREFIX);
    der.extend_from_slice(public_key);
    der
}

pub(crate) fn ed25519_raw_from_spki(spki: &[u8]) -> Result<[u8; 32], IdentityError> {
    if spki.len() != 44 || !spki.starts_with(ED25519_SPKI_PREFIX) {
        return Err(IdentityError::Encoding);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&spki[ED25519_SPKI_PREFIX.len()..]);
    Ok(key)
}

/// Algorithm identifier and nested seed header inside an Ed25519 PKCS#8 key.
const ED25519_PKCS8_ALG: &[u8] = &[
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Public-key tag used when the PKCS#8 version is 1. 32 key bytes follow this tag.
const ED25519_PKCS8_PUB_MARK: &[u8] = &[0x81, 0x21, 0x00];

pub(crate) fn ed25519_seed_from_pkcs8(
    pkcs8: &[u8],
) -> Result<([u8; 32], Option<[u8; 32]>), IdentityError> {
    if pkcs8.len() < 2 || pkcs8[0] != 0x30 {
        return Err(IdentityError::Encoding);
    }
    let length = usize::from(pkcs8[1]);
    let rest = &pkcs8[2..];
    if length != rest.len() || rest.len() < 3 || rest[0] != 0x02 || rest[1] != 0x01 {
        return Err(IdentityError::Encoding);
    }
    let version = rest[2];
    let after_version = &rest[3..];
    if !after_version.starts_with(ED25519_PKCS8_ALG) {
        return Err(IdentityError::Encoding);
    }
    let after_alg = &after_version[ED25519_PKCS8_ALG.len()..];
    let Some((seed_bytes, tail)) = after_alg.split_at_checked(32) else {
        return Err(IdentityError::Encoding);
    };
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed_bytes);
    if version == 0 && tail.is_empty() {
        return Ok((seed, None));
    }
    if version != 1
        || tail.len() != ED25519_PKCS8_PUB_MARK.len() + 32
        || !tail.starts_with(ED25519_PKCS8_PUB_MARK)
    {
        return Err(IdentityError::Encoding);
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&tail[ED25519_PKCS8_PUB_MARK.len()..]);
    Ok((seed, Some(public_key)))
}

pub(crate) fn read_pem_file(path: &Path) -> Result<String, IdentityError> {
    fs::read_to_string(path).map_err(|_| IdentityError::File)
}

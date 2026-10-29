//! The SSH host key is the node SVID key.
//!
//! The key stays in memory.
//! The server does not write an SSH key file.

use ed25519_dalek::SigningKey;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::PublicKey;
use russh::keys::PrivateKey;

/// Build an Ed25519 SSH host key from an SVID seed.
///
/// The returned public key is the raw 32-byte Ed25519 key.
pub fn host_key_from_seed(seed: &[u8; 32]) -> Result<(PrivateKey, [u8; 32]), String> {
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(seed);
    raw[32..].copy_from_slice(&public);
    let pair = Ed25519Keypair::from_bytes(&raw)
        .map_err(|_| "The SSH host key is not valid.".to_string())?;
    let private = PrivateKey::new(KeypairData::Ed25519(pair), "orblx")
        .map_err(|_| "The SSH host key is not valid.".to_string())?;
    let raw_public = ed25519_public_bytes(private.public_key())
        .ok_or_else(|| "The SSH host key is not valid.".to_string())?;
    if raw_public != public {
        return Err("The SSH host key is not valid.".to_string());
    }
    Ok((private, public))
}

/// Return the raw Ed25519 key when `key` is Ed25519.
pub fn ed25519_public_bytes(key: &PublicKey) -> Option<[u8; 32]> {
    use russh::keys::ssh_key::public::KeyData;
    match key.key_data() {
        KeyData::Ed25519(value) => {
            let bytes = value.as_ref();
            let mut out = [0u8; 32];
            if bytes.len() != 32 {
                return None;
            }
            out.copy_from_slice(&bytes[..32]);
            Some(out)
        }
        _ => None,
    }
}

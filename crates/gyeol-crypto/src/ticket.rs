use std::fmt;
use std::time::{Duration, SystemTime};

use gyeol_identity::{
    verify_ticket as verify_ed25519_ticket, DenySet, SpiffeId, TicketFlags, TicketVerifier,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::CryptoError;

/// The longest overlap for two TicketKey windows.
pub const MAX_TICKET_KEY_OVERLAP: Duration = Duration::from_secs(24 * 60 * 60);

type HmacSha256 = Hmac<Sha256>;

/// Return the bytes that HMAC-SHA256 covers.
///
/// TODO(frame-freeze): the input is the identity ticket encoding.
/// Replace this function when Datapath freezes the canonical ticket layout.
/// Do not treat a test of this function as the frozen HMAC vector.
pub fn mac_input(ticket_bytes: &[u8]) -> &[u8] {
    ticket_bytes
}

/// Return `SHA-256(ticket_bytes)[0..16]`.
///
/// The value matches Identity `ticket_hash` and the ADR 0002 frame field.
pub fn ticket_hash(ticket_bytes: &[u8]) -> [u8; 16] {
    gyeol_identity::ticket_hash(ticket_bytes)
}

/// Compute `HMAC-SHA256(K_ticket, canonical_bytes)`.
pub fn ticket_mac(mac_key: &[u8; 32], canonical_bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| CryptoError::TicketKey)?;
    mac.update(canonical_bytes);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// One Ed25519 TicketKey and its HMAC key.
///
/// The public key must differ from the SVID CA public key.
#[derive(Clone)]
#[must_use]
pub struct TicketKey {
    verifier: TicketVerifier,
    public_key: [u8; 32],
    mac_key: [u8; 32],
    not_before: SystemTime,
    not_after: SystemTime,
}

impl fmt::Debug for TicketKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TicketKey")
            .field("public_key", &self.public_key)
            .field("mac_key", &"[redacted]")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish()
    }
}

impl TicketKey {
    /// Store one ticket key.
    ///
    /// `not_after` must be greater than or equal to `not_before`.
    pub fn new(
        verifier: TicketVerifier,
        mac_key: [u8; 32],
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<Self, CryptoError> {
        if not_after < not_before {
            return Err(CryptoError::TicketKey);
        }
        Ok(Self {
            public_key: verifier.public_key(),
            verifier,
            mac_key,
            not_before,
            not_after,
        })
    }

    /// Return the Ed25519 public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    fn valid_at(&self, now: SystemTime) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    fn window(&self) -> (SystemTime, SystemTime) {
        (self.not_before, self.not_after)
    }
}

/// The TicketKey set for verify.
///
/// The set holds the current key and, during rotation, one previous key.
#[derive(Debug, Clone)]
#[must_use]
pub struct TicketRing {
    keys: Vec<TicketKey>,
}

impl TicketRing {
    /// Store one current key.
    ///
    /// The function rejects a public key that equals the SVID CA public key.
    pub fn single(key: TicketKey, svid_ca_public: &[u8; 32]) -> Result<Self, CryptoError> {
        reject_ca(&key, svid_ca_public)?;
        Ok(Self { keys: vec![key] })
    }

    /// Store a current key and one previous key.
    ///
    /// The overlap of the two windows must be 24 hours or less.
    /// The function tries the current key first.
    pub fn rotating(
        current: TicketKey,
        previous: TicketKey,
        svid_ca_public: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        reject_ca(&current, svid_ca_public)?;
        reject_ca(&previous, svid_ca_public)?;
        if current.public_key() == previous.public_key() {
            return Err(CryptoError::TicketKey);
        }
        let overlap = window_overlap(current.window(), previous.window())?;
        if overlap > MAX_TICKET_KEY_OVERLAP {
            return Err(CryptoError::TicketOverlap);
        }
        Ok(Self {
            keys: vec![current, previous],
        })
    }
}

/// A ticket that passed the Ed25519 check, the HMAC check, and the subject check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct TicketProof {
    subject: SpiffeId,
    hash: [u8; 16],
    expires: u64,
    dst_cidr: String,
    proto: u8,
    dst_port: u16,
    flags: TicketFlags,
}

impl TicketProof {
    /// Return the ticket subject.
    pub fn subject(&self) -> &SpiffeId {
        &self.subject
    }

    /// Return `ticket_hash`.
    pub fn hash(&self) -> &[u8; 16] {
        &self.hash
    }

    /// Return the ticket expiry as Unix seconds.
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// Return the destination CIDR from the identity ticket.
    pub fn dst_cidr(&self) -> &str {
        &self.dst_cidr
    }

    /// Return the IP protocol number from the identity ticket.
    pub fn proto(&self) -> u8 {
        self.proto
    }

    /// Return the destination port from the identity ticket.
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    /// Return the ticket flags.
    pub fn flags(&self) -> TicketFlags {
        self.flags
    }
}

/// Check one capability ticket for a finished peer.
///
/// The function checks the key window, the Ed25519 signature, the HMAC tag,
/// the ticket time, the deny list, and `subject == peer`.
pub fn verify_ticket(
    ring: &TicketRing,
    ticket_bytes: &[u8],
    mac: &[u8; 32],
    peer: &SpiffeId,
    now: SystemTime,
    deny: &DenySet,
) -> Result<TicketProof, CryptoError> {
    let mut saw_window = false;
    for key in &ring.keys {
        if !key.valid_at(now) {
            continue;
        }
        saw_window = true;
        match verify_ed25519_ticket(&key.verifier, ticket_bytes, now, deny) {
            Ok(verified) => {
                check_mac(key, ticket_bytes, mac)?;
                if &verified.subject != peer {
                    return Err(CryptoError::TicketSubject);
                }
                return Ok(TicketProof {
                    subject: verified.subject,
                    hash: verified.hash,
                    expires: verified.expires,
                    dst_cidr: verified.dst_cidr,
                    proto: verified.proto,
                    dst_port: verified.dst_port,
                    flags: verified.flags,
                });
            }
            Err(gyeol_identity::IdentityError::Signature) => continue,
            Err(err) => return Err(CryptoError::Identity(err)),
        }
    }
    if saw_window {
        Err(CryptoError::Identity(
            gyeol_identity::IdentityError::Signature,
        ))
    } else {
        Err(CryptoError::TicketKey)
    }
}

fn check_mac(key: &TicketKey, ticket_bytes: &[u8], mac: &[u8; 32]) -> Result<(), CryptoError> {
    let mut hasher =
        HmacSha256::new_from_slice(&key.mac_key).map_err(|_| CryptoError::TicketKey)?;
    hasher.update(mac_input(ticket_bytes));
    hasher.verify_slice(mac).map_err(|_| CryptoError::TicketMac)
}

fn reject_ca(key: &TicketKey, svid_ca_public: &[u8; 32]) -> Result<(), CryptoError> {
    if key.public_key() == svid_ca_public {
        return Err(CryptoError::TicketKeySeparation);
    }
    Ok(())
}

fn window_overlap(
    left: (SystemTime, SystemTime),
    right: (SystemTime, SystemTime),
) -> Result<Duration, CryptoError> {
    let start = max_time(left.0, right.0);
    let end = min_time(left.1, right.1);
    if end < start {
        return Ok(Duration::ZERO);
    }
    end.duration_since(start)
        .map_err(|_| CryptoError::TicketKey)
}

fn min_time(left: SystemTime, right: SystemTime) -> SystemTime {
    if left <= right {
        left
    } else {
        right
    }
}

fn max_time(left: SystemTime, right: SystemTime) -> SystemTime {
    if left >= right {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use gyeol_identity::{
        sign_ticket, DenySet, IdentityError, MiniCa, SpiffeId, TicketClaims, TicketFlags,
        TicketSigner,
    };

    use super::{
        mac_input, ticket_hash, ticket_mac, verify_ticket, TicketKey, TicketRing,
        MAX_TICKET_KEY_OVERLAP,
    };
    use crate::CryptoError;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn unix(now: SystemTime) -> u64 {
        now.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn claims(now: SystemTime, subject: &SpiffeId) -> TicketClaims {
        TicketClaims {
            issuer: SpiffeId::coord("1").unwrap(),
            subject: subject.clone(),
            not_before: unix(now),
            expires: unix(now) + 600,
            dst_cidr: "10.8.0.10/32".to_string(),
            proto: 6,
            dst_port: 443,
            flags: TicketFlags::none(),
        }
    }

    #[test]
    fn hmac_sha256_known_answer() {
        let key = [0x0b; 32];
        let tag = ticket_mac(&key, b"hi there").unwrap();
        assert_eq!(
            hex_bytes(&tag),
            "481a08ba07a1082e20c2628ba7a86446e03b4828252f0a689e4696ea89761a98"
        );
        assert_eq!(mac_input(b"ticket"), b"ticket");
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn verify_checks_mac_subject_and_key_separation() {
        let now = at(1_700_000_000);
        let ca = MiniCa::generate(now).unwrap();
        let signer = TicketSigner::generate();
        assert_ne!(signer.public_key(), *ca.public_key());
        let subject = SpiffeId::user("seogyu-dev").unwrap();
        let signed = sign_ticket(&signer, &claims(now, &subject)).unwrap();
        let mac_key = [0x42; 32];
        let mac = ticket_mac(&mac_key, mac_input(&signed.bytes)).unwrap();
        let key = TicketKey::new(
            signer.verifier(),
            mac_key,
            now,
            now + Duration::from_secs(3600),
        )
        .unwrap();
        let key_debug = format!("{key:?}");
        assert_eq!(
            TicketRing::single(key.clone(), key.public_key()).unwrap_err(),
            CryptoError::TicketKeySeparation
        );
        let ring = TicketRing::single(key, ca.public_key()).unwrap();
        let proof =
            verify_ticket(&ring, &signed.bytes, &mac, &subject, now, &DenySet::empty()).unwrap();
        assert_eq!(proof.subject(), &subject);
        assert_eq!(proof.hash(), &signed.hash);
        assert_eq!(*proof.hash(), ticket_hash(&signed.bytes));
        assert_eq!(proof.expires(), unix(now) + 600);
        assert_eq!(proof.dst_cidr(), "10.8.0.10/32");
        assert_eq!(proof.proto(), 6);
        assert_eq!(proof.dst_port(), 443);
        assert!(!proof.flags().agent_jit());

        let mut bad_mac = mac;
        bad_mac[0] ^= 0xff;
        assert_eq!(
            verify_ticket(
                &ring,
                &signed.bytes,
                &bad_mac,
                &subject,
                now,
                &DenySet::empty()
            )
            .unwrap_err(),
            CryptoError::TicketMac
        );
        let other = SpiffeId::user("other-user").unwrap();
        assert_eq!(
            verify_ticket(&ring, &signed.bytes, &mac, &other, now, &DenySet::empty()).unwrap_err(),
            CryptoError::TicketSubject
        );
        assert!(key_debug.contains("redacted"));
        assert!(key_debug.contains("mac_key"));
    }

    #[test]
    fn rotation_overlap_is_at_most_24_hours() {
        let start = at(1_700_000_000);
        let day = MAX_TICKET_KEY_OVERLAP;
        let current_signer = TicketSigner::generate();
        let previous_signer = TicketSigner::generate();
        assert_ne!(current_signer.public_key(), previous_signer.public_key());
        let ca = [0u8; 32];
        let current = TicketKey::new(
            current_signer.verifier(),
            [0x11; 32],
            start + day,
            start + day * 3u32,
        )
        .unwrap();
        let previous = TicketKey::new(
            previous_signer.verifier(),
            [0x22; 32],
            start,
            start + day * 2u32,
        )
        .unwrap();
        assert!(TicketRing::rotating(current.clone(), previous.clone(), &ca).is_ok());

        let previous_long = TicketKey::new(
            previous_signer.verifier(),
            [0x22; 32],
            start,
            start + day * 2u32 + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            TicketRing::rotating(current.clone(), previous_long, &ca).unwrap_err(),
            CryptoError::TicketOverlap
        );
        assert_eq!(
            TicketRing::rotating(current.clone(), current.clone(), &ca).unwrap_err(),
            CryptoError::TicketKey
        );

        let subject = SpiffeId::agent("worker-1").unwrap();
        let now = start + day + Duration::from_secs(10);
        let signed = sign_ticket(&previous_signer, &claims(now, &subject)).unwrap();
        let mac = ticket_mac(&[0x22; 32], mac_input(&signed.bytes)).unwrap();
        let ring = TicketRing::rotating(current, previous, &ca).unwrap();
        let proof =
            verify_ticket(&ring, &signed.bytes, &mac, &subject, now, &DenySet::empty()).unwrap();
        assert_eq!(proof.subject().kind(), gyeol_identity::WorkloadKind::Agent);

        let later = start + day * 2u32 + Duration::from_secs(1);
        let mut later_claims = claims(later, &subject);
        later_claims.not_before = unix(later);
        later_claims.expires = unix(later) + 60;
        let old_signed = sign_ticket(&previous_signer, &later_claims).unwrap();
        let old_mac = ticket_mac(&[0x22; 32], mac_input(&old_signed.bytes)).unwrap();
        assert_eq!(
            verify_ticket(
                &ring,
                &old_signed.bytes,
                &old_mac,
                &subject,
                later,
                &DenySet::empty()
            )
            .unwrap_err(),
            CryptoError::Identity(IdentityError::Signature)
        );
    }

    #[test]
    fn a_key_window_must_move_forward() {
        let now = at(1_700_000_000);
        let signer = TicketSigner::generate();
        assert_eq!(
            TicketKey::new(
                signer.verifier(),
                [1; 32],
                now,
                now - Duration::from_secs(1)
            )
            .unwrap_err(),
            CryptoError::TicketKey
        );
    }
}

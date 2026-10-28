use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use ed25519_dalek::SigningKey;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ED25519,
};
use time::OffsetDateTime;

use crate::cert::{
    cert_validity, certificate_ed25519_public_key, decode_certificate_pem, extract_spiffe_id,
    TrustBundle,
};
use crate::clock::{offset_from_unix, unix_time, whole_seconds, CA_LIFETIME_SECS, MAX_SKEW_SECS};
use crate::codec::{ed25519_seed_from_pkcs8, pem_blocks, read_pem_file};
use crate::deny::DenySet;
use crate::error::IdentityError;
use crate::spiffe::SpiffeId;

const CA_COMMON_NAME: &str = "gyeol-svid-ca";

/// An Ed25519 mini CA that issues leaf X.509-SVIDs.
pub struct MiniCa {
    key: KeyPair,
    params: CertificateParams,
    bundle: TrustBundle,
    certificate_pem: String,
    public_key: [u8; 32],
}

impl fmt::Debug for MiniCa {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiniCa")
            .field("public_key", &crate::codec::encode_hex(&self.public_key))
            .finish()
    }
}

impl MiniCa {
    /// Generate a new root and a matching trust bundle.
    pub fn generate(now: SystemTime) -> Result<Self, IdentityError> {
        let key = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| IdentityError::Certificate)?;
        let public_key =
            <[u8; 32]>::try_from(key.public_key_raw()).map_err(|_| IdentityError::Certificate)?;
        let now_unix = unix_time(now)?;
        let not_before = now_unix.saturating_sub(MAX_SKEW_SECS);
        let not_after = now_unix
            .checked_add(CA_LIFETIME_SECS)
            .ok_or(IdentityError::Time)?;
        let mut params = CertificateParams::default();
        params.not_before = offset_from_unix(not_before)?;
        params.not_after = offset_from_unix(not_after)?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, CA_COMMON_NAME);
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.extended_key_usages.clear();
        params.subject_alt_names.clear();
        params.use_authority_key_identifier_extension = false;
        let certificate = params
            .self_signed(&key)
            .map_err(|_| IdentityError::Certificate)?;
        let certificate_pem = certificate.pem();
        let bundle = TrustBundle::from_pem(&certificate_pem)?;
        Ok(Self {
            key,
            params,
            bundle,
            certificate_pem,
            public_key,
        })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn trust_bundle_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn trust_bundle(&self) -> &TrustBundle {
        &self.bundle
    }

    /// Issue one leaf X.509-SVID.
    ///
    /// The leaf subject is empty. rcgen then marks the URI SAN as critical.
    pub fn issue(
        &self,
        id: &SpiffeId,
        now: SystemTime,
        ttl: Duration,
        deny: &DenySet,
    ) -> Result<IssuedSvid, IdentityError> {
        deny.reject_uri(id)?;
        let ttl_secs = whole_seconds(ttl)?;
        if ttl > id.kind().max_ttl() {
            return Err(IdentityError::Time);
        }
        let now_unix = unix_time(now)?;
        let not_after = now_unix.checked_add(ttl_secs).ok_or(IdentityError::Time)?;
        let ca_not_before = unix_time_of_offset(self.params.not_before)?;
        let ca_not_after = unix_time_of_offset(self.params.not_after)?;
        if now_unix < ca_not_before || not_after > ca_not_after {
            return Err(IdentityError::Time);
        }

        let leaf_key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|_| IdentityError::Certificate)?;
        let mut params = CertificateParams::default();
        params.not_before = offset_from_unix(now_unix)?;
        params.not_after = offset_from_unix(not_after)?;
        // An empty subject makes the SAN critical. The locked profile requires that flag.
        params.distinguished_name = DistinguishedName::new();
        let uri = Ia5String::try_from(id.as_uri()).map_err(|_| IdentityError::SpiffeId)?;
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        let issuer = Issuer::from_params(&self.params, &self.key);
        let certificate = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|_| IdentityError::Certificate)?;
        let certificate_der = certificate.der().as_ref().to_vec();
        let (parsed_not_before, parsed_not_after) = cert_validity(&certificate_der)?;
        if parsed_not_before != now_unix || parsed_not_after != not_after {
            return Err(IdentityError::Certificate);
        }
        let authed = self
            .bundle
            .authenticate_leaf(&certificate_der, now, &DenySet::empty())?;
        if &authed != id {
            return Err(IdentityError::Profile);
        }
        Ok(IssuedSvid {
            spiffe_id: id.clone(),
            certificate_pem: certificate.pem(),
            certificate_der,
            private_key_pem: leaf_key.serialize_pem(),
            not_before: parsed_not_before,
            not_after: parsed_not_after,
        })
    }
}

fn unix_time_of_offset(value: OffsetDateTime) -> Result<u64, IdentityError> {
    u64::try_from(value.unix_timestamp()).map_err(|_| IdentityError::Time)
}

/// A leaf certificate and the matching private key.
pub struct IssuedSvid {
    pub spiffe_id: SpiffeId,
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    pub private_key_pem: String,
    pub not_before: u64,
    pub not_after: u64,
}

impl IssuedSvid {
    /// Build a leaf SVID from certificate PEM and private key PEM.
    ///
    /// The certificate must contain one CERTIFICATE block.
    /// The private key must contain one PRIVATE KEY block.
    /// The private key must match the certificate public key.
    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self, IdentityError> {
        let certificate_der = decode_certificate_pem(certificate_pem)?;
        let spiffe_id = extract_spiffe_id(&certificate_der)?;
        let (not_before, not_after) = cert_validity(&certificate_der)?;
        let key_blocks =
            pem_blocks(private_key_pem, "PRIVATE KEY").map_err(|_| IdentityError::Certificate)?;
        if key_blocks.len() != 1 {
            return Err(IdentityError::Certificate);
        }
        let (seed, embedded) =
            ed25519_seed_from_pkcs8(&key_blocks[0]).map_err(|_| IdentityError::Certificate)?;
        let derived = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        if embedded.is_some_and(|key| key != derived) {
            return Err(IdentityError::Certificate);
        }
        if derived != certificate_ed25519_public_key(&certificate_der)? {
            return Err(IdentityError::Certificate);
        }
        Ok(Self {
            spiffe_id,
            certificate_pem: certificate_pem.to_string(),
            certificate_der,
            private_key_pem: private_key_pem.to_string(),
            not_before,
            not_after,
        })
    }

    /// Read a leaf SVID from a certificate PEM file and a private key PEM file.
    ///
    /// Each file must be UTF-8 text.
    /// The function calls `from_pem` on that text.
    pub fn from_pem_files(certificate: &Path, private_key: &Path) -> Result<Self, IdentityError> {
        let certificate_pem = read_pem_file(certificate)?;
        let private_key_pem = read_pem_file(private_key)?;
        Self::from_pem(&certificate_pem, &private_key_pem)
    }
}

impl fmt::Debug for IssuedSvid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("private_key_pem", &"[elided]")
            .finish()
    }
}

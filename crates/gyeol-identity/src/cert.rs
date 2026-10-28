use x509_parser::asn1_rs::{BitString, FromDer};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{
    BasicConstraints, ExtendedKeyUsage, GeneralName, ParsedExtension, SubjectAlternativeName,
};
use x509_parser::x509::X509Version;

use crate::clock::{in_window, unix_time};
use crate::codec::pem_blocks;
use crate::deny::DenySet;
use crate::error::IdentityError;
use crate::spiffe::SpiffeId;

const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
const DIGITAL_SIGNATURE: u16 = 1 << 0;
const KEY_CERT_SIGN: u16 = 1 << 5;
const CRL_SIGN: u16 = 1 << 6;

/// Read one PEM certificate and return the DER bytes.
pub fn decode_certificate_pem(pem: &str) -> Result<Vec<u8>, IdentityError> {
    let blocks = pem_blocks(pem, "CERTIFICATE").map_err(|_| IdentityError::Certificate)?;
    if blocks.len() != 1 {
        return Err(IdentityError::Certificate);
    }
    blocks.into_iter().next().ok_or(IdentityError::Certificate)
}

/// Read the single SPIFFE URI from a leaf certificate.
///
/// The function fails when the leaf profile is not the locked profile.
pub fn extract_spiffe_id(leaf_der: &[u8]) -> Result<SpiffeId, IdentityError> {
    let cert = parse_cert(leaf_der)?;
    check_common(&cert)?;
    leaf_spiffe_id(&cert)
}

/// A PEM trust bundle of Ed25519 root certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBundle {
    roots: Vec<Root>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Root {
    subject: Vec<u8>,
    public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
    der: Vec<u8>,
}

impl TrustBundle {
    /// Load a trust bundle from a PEM concatenation of root certificates.
    pub fn from_pem(pem: &str) -> Result<Self, IdentityError> {
        let blocks = pem_blocks(pem, "CERTIFICATE").map_err(|_| IdentityError::Certificate)?;
        let mut roots = Vec::with_capacity(blocks.len());
        for der in blocks {
            let root = load_root(&der)?;
            if roots.iter().any(|item: &Root| item.subject == root.subject) {
                return Err(IdentityError::Certificate);
            }
            roots.push(root);
        }
        Ok(Self { roots })
    }

    /// Return the PEM concatenation of the root certificates.
    pub fn to_pem(&self) -> String {
        let mut text = String::new();
        for root in &self.roots {
            text.push_str(&crate::codec::pem_encode("CERTIFICATE", &root.der));
        }
        text
    }

    /// Check the leaf against this bundle, the clock, and the deny list.
    pub fn authenticate_leaf(
        &self,
        leaf_der: &[u8],
        now: std::time::SystemTime,
        deny: &DenySet,
    ) -> Result<SpiffeId, IdentityError> {
        let cert = parse_cert(leaf_der)?;
        check_common(&cert)?;
        let spiffe_id = leaf_spiffe_id(&cert)?;
        let root = self
            .roots
            .iter()
            .find(|root| root.subject.as_slice() == cert.issuer().as_raw())
            .ok_or(IdentityError::Certificate)?;
        verify_ed25519(&cert, &root.public_key)?;
        let now_unix = unix_time(now)?;
        in_window(now_unix, root.not_before, root.not_after)?;
        let (not_before, not_after) = validity_unix(&cert)?;
        in_window(now_unix, not_before, not_after)?;
        deny.reject_uri(&spiffe_id)?;
        Ok(spiffe_id)
    }
}

fn load_root(der: &[u8]) -> Result<Root, IdentityError> {
    let cert = parse_cert(der)?;
    check_common(&cert)?;
    check_root_profile(&cert)?;
    if cert.issuer().as_raw() != cert.subject().as_raw() {
        return Err(IdentityError::Certificate);
    }
    let public_key = ed25519_public_key(&cert)?;
    verify_ed25519(&cert, &public_key)?;
    let (not_before, not_after) = validity_unix(&cert)?;
    Ok(Root {
        subject: cert.subject().as_raw().to_vec(),
        public_key,
        not_before,
        not_after,
        der: der.to_vec(),
    })
}

pub(crate) fn cert_validity(der: &[u8]) -> Result<(u64, u64), IdentityError> {
    let cert = parse_cert(der)?;
    validity_unix(&cert)
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, IdentityError> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| IdentityError::Certificate)?;
    if !rest.is_empty() {
        return Err(IdentityError::Certificate);
    }
    Ok(cert)
}

fn check_common(cert: &X509Certificate<'_>) -> Result<(), IdentityError> {
    if cert.version() != X509Version::V3 {
        return Err(IdentityError::Profile);
    }
    if cert.issuer_uid.is_some() || cert.subject_uid.is_some() {
        return Err(IdentityError::Profile);
    }
    if !is_ed25519_oid(&cert.signature_algorithm.algorithm)
        || !is_ed25519_oid(&cert.tbs_certificate.signature.algorithm)
        || !is_ed25519_oid(&cert.public_key().algorithm.algorithm)
    {
        return Err(IdentityError::Profile);
    }
    Ok(())
}

fn is_ed25519_oid(oid: &x509_parser::asn1_rs::Oid<'_>) -> bool {
    oid.as_bytes() == ED25519_OID
}

fn check_root_profile(cert: &X509Certificate<'_>) -> Result<(), IdentityError> {
    let mut saw_basic = false;
    let mut saw_usage = false;
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(constraints) => {
                if saw_basic || !extension.critical || !root_basic(constraints) {
                    return Err(IdentityError::Profile);
                }
                saw_basic = true;
            }
            ParsedExtension::KeyUsage(usage) => {
                if saw_usage || !extension.critical || usage.flags != (KEY_CERT_SIGN | CRL_SIGN) {
                    return Err(IdentityError::Profile);
                }
                saw_usage = true;
            }
            ParsedExtension::SubjectKeyIdentifier(_)
            | ParsedExtension::AuthorityKeyIdentifier(_) => {
                if extension.critical {
                    return Err(IdentityError::Profile);
                }
            }
            ParsedExtension::UnsupportedExtension { .. }
            | ParsedExtension::ParseError { .. }
            | ParsedExtension::CertificatePolicies(_)
            | ParsedExtension::PolicyMappings(_)
            | ParsedExtension::SubjectAlternativeName(_)
            | ParsedExtension::IssuerAlternativeName(_)
            | ParsedExtension::NameConstraints(_)
            | ParsedExtension::PolicyConstraints(_)
            | ParsedExtension::ExtendedKeyUsage(_)
            | ParsedExtension::CRLDistributionPoints(_)
            | ParsedExtension::InhibitAnyPolicy(_)
            | ParsedExtension::AuthorityInfoAccess(_)
            | ParsedExtension::SubjectInfoAccess(_)
            | ParsedExtension::NSCertType(_)
            | ParsedExtension::NsCertComment(_)
            | ParsedExtension::IssuingDistributionPoint(_)
            | ParsedExtension::CRLNumber(_)
            | ParsedExtension::ReasonCode(_)
            | ParsedExtension::InvalidityDate(_)
            | ParsedExtension::SCT(_)
            | ParsedExtension::Unparsed => return Err(IdentityError::Profile),
        }
    }
    if saw_basic && saw_usage {
        Ok(())
    } else {
        Err(IdentityError::Profile)
    }
}

fn root_basic(constraints: &BasicConstraints) -> bool {
    constraints.ca && constraints.path_len_constraint == Some(0)
}

fn leaf_spiffe_id(cert: &X509Certificate<'_>) -> Result<SpiffeId, IdentityError> {
    let mut saw_basic = false;
    let mut saw_usage = false;
    let mut saw_eku = false;
    let mut spiffe_id = None;
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(constraints) => {
                if saw_basic || !extension.critical || !leaf_basic(constraints) {
                    return Err(IdentityError::Profile);
                }
                saw_basic = true;
            }
            ParsedExtension::KeyUsage(usage) => {
                if saw_usage || !extension.critical || usage.flags != DIGITAL_SIGNATURE {
                    return Err(IdentityError::Profile);
                }
                saw_usage = true;
            }
            ParsedExtension::ExtendedKeyUsage(usage) => {
                if saw_eku || extension.critical || !leaf_eku(usage) {
                    return Err(IdentityError::Profile);
                }
                saw_eku = true;
            }
            ParsedExtension::SubjectAlternativeName(name) => {
                if spiffe_id.is_some() || !extension.critical {
                    return Err(IdentityError::Profile);
                }
                spiffe_id = Some(one_spiffe_uri(name)?);
            }
            ParsedExtension::SubjectKeyIdentifier(_)
            | ParsedExtension::AuthorityKeyIdentifier(_) => {
                if extension.critical {
                    return Err(IdentityError::Profile);
                }
            }
            ParsedExtension::UnsupportedExtension { .. }
            | ParsedExtension::ParseError { .. }
            | ParsedExtension::CertificatePolicies(_)
            | ParsedExtension::PolicyMappings(_)
            | ParsedExtension::IssuerAlternativeName(_)
            | ParsedExtension::NameConstraints(_)
            | ParsedExtension::PolicyConstraints(_)
            | ParsedExtension::CRLDistributionPoints(_)
            | ParsedExtension::InhibitAnyPolicy(_)
            | ParsedExtension::AuthorityInfoAccess(_)
            | ParsedExtension::SubjectInfoAccess(_)
            | ParsedExtension::NSCertType(_)
            | ParsedExtension::NsCertComment(_)
            | ParsedExtension::IssuingDistributionPoint(_)
            | ParsedExtension::CRLNumber(_)
            | ParsedExtension::ReasonCode(_)
            | ParsedExtension::InvalidityDate(_)
            | ParsedExtension::SCT(_)
            | ParsedExtension::Unparsed => return Err(IdentityError::Profile),
        }
    }
    if saw_basic && saw_usage && saw_eku {
        spiffe_id.ok_or(IdentityError::Profile)
    } else {
        Err(IdentityError::Profile)
    }
}

fn leaf_basic(constraints: &BasicConstraints) -> bool {
    !constraints.ca && constraints.path_len_constraint.is_none()
}

fn leaf_eku(usage: &ExtendedKeyUsage<'_>) -> bool {
    usage.client_auth
        && usage.server_auth
        && !usage.any
        && !usage.code_signing
        && !usage.email_protection
        && !usage.time_stamping
        && !usage.ocsp_signing
        && usage.other.is_empty()
}

fn one_spiffe_uri(name: &SubjectAlternativeName<'_>) -> Result<SpiffeId, IdentityError> {
    if name.general_names.len() != 1 {
        return Err(IdentityError::Profile);
    }
    match &name.general_names[0] {
        GeneralName::URI(uri) => SpiffeId::parse(uri).map_err(|_| IdentityError::Profile),
        GeneralName::OtherName(_, _)
        | GeneralName::RFC822Name(_)
        | GeneralName::DNSName(_)
        | GeneralName::X400Address(_)
        | GeneralName::DirectoryName(_)
        | GeneralName::EDIPartyName(_)
        | GeneralName::IPAddress(_)
        | GeneralName::RegisteredID(_)
        | GeneralName::Invalid(_, _) => Err(IdentityError::Profile),
    }
}

fn ed25519_public_key(cert: &X509Certificate<'_>) -> Result<[u8; 32], IdentityError> {
    let bytes = bit_bytes(&cert.public_key().subject_public_key)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| IdentityError::Certificate)
}

fn verify_ed25519(cert: &X509Certificate<'_>, public_key: &[u8; 32]) -> Result<(), IdentityError> {
    let signature_bytes = bit_bytes(&cert.signature_value)?;
    let signature_bytes =
        <[u8; 64]>::try_from(signature_bytes).map_err(|_| IdentityError::Certificate)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| IdentityError::Certificate)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    key.verify_strict(cert.tbs_certificate.as_ref(), &signature)
        .map_err(|_| IdentityError::Signature)
}

fn bit_bytes<'a>(bits: &'a BitString<'a>) -> Result<&'a [u8], IdentityError> {
    if bits.unused_bits != 0 {
        return Err(IdentityError::Certificate);
    }
    Ok(bits.data.as_ref())
}

fn validity_unix(cert: &X509Certificate<'_>) -> Result<(u64, u64), IdentityError> {
    let not_before = unix_from_timestamp(cert.validity().not_before.timestamp())?;
    let not_after = unix_from_timestamp(cert.validity().not_after.timestamp())?;
    if not_after < not_before {
        return Err(IdentityError::Certificate);
    }
    Ok((not_before, not_after))
}

fn unix_from_timestamp(timestamp: i64) -> Result<u64, IdentityError> {
    u64::try_from(timestamp).map_err(|_| IdentityError::Certificate)
}

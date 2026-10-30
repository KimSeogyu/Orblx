//! File send between Orblx nodes (W23-3).
//!
//! The sender opens TCP to the receiver overlay address and sends one offer.
//! The offer holds the sender leaf SVID, a time stamp, the file name, the size,
//! the SHA-256 digest, and an Ed25519 signature with the sender SVID key.
//! The signature covers the receiver SPIFFE ID, so an offer for one node does not work on another node.
//!
//! The receiver checks the offer before it creates a file:
//! the leaf chain and the deny set, the signature, the time window,
//! the signed receiver grants for the file port, the name, and the size.
//! A refused offer leaves no file. An admitted file goes to a temporary part file.
//! The receiver links the part file to the final name only when the size and the digest match.
//! The receiver writes one hash chain record for each admitted or refused file.
//! The records hold the sender, the name, the size, and the digest. They hold no key.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use orblx_audit::{ConfigAction, ConfigEvent, ConfigLog, EMPTY_DIGEST};
use orblx_identity::{
    decode_certificate_pem, ed25519_seed_from_private_pem, extract_spiffe_id,
    leaf_ed25519_public_key, DenySet, SpiffeId, TrustBundle,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// TCP port of the file receiver on the overlay address.
pub const FILE_PORT: u16 = 4243;
/// Receiver hash chain file in the node state directory.
pub const FILE_AUDIT_FILE: &str = "file-audit.jsonl";
/// Name prefix of a part file. The receiver removes these files at start.
pub const PART_PREFIX: &str = ".orblx-part-";
/// Default size limit for one file: 1 GiB.
pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;

const MAGIC: &[u8; 8] = b"OBLXFIL1";
const DOMAIN: &str = "orblx-file-send-v1";
const MAX_LEAF: usize = 8 * 1024;
const MAX_NAME: usize = 255;
const PROOF_WINDOW_SECS: u64 = 60;
const MAX_ACTIVE: usize = 16;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// One error from a file send or a file receive.
///
/// The text does not hold keys or signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError(pub String);

impl std::fmt::Display for FileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FileError {}

fn fail(text: impl Into<String>) -> FileError {
    FileError(text.into())
}

/// The file facts that the sender signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// File name on the receiver. See [`name_ok`].
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 digest of the file bytes.
    pub sha256: [u8; 32],
}

/// The reason for a refused or failed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The offer bytes are not valid.
    Format,
    /// The leaf SVID is not valid, is denied, or is out of date.
    Identity,
    /// The signature does not match.
    Signature,
    /// The time stamp is out of the window.
    Stale,
    /// The signed receiver grants do not allow the sender on the file port.
    Acl,
    /// The file name is not valid.
    Name,
    /// The file is larger than the limit.
    Size,
    /// A file with the name exists.
    Exists,
    /// The receiver is busy.
    Busy,
    /// The sender closed before all bytes came.
    Short,
    /// The digest of the bytes does not match the offer.
    Digest,
    /// A local write failed.
    Io,
}

impl Refusal {
    /// Stable token for logs and records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Identity => "identity",
            Self::Signature => "signature",
            Self::Stale => "stale",
            Self::Acl => "acl",
            Self::Name => "name",
            Self::Size => "size",
            Self::Exists => "exists",
            Self::Busy => "busy",
            Self::Short => "short",
            Self::Digest => "digest",
            Self::Io => "io",
        }
    }
}

/// Return true when `name` can be a file name in the inbox.
///
/// The name has 1 to 255 bytes from `A-Z a-z 0-9 . _ -`.
/// The name does not start with a dot. Thus it cannot be `..` or a part file.
#[must_use]
pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Lower-case hex text of bytes.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signed_message(dst: &str, offer: &Offer, stamp: u64) -> Vec<u8> {
    format!(
        "{DOMAIN}\ndst={dst}\nname={}\nsize={}\nsha256={}\nstamp={stamp}\n",
        offer.name,
        offer.size,
        hex(&offer.sha256)
    )
    .into_bytes()
}

fn unix_secs(now: SystemTime) -> Result<u64, FileError> {
    now.duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| fail("The clock is not valid."))
}

/// Read a file and return its size and SHA-256 digest.
pub fn digest_file(path: &Path) -> Result<(u64, [u8; 32]), FileError> {
    let mut file = File::open(path)
        .map_err(|err| fail(format!("The file {} did not open. {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|err| fail(format!("The file did not read. {err}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size += read as u64;
    }
    Ok((size, hasher.finalize().into()))
}

/// The sender SVID: the leaf certificate and its key.
///
/// `Debug` does not show the key.
pub struct SendIdentity {
    leaf_der: Vec<u8>,
    signing: SigningKey,
}

impl std::fmt::Debug for SendIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SendIdentity")
            .field("leaf_bytes", &self.leaf_der.len())
            .finish_non_exhaustive()
    }
}

impl SendIdentity {
    /// Build the identity from the node SVID PEM files.
    pub fn from_pem(certificate_pem: &str, key_pem: &str) -> Result<Self, FileError> {
        let leaf_der =
            decode_certificate_pem(certificate_pem).map_err(|_| fail("The SVID is not valid."))?;
        let seed = ed25519_seed_from_private_pem(key_pem)
            .map_err(|_| fail("The SVID key is not valid."))?;
        let signing = SigningKey::from_bytes(&seed);
        let public =
            leaf_ed25519_public_key(&leaf_der).map_err(|_| fail("The SVID is not valid."))?;
        if signing.verifying_key().to_bytes() != public {
            return Err(fail("The SVID key does not match the SVID."));
        }
        Ok(Self { leaf_der, signing })
    }

    /// The SPIFFE ID in the leaf.
    pub fn spiffe_id(&self) -> Result<SpiffeId, FileError> {
        extract_spiffe_id(&self.leaf_der).map_err(|_| fail("The SVID is not valid."))
    }
}

/// Encode one offer. The output holds a signature but no key.
pub fn encode_offer(
    identity: &SendIdentity,
    dst: &SpiffeId,
    offer: &Offer,
    now: SystemTime,
) -> Result<Vec<u8>, FileError> {
    if !name_ok(&offer.name) {
        return Err(fail("The file name is not valid."));
    }
    if identity.leaf_der.len() > MAX_LEAF {
        return Err(fail("The SVID is too large."));
    }
    let stamp = unix_secs(now)?;
    let signature = identity
        .signing
        .sign(&signed_message(dst.as_uri(), offer, stamp));
    let mut out = Vec::with_capacity(MAGIC.len() + identity.leaf_der.len() + 400);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(identity.leaf_der.len() as u32).to_be_bytes());
    out.extend_from_slice(&identity.leaf_der);
    out.extend_from_slice(&stamp.to_be_bytes());
    out.extend_from_slice(&(offer.name.len() as u16).to_be_bytes());
    out.extend_from_slice(offer.name.as_bytes());
    out.extend_from_slice(&offer.size.to_be_bytes());
    out.extend_from_slice(&offer.sha256);
    out.extend_from_slice(&signature.to_bytes());
    Ok(out)
}

/// One parsed offer before checks.
struct RawOffer {
    leaf: Vec<u8>,
    stamp: u64,
    offer: Offer,
    signature: [u8; 64],
}

fn read_exact_vec(reader: &mut impl Read, len: usize) -> Result<Vec<u8>, Refusal> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(|_| Refusal::Format)?;
    Ok(buf)
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], Refusal> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf).map_err(|_| Refusal::Format)?;
    Ok(buf)
}

fn read_offer(reader: &mut impl Read) -> Result<RawOffer, Refusal> {
    let magic: [u8; 8] = read_array(reader)?;
    if &magic != MAGIC {
        return Err(Refusal::Format);
    }
    let leaf_len = u32::from_be_bytes(read_array(reader)?) as usize;
    if leaf_len == 0 || leaf_len > MAX_LEAF {
        return Err(Refusal::Format);
    }
    let leaf = read_exact_vec(reader, leaf_len)?;
    let stamp = u64::from_be_bytes(read_array(reader)?);
    let name_len = u16::from_be_bytes(read_array(reader)?) as usize;
    if name_len == 0 || name_len > MAX_NAME {
        return Err(Refusal::Name);
    }
    let name = String::from_utf8(read_exact_vec(reader, name_len)?).map_err(|_| Refusal::Name)?;
    let size = u64::from_be_bytes(read_array(reader)?);
    let sha256: [u8; 32] = read_array(reader)?;
    let signature: [u8; 64] = read_array(reader)?;
    Ok(RawOffer {
        leaf,
        stamp,
        offer: Offer { name, size, sha256 },
        signature,
    })
}

/// The receiver checks for one connection.
///
/// The caller loads this value again for each connection, so a new deny set
/// or new grants apply to the next offer.
pub struct Gate {
    /// The trust bundle for sender leaves.
    pub bundle: TrustBundle,
    /// The deny set.
    pub deny: DenySet,
    /// True when the signed receiver grants allow the sender on the file port.
    pub permits: Box<dyn Fn(&SpiffeId) -> bool + Send>,
}

/// Fixed receiver settings.
#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// The receiver SPIFFE ID. Offers must name it.
    pub self_id: SpiffeId,
    /// The directory for received files.
    pub inbox: PathBuf,
    /// The hash chain file.
    pub audit_path: PathBuf,
    /// The size limit for one file.
    pub max_bytes: u64,
}

/// The result of one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The sender SPIFFE ID, or `unknown` before the leaf check passes.
    pub sender: String,
    /// The file name from the offer, or `-`.
    pub name: String,
    /// The size from the offer.
    pub size: u64,
    /// The digest hex from the offer.
    pub sha256: String,
    /// None when the file is stored.
    pub refusal: Option<Refusal>,
}

impl Outcome {
    /// One log line. The line holds no key or signature.
    #[must_use]
    pub fn line(&self) -> String {
        match self.refusal {
            None => format!(
                "file_received from {} name {} size {} sha256 {}",
                self.sender, self.name, self.size, self.sha256
            ),
            Some(reason) => format!(
                "file_refused from {} name {} size {} sha256 {} reason {}",
                self.sender,
                self.name,
                self.size,
                self.sha256,
                reason.as_str()
            ),
        }
    }
}

/// Check one offer. Returns the sender ID or the refusal with the best known sender.
fn check_offer(
    raw: &RawOffer,
    config: &ReceiverConfig,
    gate: &Gate,
    now: SystemTime,
) -> Result<SpiffeId, (String, Refusal)> {
    let unknown = || "unknown".to_string();
    let now_secs = unix_secs(now).map_err(|_| (unknown(), Refusal::Stale))?;
    let src = gate
        .bundle
        .authenticate_leaf(&raw.leaf, now, &gate.deny)
        .map_err(|_| {
            let claimed = extract_spiffe_id(&raw.leaf)
                .map(|id| format!("{}(unverified)", id.as_uri()))
                .unwrap_or_else(|_| unknown());
            (claimed, Refusal::Identity)
        })?;
    let sender = src.as_uri().to_string();
    let public =
        leaf_ed25519_public_key(&raw.leaf).map_err(|_| (sender.clone(), Refusal::Identity))?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| (sender.clone(), Refusal::Identity))?;
    let message = signed_message(config.self_id.as_uri(), &raw.offer, raw.stamp);
    key.verify_strict(&message, &Signature::from_bytes(&raw.signature))
        .map_err(|_| (sender.clone(), Refusal::Signature))?;
    if now_secs.abs_diff(raw.stamp) > PROOF_WINDOW_SECS {
        return Err((sender, Refusal::Stale));
    }
    if !(gate.permits)(&src) {
        return Err((sender, Refusal::Acl));
    }
    if !name_ok(&raw.offer.name) {
        return Err((sender, Refusal::Name));
    }
    if raw.offer.size > config.max_bytes {
        return Err((sender, Refusal::Size));
    }
    if fs::symlink_metadata(config.inbox.join(&raw.offer.name)).is_ok() {
        return Err((sender, Refusal::Exists));
    }
    Ok(src)
}

fn part_path(inbox: &Path) -> PathBuf {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    inbox.join(format!("{PART_PREFIX}{}", hex(&bytes)))
}

fn open_part(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Copy exactly `size` bytes into a part file, then link it to the final name.
fn store_body(
    reader: &mut impl Read,
    config: &ReceiverConfig,
    offer: &Offer,
) -> Result<(), Refusal> {
    let part = part_path(&config.inbox);
    let result = (|| {
        let mut file = open_part(&part).map_err(|_| Refusal::Io)?;
        let mut hasher = Sha256::new();
        let mut left = offer.size;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let want = buf.len().min(usize::try_from(left).unwrap_or(buf.len()));
            let read = reader.read(&mut buf[..want]).map_err(|_| Refusal::Short)?;
            if read == 0 {
                return Err(Refusal::Short);
            }
            hasher.update(&buf[..read]);
            file.write_all(&buf[..read]).map_err(|_| Refusal::Io)?;
            left -= read as u64;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != offer.sha256 {
            return Err(Refusal::Digest);
        }
        file.sync_all().map_err(|_| Refusal::Io)?;
        let target = config.inbox.join(&offer.name);
        // A hard link does not replace a file that came after the check.
        fs::hard_link(&part, &target).map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                Refusal::Exists
            } else {
                Refusal::Io
            }
        })
    })();
    let _ = fs::remove_file(&part);
    result
}

fn record(audit: &Mutex<ConfigLog>, outcome: &Outcome) {
    let at_unix = unix_secs(SystemTime::now()).unwrap_or(0);
    let (action, detail) = match outcome.refusal {
        None => (
            ConfigAction::FileReceive,
            format!("size {} sha256 {}", outcome.size, outcome.sha256),
        ),
        Some(reason) => (
            ConfigAction::FileDeny,
            format!(
                "reason {} size {} sha256 {}",
                reason.as_str(),
                outcome.size,
                outcome.sha256
            ),
        ),
    };
    let after = if outcome.refusal.is_none() {
        let mut digest = [0u8; 32];
        for (index, pair) in outcome.sha256.as_bytes().chunks(2).enumerate().take(32) {
            let text = std::str::from_utf8(pair).unwrap_or("00");
            digest[index] = u8::from_str_radix(text, 16).unwrap_or(0);
        }
        digest
    } else {
        EMPTY_DIGEST
    };
    let mut target: String = outcome.name.chars().take(MAX_NAME).collect();
    if target.is_empty() {
        target = "-".to_string();
    }
    let event = ConfigEvent {
        actor: outcome.sender.clone(),
        at_unix,
        action,
        target,
        before: EMPTY_DIGEST,
        after,
        detail,
    };
    let mut log = audit.lock().unwrap_or_else(|err| err.into_inner());
    if let Err(err) = log.append(event) {
        eprintln!("The file audit record was not written. {err}");
    }
}

fn safe_name(name: &str) -> String {
    if name_ok(name) {
        name.to_string()
    } else {
        "-".to_string()
    }
}

/// Handle one connection. The function writes the reply lines and one record.
pub fn handle(
    mut stream: TcpStream,
    config: &ReceiverConfig,
    gate: &Gate,
    audit: &Mutex<ConfigLog>,
) -> Outcome {
    let _ = stream.set_read_timeout(Some(HEADER_TIMEOUT));
    let raw = match read_offer(&mut stream) {
        Ok(raw) => raw,
        Err(reason) => {
            let outcome = Outcome {
                sender: "unknown".to_string(),
                name: "-".to_string(),
                size: 0,
                sha256: "-".to_string(),
                refusal: Some(reason),
            };
            let _ = writeln!(stream, "deny {}", reason.as_str());
            record(audit, &outcome);
            return outcome;
        }
    };
    let mut outcome = Outcome {
        sender: "unknown".to_string(),
        name: safe_name(&raw.offer.name),
        size: raw.offer.size,
        sha256: hex(&raw.offer.sha256),
        refusal: None,
    };
    match check_offer(&raw, config, gate, SystemTime::now()) {
        Ok(src) => outcome.sender = src.as_uri().to_string(),
        Err((sender, reason)) => {
            outcome.sender = sender;
            outcome.refusal = Some(reason);
            let _ = writeln!(stream, "deny {}", reason.as_str());
            record(audit, &outcome);
            return outcome;
        }
    }
    if writeln!(stream, "ok").is_err() {
        outcome.refusal = Some(Refusal::Short);
        record(audit, &outcome);
        return outcome;
    }
    let _ = stream.set_read_timeout(Some(BODY_TIMEOUT));
    match store_body(&mut stream, config, &raw.offer) {
        Ok(()) => {
            let _ = writeln!(stream, "done {}", outcome.sha256);
        }
        Err(reason) => {
            outcome.refusal = Some(reason);
            let _ = writeln!(stream, "fail {}", reason.as_str());
        }
    }
    record(audit, &outcome);
    outcome
}

/// Remove part files that a stopped receiver left.
pub fn clean_parts(inbox: &Path) -> Result<usize, FileError> {
    let mut removed = 0;
    let entries =
        fs::read_dir(inbox).map_err(|err| fail(format!("The inbox did not open. {err}")))?;
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(PART_PREFIX)
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Run the receiver until the process stops.
///
/// `load` gives the checks for each connection.
pub fn serve<F>(listener: TcpListener, config: ReceiverConfig, load: F) -> Result<(), FileError>
where
    F: Fn() -> Result<Gate, FileError> + Send + Sync + 'static,
{
    fs::create_dir_all(&config.inbox)
        .map_err(|err| fail(format!("The inbox was not made. {err}")))?;
    let removed = clean_parts(&config.inbox)?;
    let audit = ConfigLog::open(&config.audit_path)
        .map_err(|err| fail(format!("The file audit chain did not open. {err}")))?;
    let audit = Arc::new(Mutex::new(audit));
    let config = Arc::new(config);
    let load = Arc::new(load);
    let active = Arc::new(AtomicUsize::new(0));
    let local = listener
        .local_addr()
        .map_err(|err| fail(format!("The receiver did not bind. {err}")))?;
    println!(
        "file_receive listen {local} inbox {} parts_removed {removed}",
        config.inbox.display()
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVE {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = writeln!(stream, "deny {}", Refusal::Busy.as_str());
            continue;
        }
        let audit = Arc::clone(&audit);
        let config = Arc::clone(&config);
        let load = Arc::clone(&load);
        let active = Arc::clone(&active);
        thread::spawn(move || {
            match load() {
                Ok(gate) => {
                    let outcome = handle(stream, &config, &gate, &audit);
                    println!("{}", outcome.line());
                }
                Err(err) => {
                    let _ = writeln!(stream, "deny {}", Refusal::Io.as_str());
                    eprintln!("The file receiver checks did not load. {err}");
                }
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// The result of one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReport {
    /// File size.
    pub size: u64,
    /// SHA-256 hex of the file.
    pub sha256: String,
    /// Receiver reply after the body: `done HEX`. A refusal is an error.
    pub reply: String,
}

fn read_line(reader: &mut impl BufRead) -> Result<String, FileError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|err| fail(format!("The receiver reply did not come. {err}")))?;
    Ok(line.trim().to_string())
}

/// Send one file. The receiver must answer `ok`, then `done` with the same digest.
pub fn send_file(
    addr: SocketAddr,
    dst: &SpiffeId,
    identity: &SendIdentity,
    path: &Path,
    name: &str,
    timeout: Duration,
) -> Result<SendReport, FileError> {
    let (size, sha256) = digest_file(path)?;
    let offer = Offer {
        name: name.to_string(),
        size,
        sha256,
    };
    let header = encode_offer(identity, dst, &offer, SystemTime::now())?;
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|err| fail(format!("The connection to {addr} failed. {err}")))?;
    let _ = stream.set_read_timeout(Some(BODY_TIMEOUT));
    let mut writer = stream
        .try_clone()
        .map_err(|err| fail(format!("The connection failed. {err}")))?;
    let mut reader = BufReader::new(stream);
    writer
        .write_all(&header)
        .map_err(|err| fail(format!("The offer was not sent. {err}")))?;
    let first = read_line(&mut reader)?;
    if first != "ok" {
        return Err(fail(format!(
            "The receiver refused the file. reply {first}"
        )));
    }
    let mut file = File::open(path).map_err(|err| fail(format!("The file did not open. {err}")))?;
    let copied = std::io::copy(&mut (&mut file).take(size), &mut writer)
        .map_err(|err| fail(format!("The file was not sent. {err}")))?;
    if copied != size {
        return Err(fail("The file changed during the send."));
    }
    writer
        .flush()
        .map_err(|err| fail(format!("The file was not sent. {err}")))?;
    let last = read_line(&mut reader)?;
    let digest = hex(&sha256);
    if last != format!("done {digest}") {
        return Err(fail(format!(
            "The receiver did not store the file. reply {last}"
        )));
    }
    Ok(SendReport {
        size,
        sha256: digest,
        reply: last,
    })
}

#[cfg(test)]
mod tests;

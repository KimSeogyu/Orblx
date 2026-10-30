//! `orblx-test-idp`: a small HTTPS OIDC test issuer for [C] proofs.
//!
//! Do not use this program in production.
//! The program writes private keys only to `--dir`.
//! The program does not print a token or a private key.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use orblx_test_idp::{
    discovery_json, jwks_json, mint, tamper_signature, unix_now, KeyAlg, MintSpec, TestKey,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEYS_FILE: &str = "keys.json";
const CA_FILE: &str = "ca.pem";
const TLS_CERT_FILE: &str = "tls.crt";
const TLS_KEY_FILE: &str = "tls.key";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(err) = run(&args) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(help());
    };
    let flags = Flags::parse(rest)?;
    match command.as_str() {
        "init" => init(&flags),
        "serve" => serve(&flags),
        "rotate" => rotate(&flags),
        "mint" => mint_command(&flags),
        _ => Err(help()),
    }
}

fn help() -> String {
    "orblx-test-idp init --dir DIR --host NAME
orblx-test-idp serve --dir DIR --issuer URL [--listen ADDR]
orblx-test-idp rotate --dir DIR --kid KID --alg RS256|ES256 [--drop KID]
orblx-test-idp mint --dir DIR --kid KID --issuer URL --aud AUD --sub SUB --out FILE
    [--email ADDR] [--nonce TEXT] [--ttl SECS] [--age SECS] [--header-kid KID] [--tamper]

This is a test issuer. Do not use it in production."
        .to_string()
}

struct Flags {
    values: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut switches = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let flag = &args[index];
            if flag == "--tamper" {
                switches.push(flag.clone());
                index += 1;
                continue;
            }
            if !flag.starts_with("--") {
                return Err(format!("The argument {flag} is not valid.\n{}", help()));
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("The flag {flag} needs a value."))?;
            values.push((flag.clone(), value.clone()));
            index += 2;
        }
        Ok(Self { values, switches })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
    }

    fn need(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("The command needs {name}."))
    }

    fn number(&self, name: &str, default: u64) -> Result<u64, String> {
        match self.get(name) {
            Some(value) => value
                .parse()
                .map_err(|_| format!("The {name} value is not a number.")),
            None => Ok(default),
        }
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|flag| flag == name)
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("The file {} did not open: {err}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|err| format!("The file write failed: {err}"))
}

fn load_keys(dir: &Path) -> Result<Vec<TestKey>, String> {
    let text = std::fs::read_to_string(dir.join(KEYS_FILE))
        .map_err(|err| format!("The key file did not open: {err}"))?;
    serde_json::from_str(&text).map_err(|err| format!("The key file is not valid: {err}"))
}

fn save_keys(dir: &Path, keys: &[TestKey]) -> Result<(), String> {
    let text = serde_json::to_string(keys).map_err(|err| err.to_string())?;
    let temp = dir.join(format!("{KEYS_FILE}.tmp"));
    write_private(&temp, &text)?;
    std::fs::rename(&temp, dir.join(KEYS_FILE)).map_err(|err| err.to_string())
}

fn init(flags: &Flags) -> Result<(), String> {
    let dir = PathBuf::from(flags.need("--dir")?);
    let host = flags.need("--host")?;
    std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    let ca_key = rcgen::KeyPair::generate().map_err(|err| err.to_string())?;
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|err| err.to_string())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "orblx test idp ca");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|err| err.to_string())?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().map_err(|err| err.to_string())?;
    let leaf_params =
        rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|err| err.to_string())?;
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .map_err(|err| err.to_string())?;
    std::fs::write(dir.join(CA_FILE), ca_cert.pem()).map_err(|err| err.to_string())?;
    std::fs::write(dir.join(TLS_CERT_FILE), leaf.pem()).map_err(|err| err.to_string())?;
    write_private(&dir.join(TLS_KEY_FILE), &leaf_key.serialize_pem())?;
    let keys = vec![
        TestKey::generate("rs1", KeyAlg::RS256)?,
        TestKey::generate("es1", KeyAlg::ES256)?,
    ];
    save_keys(&dir, &keys)?;
    println!("idp init host {host} kids rs1 es1");
    Ok(())
}

fn rotate(flags: &Flags) -> Result<(), String> {
    let dir = PathBuf::from(flags.need("--dir")?);
    let kid = flags.need("--kid")?;
    let alg = KeyAlg::parse(flags.need("--alg")?)
        .ok_or_else(|| "The --alg value must be RS256 or ES256.".to_string())?;
    let mut keys = load_keys(&dir)?;
    if keys.iter().any(|key| key.kid == kid) {
        return Err(format!("The key {kid} exists."));
    }
    if let Some(drop) = flags.get("--drop") {
        keys.retain(|key| key.kid != drop);
    }
    keys.push(TestKey::generate(kid, alg)?);
    save_keys(&dir, &keys)?;
    let kids: Vec<&str> = keys.iter().map(|key| key.kid.as_str()).collect();
    println!("idp rotate kids {}", kids.join(" "));
    Ok(())
}

fn mint_command(flags: &Flags) -> Result<(), String> {
    let dir = PathBuf::from(flags.need("--dir")?);
    let kid = flags.need("--kid")?;
    let out = PathBuf::from(flags.need("--out")?);
    let keys = load_keys(&dir)?;
    let key = keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(|| format!("The key {kid} is not in the key file."))?;
    let ttl = flags.number("--ttl", 600)?;
    let age = flags.number("--age", 0)?;
    let issued_at = unix_now().saturating_sub(age);
    let mut spec = MintSpec::now(
        flags.need("--issuer")?,
        flags.need("--aud")?,
        flags.need("--sub")?,
        ttl,
    );
    spec.issued_at = issued_at;
    spec.expires_at = issued_at + ttl;
    spec.email = flags.get("--email").map(str::to_string);
    spec.nonce = flags.get("--nonce").map(str::to_string);
    let mut token = mint(key, &spec, flags.get("--header-kid"))?;
    if flags.has("--tamper") {
        token = tamper_signature(&token);
    }
    write_private(&out, &token)?;
    println!(
        "minted kid {} alg {:?} exp {} file {}",
        flags.get("--header-kid").unwrap_or(kid),
        key.alg,
        spec.expires_at,
        out.display()
    );
    Ok(())
}

fn serve(flags: &Flags) -> Result<(), String> {
    let dir = PathBuf::from(flags.need("--dir")?);
    let issuer = flags.need("--issuer")?.to_string();
    let listen: SocketAddr = flags
        .get("--listen")
        .unwrap_or("0.0.0.0:8443")
        .parse()
        .map_err(|_| "The --listen value is not valid.".to_string())?;
    let config = tls_config(&dir)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|err| err.to_string())?;
        println!("idp serve {issuer} on {listen}");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        loop {
            let (tcp, _) = listener.accept().await.map_err(|err| err.to_string())?;
            let acceptor = acceptor.clone();
            let dir = dir.clone();
            let issuer = issuer.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let mut used = 0;
                while used < buf.len() {
                    let Ok(count) = tls.read(&mut buf[used..]).await else {
                        return;
                    };
                    if count == 0 {
                        break;
                    }
                    used += count;
                    if buf[..used].windows(4).any(|mark| mark == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..used]);
                let line = head.lines().next().unwrap_or_default().to_string();
                let path = line.split_whitespace().nth(1).unwrap_or_default();
                let (code, body) = match path {
                    "/.well-known/openid-configuration" => ("200 OK", discovery_json(&issuer)),
                    "/jwks" => match load_keys(&dir) {
                        Ok(keys) => ("200 OK", jwks_json(&keys)),
                        Err(_) => ("500 Error", "{}".to_string()),
                    },
                    _ => ("404 Not Found", "{}".to_string()),
                };
                println!("idp request {} {}", path, &code[..3]);
                let response = format!(
                    "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    })
}

fn tls_config(dir: &Path) -> Result<rustls::ServerConfig, String> {
    let cert_pem = std::fs::read(dir.join(TLS_CERT_FILE)).map_err(|err| err.to_string())?;
    let key_pem = std::fs::read(dir.join(TLS_KEY_FILE)).map_err(|err| err.to_string())?;
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "The TLS key file is empty.".to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| err.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| err.to_string())
}

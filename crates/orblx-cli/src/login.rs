use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use orblx_identity::{
    GoogleClient, GoogleJwks, GoogleTokenRequest, OidcMode, GOOGLE_REDIRECT_LOOPBACK,
};

use super::{parse_socket, take_value};
use orblx_coord::{
    enroll_with_oidc_blocking, fetch_google_jwks_blocking, post_google_token_blocking, OidcEnroll,
};

const DEFAULT_PORT: u16 = 443;

/// A laptop login command.
#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Login {
        name: String,
        coord: SocketAddr,
        coord_name: String,
        bundle: PathBuf,
        state: PathBuf,
        endpoints: Vec<String>,
        routes: Vec<String>,
    },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let mut name = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut state = None;
    let mut endpoints = Vec::new();
    let mut routes = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--name" => name = Some(value),
            "--coord" => coord = Some(parse_socket(&value, DEFAULT_PORT)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--state" => state = Some(PathBuf::from(value)),
            "--endpoint" => endpoints.push(value),
            "--route" => routes.push(value),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Login {
        name: name.ok_or_else(|| "The command needs --name.".to_string())?,
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.ok_or_else(|| "The command needs --bundle.".to_string())?,
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        endpoints,
        routes,
    })
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Login {
            name,
            coord,
            coord_name,
            bundle,
            state,
            endpoints,
            routes,
        } => login(
            &name,
            coord,
            &coord_name,
            &bundle,
            &state,
            &endpoints,
            &routes,
        ),
    }
}

fn login(
    name: &str,
    coord: SocketAddr,
    coord_name: &str,
    bundle: &std::path::Path,
    state: &std::path::Path,
    endpoints: &[String],
    routes: &[String],
) -> Result<(), String> {
    let mode = OidcMode::from_env().map_err(|err| err.to_string())?;
    match mode {
        OidcMode::Mock => {
            return Err(
                "Mock mode is for tests. orblx login uses Google. Set ORBLX_OIDC_MODE to google."
                    .to_string(),
            );
        }
        OidcMode::Google => {}
    }
    let client = GoogleClient::from_env().map_err(|err| err.to_string())?;
    let oidc_state = random_hex(16)?;
    let nonce = random_hex(16)?;
    let url = client
        .authorize_url(GOOGLE_REDIRECT_LOOPBACK, &oidc_state, &nonce)
        .map_err(|err| err.to_string())?;
    println!("Open this URL in a browser.");
    println!("Do not paste the URL. The URL contains the OIDC nonce.");
    println!("{url}");
    let code = wait_for_code(&oidc_state)?;
    let request = client
        .token_request(&code, GOOGLE_REDIRECT_LOOPBACK)
        .map_err(|err| err.to_string())?;
    let response = post_google_token_blocking(request.body())
        .map_err(|_| "The token endpoint request failed.".to_string())?;
    let id_token = GoogleTokenRequest::id_token_from_response(&response)
        .map_err(|_| "The token response did not contain an ID token.".to_string())?;
    let jwks_text =
        fetch_google_jwks_blocking().map_err(|_| "The Google JWKS request failed.".to_string())?;
    let jwks = GoogleJwks::from_json(&jwks_text).map_err(|err| err.to_string())?;
    jwks.verify(&id_token, client.client_id(), &nonce, SystemTime::now())
        .map_err(|_| "The ID token check failed.".to_string())?;
    let bundle_pem = std::fs::read_to_string(bundle)
        .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
    let result = enroll_with_oidc_blocking(OidcEnroll {
        coord,
        coord_name,
        bundle_pem: &bundle_pem,
        name,
        id_token: &id_token,
        nonce: Some(&nonce),
        endpoints,
        routes,
    })
    .map_err(|err| err.to_string())?;
    result.write_state(state).map_err(|err| err.to_string())?;
    println!("enrolled");
    println!("name {}", result.name);
    println!("overlay_ip {}", result.overlay_ip);
    println!("svid {}", result.svid);
    println!("peers {}", result.signed_netmap.netmap.peers.len());
    Ok(())
}

fn wait_for_code(expected_state: &str) -> Result<String, String> {
    let listener = TcpListener::bind(("127.0.0.1", 8787))
        .map_err(|err| format!("The callback port 8787 did not bind. {err}"))?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|err| format!("The callback did not arrive. {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|err| format!("The callback did not arrive. {err}"))?;
    let mut buf = [0u8; 8192];
    let size = stream
        .read(&mut buf)
        .map_err(|err| format!("The callback did not arrive. {err}"))?;
    let text = String::from_utf8_lossy(&buf[..size]);
    let code = parse_callback(&text, expected_state)?;
    let body = "<!DOCTYPE html><p>Sign-in is complete. You can close this window.</p>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    Ok(code)
}

pub(crate) fn parse_callback(request: &str, expected_state: &str) -> Result<String, String> {
    let line = request.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" || !target.starts_with("/oidc/callback?") {
        return Err("The OIDC callback is not valid.".to_string());
    }
    let query = target.trim_start_matches("/oidc/callback?");
    let mut code = None;
    let mut state = None;
    let mut failed = false;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err("The OIDC callback is not valid.".to_string());
        };
        let value = percent_decode(value)?;
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => failed = true,
            _ => {}
        }
    }
    if failed {
        return Err("The OIDC sign-in failed.".to_string());
    }
    if state.as_deref() != Some(expected_state) {
        return Err("The OIDC state does not match.".to_string());
    }
    let code = code.ok_or_else(|| "The OIDC callback is not valid.".to_string())?;
    if code.is_empty() || code.len() > 1024 {
        return Err("The OIDC callback is not valid.".to_string());
    }
    Ok(code)
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("The OIDC callback is not valid.".to_string());
                }
                let high = from_hex(bytes[index + 1])?;
                let low = from_hex(bytes[index + 2])?;
                out.push((high << 4) | low);
                index += 3;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "The OIDC callback is not valid.".to_string())
}

fn from_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("The OIDC callback is not valid.".to_string()),
    }
}

fn random_hex(nbytes: usize) -> Result<String, String> {
    let mut file =
        File::open("/dev/urandom").map_err(|err| format!("The random source failed. {err}"))?;
    let mut bytes = vec![0u8; nbytes];
    file.read_exact(&mut bytes)
        .map_err(|err| format!("The random source failed. {err}"))?;
    let mut text = String::with_capacity(nbytes * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(text)
}

fn help() -> String {
    "\
orblx login --name NAME --coord ADDR --bundle FILE --state DIR [--coord-name NAME] [--endpoint HOST:PORT] [--route CIDR]

The command uses Google OIDC.
Mock mode is for tests.
The command listens on 127.0.0.1:8787 for the callback.
The command does not print the ID token, the OAuth code, or the client secret.
Do not paste the authorize URL.
The URL contains the OIDC nonce.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_callback;

    #[test]
    fn callback_returns_the_code_when_the_state_matches() {
        let request = "GET /oidc/callback?code=abc%2F1&state=00112233445566778899aabbccddeeff HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let code = parse_callback(request, "00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(code, "abc/1");
    }

    #[test]
    fn callback_rejects_a_bad_state() {
        let request =
            "GET /oidc/callback?code=abc&state=00112233445566778899aabbccddeeff HTTP/1.1\r\n\r\n";
        let err = parse_callback(request, "ff").unwrap_err();
        assert!(err.contains("state"));
        assert!(!err.contains("abc"));
    }
}

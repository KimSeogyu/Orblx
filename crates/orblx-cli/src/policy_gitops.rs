//! `orblx policy diff` and `orblx policy apply` (W25-9 policy GitOps).
//!
//! `diff` reads the live policy with `admin-policy` and compares it with a file.
//! `apply` tests the file and writes it with `admin-policy-set` and an expected
//! live sha256. A stale apply gets status 409 and does not write.
//! The commands never print the API token.

use std::net::SocketAddr;
use std::path::PathBuf;

use orblx_coord::{admin_blocking, admin_token_expect_blocking, encode_hex};
use orblx_identity::Policy;
use serde_json::Value;

use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";

/// The largest diff table. A larger diff prints every line as removed and added.
const DIFF_CELL_LIMIT: usize = 4_000_000;

/// How to reach the coordinator.
#[derive(Debug)]
pub(crate) struct Remote {
    coord: SocketAddr,
    coord_name: String,
    bundle: PathBuf,
    state: PathBuf,
    token_file: Option<PathBuf>,
}

/// `orblx policy diff`.
#[derive(Debug)]
pub(crate) struct Diff {
    file: PathBuf,
    sha_out: Option<PathBuf>,
    remote: Remote,
}

/// `orblx policy apply`.
#[derive(Debug)]
pub(crate) struct Apply {
    file: PathBuf,
    expect: String,
    remote: Remote,
}

pub(crate) fn parse_diff(args: &[String]) -> Result<Diff, String> {
    let mut file = None;
    let mut sha_out = None;
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--file" => file = Some(PathBuf::from(value)),
            "--sha-out" => sha_out = Some(PathBuf::from(value)),
            _ => rest.push((flag.to_string(), value)),
        }
    }
    Ok(Diff {
        file: file.ok_or_else(|| "The command needs --file.".to_string())?,
        sha_out,
        remote: parse_remote(rest)?,
    })
}

pub(crate) fn parse_apply(args: &[String]) -> Result<Apply, String> {
    let mut file = None;
    let mut expect = None;
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--file" => file = Some(PathBuf::from(value)),
            "--expect-sha" => expect = Some(value),
            "--expect-sha-file" => {
                let text = std::fs::read_to_string(&value)
                    .map_err(|err| format!("The file {value} did not open. {err}"))?;
                expect = Some(text.trim().to_string());
            }
            _ => rest.push((flag.to_string(), value)),
        }
    }
    let expect = expect.ok_or_else(|| {
        "The command needs --expect-sha or --expect-sha-file. Use the sha that policy diff printed."
            .to_string()
    })?;
    if !(expect == "none" || (expect.len() == 64 && expect.bytes().all(|b| b.is_ascii_hexdigit())))
    {
        return Err("The expected sha256 is not valid.".to_string());
    }
    let remote = parse_remote(rest)?;
    if remote.token_file.is_none() {
        return Err("The command needs --token-file with a policy:write token.".to_string());
    }
    Ok(Apply {
        file: file.ok_or_else(|| "The command needs --file.".to_string())?,
        expect: expect.to_ascii_lowercase(),
        remote,
    })
}

fn parse_remote(flags: Vec<(String, String)>) -> Result<Remote, String> {
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut state = None;
    let mut token_file = None;
    for (flag, value) in flags {
        match flag.as_str() {
            "--coord" => coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--state" => state = Some(PathBuf::from(value)),
            "--token-file" => token_file = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.")),
        }
    }
    let state = state.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE));
    Ok(Remote {
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.unwrap_or_else(|| state.join("bundle.pem")),
        state,
        token_file,
    })
}

/// The sha256 of a policy text, as lowercase hex.
pub(crate) fn text_sha(text: &str) -> String {
    encode_hex(&orblx_audit::sha256_digest(text.as_bytes()))
}

/// Run one admin call. Return the status and the reply document or error.
fn call(
    remote: &Remote,
    op: &str,
    name: &str,
    expect: Option<&str>,
) -> Result<(u16, Result<Value, String>), String> {
    let bundle = std::fs::read_to_string(&remote.bundle)
        .map_err(|err| format!("The file {} did not open. {err}", remote.bundle.display()))?;
    let (status, detail) = match &remote.token_file {
        Some(file) => {
            let token = std::fs::read_to_string(file)
                .map_err(|err| format!("The file {} did not open. {err}", file.display()))?;
            let reply = admin_token_expect_blocking(
                remote.coord,
                &remote.coord_name,
                &bundle,
                token.trim(),
                op,
                name,
                expect,
            )
            .map_err(|err| err.to_string())?;
            if reply.status != 200 {
                let text = reply
                    .error
                    .unwrap_or_else(|| "The coordinator request failed.".to_string());
                return Ok((reply.status, Err(text)));
            }
            (200, reply.detail.unwrap_or_default())
        }
        None => {
            if expect.is_some() {
                return Err("The expected sha256 needs --token-file.".to_string());
            }
            let detail = admin_blocking(
                remote.coord,
                &remote.coord_name,
                &bundle,
                &remote.state,
                op,
                name,
            )
            .map_err(|err| err.to_string())?;
            (200, detail)
        }
    };
    let value: Value = serde_json::from_str(&detail)
        .map_err(|_| "The coordinator response is not valid.".to_string())?;
    Ok((status, Ok(value)))
}

/// Print the diff. Return true when the live policy is the same as the file.
pub(crate) fn run_diff(diff: &Diff) -> Result<bool, String> {
    let file_text = std::fs::read_to_string(&diff.file)
        .map_err(|err| format!("The file {} did not open. {err}", diff.file.display()))?;
    let (status, reply) = call(&diff.remote, "admin-policy", "", None)?;
    println!("status {status}");
    let value = reply?;
    let present = value.get("present").and_then(Value::as_bool) == Some(true);
    let (live_sha, live_text) = if present {
        let text = value
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| "The coordinator response is not valid.".to_string())?
            .to_string();
        (text_sha(&text), text)
    } else {
        ("none".to_string(), String::new())
    };
    let file_sha = text_sha(&file_text);
    println!("live_sha256 {live_sha}");
    println!("file_sha256 {file_sha}");
    if let Some(out) = &diff.sha_out {
        std::fs::write(out, format!("{live_sha}\n"))
            .map_err(|err| format!("The file {} did not open. {err}", out.display()))?;
    }
    if live_sha == file_sha {
        println!("policy same");
        return Ok(true);
    }
    println!("--- live");
    println!("+++ {}", diff.file.display());
    let (removed, added) = print_line_diff(&live_text, &file_text);
    println!("policy differs removed {removed} added {added}");
    Ok(false)
}

/// Test the file, then write it when the live sha256 is the expected sha256.
pub(crate) fn run_apply(apply: &Apply) -> Result<(), String> {
    let policy = Policy::from_path(&apply.file).map_err(|err| err.to_string())?;
    let tests = policy.assertions().len() + policy.ssh_assertions().len();
    println!("policy ok tests {tests}");
    let text = std::fs::read_to_string(&apply.file)
        .map_err(|err| format!("The file {} did not open. {err}", apply.file.display()))?;
    let file_sha = text_sha(&text);
    println!("file_sha256 {file_sha}");
    println!("expect_sha256 {}", apply.expect);
    let (status, reply) = call(
        &apply.remote,
        "admin-policy-set",
        &text,
        Some(&apply.expect),
    )?;
    println!("status {status}");
    let value = match reply {
        Ok(value) => value,
        Err(text) if status == 409 => {
            return Err(format!(
                "{text} Run policy diff again, then review the change. The policy is not written."
            ))
        }
        Err(text) => return Err(text),
    };
    let live = value
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
    let changed = value.get("changed").and_then(Value::as_bool);
    let changed = match changed {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    };
    println!("policy_set {live} changed {changed}");
    if live != file_sha {
        return Err("The live policy sha256 is not the file sha256.".to_string());
    }
    Ok(())
}

/// Print removed lines with `-` and added lines with `+`. Return the counts.
fn print_line_diff(old: &str, new: &str) -> (usize, usize) {
    let ops = line_diff(old, new);
    let mut removed = 0;
    let mut added = 0;
    for (kind, line) in ops {
        match kind {
            '-' => removed += 1,
            '+' => added += 1,
            _ => continue,
        }
        println!("{kind}{line}");
    }
    (removed, added)
}

/// A line diff from the longest common subsequence.
/// Each item is `(' ', line)`, `('-', line)`, or `('+', line)`.
fn line_diff<'a>(old: &'a str, new: &'a str) -> Vec<(char, &'a str)> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    if (n + 1).saturating_mul(m + 1) > DIFF_CELL_LIMIT {
        let mut out: Vec<(char, &str)> = a.iter().map(|line| ('-', *line)).collect();
        out.extend(b.iter().map(|line| ('+', *line)));
        return out;
    }
    let width = m + 1;
    let mut table = vec![0u32; (n + 1) * width];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i * width + j] = if a[i] == b[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            out.push(('-', a[i]));
            i += 1;
        } else {
            out.push(('+', b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|line| ('-', *line)));
    out.extend(b[j..].iter().map(|line| ('+', *line)));
    out
}

#[cfg(test)]
mod tests {
    use super::{line_diff, parse_apply, parse_diff, text_sha};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn diff_needs_a_file_and_a_coordinator() {
        assert!(parse_diff(&args(&["--coord", "127.0.0.1:443"]))
            .unwrap_err()
            .contains("--file"));
        assert!(parse_diff(&args(&["--file", "p.hujson"]))
            .unwrap_err()
            .contains("--coord"));
        let diff = parse_diff(&args(&[
            "--file",
            "p.hujson",
            "--coord",
            "10.0.0.1",
            "--token-file",
            "t",
            "--sha-out",
            "s",
        ]))
        .unwrap();
        assert_eq!(diff.remote.coord.port(), 443);
        assert!(diff.remote.token_file.is_some());
    }

    #[test]
    fn apply_needs_an_expected_sha_and_a_token() {
        let base = ["--file", "p.hujson", "--coord", "10.0.0.1:443"];
        let err = parse_apply(&args(&[&base[..], &["--token-file", "t"]].concat())).unwrap_err();
        assert!(err.contains("--expect-sha"));
        let err = parse_apply(&args(&[&base[..], &["--expect-sha", "none"]].concat())).unwrap_err();
        assert!(err.contains("--token-file"));
        let err = parse_apply(&args(
            &[&base[..], &["--expect-sha", "abc", "--token-file", "t"]].concat(),
        ))
        .unwrap_err();
        assert!(err.contains("not valid"));
        let sha = "A".repeat(64);
        let apply = parse_apply(&args(
            &[&base[..], &["--expect-sha", &sha, "--token-file", "t"]].concat(),
        ))
        .unwrap();
        assert_eq!(apply.expect, "a".repeat(64));
    }

    #[test]
    fn expect_sha_file_is_trimmed() {
        let dir = std::env::temp_dir().join(format!("orblx-gitops-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("live.sha");
        std::fs::write(&file, format!("{}\n", "b".repeat(64))).unwrap();
        let apply = parse_apply(&args(&[
            "--file",
            "p.hujson",
            "--coord",
            "10.0.0.1:443",
            "--token-file",
            "t",
            "--expect-sha-file",
            file.to_str().unwrap(),
        ]))
        .unwrap();
        assert_eq!(apply.expect, "b".repeat(64));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn line_diff_marks_removed_and_added_lines() {
        let ops = line_diff("a\nb\nc\n", "a\nx\nc\nd\n");
        assert_eq!(
            ops,
            vec![(' ', "a"), ('-', "b"), ('+', "x"), (' ', "c"), ('+', "d")]
        );
        assert!(line_diff("a\n", "a\n").iter().all(|(kind, _)| *kind == ' '));
    }

    #[test]
    fn text_sha_is_the_sha256_hex() {
        assert_eq!(
            text_sha(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

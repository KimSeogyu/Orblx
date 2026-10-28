use std::path::PathBuf;

use gyeol_audit::{escape_demo, verify_file};

use super::take_value;

/// An audit command.
#[derive(Debug)]
pub(crate) enum Command {
    Help(String),
    Demo { out: PathBuf },
    Verify { file: PathBuf },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help(help()));
    }
    match args[0].as_str() {
        "demo" => parse_demo(&args[1..]),
        "verify" => parse_verify(&args[1..]),
        other => Err(format!("The mode {other} is not valid.\n{}", help())),
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Demo { out } => {
            let log = escape_demo();
            log.write_jsonl(&out).map_err(|err| err.to_string())?;
            let metrics = log.metrics();
            println!("chain {}", out.display());
            println!("tip {}", log.tip_hex());
            println!("start {}", metrics.start);
            println!("end {}", metrics.end);
            println!("deny {}", metrics.deny);
            println!("records {}", log.records().len());
            Ok(())
        }
        Command::Verify { file } => {
            let checked = verify_file(&file).map_err(|err| err.to_string())?;
            println!("ok");
            println!("tip {}", checked.tip_hex());
            println!("start {}", checked.metrics.start);
            println!("end {}", checked.metrics.end);
            println!("deny {}", checked.metrics.deny);
            println!("records {}", checked.records);
            Ok(())
        }
    }
}

fn parse_demo(args: &[String]) -> Result<Command, String> {
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--out" => out = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let out = out.ok_or_else(|| format!("The command needs --out.\n{}", help()))?;
    Ok(Command::Demo { out })
}

fn parse_verify(args: &[String]) -> Result<Command, String> {
    let mut file = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--file" => file = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let file = file.ok_or_else(|| format!("The command needs --file.\n{}", help()))?;
    Ok(Command::Verify { file })
}

fn help() -> String {
    "\
gyeol audit demo --out FILE
gyeol audit verify --file FILE

The demo writes one session deny.
The demo writes one session start.
The demo writes one session end.
The session id is a Relay session id.
The peer is a SPIFFE ID.
The chain uses SHA-256.
Each record stores the previous hash.
The verify command reads the file.
The verify command checks the hashes.
The verify command counts start, end, and deny.
The verify command does not use the data path.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn help_names_the_chain_and_the_three_events() {
        let command = parse(&["--help".to_string()]).unwrap();
        match command {
            Command::Help(text) => {
                assert!(text.contains("demo"));
                assert!(text.contains("verify"));
                assert!(text.contains("SHA-256"));
                assert!(text.contains("data path"));
            }
            Command::Demo { .. } | Command::Verify { .. } => {
                panic!("the parser did not select help");
            }
        }
    }

    #[test]
    fn demo_requires_out() {
        let err = parse(&["demo".to_string()]).unwrap_err();
        assert!(err.contains("--out"));
    }

    #[test]
    fn verify_reads_the_file_flag() {
        let command = parse(&[
            "verify".to_string(),
            "--file".to_string(),
            "chain.jsonl".to_string(),
        ])
        .unwrap();
        match command {
            Command::Verify { file } => assert_eq!(file.as_os_str(), "chain.jsonl"),
            Command::Help(_) | Command::Demo { .. } => {
                panic!("the parser did not select verify");
            }
        }
    }
}

use std::path::PathBuf;

use orblx_audit::{escape_demo, verify_config_file, verify_file, ConfigAction};

use super::take_value;

/// An audit command.
#[derive(Debug)]
pub(crate) enum Command {
    Help(String),
    Demo { out: PathBuf },
    Verify { file: PathBuf },
    VerifyConfig { file: PathBuf },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help(help()));
    }
    match args[0].as_str() {
        "demo" => parse_demo(&args[1..]),
        "verify" => parse_verify(&args[1..]),
        "verify-config" => match parse_verify(&args[1..])? {
            Command::Verify { file } => Ok(Command::VerifyConfig { file }),
            other => Ok(other),
        },
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
            println!("record {}", checked.metrics.record);
            println!("records {}", checked.records);
            Ok(())
        }
        Command::VerifyConfig { file } => {
            let checked = verify_config_file(&file).map_err(|err| err.to_string())?;
            println!("ok");
            println!("tip {}", checked.tip_hex());
            for action in ConfigAction::ALL {
                let count = checked
                    .records
                    .iter()
                    .filter(|record| record.event.action == action)
                    .count();
                println!("{} {count}", action.as_str());
            }
            println!("records {}", checked.records.len());
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
orblx audit demo --out FILE
orblx audit verify --file FILE
orblx audit verify-config --file FILE

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
The verify-config command checks the coordinator config chain.
The config chain file is config-audit.jsonl in the coordinator state directory.
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
            Command::Demo { .. } | Command::Verify { .. } | Command::VerifyConfig { .. } => {
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
            Command::Help(_) | Command::Demo { .. } | Command::VerifyConfig { .. } => {
                panic!("the parser did not select verify");
            }
        }
    }
}

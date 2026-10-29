//! The `gyeol-sim` command.
//!
//! The command serves the game.
//! The game reads the harness feed.

use std::net::SocketAddr;

use gyeol_sim::{default_listen, parse_listen, serve_blocking};

fn main() {
    match command_from_args(std::env::args().skip(1)) {
        Ok(Command::Help) => println!("{}", help_text()),
        Ok(Command::Serve { listen }) => {
            if let Err(err) = serve_blocking(listen) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Serve { listen: SocketAddr },
}

fn command_from_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    if args.is_empty() {
        return Ok(Command::Serve {
            listen: default_listen(),
        });
    }
    if args.len() == 2 && args[0] == "--listen" {
        let listen = parse_listen(&args[1]).map_err(|err| err.to_string())?;
        return Ok(Command::Serve { listen });
    }
    Err(help_text())
}

fn help_text() -> String {
    format!(
        "\
gyeol-sim [--listen ADDR]

The command serves the Orblx game.
The default address is {addr}.
Open that URL in a browser.
The default page is the game.
Easy and City Breeze open Google sign-in.
The redirect URI is http://127.0.0.1:8787/oidc/callback.
Set ORBLX_GOOGLE_CLIENT_ID and ORBLX_GOOGLE_CLIENT_SECRET.
The callback issues the human SVID.
The board shows the feed events.
Select Medium or Hard on the board.
Press UDP block to see Direct fail and the Relay recover.
ORBLX_OIDC_MODE=mock selects the local mock IdP.
",
        addr = default_listen(),
    )
}

#[cfg(test)]
mod tests {
    use super::{command_from_args, help_text, Command};

    #[test]
    fn empty_args_select_the_default_address() {
        let command = command_from_args(std::iter::empty()).unwrap();
        match command {
            Command::Serve { listen } => assert_eq!(listen.port(), 8787),
            Command::Help => panic!("the parser did not select serve"),
        }
    }

    #[test]
    fn listen_flag_selects_the_address() {
        let command =
            command_from_args(["--listen".to_string(), "127.0.0.1:9".to_string()]).unwrap();
        match command {
            Command::Serve { listen } => assert_eq!(listen.port(), 9),
            Command::Help => panic!("the parser did not select serve"),
        }
    }

    #[test]
    fn help_flag_selects_help() {
        let command = command_from_args(["--help".to_string()]).unwrap();
        assert_eq!(command, Command::Help);
        assert!(help_text().contains("8787"));
        assert!(help_text().contains("Easy"));
        assert!(help_text().contains("Google"));
        assert!(help_text().contains("ORBLX_GOOGLE_CLIENT_ID"));
        assert!(help_text().contains("ORBLX_OIDC_MODE=mock"));
    }

    #[test]
    fn a_bad_address_is_an_error() {
        let err = command_from_args(["--listen".to_string(), "nope".to_string()]).unwrap_err();
        assert!(err.contains("not valid"));
    }

    #[test]
    fn an_unknown_flag_prints_help() {
        let err = command_from_args(["--port".to_string()]).unwrap_err();
        assert!(err.contains("--listen"));
    }
}

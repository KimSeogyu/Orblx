use gyeol_coord::crate_name as coord_crate;
use gyeol_crypto::crate_name as crypto_crate;
use gyeol_datapath::crate_name as datapath_crate;
use gyeol_edge::crate_name as edge_crate;
use gyeol_identity::crate_name as identity_crate;

enum Action {
    Hello,
    Version,
}

fn main() {
    match action_from_args(std::env::args().skip(1)) {
        Action::Hello => println!("{}", hello_line()),
        Action::Version => println!("gyeol {}", env!("CARGO_PKG_VERSION")),
    }
}

fn action_from_args<I>(args: I) -> Action
where
    I: IntoIterator<Item = String>,
{
    for arg in args {
        if arg == "--version" || arg == "-V" {
            return Action::Version;
        }
    }
    Action::Hello
}

fn hello_line() -> String {
    format!(
        "Hello from gyeol. This is the week 1 build: {}, {}, {}, {}, {}",
        datapath_crate(),
        crypto_crate(),
        edge_crate(),
        identity_crate(),
        coord_crate(),
    )
}

#[cfg(test)]
mod tests {
    use super::{action_from_args, hello_line, Action};

    #[test]
    fn version_flag_selects_version() {
        let action = action_from_args(["--version".to_string()]);
        assert!(matches!(action, Action::Version));
    }

    #[test]
    fn short_version_flag_selects_version() {
        let action = action_from_args(["-V".to_string()]);
        assert!(matches!(action, Action::Version));
    }

    #[test]
    fn empty_args_select_hello() {
        let action = action_from_args(std::iter::empty());
        assert!(matches!(action, Action::Hello));
    }

    #[test]
    fn hello_names_workspace_crates() {
        let line = hello_line();
        assert!(line.contains("gyeol-datapath"));
        assert!(line.contains("gyeol-crypto"));
        assert!(line.contains("gyeol-edge"));
        assert!(line.contains("gyeol-identity"));
        assert!(line.contains("gyeol-coord"));
    }
}

/// This function returns the name of this crate.
/// This crate does not contain identity functions.
pub fn crate_name() -> &'static str {
    "gyeol-identity"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "gyeol-identity");
    }
}

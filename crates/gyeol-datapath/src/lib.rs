/// This function returns the name of this crate.
/// This crate does not contain data path functions.
pub fn crate_name() -> &'static str {
    "gyeol-datapath"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "gyeol-datapath");
    }
}

//! Network ids. An id names a directory under the minimina home, so it is
//! restricted to letters, digits, `.`, `_` and `-`, starting with a letter or
//! digit: no `..`, no `/`, and no hidden directories, which minimina keeps for
//! itself (`.tools`).

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid network id '{0}': use letters, digits, '.', '_' and '-', starting with a letter or digit")]
pub struct InvalidNetworkId(pub String);

/// `id` if it is a valid network id (usable as a clap value parser).
pub fn parse(id: &str) -> Result<String, InvalidNetworkId> {
    let mut chars = id.chars();
    let starts_well = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    if starts_well && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        Ok(id.to_string())
    } else {
        Err(InvalidNetworkId(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_name_plain_directories() {
        for ok in ["default", "hf-4.0.2", "My_Net.1"] {
            assert_eq!(parse(ok).as_deref(), Ok(ok));
        }
        for bad in ["", "../x", "a/b", ".tools", "-x", "a b"] {
            assert_eq!(parse(bad), Err(InvalidNetworkId(bad.to_string())), "{bad}");
        }
    }
}

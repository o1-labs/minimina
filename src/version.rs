//! Versions of the programs minimina runs or needs.

/// `MAJOR.MINOR.PATCH` of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    /// Parses `MAJOR.MINOR[.PATCH]` with an optional `v` prefix and `-`/`+`
    /// suffix (`2.29.1`, `v24.21.0`, `v2.30.3-desktop.1`).
    pub fn parse(text: &str) -> Option<Self> {
        let core = text
            .trim()
            .trim_start_matches('v')
            .split(['-', '+'])
            .next()?;
        let mut parts = core.split('.').map(str::parse::<u32>);
        let major = parts.next()?.ok()?;
        let minor = parts.next()?.ok()?;
        let patch = parts.next().unwrap_or(Ok(0)).ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version(major, minor, patch))
    }

    /// The first word of `text` that is a version (`Docker version 27.0.0, build x`).
    pub fn find_in(text: &str) -> Option<Self> {
        text.split(|c: char| c.is_whitespace() || c == ',')
            .find_map(Self::parse)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare_numerically() {
        assert_eq!(Version::parse("2.29.1"), Some(Version(2, 29, 1)));
        assert_eq!(
            Version::parse("v2.30.3-desktop.1\n"),
            Some(Version(2, 30, 3))
        );
        assert_eq!(Version::parse("2.40"), Some(Version(2, 40, 0)));
        assert_eq!(Version::parse("2.x"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        // compared as text, "2.3.0" sorts after "2.21.0"
        assert!(Version::parse("2.3.0") < Version::parse("2.21.0"));
        assert_eq!(
            Version::find_in("Docker version 27.0.0, build 1234"),
            Some(Version(27, 0, 0))
        );
        assert_eq!(Version(22, 12, 0).to_string(), "22.12.0");
    }
}

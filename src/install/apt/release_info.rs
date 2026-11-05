use super::ControlFile;

/// What minimina reads from the `Release` file of a codename.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// The channels (`Components`) the codename has.
    pub channels: Vec<String>,
}

impl ReleaseInfo {
    pub fn parse(text: &str) -> Self {
        let file = ControlFile::parse(text);
        let channels = file
            .stanzas
            .first()
            .and_then(|s| s.get("Components"))
            .map(|c| c.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        ReleaseInfo { channels }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_are_the_components() {
        assert_eq!(
            ReleaseInfo::parse("Codename: noble\nComponents: alpha stable umt-no-upgrade\n")
                .channels,
            ["alpha", "stable", "umt-no-upgrade"]
        );
    }
}

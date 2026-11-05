use crate::version::Version;
use std::cmp::Ordering;

/// The version of a mina package: a release and the commit it was built
/// from, `<release>-<commit>`. The release may have dashes of its own
/// (`4.0.0-mainnet-893c877`); a version without a commit is all release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageVersion<'a> {
    pub release: &'a str,
    pub commit: Option<&'a str>,
}

impl<'a> PackageVersion<'a> {
    pub fn parse(version: &'a str) -> Self {
        match version.rsplit_once('-') {
            Some((release, commit))
                if commit.len() >= 7 && commit.chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                PackageVersion {
                    release,
                    commit: Some(commit),
                }
            }
            _ => PackageVersion {
                release: version,
                commit: None,
            },
        }
    }

    /// Whether the user means this version by `wanted`: the whole version
    /// (`4.0.2-84b8d96`), or its release (`4.0.2`). `4.0.0` is not
    /// `4.0.0-mainnet-893c877`, whose release is `4.0.0-mainnet`.
    pub fn matches(&self, wanted: &str) -> bool {
        wanted == self.release
            || self
                .commit
                .is_some_and(|commit| wanted == format!("{}-{commit}", self.release))
    }

    /// Oldest first: numerically by release (`4.0.2` < `4.0.10`), then as text.
    pub fn compare(a: &str, b: &str) -> Ordering {
        let release = |v| Version::parse(PackageVersion::parse(v).release);
        release(a).cmp(&release(b)).then_with(|| a.cmp(b))
    }
}

/// The items of `all` (sorted oldest first) that `wanted` names: the newest
/// for `latest`, else those [`PackageVersion::matches`] picks.
pub fn select<'a, T>(all: &'a [T], version: impl Fn(&T) -> &str, wanted: &str) -> Vec<&'a T> {
    if wanted == "latest" {
        all.last().into_iter().collect()
    } else {
        all.iter()
            .filter(|item| PackageVersion::parse(version(item)).matches(wanted))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_with_or_without_the_commit() {
        assert_eq!(
            PackageVersion::parse("4.0.0-mainnet-893c877"),
            PackageVersion {
                release: "4.0.0-mainnet",
                commit: Some("893c877")
            }
        );
        assert_eq!(PackageVersion::parse("4.0.2").commit, None);
        let matches = |v, wanted| PackageVersion::parse(v).matches(wanted);
        assert!(matches("4.0.2-84b8d96", "4.0.2"));
        assert!(matches("4.0.2-84b8d96", "4.0.2-84b8d96"));
        assert!(!matches("4.0.20-84b8d96", "4.0.2"));
        assert!(!matches("4.0.0-mainnet-893c877", "4.0.0"));
    }

    #[test]
    fn select_latest_or_matching() {
        let all = ["3.2.0-49b523c", "3.2.0-97ad487", "4.0.2-84b8d96"];
        assert_eq!(select(&all, |v| v, "latest"), [&"4.0.2-84b8d96"]);
        assert_eq!(select(&all, |v| v, "3.2.0").len(), 2);
        assert_eq!(select(&all, |v| v, "3.2.0-97ad487"), [&"3.2.0-97ad487"]);
        assert!(select(&all, |v| v, "5").is_empty());
    }
}

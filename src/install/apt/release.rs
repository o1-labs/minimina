use super::Entry;

/// The [`PACKAGES`](super::PACKAGES) of one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub debs: Vec<Entry>,
}

impl Release {
    pub fn size(&self) -> u64 {
        self.debs.iter().map(|d| d.size).sum()
    }
}

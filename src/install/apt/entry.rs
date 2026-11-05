use super::{Dependency, Stanza};

/// One package of the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub package: String,
    pub version: String,
    /// Path of the `.deb` from the repository root.
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    /// `Pre-Depends` and `Depends`.
    pub depends: Vec<Dependency>,
}

impl Entry {
    /// `None` without the fields minimina needs.
    pub(super) fn from_stanza(stanza: &Stanza) -> Option<Self> {
        Some(Entry {
            package: stanza.get("Package")?.to_string(),
            version: stanza.get("Version")?.to_string(),
            filename: stanza.get("Filename")?.to_string(),
            size: stanza.get("Size")?.parse().ok()?,
            sha256: stanza.get("SHA256")?.to_ascii_lowercase(),
            depends: ["Pre-Depends", "Depends"]
                .iter()
                .filter_map(|field| stanza.get(field))
                .flat_map(Dependency::parse_list)
                .collect(),
        })
    }
}

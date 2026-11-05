use super::{Dependency, Entry, PACKAGES};

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

    /// What the debs depend on, each once, without the debs themselves
    /// (`mina-generic` depends on `mina-logproc`).
    pub fn depends(&self) -> Vec<Dependency> {
        let mut all: Vec<Dependency> = vec![];
        for dep in self.debs.iter().flat_map(|d| &d.depends) {
            let ours = dep
                .alternatives
                .iter()
                .any(|a| PACKAGES.contains(&a.as_str()));
            if !ours && !all.contains(dep) {
                all.push(dep.clone());
            }
        }
        all
    }
}

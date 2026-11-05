use super::{select, ControlFile, Entry, PackageVersion, Release, PACKAGES};

/// A `Packages` index.
#[derive(Debug, Default)]
pub struct Index {
    entries: Vec<Entry>,
}

impl Index {
    pub fn parse(text: &str) -> Self {
        let entries = ControlFile::parse(text)
            .stanzas
            .iter()
            .filter_map(Entry::from_stanza)
            .collect();
        Index { entries }
    }

    /// Versions that have every one of [`PACKAGES`], oldest first.
    pub fn versions(&self) -> Vec<String> {
        let mut versions: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.package == PACKAGES[0])
            .map(|e| e.version.clone())
            .filter(|v| self.release(v).is_some())
            .collect();
        versions.sort_by(|a, b| PackageVersion::compare(a, b));
        versions.dedup();
        versions
    }

    /// The packages of `version` (a whole version), if the index has them all.
    pub fn release(&self, version: &str) -> Option<Release> {
        let debs = PACKAGES
            .iter()
            .map(|p| {
                self.entries
                    .iter()
                    .find(|e| e.package == *p && e.version == version)
                    .cloned()
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Release {
            version: version.to_string(),
            debs,
        })
    }

    /// The releases `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`) names.
    pub fn select(&self, wanted: &str) -> Vec<Release> {
        let versions = self.versions();
        select(&versions, |v| v, wanted)
            .into_iter()
            .filter_map(|v| self.release(v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(package: &str, version: &str) -> String {
        format!(
            "Package: {package}\nVersion: {version}\nDepends: libssl3t64, libgmp10\n\
             Filename: pool/noble/m/mi/{package}_{version}_amd64.deb\nSize: 100\n\
             SHA256: ABC{version}\nDescription: x\n built from y\n"
        )
    }

    fn index(versions: &[&str]) -> Index {
        let text: Vec<String> = versions
            .iter()
            .flat_map(|v| PACKAGES.iter().map(move |p| stanza(p, v)))
            .collect();
        Index::parse(&text.join("\n"))
    }

    #[test]
    fn index_stanzas_parse() {
        let index = Index::parse(&stanza("mina-generic", "4.0.2-84b8d96"));
        assert_eq!(
            index.entries,
            vec![Entry {
                package: "mina-generic".into(),
                version: "4.0.2-84b8d96".into(),
                filename: "pool/noble/m/mi/mina-generic_4.0.2-84b8d96_amd64.deb".into(),
                size: 100,
                sha256: "abc4.0.2-84b8d96".into(),
                depends: vec!["libssl3t64".into(), "libgmp10".into()],
            }]
        );
        // a stanza without a size is skipped
        assert!(Index::parse("Package: a\nVersion: 1\n").entries.is_empty());
    }

    #[test]
    fn versions_need_every_package_and_sort_numerically() {
        let mut text = index(&["4.0.10-aaaaaaa", "4.0.2-84b8d96"])
            .entries
            .iter()
            .map(|e| stanza(&e.package, &e.version))
            .collect::<Vec<_>>();
        // 4.0.3 has no archive package
        text.push(stanza("mina-generic", "4.0.3-73134bf"));
        let index = Index::parse(&text.join("\n"));
        assert_eq!(index.versions(), ["4.0.2-84b8d96", "4.0.10-aaaaaaa"]);
        assert_eq!(index.select("latest")[0].version, "4.0.10-aaaaaaa");
        assert!(index.select("4.0.3").is_empty());
        let release = index.release("4.0.2-84b8d96").unwrap();
        assert_eq!(release.debs.len(), PACKAGES.len());
        assert_eq!(release.size(), 400);
    }

    #[test]
    fn a_release_depends_on_what_its_packages_do() {
        let mut text: Vec<String> = PACKAGES
            .iter()
            .map(|p| stanza(p, "4.0.2-84b8d96"))
            .collect();
        text[0] = text[0].replace(
            "Depends: libssl3t64, libgmp10",
            "Pre-Depends: tzdata\nDepends: libssl3t64, mina-logproc, libpq-dev | libpq5",
        );
        let release = Index::parse(&text.join("\n"))
            .release("4.0.2-84b8d96")
            .unwrap();
        let depends: Vec<String> = release.depends().iter().map(ToString::to_string).collect();
        assert_eq!(
            depends,
            ["tzdata", "libssl3t64", "libpq-dev | libpq5", "libgmp10"]
        );
    }

    #[test]
    fn several_builds_of_a_release() {
        let index = index(&["3.2.0-49b523c", "3.2.0-97ad487"]);
        assert_eq!(index.select("3.2.0").len(), 2);
        assert_eq!(index.select("3.2.0-97ad487")[0].version, "3.2.0-97ad487");
    }
}

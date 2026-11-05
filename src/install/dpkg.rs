//! The packages installed on a Debian-based host, from `dpkg-query`.

use super::apt::Dependency;
use crate::runner::Runner;
use std::collections::HashSet;

/// Names installed packages answer to: their own and what they `Provide`.
#[derive(Debug, Default)]
pub struct DpkgDatabase {
    names: HashSet<String>,
}

impl DpkgDatabase {
    /// One `dpkg-query` for every package. `None` when the host has no dpkg
    /// (not Debian-based) or it fails.
    pub fn load(runner: &dyn Runner) -> Option<Self> {
        let output = runner
            .run(
                "dpkg-query".as_ref(),
                &["-W", "-f", "${Package}\t${db:Status-Abbrev}\t${Provides}\n"],
                &[],
            )
            .ok()
            .filter(|o| o.status.success())?;
        Some(Self::parse(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Lines of `<package>\t<status>\t<provides>`; `ii` is installed.
    fn parse(text: &str) -> Self {
        let mut names = HashSet::new();
        for line in text.lines() {
            let mut fields = line.split('\t');
            let (Some(package), Some(status)) = (fields.next(), fields.next()) else {
                continue;
            };
            if !status.starts_with("ii") {
                continue;
            }
            names.insert(package.to_string());
            for provided in Dependency::parse_list(fields.next().unwrap_or("")) {
                names.extend(provided.alternatives);
            }
        }
        DpkgDatabase { names }
    }

    pub fn satisfies(&self, dependency: &Dependency) -> bool {
        dependency
            .alternatives
            .iter()
            .any(|a| self.names.contains(a))
    }

    /// The dependencies that nothing installed satisfies.
    pub fn missing(&self, depends: &[Dependency]) -> Vec<Dependency> {
        depends
            .iter()
            .filter(|d| !self.satisfies(d))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn installed_packages_and_what_they_provide() {
        let fake = FakeRunner::default();
        fake.reply(
            0,
            "libssl3t64\tii \t\n\
             libgmp10\trc \t\n\
             postfix\tii \tmail-transport-agent, default-mta (= 3.8)\n",
            "",
        );
        let db = DpkgDatabase::load(&fake).unwrap();
        assert_eq!(
            fake.lines(),
            ["dpkg-query -W -f ${Package}\t${db:Status-Abbrev}\t${Provides}\n"]
        );
        let depends =
            Dependency::parse_list("libssl3t64, libgmp10, exim4 | mail-transport-agent, curl");
        let missing: Vec<String> = db
            .missing(&depends)
            .iter()
            .map(ToString::to_string)
            .collect();
        // libgmp10 was removed (rc): only its config files are left
        assert_eq!(missing, ["libgmp10", "curl"]);
    }

    #[test]
    fn no_dpkg_is_no_database() {
        let fake = FakeRunner::default();
        fake.reply_err(std::io::ErrorKind::NotFound);
        assert!(DpkgDatabase::load(&fake).is_none());
    }
}

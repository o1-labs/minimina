//! dpkg on the host: `dpkg-deb` unpacks the mina packages, `dpkg-query`
//! says which packages are installed.

use super::apt::Dependency;
use super::requirement::{Tool, ToolError};
use crate::runner::{check, Runner};
use crate::version::Version;
use std::collections::HashSet;
use std::path::Path;

/// Unpacks debs.
pub const DPKG_DEB: Tool = Tool {
    name: "dpkg-deb",
    program: "dpkg-deb",
    version_args: &["--version"],
    min: Version(1, 17, 0),
    install: "Install the dpkg package.",
};

/// Reads the dpkg database.
pub const DPKG_QUERY: Tool = Tool {
    name: "dpkg-query",
    program: "dpkg-query",
    version_args: &["--version"],
    min: Version(1, 17, 0),
    install: "Install the dpkg package.",
};

/// `dpkg-deb -x`: the files of `deb` under `into`, without installing it.
pub fn unpack(runner: &dyn Runner, deb: &Path, into: &Path) -> anyhow::Result<()> {
    let output = DPKG_DEB.run(
        runner,
        &["-x", &deb.to_string_lossy(), &into.to_string_lossy()],
    )?;
    let name = deb.file_name().unwrap_or(deb.as_os_str()).to_string_lossy();
    check(output, &format!("dpkg-deb -x {name}"))?;
    Ok(())
}

/// Names installed packages answer to: their own and what they `Provide`.
#[derive(Debug, Default)]
pub struct DpkgDatabase {
    names: HashSet<String>,
}

impl DpkgDatabase {
    /// One `dpkg-query` for every package. [`ToolError::Missing`] on a host
    /// without dpkg (not Debian-based).
    pub fn load(runner: &dyn Runner) -> Result<Self, ToolError> {
        let args = ["-W", "-f", "${Package}\t${db:Status-Abbrev}\t${Provides}\n"];
        let output = DPKG_QUERY.run(runner, &args)?;
        let output = check(output, "dpkg-query -W").map_err(|cause| ToolError::Failed {
            name: DPKG_QUERY.name.to_string(),
            cause,
            install: DPKG_QUERY.install.to_string(),
        })?;
        Ok(Self::parse(&String::from_utf8_lossy(&output.stdout)))
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
        assert!(matches!(
            DpkgDatabase::load(&fake),
            Err(ToolError::Missing { .. })
        ));
    }
}

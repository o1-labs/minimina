//! The shared libraries a binary needs and the host does not have, from
//! `ldd`: what makes a mina binary fail at load time
//! (`libssl.so.3: cannot open shared object file`).

use super::requirement::{Tool, ToolError};
use crate::runner::Runner;
use crate::version::Version;
use std::io::Read;
use std::path::Path;

/// Lists the libraries of a binary, and where they are found.
pub const LDD: Tool = Tool {
    name: "ldd",
    program: "ldd",
    version_args: &["--version"],
    min: Version(2, 0, 0),
    install: "Install libc-bin.",
};

/// Whether `path` starts like an ELF file. Anything else (a script, an
/// empty file) has no libraries for `ldd` to look at.
fn is_elf(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok_and(|()| magic == *b"\x7fELF")
}

/// The libraries of `binaries` that are `not found`, each once, sorted.
/// [`ToolError::Missing`] when the host has no `ldd`.
pub fn missing_libraries(
    runner: &dyn Runner,
    binaries: &[&Path],
) -> Result<Vec<String>, ToolError> {
    let mut missing = vec![];
    for binary in binaries.iter().filter(|b| is_elf(b)) {
        let output = LDD.run(runner, &[&binary.to_string_lossy()])?;
        // `\tlibssl.so.3 => not found`
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some((library, "not found")) = line
                .split_once("=>")
                .map(|(lib, to)| (lib.trim(), to.trim()))
            {
                missing.push(library.to_string());
            }
        }
    }
    missing.sort();
    missing.dedup();
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn not_found_libraries_of_elf_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let elf = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, b"\x7fELF...").unwrap();
            path
        };
        let (mina, archive) = (elf("mina"), elf("mina-archive"));
        let script = dir.path().join("script");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();

        let fake = FakeRunner::default();
        fake.reply(
            0,
            "\tlinux-vdso.so.1 (0x00007ffd)\n\tlibssl.so.3 => not found\n\
             \tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb7)\n",
            "",
        )
        .reply(
            0,
            "\tlibssl.so.3 => not found\n\tlibpq.so.5 => not found\n",
            "",
        );
        let missing = missing_libraries(&fake, &[&mina, &script, &archive]).unwrap();
        assert_eq!(missing, ["libpq.so.5", "libssl.so.3"]);
        // the script is not looked at
        assert_eq!(fake.lines().len(), 2);

        let fake = FakeRunner::default();
        fake.reply_err(std::io::ErrorKind::NotFound);
        assert!(matches!(
            missing_libraries(&fake, &[&mina]),
            Err(ToolError::Missing { .. })
        ));
    }
}

//! External command execution.
//!
//! Every `docker` / `mina` / `psql` invocation goes through [`Runner`] so that
//! the code driving them can be unit-tested against [`fake::FakeRunner`].

use log::debug;
use std::ffi::OsStr;
use std::io;
use std::process::{Command, Output};

pub trait Runner {
    /// Runs `program` with `args` and extra environment `envs`, capturing its output.
    fn run(&self, program: &OsStr, args: &[&str], envs: &[(&str, &str)]) -> io::Result<Output>;

    /// Like [`Runner::run`], but fails unless the program exits 0; the error
    /// names `what` and has the program's stderr (else stdout).
    fn run_checked(
        &self,
        program: &OsStr,
        args: &[&str],
        envs: &[(&str, &str)],
        what: &str,
    ) -> io::Result<Output> {
        check(self.run(program, args, envs)?, what)
    }

    /// Checks that a tool is installed and new enough; returns its version.
    fn require(&self, tool: &Tool) -> Result<Version, ToolError> {
        let output = self
            .run(tool.program.as_ref(), tool.version_args, &[])
            .map_err(|_| ToolError::Missing {
                name: tool.name.to_string(),
                program: tool.program.to_string(),
                install: tool.install.to_string(),
            })?;
        let output = check(
            output,
            &format!("{} {}", tool.program, tool.version_args.join(" ")),
        )
        .map_err(|e| ToolError::Failed {
            name: tool.name.to_string(),
            cause: e,
            install: tool.install.to_string(),
        })?;
        let text = String::from_utf8_lossy(&output.stdout);
        let found = Version::find_in(&text).ok_or_else(|| ToolError::Unrecognised {
            name: tool.name.to_string(),
            output: text.trim().to_string(),
        })?;
        if found < tool.min {
            return Err(ToolError::TooOld {
                name: tool.name.to_string(),
                found,
                min: tool.min,
                install: tool.install.to_string(),
            });
        }
        Ok(found)
    }
}

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

/// A program minimina needs, and how to ask it for its version.
pub struct Tool<'a> {
    /// Name for messages (`Node.js`, `Docker Compose`).
    pub name: &'a str,
    pub program: &'a str,
    pub version_args: &'a [&'a str],
    pub min: Version,
    /// Where to get it, appended to errors.
    pub install: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{name} is required, but `{program}` was not found. {install}")]
    Missing {
        name: String,
        program: String,
        install: String,
    },
    #[error("{name} is required, but {cause}. {install}")]
    Failed {
        name: String,
        cause: io::Error,
        install: String,
    },
    #[error("Unrecognised {name} version '{output}'")]
    Unrecognised { name: String, output: String },
    #[error("{name} {found} is older than the minimum supported version {min}. {install}")]
    TooOld {
        name: String,
        found: Version,
        min: Version,
        install: String,
    },
}

/// Runs commands on the host.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &OsStr, args: &[&str], envs: &[(&str, &str)]) -> io::Result<Output> {
        debug!(
            "Running command: {} {}",
            program.to_string_lossy(),
            args.join(" ")
        );
        let output = Command::new(program)
            .args(args)
            .envs(envs.iter().copied())
            .output()?;
        debug!("status: {}", output.status);
        debug!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        debug!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        Ok(output)
    }
}

/// Fails with the command's stderr (stdout when stderr is empty) unless it
/// exited successfully.
pub fn check(output: Output, what: &str) -> io::Result<Output> {
    if output.status.success() {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = match (stderr.trim(), stdout.trim()) {
        ("", "") => "no output",
        ("", stdout) => stdout,
        (stderr, _) => stderr,
    };
    Err(io::Error::other(format!(
        "{what} failed ({}): {detail}",
        output.status
    )))
}

#[cfg(test)]
pub mod fake {
    use super::Runner;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    use std::io;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    #[derive(Debug, Clone, PartialEq)]
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub envs: Vec<(String, String)>,
    }

    impl Call {
        pub fn line(&self) -> String {
            std::iter::once(self.program.as_str())
                .chain(self.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    /// Records calls and replays queued outputs; an empty queue yields success with no output.
    #[derive(Default)]
    pub struct FakeRunner {
        pub calls: RefCell<Vec<Call>>,
        replies: RefCell<VecDeque<io::Result<Output>>>,
    }

    pub fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    impl FakeRunner {
        pub fn reply(&self, code: i32, stdout: &str, stderr: &str) -> &Self {
            self.replies
                .borrow_mut()
                .push_back(Ok(output(code, stdout, stderr)));
            self
        }

        pub fn reply_err(&self, kind: io::ErrorKind) -> &Self {
            self.replies
                .borrow_mut()
                .push_back(Err(io::Error::new(kind, "fake failure")));
            self
        }

        pub fn lines(&self) -> Vec<String> {
            self.calls.borrow().iter().map(Call::line).collect()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &OsStr, args: &[&str], envs: &[(&str, &str)]) -> io::Result<Output> {
            self.calls.borrow_mut().push(Call {
                program: program.to_string_lossy().into_owned(),
                args: args.iter().map(|a| a.to_string()).collect(),
                envs: envs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            });
            self.replies
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(output(0, "", "")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{output, FakeRunner};
    use super::*;

    #[test]
    fn system_runner_captures_output_and_env() {
        let out = SystemRunner
            .run(
                OsStr::new("sh"),
                &["-c", "printf %s \"$X\""],
                &[("X", "hi")],
            )
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hi");
    }

    #[test]
    fn system_runner_reports_missing_program() {
        let err = SystemRunner
            .run(OsStr::new("/nonexistent/minimina-test"), &[], &[])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn check_passes_success_and_reports_failure() {
        assert!(check(output(0, "ok", ""), "x").is_ok());
        let err = check(output(3, "", " boom \n"), "createdb").unwrap_err();
        assert_eq!(err.to_string(), "createdb failed (exit status: 3): boom");
        let err = check(output(1, "usage: x\n", ""), "mina").unwrap_err();
        assert_eq!(err.to_string(), "mina failed (exit status: 1): usage: x");
        // mina without its libp2p helper exits 20 and prints nothing
        let err = check(output(20, "", ""), "mina").unwrap_err();
        assert_eq!(err.to_string(), "mina failed (exit status: 20): no output");
    }

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

    #[test]
    fn require_reports_missing_failing_unparsable_and_old_tools() {
        let tool = Tool {
            name: "Node.js",
            program: "node",
            version_args: &["--version"],
            min: Version(22, 12, 0),
            install: "See nodejs.org.",
        };
        let fake = FakeRunner::default();
        fake.reply(0, "v24.21.0\n", "");
        assert_eq!(fake.require(&tool).unwrap(), Version(24, 21, 0));

        fake.reply_err(io::ErrorKind::NotFound);
        assert_eq!(
            fake.require(&tool).unwrap_err().to_string(),
            "Node.js is required, but `node` was not found. See nodejs.org."
        );
        fake.reply(1, "", "boom");
        assert_eq!(
            fake.require(&tool).unwrap_err().to_string(),
            "Node.js is required, but node --version failed (exit status: 1): boom. See nodejs.org."
        );
        fake.reply(0, "dev\n", "");
        assert_eq!(
            fake.require(&tool).unwrap_err().to_string(),
            "Unrecognised Node.js version 'dev'"
        );
        fake.reply(0, "v18.19.1\n", "");
        assert_eq!(
            fake.require(&tool).unwrap_err().to_string(),
            "Node.js 18.19.1 is older than the minimum supported version 22.12.0. See nodejs.org."
        );
    }

    #[test]
    fn run_checked_fails_on_exit_code() {
        let fake = FakeRunner::default();
        fake.reply(2, "", "nope");
        let err = fake
            .run_checked("x".as_ref(), &[], &[], "doing x")
            .unwrap_err();
        assert_eq!(err.to_string(), "doing x failed (exit status: 2): nope");
    }

    #[test]
    fn fake_runner_records_and_replays() {
        let fake = FakeRunner::default();
        fake.reply(1, "", "bad");
        let first = fake
            .run(OsStr::new("docker"), &["ps"], &[("A", "b")])
            .unwrap();
        let second = fake.run(OsStr::new("docker"), &["ls"], &[]).unwrap();
        assert_eq!(first.status.code(), Some(1));
        assert!(second.status.success());
        assert_eq!(fake.lines(), vec!["docker ps", "docker ls"]);
        assert_eq!(fake.calls.borrow()[0].envs, vec![("A".into(), "b".into())]);
    }
}

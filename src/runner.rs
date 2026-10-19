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

/// Fails with the command's stderr unless it exited successfully.
pub fn check(output: Output, what: &str) -> io::Result<Output> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "{what} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
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

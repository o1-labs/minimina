//! What minimina needs on the host: a program, new enough.

use crate::runner::{check, Runner};
use crate::version::Version;
use std::io;
use std::process::Output;

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

impl Tool<'_> {
    /// Runs the tool with `args`. A tool that is not installed is
    /// [`ToolError::Missing`]; the exit status is the caller's to check.
    pub fn run(&self, runner: &dyn Runner, args: &[&str]) -> Result<Output, ToolError> {
        runner
            .run(self.program.as_ref(), args, &[])
            .map_err(|cause| match cause.kind() {
                io::ErrorKind::NotFound => self.missing(),
                _ => ToolError::Failed {
                    name: self.name.to_string(),
                    cause,
                    install: self.install.to_string(),
                },
            })
    }

    fn missing(&self) -> ToolError {
        ToolError::Missing {
            name: self.name.to_string(),
            program: self.program.to_string(),
            install: self.install.to_string(),
        }
    }
}

/// Checks that `tool` is installed and new enough; returns its version.
pub fn require(runner: &dyn Runner, tool: &Tool) -> Result<Version, ToolError> {
    let output = runner
        .run(tool.program.as_ref(), tool.version_args, &[])
        .map_err(|_| tool.missing())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn run_tells_a_missing_tool_from_a_failing_one() {
        let tool = Tool {
            name: "ldd",
            program: "ldd",
            version_args: &["--version"],
            min: Version(2, 0, 0),
            install: "Install libc-bin.",
        };
        let fake = FakeRunner::default();
        fake.reply(1, "", "not a dynamic executable")
            .reply_err(io::ErrorKind::NotFound)
            .reply_err(io::ErrorKind::PermissionDenied);
        // a non-zero exit is still output
        assert!(!tool.run(&fake, &["x"]).unwrap().status.success());
        assert!(matches!(
            tool.run(&fake, &["x"]),
            Err(ToolError::Missing { .. })
        ));
        assert!(matches!(
            tool.run(&fake, &["x"]),
            Err(ToolError::Failed { .. })
        ));
        assert_eq!(fake.lines(), ["ldd x"; 3]);
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
        assert_eq!(require(&fake, &tool).unwrap(), Version(24, 21, 0));

        fake.reply_err(io::ErrorKind::NotFound);
        assert_eq!(
            require(&fake, &tool).unwrap_err().to_string(),
            "Node.js is required, but `node` was not found. See nodejs.org."
        );
        fake.reply(1, "", "boom");
        assert_eq!(
            require(&fake, &tool).unwrap_err().to_string(),
            "Node.js is required, but node --version failed (exit status: 1): boom. See nodejs.org."
        );
        fake.reply(0, "dev\n", "");
        assert_eq!(
            require(&fake, &tool).unwrap_err().to_string(),
            "Unrecognised Node.js version 'dev'"
        );
        fake.reply(0, "v18.19.1\n", "");
        assert_eq!(
            require(&fake, &tool).unwrap_err().to_string(),
            "Node.js 18.19.1 is older than the minimum supported version 22.12.0. See nodejs.org."
        );
    }
}

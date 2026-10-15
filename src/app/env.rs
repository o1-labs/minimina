//! Host checks done before any command runs.

use crate::{cli::ExecutionMode, native::mina_locator, runner::Runner};
use anyhow::{bail, Result};
use std::path::PathBuf;

// The least supported version of docker compose
const LEAST_COMPOSE_VERSION: &str = "2.21.0";

/// Docker mode needs `docker` and the compose v2 plugin; native mode needs nothing here.
pub fn check_execution_environment(mode: &ExecutionMode, runner: &dyn Runner) -> Result<()> {
    if *mode == ExecutionMode::Native {
        // Native mode's mina discovery lives in `resolve_bin_path`.
        return Ok(());
    }

    let docker_available = runner
        .run("docker".as_ref(), &["--version"], &[])
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !docker_available {
        bail!(
            "Docker is not installed. Please install Docker: https://docs.docker.com/get-docker/"
        );
    }

    match runner.run("docker".as_ref(), &["compose", "version", "--short"], &[]) {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if version.as_str() < LEAST_COMPOSE_VERSION {
                bail!(
                    "Docker Compose version '{version}' is older than \
                     the minimum supported version '{LEAST_COMPOSE_VERSION}'. \
                     Please update Docker Compose: https://docs.docker.com/compose/install/"
                );
            }
            Ok(())
        }
        Ok(output) => bail!(
            "Docker Compose plugin (v2) is not installed. \
             'docker compose' command failed. \
             Please install Docker Compose: https://docs.docker.com/compose/install/\n\
             stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(e) => bail!(
            "Docker Compose plugin (v2) is not installed. \
             'docker compose' command failed: {e}. \
             Please install Docker Compose: https://docs.docker.com/compose/install/"
        ),
    }
}

/// Decide the effective `--bin-path` for this run.
///
/// * Docker mode: `--bin-path` is rejected (the flag is exclusive to native mode).
/// * Native mode, flag supplied: validate that `<dir>/mina` exists.
/// * Native mode, flag omitted: delegate to [`mina_locator::locate`].
pub fn resolve_bin_path(
    mode: &ExecutionMode,
    provided: Option<PathBuf>,
) -> Result<Option<PathBuf>> {
    match (mode, provided) {
        (ExecutionMode::Docker, Some(_)) => bail!("--bin-path is only valid in native mode"),
        (ExecutionMode::Docker, None) => Ok(None),
        (ExecutionMode::Native, Some(dir)) => {
            let mina_bin = dir.join("mina");
            if !mina_bin.exists() {
                bail!("Mina binary not found at '{}'.", mina_bin.display());
            }
            Ok(Some(dir))
        }
        (ExecutionMode::Native, None) => Ok(Some(mina_locator::locate()?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;
    use std::io::ErrorKind;

    #[test]
    fn native_mode_skips_docker_checks() {
        let fake = FakeRunner::default();
        check_execution_environment(&ExecutionMode::Native, &fake).unwrap();
        assert!(fake.lines().is_empty());
    }

    #[test]
    fn docker_mode_accepts_supported_compose() {
        let fake = FakeRunner::default();
        fake.reply(0, "Docker version 27.0.0", "")
            .reply(0, "2.29.1\n", "");
        check_execution_environment(&ExecutionMode::Docker, &fake).unwrap();
        assert_eq!(
            fake.lines(),
            vec!["docker --version", "docker compose version --short"]
        );
    }

    #[test]
    fn docker_mode_requires_docker() {
        let fake = FakeRunner::default();
        fake.reply_err(ErrorKind::NotFound);
        let err = check_execution_environment(&ExecutionMode::Docker, &fake).unwrap_err();
        assert!(err.to_string().contains("Docker is not installed"));
    }

    #[test]
    fn docker_mode_requires_compose_plugin() {
        let fake = FakeRunner::default();
        fake.reply(0, "", "").reply(1, "", "unknown command");
        let err = check_execution_environment(&ExecutionMode::Docker, &fake).unwrap_err();
        assert!(err.to_string().contains("unknown command"));
    }

    #[test]
    fn docker_mode_rejects_old_compose() {
        let fake = FakeRunner::default();
        fake.reply(0, "", "").reply(0, "2.20.3", "");
        let err = check_execution_environment(&ExecutionMode::Docker, &fake).unwrap_err();
        assert!(err.to_string().contains("older than"));
    }

    #[test]
    fn bin_path_is_rejected_in_docker_mode() {
        let err = resolve_bin_path(&ExecutionMode::Docker, Some("/x".into())).unwrap_err();
        assert!(err.to_string().contains("only valid in native mode"));
        assert_eq!(
            resolve_bin_path(&ExecutionMode::Docker, None).unwrap(),
            None
        );
    }

    #[test]
    fn native_bin_path_must_contain_mina() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            resolve_bin_path(&ExecutionMode::Native, Some(dir.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("Mina binary not found"));

        std::fs::write(dir.path().join("mina"), "").unwrap();
        assert_eq!(
            resolve_bin_path(&ExecutionMode::Native, Some(dir.path().to_path_buf())).unwrap(),
            Some(dir.path().to_path_buf())
        );
    }
}

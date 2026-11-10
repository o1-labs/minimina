use super::{CheckDataConfig, CheckDataResult, RosettaCliConfig, RosettaError};
use crate::runner::Runner;
use mina_rosetta_sdk::NetworkIdentifier;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Output,
};

const CONFIG_JSON: &str = "config.json";
const RESULTS_JSON: &str = "results.json";
const DATA_DIR: &str = "data";

/// One `rosetta-cli check:data` run in `dir`: its config is made from the
/// package's `template`, and its data directory is new.
#[derive(Debug, Clone)]
pub struct CheckDataRun {
    pub program: PathBuf,
    pub template: PathBuf,
    pub dir: PathBuf,
    pub online_url: String,
    pub network: NetworkIdentifier,
    pub start_index: Option<u64>,
}

impl CheckDataRun {
    /// Writes the config, runs rosetta-cli and reads its results file.
    pub fn run(&self, runner: &dyn Runner) -> Result<CheckDataResult, RosettaError> {
        let template = RosettaCliConfig::read(&self.template)?;
        self.clear_last_run()?;
        self.config(template).write(&self.config_path())?;
        let out = self.run_cli(runner)?;
        self.read_results(&out)
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_JSON)
    }

    fn results_path(&self) -> PathBuf {
        self.dir.join(RESULTS_JSON)
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.join(DATA_DIR)
    }

    /// Removes the data and results of the last run, so this one syncs anew.
    fn clear_last_run(&self) -> Result<(), RosettaError> {
        let data = self.data_dir();
        if data.exists() {
            fs::remove_dir_all(&data).map_err(io_error(&data))?;
        }
        fs::create_dir_all(&self.dir).map_err(io_error(&self.dir))?;
        let results = self.results_path();
        match fs::remove_file(&results) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_error(&results)(e)),
            _ => Ok(()),
        }
    }

    fn config(&self, template: RosettaCliConfig) -> RosettaCliConfig {
        CheckDataConfig {
            online_url: self.online_url.clone(),
            network: self.network.clone(),
            data_directory: self.data_dir(),
            results_file: self.results_path(),
            start_index: self.start_index,
        }
        .apply(template)
    }

    fn run_cli(&self, runner: &dyn Runner) -> Result<Output, RosettaError> {
        let program = &self.program;
        let config = self.config_path();
        runner
            .run(
                program.as_os_str(),
                &[
                    "check:data",
                    "--configuration-file",
                    &config.to_string_lossy(),
                ],
                &[],
            )
            .map_err(|cause| match cause.kind() {
                io::ErrorKind::NotFound => RosettaError::CliMissing(program.clone()),
                _ => RosettaError::Cli {
                    program: program.clone(),
                    cause,
                },
            })
    }

    /// The results file; when rosetta-cli stopped before writing it, its
    /// last words say why.
    fn read_results(&self, out: &Output) -> Result<CheckDataResult, RosettaError> {
        let path = self.results_path();
        match fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).map_err(|cause| RosettaError::Json { path, cause })
            }
            Err(_) => Ok(CheckDataResult::stopped(
                last_line(&out.stderr)
                    .or_else(|| last_line(&out.stdout))
                    .unwrap_or_else(|| format!("rosetta-cli exited with {}", out.status)),
            )),
        }
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> RosettaError {
    let path = path.to_path_buf();
    move |cause| RosettaError::Io { path, cause }
}

fn last_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    fn testnet() -> NetworkIdentifier {
        NetworkIdentifier::mina("testnet")
    }

    #[test]
    fn check_data_writes_the_config_and_reads_the_results() {
        let dir = tempfile::tempdir().unwrap();
        let template = dir.path().join("template.json");
        fs::write(
            &template,
            r#"{"network": {"blockchain": "mina", "network": "X"}, "online_url": "", "data_directory": "", "data": {}}"#,
        )
        .unwrap();
        let work = dir.path().join("rosetta-cli");
        let fake = FakeRunner::default();
        // rosetta-cli itself is a fake: no results file, its stderr says why
        fake.reply(
            1,
            "",
            "Error: unable to sync to 25: cannot remove genesis block\n",
        );
        let mut run = CheckDataRun {
            program: "/tools/rosetta-cli".into(),
            template: template.clone(),
            dir: work.clone(),
            online_url: "http://localhost:3140".into(),
            network: testnet(),
            start_index: Some(2),
        };
        let result = run.run(&fake).unwrap();
        assert!(!result.passed());
        assert_eq!(
            result.error,
            "Error: unable to sync to 25: cannot remove genesis block"
        );
        let config_path = work.join(CONFIG_JSON);
        assert_eq!(
            fake.lines(),
            [format!(
                "/tools/rosetta-cli check:data --configuration-file {}",
                config_path.display()
            )]
        );
        let config: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(config["data"]["start_index"], 2);

        fake.reply_err(io::ErrorKind::NotFound);
        run.program = "rosetta-cli".into();
        let err = run.run(&fake).unwrap_err().to_string();
        assert!(err.starts_with("rosetta-cli is not found"), "{err}");
    }
}

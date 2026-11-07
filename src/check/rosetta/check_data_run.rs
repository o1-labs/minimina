use super::{api::NetworkIdentifier, CheckDataConfig, CheckDataResult, RosettaError};
use crate::runner::Runner;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const CONFIG_JSON: &str = "config.json";
const RESULTS_JSON: &str = "results.json";

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
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |cause| RosettaError::Io { path, cause }
        };
        let template = &self.template;
        let text = fs::read_to_string(template).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => RosettaError::NoTemplate(template.clone()),
            _ => RosettaError::Io {
                path: template.clone(),
                cause: e,
            },
        })?;
        let template_json = serde_json::from_str(&text).map_err(|cause| RosettaError::Json {
            path: template.clone(),
            cause,
        })?;
        let dir = &self.dir;
        let data = dir.join("data");
        if data.exists() {
            fs::remove_dir_all(&data).map_err(io(&data))?;
        }
        fs::create_dir_all(dir).map_err(io(dir))?;
        let results = dir.join(RESULTS_JSON);
        let _ = fs::remove_file(&results);
        let config = CheckDataConfig {
            online_url: self.online_url.clone(),
            network: self.network.clone(),
            data_directory: data,
            results_file: results.clone(),
            start_index: self.start_index,
        }
        .apply(template_json);
        let config_path = dir.join(CONFIG_JSON);
        fs::write(
            &config_path,
            serde_json::to_string_pretty(&config).unwrap_or_default(),
        )
        .map_err(io(&config_path))?;

        let program = &self.program;
        let config_arg = config_path.to_string_lossy();
        let out = runner
            .run(
                program.as_os_str(),
                &["check:data", "--configuration-file", &config_arg],
                &[],
            )
            .map_err(|cause| match cause.kind() {
                io::ErrorKind::NotFound => RosettaError::CliMissing(program.clone()),
                _ => RosettaError::Cli {
                    program: program.clone(),
                    cause,
                },
            })?;
        match fs::read_to_string(&results) {
            Ok(text) => serde_json::from_str(&text).map_err(|cause| RosettaError::Json {
                path: results,
                cause,
            }),
            // it stopped before writing results: its last words say why
            Err(_) => Ok(CheckDataResult {
                error: last_line(&out.stderr)
                    .or_else(|| last_line(&out.stdout))
                    .unwrap_or_else(|| format!("rosetta-cli exited with {}", out.status)),
                end_condition: None,
                tests: Default::default(),
                stats: None,
            }),
        }
    }
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
        NetworkIdentifier {
            blockchain: "mina".into(),
            network: "testnet".into(),
        }
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
        assert!(err.starts_with("rosetta-cli is not installed"), "{err}");
    }
}

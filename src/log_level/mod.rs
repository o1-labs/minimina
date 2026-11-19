//! Log level of the mina processes: `log_level` in the spec sets the
//! `-log-level` and `-file-log-level` of the daemons and snark workers and the
//! `--log-level` of `mina-archive`.

mod error;

pub use error::LogLevelError;

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// A level of mina's logger, read in any case (`trace`, `Trace`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum LogLevel {
    Spam,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    pub const ALL: [LogLevel; 7] = [
        LogLevel::Spam,
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
        LogLevel::Fatal,
    ];

    /// The level as mina prints it.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Spam => "Spam",
            LogLevel::Trace => "Trace",
            LogLevel::Debug => "Debug",
            LogLevel::Info => "Info",
            LogLevel::Warn => "Warn",
            LogLevel::Error => "Error",
            LogLevel::Fatal => "Fatal",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = LogLevelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        LogLevel::ALL
            .into_iter()
            .find(|level| level.as_str().eq_ignore_ascii_case(text))
            .ok_or_else(|| LogLevelError::Unknown(text.to_string()))
    }
}

impl TryFrom<String> for LogLevel {
    type Error = LogLevelError;

    fn try_from(text: String) -> Result<Self, LogLevelError> {
        text.parse()
    }
}

impl From<LogLevel> for String {
    fn from(level: LogLevel) -> Self {
        level.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_level_in_any_case() {
        assert_eq!("Trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("WARN".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        for level in LogLevel::ALL {
            assert_eq!(level.as_str().parse::<LogLevel>().unwrap(), level);
        }
    }

    #[test]
    fn names_the_levels_of_an_unknown_one() {
        let error = "loud".parse::<LogLevel>().unwrap_err().to_string();
        assert!(error.contains("'loud'"), "{error}");
        assert!(
            error.contains("Spam, Trace, Debug, Info, Warn, Error, Fatal"),
            "{error}"
        );
    }

    #[test]
    fn writes_a_level_as_mina_prints_it() {
        #[derive(Serialize, Deserialize)]
        struct Spec {
            log_level: LogLevel,
        }
        let spec: Spec = toml::from_str("log_level = \"debug\"").unwrap();
        assert_eq!(spec.log_level, LogLevel::Debug);
        assert_eq!(toml::to_string(&spec).unwrap(), "log_level = \"Debug\"\n");
    }
}

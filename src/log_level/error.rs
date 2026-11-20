#[derive(Debug, thiserror::Error)]
pub enum LogLevelError {
    #[error("unknown log level '{0}': use Spam, Trace, Debug, Info, Warn, Error, Fatal")]
    Unknown(String),
}

use super::PassKind;
use serde::Serialize;

/// What a replayer run printed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PassLog {
    pub pass: PassKind,
    pub logs: String,
}

use serde::Serialize;

/// One check and what was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl Check {
    pub fn new(name: impl Into<String>, passed: bool, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            passed,
            detail: detail.into(),
        }
    }
}

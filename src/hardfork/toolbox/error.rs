use std::{io, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ToolboxError {
    #[error("{} is not installed", .0.display())]
    Missing(PathBuf),
    #[error("running {check}: {cause}")]
    Run {
        check: &'static str,
        cause: io::Error,
    },
    #[error("{check} failed: {detail}")]
    Failed { check: &'static str, detail: String },
    #[error("{check} printed no block: {output}")]
    NoBlock { check: &'static str, output: String },
}

use serde::Serialize;

/// The part of the chain a replayer run replays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PassKind {
    /// The whole chain of a network without an applied hardfork.
    Chain,
    /// The genesis to the fork block; writes the postfork input.
    Prefork,
    /// The fork genesis to the tip, from the postfork input.
    Postfork,
}

impl std::fmt::Display for PassKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PassKind::Chain => "chain",
            PassKind::Prefork => "prefork",
            PassKind::Postfork => "postfork",
        })
    }
}

/// One `mina-replayer` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPass {
    pub kind: PassKind,
    pub args: Vec<String>,
}

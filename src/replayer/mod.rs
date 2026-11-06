//! `mina-replayer` runs on an archive database. A network without an applied
//! hardfork takes one pass. After one, the replayer stops at the fork
//! boundary, so it takes two: the prefork chain, which writes the postfork
//! replayer input, then the postfork chain from it.
//!
//! No `--continue-on-error`: a ledger hash that does not match fails the run.

mod applied_fork;
mod error;
mod fork;
mod pass;
mod pass_log;
mod replay;
#[allow(clippy::module_inception)]
mod replayer;
mod target;

pub use applied_fork::AppliedFork;
pub use error::ReplayerError;
pub use fork::Fork;
pub use pass::{PassKind, ReplayPass};
pub use pass_log::PassLog;
pub use replay::Replay;
pub use replayer::Replayer;
pub use target::HardForkTarget;

/// Directory of the replayer's files in the network directory: ledger
/// tarballs (which go to the global `/tmp/coda_cache_dir` otherwise,
/// MinaProtocol/mina#19985), checkpoints and the postfork input.
pub const REPLAYER_DIR: &str = "replayer";
/// The replayer input of the postfork chain, written by the prefork pass.
pub const POSTFORK_INPUT_JSON: &str = "postfork_input.json";

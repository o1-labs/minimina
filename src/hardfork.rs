//! Hardfork of a spec network: the `[hardfork]` section, the fork schedule
//! made from it, and the phase of a running network.
//!
//! ```toml
//! [hardfork]
//! mode = "manual"                  # or "auto": --hardfork-handling migrate-exit
//! at = { slot = 42 }               # or an RFC 3339 date: at = "2026-10-29T14:00:00Z"
//! tx_end_before = 12               # slot_tx_end = slot_chain_end - 12 [default: k + 2]
//! genesis_slot_delta = 10          # fork genesis slot = slot_chain_end + 10
//! method = "legacy"                # manual only: legacy | advanced [default: legacy]
//!
//! [hardfork.postfork]
//! bin_path = "/opt/mina-postfork/bin"
//! ```
//!
//! `at` is `slot_chain_end`, the last slot of the prefork chain. A date is
//! changed to a slot from the genesis timestamp, so it is placed again when
//! the first `network start` sets the genesis timestamp.

use crate::runtime_config::{self, RuntimeConfig};
use chrono::{DateTime, Duration, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Time from the genesis to `slot_tx_end` that a network needs: the daemons
/// start their provers and sync before they produce blocks (about 12 minutes
/// for 5 nodes with 30 s slots).
pub const MIN_LEAD: Duration = Duration::minutes(10);
const DEFAULT_GENESIS_SLOT_DELTA: u32 = 10;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HardforkSpec {
    pub mode: HardforkMode,
    pub at: ForkAt,
    /// Slots from `slot_tx_end` to `slot_chain_end`; must be more than k.
    pub tx_end_before: Option<u32>,
    #[serde(default = "default_genesis_slot_delta")]
    pub genesis_slot_delta: u32,
    /// How `manual` mode makes the fork config.
    pub method: Option<ForkMethod>,
    /// The binaries the network switches to; required.
    pub postfork: Option<PostforkSpec>,
}

fn default_genesis_slot_delta() -> u32 {
    DEFAULT_GENESIS_SLOT_DELTA
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HardforkMode {
    /// The daemons run with `--hardfork-handling migrate-exit`: they write the
    /// fork config themselves and exit; the dispatcher starts the postfork binary.
    Auto,
    /// minimina gets the fork config from the network and restarts every node.
    Manual,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForkMethod {
    /// GraphQL `fork_config`, then the postfork `runtime_genesis_ledger`.
    #[default]
    Legacy,
    /// `mina advanced generate-hardfork-config` of the prefork daemon.
    Advanced,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ForkAt {
    Slot {
        slot: u32,
    },
    /// RFC 3339 date.
    Date(String),
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PostforkSpec {
    /// Directory with the postfork `mina`, `mina-archive`, `mina-rosetta`, ...
    /// A relative path is relative to the spec file.
    pub bin_path: Option<PathBuf>,
}

/// Genesis constants the schedule depends on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Constants {
    pub k: u32,
    pub slot_ms: u64,
}

impl Constants {
    /// `genesis.k` and `proof.block_window_duration_ms` of a runtime config.
    pub fn from_runtime_config(config: &RuntimeConfig) -> Result<Self, Vec<String>> {
        let k = config.genesis.k.filter(|k| *k > 0);
        let slot_ms = config.proof.block_window_duration_ms.filter(|ms| *ms > 0);
        match (k, slot_ms) {
            (Some(k), Some(slot_ms)) => Ok(Constants { k, slot_ms }),
            _ => Err([
                k.is_none().then_some("genesis.k"),
                slot_ms
                    .is_none()
                    .then_some("proof.block_window_duration_ms"),
            ]
            .into_iter()
            .flatten()
            .map(|key| format!("set [runtime_config] {key}: the fork schedule depends on it"))
            .collect()),
        }
    }
}

/// The fork slots of a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Schedule {
    pub slot_tx_end: u32,
    pub slot_chain_end: u32,
    pub genesis_slot_delta: u32,
}

impl Schedule {
    /// First slot of the postfork chain.
    pub fn fork_genesis_slot(&self) -> u32 {
        self.slot_chain_end + self.genesis_slot_delta
    }

    /// The schedule in the `daemon` keys of a runtime config, if they are all set.
    pub fn from_daemon(daemon: &runtime_config::Daemon) -> Option<Self> {
        Some(Schedule {
            slot_tx_end: daemon.slot_tx_end?,
            slot_chain_end: daemon.slot_chain_end?,
            genesis_slot_delta: daemon.hard_fork_genesis_slot_delta?,
        })
    }
}

impl From<Schedule> for runtime_config::Daemon {
    fn from(s: Schedule) -> Self {
        runtime_config::Daemon {
            slot_tx_end: Some(s.slot_tx_end),
            slot_chain_end: Some(s.slot_chain_end),
            hard_fork_genesis_slot_delta: Some(s.genesis_slot_delta),
        }
    }
}

/// Start of `slot` for a chain with this genesis.
pub fn slot_time(genesis: DateTime<FixedOffset>, c: Constants, slot: u32) -> DateTime<FixedOffset> {
    genesis + Duration::milliseconds((c.slot_ms * u64::from(slot)) as i64)
}

impl HardforkSpec {
    /// The fork slots for a chain that begins at `genesis`, or every problem
    /// of the section. `runtime_daemon` holds the fork keys that the spec's
    /// `[runtime_config]` sets itself.
    pub fn schedule(
        &self,
        genesis: DateTime<FixedOffset>,
        c: Constants,
        runtime_daemon: &runtime_config::Daemon,
    ) -> Result<Schedule, Vec<String>> {
        let mut problems: Vec<String> = runtime_daemon
            .keys()
            .into_iter()
            .map(|key| {
                format!("[runtime_config] daemon.{key} conflicts with [hardfork]: remove it")
            })
            .collect();
        if self.mode == HardforkMode::Auto && self.method.is_some() {
            problems.push(
                "[hardfork] method is for mode = \"manual\": in auto mode the daemons \
                 write the fork config themselves"
                    .into(),
            );
        }
        if self.genesis_slot_delta == 0 {
            problems.push("[hardfork] genesis_slot_delta must be at least 1".into());
        }

        let slot_chain_end = match &self.at {
            ForkAt::Slot { slot } => Some(*slot),
            ForkAt::Date(date) => match DateTime::parse_from_rfc3339(date) {
                Err(e) => {
                    problems.push(format!(
                        "[hardfork] at = \"{date}\" is not an RFC 3339 date ({e}); \
                         for example \"2026-10-29T14:00:00Z\", or use at = {{ slot = N }}"
                    ));
                    None
                }
                Ok(at) if at <= genesis => {
                    problems.push(format!(
                        "[hardfork] at = \"{date}\" is not after the genesis ({genesis})"
                    ));
                    None
                }
                // the first slot that starts at `at` or later
                Ok(at) => {
                    let ms = (at - genesis).num_milliseconds() as u64;
                    u32::try_from(ms.div_ceil(c.slot_ms)).ok()
                }
            },
        };

        let before = self.tx_end_before.unwrap_or(c.k + 2);
        if before <= c.k {
            problems.push(format!(
                "[hardfork] tx_end_before = {before} must be more than k = {}: the blocks \
                 after slot_tx_end must be final before slot_chain_end",
                c.k
            ));
        }
        let schedule = slot_chain_end.and_then(|chain_end| {
            if chain_end <= before {
                problems.push(format!(
                    "[hardfork] slot_chain_end {chain_end} must be after tx_end_before = {before}: \
                     slot_tx_end would be {}",
                    i64::from(chain_end) - i64::from(before)
                ));
                return None;
            }
            Some(Schedule {
                slot_tx_end: chain_end - before,
                slot_chain_end: chain_end,
                genesis_slot_delta: self.genesis_slot_delta,
            })
        });
        if let Some(s) = schedule {
            let lead = slot_time(genesis, c, s.slot_tx_end) - genesis;
            if lead < MIN_LEAD {
                problems.push(format!(
                    "slot_tx_end {} is {} s after the genesis; the network needs at least {} s \
                     to start and sync: move [hardfork] at {} slots later",
                    s.slot_tx_end,
                    lead.num_seconds(),
                    MIN_LEAD.num_seconds(),
                    (MIN_LEAD - lead)
                        .num_milliseconds()
                        .unsigned_abs()
                        .div_ceil(c.slot_ms)
                ));
            }
        }

        match schedule {
            Some(s) if problems.is_empty() => Ok(s),
            _ => Err(problems),
        }
    }
}

/// Where a network is in the fork schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// `network start` has not set the genesis timestamp yet.
    NotStarted,
    BeforeGenesis,
    /// Blocks and transactions.
    Prefork,
    /// From `slot_tx_end`: blocks without transactions.
    TxEnd,
    /// From `slot_chain_end`: no blocks; the fork config is final.
    ChainEnd,
    /// From the fork genesis slot: the postfork chain.
    ForkGenesis,
}

/// The next phase and when it begins.
pub type NextPhase = Option<(Phase, DateTime<FixedOffset>)>;

/// The phase at `now`, the global slot (none before the genesis), and the next phase.
pub fn phase(
    genesis: DateTime<FixedOffset>,
    c: Constants,
    s: Schedule,
    now: DateTime<Utc>,
) -> (Phase, Option<u64>, NextPhase) {
    let at = |slot| slot_time(genesis, c, slot);
    if now < genesis {
        return (Phase::BeforeGenesis, None, Some((Phase::Prefork, genesis)));
    }
    let slot =
        (now.with_timezone(genesis.offset()) - genesis).num_milliseconds() as u64 / c.slot_ms;
    let (phase, next) = match slot {
        x if x < u64::from(s.slot_tx_end) => {
            (Phase::Prefork, Some((Phase::TxEnd, at(s.slot_tx_end))))
        }
        x if x < u64::from(s.slot_chain_end) => {
            (Phase::TxEnd, Some((Phase::ChainEnd, at(s.slot_chain_end))))
        }
        x if x < u64::from(s.fork_genesis_slot()) => (
            Phase::ChainEnd,
            Some((Phase::ForkGenesis, at(s.fork_genesis_slot()))),
        ),
        _ => (Phase::ForkGenesis, None),
    };
    (phase, Some(slot), next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: Constants = Constants {
        k: 10,
        slot_ms: 30_000,
    };

    fn genesis() -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339("2026-10-29T12:00:00+01:00").unwrap()
    }

    fn hardfork(toml: &str) -> HardforkSpec {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn slot_gives_the_schedule_with_defaults() {
        let h = hardfork("mode = \"manual\"\nat = { slot = 42 }\n[postfork]\nbin_path = \"/b\"");
        let s = h.schedule(genesis(), C, &Default::default()).unwrap();
        assert_eq!(
            s,
            Schedule {
                slot_tx_end: 30,
                slot_chain_end: 42,
                genesis_slot_delta: 10
            }
        );
        assert_eq!(s.fork_genesis_slot(), 52);
        assert_eq!(Schedule::from_daemon(&s.into()), Some(s));
    }

    #[test]
    fn date_is_the_first_slot_at_or_after_it() {
        // 21 min 10 s after the genesis: slot 42.33 -> 43
        let h = hardfork("mode = \"auto\"\nat = \"2026-10-29T11:21:10Z\"");
        let s = h.schedule(genesis(), C, &Default::default()).unwrap();
        assert_eq!((s.slot_tx_end, s.slot_chain_end), (31, 43));
    }

    #[test]
    fn every_problem_is_reported() {
        let h = hardfork(
            "mode = \"auto\"\nat = { slot = 15 }\ntx_end_before = 10\ngenesis_slot_delta = 0\nmethod = \"legacy\"",
        );
        let daemon = runtime_config::Daemon {
            slot_chain_end: Some(1),
            ..Default::default()
        };
        let problems = h.schedule(genesis(), C, &daemon).unwrap_err();
        let text = problems.join("\n");
        for part in [
            "daemon.slot_chain_end conflicts",
            "method is for mode = \"manual\"",
            "genesis_slot_delta must be at least 1",
            "tx_end_before = 10 must be more than k = 10",
            "slot_tx_end 5 is 150 s after the genesis",
            "move [hardfork] at 15 slots later",
        ] {
            assert!(text.contains(part), "no '{part}' in:\n{text}");
        }
    }

    #[test]
    fn bad_dates_are_explained() {
        let err = |at: &str| {
            hardfork(&format!("mode = \"auto\"\nat = \"{at}\""))
                .schedule(genesis(), C, &Default::default())
                .unwrap_err()
                .join("\n")
        };
        assert!(err("tomorrow").contains("is not an RFC 3339 date"));
        assert!(err("2026-10-29T10:00:00Z").contains("is not after the genesis"));
        assert!(err("2026-10-29T11:05:00Z").contains("must be after tx_end_before = 12"));
    }

    #[test]
    fn constants_must_be_set() {
        let config = |json| RuntimeConfig::from_json(&json).unwrap();
        let err =
            Constants::from_runtime_config(&config(serde_json::json!({"genesis": {"k": 10}})))
                .unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("proof.block_window_duration_ms"));
        let c = Constants::from_runtime_config(&config(serde_json::json!({
            "genesis": {"k": 10}, "proof": {"block_window_duration_ms": 30000}
        })))
        .unwrap();
        assert_eq!(c, C);
    }

    #[test]
    fn phases_follow_the_slots() {
        let s = Schedule {
            slot_tx_end: 30,
            slot_chain_end: 42,
            genesis_slot_delta: 10,
        };
        let at = |min: i64| genesis().with_timezone(&Utc) + Duration::minutes(min);
        let p = |min| {
            let (phase, slot, next) = phase(genesis(), C, s, at(min));
            (phase, slot, next.map(|(n, _)| n))
        };
        assert_eq!(p(-1), (Phase::BeforeGenesis, None, Some(Phase::Prefork)));
        assert_eq!(p(0), (Phase::Prefork, Some(0), Some(Phase::TxEnd)));
        assert_eq!(p(15), (Phase::TxEnd, Some(30), Some(Phase::ChainEnd)));
        assert_eq!(p(21), (Phase::ChainEnd, Some(42), Some(Phase::ForkGenesis)));
        assert_eq!(p(26), (Phase::ForkGenesis, Some(52), None));
        let (_, _, next) = phase(genesis(), C, s, at(1));
        assert_eq!(next.unwrap().1, slot_time(genesis(), C, 30));
    }

    #[test]
    fn unknown_fields_and_modes_are_rejected() {
        assert!(toml::from_str::<HardforkSpec>("mode = \"magic\"\nat = { slot = 1 }").is_err());
        assert!(
            toml::from_str::<HardforkSpec>("mode = \"auto\"\nat = { slot = 1 }\nwhen = 2").is_err()
        );
    }
}

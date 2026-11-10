use super::{ExpectedFork, GenesisView};
use crate::check::Check;
use std::collections::BTreeMap;

/// The postfork genesis of every daemon (or why it did not answer), against
/// what `prepare` made, and the height of the best tip.
pub fn chain_checks(
    expected: &ExpectedFork,
    daemons: &BTreeMap<String, Result<GenesisView, String>>,
    tip_height: Option<u64>,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let answered: Vec<(&String, &GenesisView)> = daemons
        .iter()
        .filter_map(|(name, view)| Some((name, view.as_ref().ok()?)))
        .collect();
    let hashes: BTreeMap<&str, Vec<&str>> =
        answered
            .iter()
            .fold(BTreeMap::new(), |mut by, (name, view)| {
                by.entry(view.state_hash.as_str())
                    .or_insert_with(Vec::new)
                    .push(name.as_str());
                by
            });
    let silent: Vec<String> = daemons
        .iter()
        .filter_map(|(name, view)| Some(format!("{name}: {}", view.as_ref().err()?)))
        .collect();
    checks.push(Check::new(
        "every daemon runs the same postfork genesis",
        silent.is_empty() && hashes.len() == 1,
        match (silent.is_empty(), hashes.len()) {
            (true, 1) => format!("{} daemons: {}", answered.len(), answered[0].1.state_hash),
            _ => {
                let mut parts: Vec<String> = hashes
                    .iter()
                    .map(|(hash, names)| format!("{hash}: {}", names.join(", ")))
                    .collect();
                parts.extend(silent);
                parts.join("; ")
            }
        },
    ));
    let Some((_, genesis)) = answered.first() else {
        return checks;
    };
    let fork = &expected.fork;
    checks.push(Check::new(
        "the postfork genesis follows the fork block",
        genesis.previous_state_hash == fork.state_hash
            && genesis.height == u64::from(fork.blockchain_length) + 1,
        format!(
            "parent {} at height {}; the fork block is {} at height {}",
            genesis.previous_state_hash, genesis.height, fork.state_hash, fork.blockchain_length
        ),
    ));
    checks.push(Check::new(
        "the postfork genesis is at the fork slot",
        genesis.slot == u64::from(fork.global_slot_since_genesis),
        format!(
            "slot {}; the fork config says {}",
            genesis.slot, fork.global_slot_since_genesis
        ),
    ));
    checks.push(Check::new(
        "the postfork genesis ledger is the one prepare made",
        genesis.ledger_hash == expected.ledger_hash
            && genesis.staking_ledger_hash == expected.staking_ledger_hash,
        format!(
            "ledger {}, staking ledger {}; prepare made {} and {}",
            genesis.ledger_hash,
            genesis.staking_ledger_hash,
            expected.ledger_hash,
            expected.staking_ledger_hash
        ),
    ));
    checks.push(Check::new(
        "the postfork chain grows",
        tip_height.is_some_and(|h| h > genesis.height),
        match tip_height {
            Some(h) => format!("best tip at height {h}, the genesis at {}", genesis.height),
            None => "no daemon gave its best tip".to_string(),
        },
    ));
    checks
}

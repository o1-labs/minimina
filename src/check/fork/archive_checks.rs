use super::{ArchiveMigration, ChainBlock, ExpectedFork};
use crate::check::Check;

/// The archive after the fork: migrated, and one chain from its highest
/// block through the postfork genesis and the fork block down to the first
/// block, canonical up to the postfork genesis.
pub fn archive_checks(
    expected: &ExpectedFork,
    migration: Option<&ArchiveMigration>,
    chain: &[ChainBlock],
) -> Vec<Check> {
    let mut checks = vec![Check::new(
        "the archive schema is migrated",
        migration.is_some_and(|m| m.status == "applied"),
        match migration {
            Some(m) => format!(
                "{} (protocol {}): {}",
                m.migration_version, m.protocol_version, m.status
            ),
            None => "no migration_history".to_string(),
        },
    )];

    let breaks: Vec<String> = chain
        .windows(2)
        .filter(|w| w[0].parent_id != Some(w[1].id) || w[0].height != w[1].height + 1)
        .map(|w| {
            format!(
                "{} at {} after {} at {}",
                w[0].state_hash, w[0].height, w[1].state_hash, w[1].height
            )
        })
        .collect();
    let (top, bottom) = (chain.first(), chain.last());
    let whole = !chain.is_empty() && breaks.is_empty() && bottom.is_some_and(|b| b.height == 1);
    checks.push(Check::new(
        "one chain from the archive's highest block down to the first",
        whole,
        match (top, bottom) {
            (Some(top), Some(bottom)) if breaks.is_empty() => format!(
                "{} blocks, height {} down to {}",
                chain.len(),
                top.height,
                bottom.height
            ),
            (Some(_), Some(_)) => format!("gaps: {}", breaks.join("; ")),
            _ => "no block at or after the fork slot".to_string(),
        },
    ));

    let fork = &expected.fork;
    let fork_height = i64::from(fork.blockchain_length);
    let at = |height: i64| chain.iter().find(|b| b.height == height);
    let (fork_block, genesis) = (at(fork_height), at(fork_height + 1));
    checks.push(Check::new(
        "the chain goes through the fork block to the postfork genesis",
        fork_block.is_some_and(|b| b.state_hash == fork.state_hash)
            && genesis.is_some_and(|g| {
                g.slot_since_genesis == i64::from(fork.global_slot_since_genesis)
                    && g.slot_since_hard_fork == 0
            }),
        format!(
            "height {fork_height}: {}; height {}: {}",
            fork_block.map_or("none", |b| b.state_hash.as_str()),
            fork_height + 1,
            genesis.map_or("none".to_string(), |g| format!(
                "{} at slot {} ({} since the fork)",
                g.state_hash, g.slot_since_genesis, g.slot_since_hard_fork
            ))
        ),
    ));

    let not_canonical: Vec<String> = chain
        .iter()
        .filter(|b| b.height <= fork_height + 1 && b.chain_status != "canonical")
        .map(|b| format!("{} at {}: {}", b.state_hash, b.height, b.chain_status))
        .collect();
    checks.push(Check::new(
        "the chain is canonical up to the postfork genesis",
        !chain.is_empty() && not_canonical.is_empty(),
        if not_canonical.is_empty() {
            format!(
                "{} blocks",
                chain.iter().filter(|b| b.height <= fork_height + 1).count()
            )
        } else {
            not_canonical.join("; ")
        },
    ));
    checks
}

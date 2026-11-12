use crate::archive_db::ChainBlock;
use crate::check::Check;

/// No block before the postfork genesis is still pending: settling the fork
/// (the archive's `--hardfork-handover`, or the toolbox's
/// `convert-chain-to-canonical`) makes the chain to the fork block canonical
/// and orphans the rest of the prefork chain.
pub fn pending_check(pending: &[ChainBlock]) -> Check {
    Check::new(
        "no prefork block is pending",
        pending.is_empty(),
        if pending.is_empty() {
            "every block before the postfork genesis is canonical or orphaned".to_string()
        } else {
            let heights: Vec<String> = pending
                .iter()
                .map(|b| format!("{} at {}", b.state_hash, b.height))
                .collect();
            format!("{} pending: {}", pending.len(), heights.join("; "))
        },
    )
}

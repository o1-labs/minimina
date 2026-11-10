use super::PaymentEvidence;
use crate::{check::Check, load::PaymentRecord};
use std::collections::BTreeMap;

/// The payment checks and what could not be checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaymentChecks {
    pub checks: Vec<Check>,
    pub notes: Vec<String>,
}

/// Where a payment is on the archive's chain.
struct Inclusion<'a> {
    height: i64,
    status: &'a str,
}

/// The loads' payments against the archive:
///
/// - a payment sent before the fork is in a block up to the fork block, or
///   in none (it was still in the pool at `slot_tx_end`, which the fork
///   drops), never after it, and applied;
/// - each sender's nonce in the fork ledger follows its last prefork payment
///   in a block;
/// - a payment sent after the fork is in a postfork block, applied, or still
///   pending: a nonce below the sender's nonce now would be lost.
pub fn payment_checks(e: &PaymentEvidence) -> PaymentChecks {
    let mut out = PaymentChecks::default();
    if e.payments.is_empty() {
        out.notes.push(
            "no load sent payments: start one with `network load start` before the fork, \
             and with --across-fork (or after the fork) to check payments on both chains"
                .to_string(),
        );
        return out;
    }
    let heights: BTreeMap<&str, i64> = e
        .chain
        .iter()
        .map(|b| (b.state_hash.as_str(), b.height))
        .collect();
    let inclusions = |p: &PaymentRecord| -> Vec<Inclusion> {
        e.commands
            .iter()
            .filter(|c| Some(&c.hash) == p.hash.as_ref())
            .filter_map(|c| {
                Some(Inclusion {
                    height: *heights.get(c.block_state_hash.as_str())?,
                    status: &c.status,
                })
            })
            .collect()
    };
    let (postfork, prefork): (Vec<&PaymentRecord>, Vec<&PaymentRecord>) = e
        .payments
        .iter()
        .partition(|p| p.genesis == e.postfork_genesis);

    if prefork.is_empty() {
        out.notes
            .push("no payments before the fork: none to find up to the fork block".to_string());
    } else {
        let mut problems = Vec::new();
        let mut included = 0;
        let mut last_nonce: BTreeMap<&str, u64> = BTreeMap::new();
        for p in &prefork {
            let found = inclusions(p);
            for i in &found {
                if i.height > e.fork_height {
                    problems.push(format!(
                        "{} at height {}, after the fork block",
                        hash(p),
                        i.height
                    ));
                } else if i.status != "applied" {
                    problems.push(format!("{} {} at height {}", hash(p), i.status, i.height));
                }
            }
            if found.iter().any(|i| i.height <= e.fork_height) {
                included += 1;
                if let Some(nonce) = p.nonce {
                    let last = last_nonce.entry(p.sender.as_str()).or_default();
                    *last = (*last).max(nonce + 1);
                }
            }
        }
        out.checks.push(Check::new(
            "payments sent before the fork are in blocks up to the fork block, or dropped",
            problems.is_empty(),
            if problems.is_empty() {
                format!(
                    "{included} of {} in blocks, {} dropped (in the pool at slot_tx_end)",
                    prefork.len(),
                    prefork.len() - included
                )
            } else {
                problems.join("; ")
            },
        ));
        if last_nonce.is_empty() {
            out.notes.push(
                "no payment sent before the fork is in a block: no fork ledger nonce to check"
                    .to_string(),
            );
        } else {
            let nonces: Vec<(String, bool)> = last_nonce
                .iter()
                .map(|(sender, next)| {
                    let fork = e.fork_nonces.get(*sender).copied();
                    (
                        format!(
                            "{sender}: {} in the fork ledger, {next} after its last payment",
                            fork.map_or("none".to_string(), |n| n.to_string())
                        ),
                        fork == Some(*next),
                    )
                })
                .collect();
            out.checks.push(Check::new(
                "the fork ledger nonces follow the last prefork payments",
                nonces.iter().all(|(_, ok)| *ok),
                nonces
                    .into_iter()
                    .map(|(line, _)| line)
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
    }

    if postfork.is_empty() {
        out.notes.push(
            "no payments after the fork: run `network load start --scenario once` and check again"
                .to_string(),
        );
    } else {
        let mut problems = Vec::new();
        let (mut included, mut pending) = (0, 0);
        for p in &postfork {
            let found = inclusions(p);
            for i in found.iter().filter(|i| i.status != "applied") {
                problems.push(format!("{} {} at height {}", hash(p), i.status, i.height));
            }
            if !found.is_empty() {
                included += 1;
                continue;
            }
            let now = e.daemon_nonces.get(&p.sender).copied();
            match (p.nonce, now) {
                (Some(nonce), Some(now)) if nonce < now => problems.push(format!(
                    "{} (nonce {nonce}) is in no block, and the sender's nonce is {now}",
                    hash(p)
                )),
                _ => pending += 1,
            }
        }
        out.checks.push(Check::new(
            "payments sent after the fork are in postfork blocks",
            problems.is_empty(),
            if problems.is_empty() {
                format!(
                    "{included} of {} in blocks, {pending} pending",
                    postfork.len()
                )
            } else {
                problems.join("; ")
            },
        ));
    }
    out
}

fn hash(p: &PaymentRecord) -> &str {
    p.hash.as_deref().unwrap_or("?")
}

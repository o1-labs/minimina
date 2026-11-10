use super::{mina_amount, Scenario, Sender};
use mina_sdk::Currency;
use serde::{Deserialize, Serialize};

/// What `network load start` asked for, kept in `load.json` for the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadSpec {
    pub id: String,
    pub network_id: String,
    pub scenario: Scenario,
    /// Payments go from these in turn.
    pub senders: Vec<Sender>,
    /// Each sender pays the next test account of the network.
    pub accounts: Vec<Sender>,
    #[serde(with = "mina_amount")]
    pub amount: Currency,
    #[serde(with = "mina_amount")]
    pub fee: Currency,
    /// The daemon the payments are sent through, and its GraphQL.
    pub node: String,
    pub graphql_uri: String,
    /// On `After_slot_tx_end`, wait for the postfork chain and go on.
    pub across_fork: bool,
    /// Failed payments in a row after which the load gives up.
    pub max_failures: u32,
}

impl LoadSpec {
    /// The account `sender` pays: the test account after it.
    pub fn receiver_of<'s>(&'s self, sender: &'s Sender) -> &'s Sender {
        let i = self
            .accounts
            .iter()
            .position(|a| a.public_key == sender.public_key)
            .unwrap_or(0);
        self.accounts
            .get((i + 1) % self.accounts.len().max(1))
            .unwrap_or(sender)
    }

    /// Memo of the `n`th payment: the load id and the number, so the archive
    /// can be matched with the load's log.
    pub fn memo(&self, n: u64) -> String {
        format!("{} {n}", self.id)
    }
}

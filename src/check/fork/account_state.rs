use super::ForkCheckError;
use crate::{check::vesting::VestingSchedule, spec::ledger::LedgerAccount};
use mina_sdk::Currency;

/// An account as the fork ledger has it, to hold against the archive's
/// postfork genesis accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub public_key: String,
    pub balance: Currency,
    pub nonce: u64,
    pub receipt_chain_hash: Option<String>,
    pub delegate: Option<String>,
    pub timing: Option<VestingSchedule>,
}

impl AccountState {
    /// A fork config account; none for an account of another token than MINA.
    pub fn of_ledger(account: &LedgerAccount) -> Result<Option<Self>, ForkCheckError> {
        let public_key = account.pk.to_string();
        let field = |name: &str| account.other.get(name).and_then(|v| v.as_str());
        if field("token").is_some_and(|t| t != super::MINA_TOKEN) {
            return Ok(None);
        }
        let invalid = |field: &'static str, value: &str| ForkCheckError::Account {
            public_key: public_key.clone(),
            field,
            value: value.to_string(),
        };
        let balance = Currency::from_mina(account.balance.as_str())
            .map_err(|_| invalid("balance", account.balance.as_str()))?;
        let nonce = match account.other.get("nonce") {
            None => 0,
            Some(v) => {
                let text = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                text.parse().map_err(|_| invalid("nonce", &text))?
            }
        };
        let timing = match &account.timing {
            None => None,
            Some(t) => Some(
                VestingSchedule::from_timing(t).map_err(|e| invalid("timing", &e.to_string()))?,
            ),
        };
        Ok(Some(AccountState {
            balance,
            nonce,
            receipt_chain_hash: field("receipt_chain_hash").map(str::to_string),
            delegate: account.delegate.as_ref().map(|d| d.to_string()),
            timing,
            public_key,
        }))
    }

    /// How `archive` differs from this account, field by field. A field the
    /// fork ledger leaves out is not compared.
    pub fn differences(&self, archive: &AccountState) -> Vec<String> {
        let mut found = Vec::new();
        if self.balance != archive.balance {
            found.push(format!(
                "balance {} in the archive, {} in the fork ledger",
                archive.balance.mina(),
                self.balance.mina()
            ));
        }
        if self.nonce != archive.nonce {
            found.push(format!(
                "nonce {} in the archive, {} in the fork ledger",
                archive.nonce, self.nonce
            ));
        }
        if self.receipt_chain_hash.is_some()
            && self.receipt_chain_hash != archive.receipt_chain_hash
        {
            found.push("another receipt chain hash".to_string());
        }
        if self.delegate.is_some() && self.delegate != archive.delegate {
            found.push(format!(
                "delegate {} in the archive",
                archive.delegate.as_deref().unwrap_or("none")
            ));
        }
        if self.timing != archive.timing {
            let show = |t: &Option<VestingSchedule>| t.map_or("untimed".into(), |t| t.to_string());
            found.push(format!(
                "timing {} in the archive, {} in the fork ledger",
                show(&archive.timing),
                show(&self.timing)
            ));
        }
        found
    }
}

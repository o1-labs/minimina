use super::ForkCheckError;
use crate::{check::vesting::VestingSchedule, spec::ledger::LedgerAccount};
use mina_sdk::{AccountBalance, AccountData, Currency};

/// What the fork check needs of mina-sdk's account: one from the fork
/// ledger, and how the archive's postfork genesis account differs from it.
pub trait ForkAccount: Sized {
    /// An account with only the fields the fork ledger and the archive
    /// have: a public key, a balance and a nonce; the rest is unset.
    fn with_balance(public_key: String, balance: Currency, nonce: u64) -> Self;

    /// A fork config account; none for an account of another token than MINA.
    fn of_ledger(account: &LedgerAccount) -> Result<Option<Self>, ForkCheckError>;

    /// The vesting schedule; none for an untimed account.
    fn schedule(&self) -> Option<VestingSchedule>;

    /// How `archive` differs from this account, field by field. A field the
    /// fork ledger leaves out is not compared.
    fn differences(&self, archive: &Self) -> Vec<String>;
}

impl ForkAccount for AccountData {
    fn with_balance(public_key: String, balance: Currency, nonce: u64) -> Self {
        AccountData {
            public_key,
            nonce,
            balance: AccountBalance {
                total: balance,
                liquid: None,
                locked: None,
                block_height: None,
            },
            delegate: None,
            token_id: None,
            token_symbol: None,
            voting_for: None,
            receipt_chain_hash: None,
            timing: None,
            permissions: None,
            zkapp_state: None,
            proved_state: None,
            zkapp_uri: None,
        }
    }

    fn of_ledger(account: &LedgerAccount) -> Result<Option<Self>, ForkCheckError> {
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
                VestingSchedule::from_timing(t)
                    .map_err(|e| invalid("timing", &e.to_string()))?
                    .into(),
            ),
        };
        Ok(Some(AccountData {
            receipt_chain_hash: field("receipt_chain_hash").map(str::to_string),
            delegate: account.delegate.as_ref().map(|d| d.to_string()),
            timing,
            ..AccountData::with_balance(public_key.clone(), balance, nonce)
        }))
    }

    fn schedule(&self) -> Option<VestingSchedule> {
        self.timing.as_ref().and_then(VestingSchedule::from_daemon)
    }

    fn differences(&self, archive: &Self) -> Vec<String> {
        let mut found = Vec::new();
        if self.balance.total != archive.balance.total {
            found.push(format!(
                "balance {} in the archive, {} in the fork ledger",
                archive.balance.total.mina(),
                self.balance.total.mina()
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
        if self.schedule() != archive.schedule() {
            let show = |t: Option<VestingSchedule>| t.map_or("untimed".into(), |t| t.to_string());
            found.push(format!(
                "timing {} in the archive, {} in the fork ledger",
                show(archive.schedule()),
                show(self.schedule())
            ));
        }
        found
    }
}

//! The accounts of `[ledger] file`, which the genesis ledger starts with.
//!
//! - `.json`: a runtime config (`ledger.accounts`, as `-g` takes it), a
//!   `{"accounts": [...]}` object, or the array of accounts. Fields other
//!   than `pk`, `balance`, `sk` and `delegate` are kept as they are.
//! - `.csv`: a [`CsvHeader`] line naming the columns, then one account per
//!   line: `public_key` and `balance` (in MINA, as in the rest of the spec),
//!   optionally `private_key` and `delegate`. Empty lines and lines that start
//!   with `#` are skipped.

mod account;
mod balance;
mod csv_header;
mod public_key;

pub use account::LedgerAccount;
pub use balance::Balance;
pub use csv_header::{Column, CsvHeader};
pub use public_key::PublicKey;

use super::{LedgerProblem, SpecError};
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The accounts of a ledger file.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerFile {
    pub path: PathBuf,
    pub accounts: Vec<LedgerAccount>,
}

impl LedgerFile {
    pub fn load(path: &Path) -> Result<Self, SpecError> {
        let error = |problem| SpecError::LedgerFile {
            file: path.to_path_buf(),
            problem,
        };
        let text =
            std::fs::read_to_string(path).map_err(|e| error(LedgerProblem::Unreadable(e)))?;
        let accounts = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => from_json(&text),
            Some("csv") => from_csv(&text),
            _ => Err(LedgerProblem::Extension),
        }
        .map_err(error)?;
        let mut keys = HashSet::new();
        if let Some(twice) = accounts.iter().find(|a| !keys.insert(&a.pk)) {
            return Err(error(LedgerProblem::Duplicate(twice.pk.to_string())));
        }
        Ok(LedgerFile {
            path: path.to_path_buf(),
            accounts,
        })
    }
}

fn from_json(text: &str) -> Result<Vec<LedgerAccount>, LedgerProblem> {
    let value: Value = serde_json::from_str(text).map_err(LedgerProblem::Json)?;
    let accounts = match &value {
        Value::Array(accounts) => accounts,
        _ => value
            .pointer("/ledger/accounts")
            .or_else(|| value.get("accounts"))
            .and_then(Value::as_array)
            .ok_or(LedgerProblem::NoAccounts)?,
    };
    accounts
        .iter()
        .enumerate()
        .map(|(i, account)| {
            serde_json::from_value(account.clone()).map_err(|cause| LedgerProblem::JsonAccount {
                index: i + 1,
                cause,
            })
        })
        .collect()
}

fn from_csv(text: &str) -> Result<Vec<LedgerAccount>, LedgerProblem> {
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'));
    let (_, header) = lines.next().ok_or(LedgerProblem::NoHeader)?;
    let header: CsvHeader = header.parse()?;
    lines
        .map(|(line, text)| {
            csv_account(&header, line, text).map_err(|problem| match problem {
                LedgerProblem::ValueCount { .. } => problem,
                problem => LedgerProblem::Line {
                    line,
                    problem: Box::new(problem),
                },
            })
        })
        .collect()
}

/// The account of one CSV line.
fn csv_account(
    header: &CsvHeader,
    line: usize,
    text: &str,
) -> Result<LedgerAccount, LedgerProblem> {
    let values: Vec<&str> = text.split(',').map(str::trim).collect();
    if values.len() != header.columns.len() {
        return Err(LedgerProblem::ValueCount {
            line,
            values: values.len(),
            columns: header.columns.len(),
        });
    }
    let (mut pk, mut balance, mut sk, mut delegate) = (None, None, None, None);
    for (column, value) in header.columns.iter().zip(values) {
        if value.is_empty() {
            continue;
        }
        match column {
            Column::PublicKey => pk = Some(value.parse()?),
            Column::Balance => balance = Some(value.parse()?),
            Column::PrivateKey => sk = Some(value.to_string()),
            Column::Delegate => delegate = Some(value.parse()?),
        }
    }
    let (Some(pk), Some(balance)) = (pk, balance) else {
        return Err(LedgerProblem::RequiredValues);
    };
    Ok(LedgerAccount {
        sk,
        delegate,
        ..LedgerAccount::new(pk, balance)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PK1: &str = "B62qrPN5Y5yq8kGE3FbVKbGTdTAJNdtNtB5sNVpxyRwWGcDEhpMzc8g";
    const PK2: &str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";

    fn file(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn account(pk: &str, balance: &str) -> LedgerAccount {
        LedgerAccount::new(pk.parse().unwrap(), balance.parse().unwrap())
    }

    #[test]
    fn csv_columns_come_from_the_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(
            &dir,
            "a.csv",
            &format!("# exported\nbalance, public_key, delegate\n1000.5,{PK1},{PK2}\n\n7,{PK2},\n"),
        );
        let ledger = LedgerFile::load(&path).unwrap();
        assert_eq!(
            ledger.accounts,
            [
                LedgerAccount {
                    delegate: Some(PK2.parse().unwrap()),
                    ..account(PK1, "1000.5")
                },
                account(PK2, "7"),
            ]
        );
        // written as the runtime config writes accounts
        assert_eq!(
            serde_json::to_value(&ledger.accounts[1]).unwrap(),
            json!({"pk": PK2, "balance": "7"})
        );
    }

    #[test]
    fn mistakes_name_the_file_and_line() {
        let dir = tempfile::tempdir().unwrap();
        let err = |text: &str| {
            let path = file(&dir, "a.csv", text);
            let err = LedgerFile::load(&path).unwrap_err().to_string();
            err.strip_prefix(&format!("ledger file {}: ", path.display()))
                .unwrap()
                .to_string()
        };
        assert_eq!(
            err("pk,balance\n"),
            "unknown column 'pk'; the columns are public_key, balance, private_key, delegate"
        );
        assert_eq!(
            err(&format!("public_key,balance\n{PK1},1,2\n")),
            "line 2: 3 values for 2 columns"
        );
        assert_eq!(
            err(&format!("public_key,balance\n{PK1},1e9\n")),
            "line 2: balance '1e9' is not an amount of MINA (like 1000 or 0.5)"
        );
        assert_eq!(
            err("public_key,balance\n,1\n"),
            "line 2: public_key and balance are required"
        );
        assert_eq!(
            err(&format!("public_key,balance\n{PK1},1\n{PK1},2\n")),
            format!("account {PK1} is there twice")
        );
    }

    #[test]
    fn json_takes_a_runtime_config_or_its_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let given = json!({"pk": PK1, "balance": "5", "sk": null, "timing": {"cliff_time": "10"}});
        for text in [
            json!({"genesis": {}, "ledger": {"name": "x", "accounts": [given]}}),
            json!({"accounts": [given]}),
            json!([given]),
        ] {
            let ledger = LedgerFile::load(&file(&dir, "l.json", &text.to_string())).unwrap();
            assert_eq!(ledger.accounts.len(), 1);
            // other fields are kept; a null sk is no sk
            assert_eq!(
                serde_json::to_value(&ledger.accounts[0]).unwrap(),
                json!({"pk": PK1, "balance": "5", "timing": {"cliff_time": "10"}})
            );
        }
        let path = file(&dir, "l.json", &json!([{"pk": PK1}]).to_string());
        let err = LedgerFile::load(&path).unwrap_err().to_string();
        assert!(err.contains("account 1: missing field `balance`"), "{err}");
        assert!(LedgerFile::load(&file(&dir, "l.txt", "")).is_err());
    }
}

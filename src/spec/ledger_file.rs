//! The accounts of `[ledger] file`, which the genesis ledger starts with.
//!
//! - `.json`: a runtime config (`ledger.accounts`, as `-g` takes it), a
//!   `{"accounts": [...]}` object, or the array of accounts. Accounts are
//!   kept as they are (timing, permissions, ...).
//! - `.csv`: one account per line after a header that names the columns:
//!   `public_key` and `balance` (in MINA, as in the rest of the spec), and
//!   optionally `private_key` and `delegate`. Empty lines and lines that start
//!   with `#` are skipped.

use anyhow::{bail, Context as _, Result};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::Path;

/// The accounts of `path`, as runtime config ledger accounts (`pk`,
/// `balance`, ...).
pub fn load(path: &Path) -> Result<Vec<Value>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading ledger file {}", path.display()))?;
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let accounts = match extension {
        "json" => from_json(&text),
        "csv" => from_csv(&text),
        _ => bail!("the ledger file must be .json or .csv"),
    }
    .with_context(|| format!("ledger file {}", path.display()))?;
    let mut keys = HashSet::new();
    for account in &accounts {
        let pk = account["pk"].as_str().unwrap_or_default();
        if !keys.insert(pk.to_string()) {
            bail!(
                "ledger file {}: account {pk} is there twice",
                path.display()
            );
        }
    }
    Ok(accounts)
}

fn from_json(text: &str) -> Result<Vec<Value>> {
    let value: Value = serde_json::from_str(text).context("not valid JSON")?;
    let accounts = match &value {
        Value::Array(accounts) => accounts,
        _ => value
            .pointer("/ledger/accounts")
            .or_else(|| value.get("accounts"))
            .and_then(Value::as_array)
            .context("no accounts: expected ledger.accounts, accounts, or an array")?,
    };
    accounts
        .iter()
        .enumerate()
        .map(|(i, account)| {
            let pk = account.get("pk").and_then(Value::as_str);
            let balance = account.get("balance");
            match (pk, balance) {
                (Some(pk), Some(_)) => {
                    check_public_key(pk).with_context(|| format!("account {}", i + 1))?;
                    Ok(account.clone())
                }
                _ => bail!("account {} has no pk or no balance", i + 1),
            }
        })
        .collect()
}

/// Columns of a CSV ledger file, and the runtime config field of each.
const COLUMNS: [(&str, &str); 4] = [
    ("public_key", "pk"),
    ("balance", "balance"),
    ("private_key", "sk"),
    ("delegate", "delegate"),
];

fn from_csv(text: &str) -> Result<Vec<Value>> {
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'));
    let (_, header) = lines.next().context("empty: expected a header line")?;
    let columns: Vec<&str> = header
        .split(',')
        .map(|name| {
            let name = name.trim();
            COLUMNS
                .iter()
                .find(|(column, _)| *column == name)
                .map(|(_, field)| *field)
                .with_context(|| {
                    format!(
                        "unknown column '{name}'; the columns are {}",
                        COLUMNS.map(|(c, _)| c).join(", ")
                    )
                })
        })
        .collect::<Result<_>>()?;
    for required in ["pk", "balance"] {
        if !columns.contains(&required) {
            bail!("the header has no public_key or no balance column");
        }
    }
    lines
        .map(|(number, line)| {
            let cells: Vec<&str> = line.split(',').map(str::trim).collect();
            if cells.len() != columns.len() {
                bail!(
                    "line {number}: {} values for {} columns",
                    cells.len(),
                    columns.len()
                );
            }
            let mut account = Map::new();
            for (field, cell) in columns.iter().zip(cells) {
                if cell.is_empty() {
                    continue;
                }
                match *field {
                    "pk" | "delegate" => check_public_key(cell),
                    "balance" => check_balance(cell),
                    _ => Ok(()),
                }
                .with_context(|| format!("line {number}"))?;
                account.insert(field.to_string(), json!(cell));
            }
            if !account.contains_key("pk") || !account.contains_key("balance") {
                bail!("line {number}: public_key and balance are required");
            }
            Ok(Value::Object(account))
        })
        .collect()
}

/// A mina public key: `B62` and 52 more base58 characters.
fn check_public_key(key: &str) -> Result<()> {
    if key.len() != 55 || !key.starts_with("B62") {
        bail!("'{key}' is not a mina public key (B62..., 55 characters)");
    }
    Ok(())
}

/// MINA with at most 9 decimals (`1000`, `0.5`).
fn check_balance(balance: &str) -> Result<()> {
    let (whole, fraction) = balance.split_once('.').unwrap_or((balance, ""));
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    let valid = !whole.is_empty()
        && digits(whole)
        && digits(fraction)
        && fraction.len() <= 9
        && !(balance.contains('.') && fraction.is_empty());
    if !valid {
        bail!("balance '{balance}' is not an amount of MINA (like 1000 or 0.5)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK1: &str = "B62qrPN5Y5yq8kGE3FbVKbGTdTAJNdtNtB5sNVpxyRwWGcDEhpMzc8g";
    const PK2: &str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";

    fn file(dir: &tempfile::TempDir, name: &str, text: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn csv_columns_come_from_the_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(
            &dir,
            "a.csv",
            &format!("# exported\nbalance, public_key, delegate\n1000.5,{PK1},{PK2}\n\n7,{PK2},\n"),
        );
        let accounts = load(&path).unwrap();
        assert_eq!(
            accounts,
            [
                json!({"pk": PK1, "balance": "1000.5", "delegate": PK2}),
                json!({"pk": PK2, "balance": "7"}),
            ]
        );
    }

    #[test]
    fn csv_mistakes_name_their_line() {
        let dir = tempfile::tempdir().unwrap();
        let err = |text: &str| format!("{:#}", load(&file(&dir, "a.csv", text)).unwrap_err());
        assert!(err("pk,balance\n").contains("unknown column 'pk'"));
        assert!(err("public_key\n").contains("no public_key or no balance column"));
        assert!(err(&format!("public_key,balance\n{PK1},1,2\n")).contains("line 2: 3 values"));
        assert!(err(&format!("public_key,balance\n{PK1},1e9\n")).contains("line 2: balance '1e9'"));
        assert!(err("public_key,balance\nB62x,1\n").contains("not a mina public key"));
        assert!(err(&format!("public_key,balance\n{PK1},1\n{PK1},2\n")).contains("twice"));
    }

    #[test]
    fn json_takes_a_runtime_config_or_its_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let account = json!({"pk": PK1, "balance": "5", "timing": {"cliff_time": "10"}});
        for text in [
            json!({"genesis": {}, "ledger": {"name": "x", "accounts": [account]}}),
            json!({"accounts": [account]}),
            json!([account]),
        ] {
            let path = file(&dir, "l.json", &text.to_string());
            assert_eq!(load(&path).unwrap(), std::slice::from_ref(&account));
        }
        let path = file(&dir, "l.json", &json!([{"pk": PK1}]).to_string());
        assert!(format!("{:#}", load(&path).unwrap_err()).contains("no pk or no balance"));
        let path = file(&dir, "l.txt", "");
        assert!(load(&path).is_err());
    }

    #[test]
    fn balances_are_mina() {
        for ok in ["0", "1000", "0.5", "1.000000001"] {
            check_balance(ok).unwrap();
        }
        for bad in ["", "1.", ".5", "-1", "1.0000000001", "1,5"] {
            assert!(check_balance(bad).is_err(), "{bad}");
        }
    }
}

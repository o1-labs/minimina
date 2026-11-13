use super::*;
use crate::hardfork::fork_config::EpochHashes;
use serde_json::json;

fn hash(hash: &str, s3: &str) -> LedgerHash {
    LedgerHash {
        hash: hash.into(),
        s3_data_hash: s3.into(),
    }
}

fn reference() -> LegacyReference {
    LegacyReference {
        source: "seed-1".into(),
        fork: ForkPoint {
            state_hash: "3NK7".into(),
            blockchain_length: 14,
            global_slot_since_genesis: 40,
        },
        hashes: LedgerHashes {
            ledger: hash("jwkh", "4649"),
            epoch_data: EpochHashes {
                staking: hash("jxoH", "625b"),
                next: Some(hash("jxoH", "0749")),
            },
        },
    }
}

/// A dumped `daemon.json`, with tarball checksums of its own.
fn dump(state_hash: &str, ledger: &str, next: &str) -> Result<Value, String> {
    Ok(json!({
        "proof": {"fork": {"state_hash": state_hash, "blockchain_length": 14, "global_slot_since_genesis": 40}},
        "ledger": {"hash": ledger, "s3_data_hash": "6e31", "add_genesis_winner": false},
        "epoch_data": {
            "staking": {"seed": "2va9", "hash": "jxoH", "s3_data_hash": "34e8"},
            "next": {"seed": "2vaD", "hash": next, "s3_data_hash": "d13c"}
        }
    }))
}

#[test]
fn dumps_of_the_same_ledgers_match_whatever_their_tarballs() {
    let dumps = BTreeMap::from([
        ("bp-1".to_string(), dump("3NK7", "jwkh", "jxoH")),
        ("bp-2".to_string(), dump("3NK7", "jwkh", "jxoH")),
    ]);
    assert_eq!(reference().mismatches(&dumps), Vec::<String>::new());
}

#[test]
fn another_fork_point_or_ledger_is_a_mismatch() {
    let dumps = BTreeMap::from([
        ("bp-1".to_string(), dump("3NLx", "jwkh", "jxoH")),
        ("bp-2".to_string(), dump("3NK7", "jwOther", "jxNext")),
        ("seed-1".to_string(), Err("unreadable".to_string())),
    ]);
    assert_eq!(
        reference().mismatches(&dumps),
        [
            "bp-1 dumped fork point 3NLx (height 14), the legacy fork config has 3NK7 (height 14)",
            "bp-2 dumped genesis ledger jwOther, the legacy fork config makes jwkh",
            "bp-2 dumped next epoch ledger jxNext, the legacy fork config makes jxoH",
        ]
    );
}

#[test]
fn a_dump_without_ledger_hashes_is_a_mismatch() {
    let dumps = BTreeMap::from([(
        "bp-1".to_string(),
        Ok(
            json!({"proof": {"fork": {"state_hash": "3NK7", "blockchain_length": 14, "global_slot_since_genesis": 40}}}),
        ),
    )]);
    let problems = reference().mismatches(&dumps);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].starts_with("bp-1: the ledger hashes of its dump:"),
        "{problems:?}"
    );
}

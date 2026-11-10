//! Serde for [`Currency`] as a MINA string (`"1.000000000"`), the way the
//! reports show amounts.

use mina_sdk::Currency;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(amount: &Currency, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&amount.mina())
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Currency, D::Error> {
    let mina = String::deserialize(d)?;
    Currency::from_mina(&mina).map_err(serde::de::Error::custom)
}

/// The same for `Option<Currency>`.
pub mod option {
    use mina_sdk::Currency;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(amount: &Option<Currency>, s: S) -> Result<S::Ok, S::Error> {
        match amount {
            Some(amount) => s.serialize_str(&amount.mina()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Currency>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|mina| Currency::from_mina(&mina).map_err(serde::de::Error::custom))
            .transpose()
    }
}

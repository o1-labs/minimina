use serde::{Deserialize, Serialize};

/// A channel of a [`Repository`](super::Repository): one of its apt components (`stable`,
/// `unstable`, `alpha`, ...), which [`ReleaseInfo::channels`](super::ReleaseInfo::channels) lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Channel(String);

impl Default for Channel {
    fn default() -> Self {
        Channel("stable".into())
    }
}

impl std::str::FromStr for Channel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        // it goes into URLs
        if s.is_empty()
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(format!("'{s}' is not a channel name"));
        }
        Ok(Channel(s.to_string()))
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked() {
        assert_eq!("alpha".parse::<Channel>().unwrap().to_string(), "alpha");
        assert_eq!(Channel::default().to_string(), "stable");
        assert!("../x".parse::<Channel>().is_err());
        assert!("".parse::<Channel>().is_err());
    }
}

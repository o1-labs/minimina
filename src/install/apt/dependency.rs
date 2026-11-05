use serde::{Deserialize, Serialize};

/// One dependency of a package, from its `Depends` field: a package, or
/// alternatives of which any one does (`default-mta | mail-transport-agent`).
/// Version constraints and architecture qualifiers are dropped: minimina only
/// asks whether something of that name is installed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", from = "String")]
pub struct Dependency {
    pub alternatives: Vec<String>,
}

impl Dependency {
    /// The dependencies of a `Depends` value
    /// (`libssl3t64, libgmp10 (>= 2:6), a | b:any`).
    pub fn parse_list(field: &str) -> Vec<Self> {
        field
            .split(',')
            .map(Dependency::from)
            .filter(|d| !d.alternatives.is_empty())
            .collect()
    }

    /// The package `apt-get install` should get: the first alternative.
    pub fn first(&self) -> &str {
        &self.alternatives[0]
    }
}

impl From<&str> for Dependency {
    fn from(text: &str) -> Self {
        let alternatives = text
            .split('|')
            .filter_map(|alt| {
                let name = alt.split_whitespace().next()?;
                let name = name.split(':').next().unwrap_or(name);
                (!name.is_empty()).then(|| name.to_string())
            })
            .collect();
        Dependency { alternatives }
    }
}

impl From<String> for Dependency {
    fn from(text: String) -> Self {
        Dependency::from(text.as_str())
    }
}

impl From<Dependency> for String {
    fn from(d: Dependency) -> Self {
        d.to_string()
    }
}

impl std::fmt::Display for Dependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.alternatives.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_architectures_are_dropped() {
        let deps = Dependency::parse_list("libssl3t64, libgmp10 (>= 2:6.3), a:any | b (<< 2) ,");
        let text: Vec<String> = deps.iter().map(ToString::to_string).collect();
        assert_eq!(text, ["libssl3t64", "libgmp10", "a | b"]);
        assert_eq!(deps[2].first(), "a");
        assert!(Dependency::parse_list("").is_empty());
        // stored as text in install.json
        let json = serde_json::to_string(&deps[2]).unwrap();
        assert_eq!(json, r#""a | b""#);
        assert_eq!(serde_json::from_str::<Dependency>(&json).unwrap(), deps[2]);
    }
}

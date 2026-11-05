/// One stanza of a [`ControlFile`](super::ControlFile).
#[derive(Debug, Default)]
pub struct Stanza {
    pub(super) fields: Vec<(String, String)>,
}

impl Stanza {
    /// The value of `name` (field names are case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

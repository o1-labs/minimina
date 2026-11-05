use super::Stanza;

/// A file of `Field: value` stanzas separated by blank lines (deb822), as
/// `Release` and `Packages` are. A line that starts with a space continues
/// the field before it.
#[derive(Debug, Default)]
pub struct ControlFile {
    pub stanzas: Vec<Stanza>,
}

impl ControlFile {
    pub fn parse(text: &str) -> Self {
        let mut stanzas = vec![];
        let mut stanza = Stanza::default();
        for line in text.lines() {
            if line.trim().is_empty() {
                if !stanza.fields.is_empty() {
                    stanzas.push(std::mem::take(&mut stanza));
                }
            } else if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = stanza.fields.last_mut() {
                    value.push('\n');
                    value.push_str(line.trim());
                }
            } else if let Some((key, value)) = line.split_once(':') {
                stanza
                    .fields
                    .push((key.trim().to_string(), value.trim().to_string()));
            }
        }
        if !stanza.fields.is_empty() {
            stanzas.push(stanza);
        }
        ControlFile { stanzas }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stanzas_and_continuation_lines() {
        let file = ControlFile::parse(
            "Codename: noble\nComponents: alpha stable\nMD5Sum:\n abc 1 x\n def 2 y\n\n\nPackage: a\n",
        );
        assert_eq!(file.stanzas.len(), 2);
        assert_eq!(file.stanzas[0].get("components"), Some("alpha stable"));
        assert_eq!(file.stanzas[0].get("MD5Sum"), Some("\nabc 1 x\ndef 2 y"));
        assert_eq!(file.stanzas[1].get("Package"), Some("a"));
    }
}

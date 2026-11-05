use super::{Fetch, MinaError};
use crate::install::apt::{self, Channel, Index, Release, ReleaseInfo, Repository};
use anyhow::{Context as _, Result};

/// Where to install from: a channel of a repository, for a codename and
/// architecture.
#[derive(Debug, Clone)]
pub struct Source {
    pub repository: Repository,
    pub channel: Channel,
    pub codename: String,
    pub arch: String,
}

impl Source {
    pub fn index(&self, fetch: &dyn Fetch) -> Result<Index> {
        let url = self
            .repository
            .index_url(&self.codename, &self.channel, &self.arch);
        match fetch.text(&url) {
            Ok(text) => Ok(Index::parse(&text)),
            Err(e) => match self.unknown_channel(fetch) {
                Some(unknown) => Err(unknown.into()),
                None => Err(e)
                    .with_context(|| format!("no {} packages for {}", self.channel, self.codename)),
            },
        }
    }

    /// When the codename has no such channel: the error that says which
    /// channels it has. `None` when it does, or its `Release` cannot be read.
    fn unknown_channel(&self, fetch: &dyn Fetch) -> Option<MinaError> {
        let release = fetch
            .text(&self.repository.release_url(&self.codename))
            .ok()?;
        let channels = ReleaseInfo::parse(&release).channels;
        let known = channels.is_empty() || channels.contains(&self.channel.to_string());
        (!known).then(|| MinaError::UnknownChannel {
            repository: self.repository.clone(),
            channel: self.channel.clone(),
            codename: self.codename.clone(),
            channels,
        })
    }

    /// The release `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`) names in
    /// `index`.
    pub(super) fn find(&self, fetch: &dyn Fetch, index: &Index, wanted: &str) -> Result<Release> {
        let mut found = index.select(wanted);
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => Err(MinaError::NotAvailable {
                wanted: wanted.to_string(),
                channel: self.channel.clone(),
                codename: self.codename.clone(),
                elsewhere: self.codenames_with(fetch, wanted),
                recent: index.versions().into_iter().rev().take(5).rev().collect(),
            }
            .into()),
            _ => Err(MinaError::Ambiguous {
                wanted: wanted.to_string(),
                what: "builds",
                versions: found.into_iter().map(|r| r.version).collect(),
            }
            .into()),
        }
    }

    /// The other codenames whose index (same channel and architecture) has
    /// `wanted`, so that a version missing for this host says where it is
    /// built, e.g. a release built for jammy only.
    fn codenames_with(&self, fetch: &dyn Fetch, wanted: &str) -> Vec<String> {
        apt::CODENAMES
            .iter()
            .filter(|codename| **codename != self.codename)
            .map(|codename| Source {
                codename: codename.to_string(),
                ..self.clone()
            })
            .filter(|other| {
                other
                    .index(fetch)
                    .is_ok_and(|index| !index.select(wanted).is_empty())
            })
            .map(|other| other.codename)
            .collect()
    }
}

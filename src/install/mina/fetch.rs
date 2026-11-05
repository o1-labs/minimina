use anyhow::{Context as _, Result};
use log::info;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

/// How minimina gets files from the package repositories.
pub trait Fetch {
    fn text(&self, url: &str) -> Result<String>;
    /// Saves `url` as `dest` and returns the SHA-256 (hex) of what it saved.
    fn download(&self, url: &str, dest: &Path) -> Result<String>;
}

/// [`Fetch`] over HTTP.
pub struct Http;

impl Http {
    fn get(url: &str) -> Result<reqwest::blocking::Response> {
        // no overall timeout: mina-generic is about 350 MB
        // the repositories answer 403 to requests without a user agent
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("minimina/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(30))
            .timeout(None)
            .build()?;
        client
            .get(url)
            .send()
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("fetching {url}"))
    }
}

impl Fetch for Http {
    fn text(&self, url: &str) -> Result<String> {
        Self::get(url)?
            .text()
            .with_context(|| format!("reading {url}"))
    }

    fn download(&self, url: &str, dest: &Path) -> Result<String> {
        let mut response = Self::get(url)?;
        let total = response.content_length().filter(|t| *t > 0);
        let mut file =
            std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let (mut done, mut reported) = (0u64, 0u64);
        loop {
            let n = response
                .read(&mut buf)
                .with_context(|| format!("downloading {url}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])
                .with_context(|| format!("writing {}", dest.display()))?;
            done += n as u64;
            if let Some(total) = total {
                let percent = done * 100 / total;
                if percent >= reported + 10 {
                    reported = percent - percent % 10;
                    info!("  {reported}%");
                }
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

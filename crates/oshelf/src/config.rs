//! Local device state: which Pi this device is paired with, its signing key,
//! and the last manifest position it verified (to catch rollbacks).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub device_id: String,
    pub device_name: String,
    pub server_pubkey: String,
}

/// Highest manifest position this device has verified.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Seen {
    pub revision: u64,
    pub hash: String,
}

pub struct Home {
    dir: PathBuf,
}

impl Home {
    /// `$OSHELF_HOME`, else `~/.config/oshelf`.
    pub fn default_dir() -> anyhow::Result<PathBuf> {
        if let Some(d) = std::env::var_os("OSHELF_HOME") {
            return Ok(PathBuf::from(d));
        }
        let home = std::env::var_os("HOME").context("HOME is not set; set OSHELF_HOME")?;
        Ok(Path::new(&home).join(".config/oshelf"))
    }

    pub fn open(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn write_private(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(name);
        let tmp = self.dir.join(format!("{name}.tmp"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        std::io::Write::write_all(&mut opts.open(&tmp)?, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn config(&self) -> anyhow::Result<Config> {
        let path = self.dir.join("config.json");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("not paired yet (no {}); run `oshelf pair`", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn is_paired(&self) -> bool {
        self.dir.join("config.json").exists()
    }

    pub fn save_config(&self, c: &Config) -> anyhow::Result<()> {
        self.write_private("config.json", serde_json::to_string_pretty(c)?.as_bytes())
    }

    pub fn device_key(&self) -> anyhow::Result<SigningKey> {
        let bytes = std::fs::read(self.dir.join("device.key")).context("missing device.key")?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("device.key is corrupt"))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    pub fn save_device_key(&self, k: &SigningKey) -> anyhow::Result<()> {
        self.write_private("device.key", &k.to_bytes())
    }

    pub fn seen(&self) -> anyhow::Result<Seen> {
        match std::fs::read_to_string(self.dir.join("seen.json")) {
            Ok(t) => Ok(serde_json::from_str(&t)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Seen::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Records a newly verified position, refusing to go backwards.
    pub fn advance_seen(&self, revision: u64, hash: &str) -> anyhow::Result<()> {
        let seen = self.seen()?;
        if revision < seen.revision {
            bail!(
                "the Pi is at revision {revision} but this device already verified {}; refusing to go back in time",
                seen.revision
            );
        }
        if revision == seen.revision && !seen.hash.is_empty() && seen.hash != hash {
            bail!("the Pi changed revision {revision} after this device verified it");
        }
        self.write_private(
            "seen.json",
            serde_json::to_string(&Seen {
                revision,
                hash: hash.into(),
            })?
            .as_bytes(),
        )
    }
}

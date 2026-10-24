//! Per-Mac settings that the engine itself acts on: pins, cache size, auto
//! offload and hosts. Saved as JSON next to the cache.

use std::path::{Path, PathBuf};

use oshelf_core::manifest::Id;
use serde::{Deserialize, Serialize};

/// Which files auto offload drops first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OffloadOrder {
    #[default]
    Oldest,
    Biggest,
}

/// One address of the Pi and when to use it. A host with no Wi-Fi names
/// matches anywhere (the tunnel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub ssids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    #[serde(with = "hex_ids")]
    pub pins: Vec<Id>,
    /// Streaming cache cap in bytes (pinned files don't count).
    pub cache_cap: u64,
    pub auto_offload: bool,
    /// Offload when free disk space drops below this percentage.
    pub threshold_pct: u8,
    pub offload_order: OffloadOrder,
    /// First match wins, then falls back down the list.
    pub hosts: Vec<Host>,
    #[serde(skip)]
    path: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            pins: Vec::new(),
            cache_cap: 50_000_000_000,
            auto_offload: true,
            threshold_pct: 15,
            offload_order: OffloadOrder::Oldest,
            hosts: Vec::new(),
            path: PathBuf::new(),
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("settings.json");
        let mut s: Settings = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        s.path = path;
        s
    }

    pub fn save(&self) {
        let Ok(json) = serde_json::to_vec_pretty(self) else {
            return;
        };
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

mod hex_ids {
    use oshelf_core::manifest::Id;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[Id], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Id>, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        Ok(v.iter()
            .filter_map(|h| {
                let mut id = [0u8; 16];
                hex::decode_to_slice(h, &mut id).ok().map(|_| id)
            })
            .collect())
    }
}

//! The local chunk cache: sealed chunks exactly as the Pi stores them, kept on
//! disk by chunk id. They stay encrypted at rest and are checked against their
//! id on every read, so a damaged cache file is just a miss.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oshelf_core::chunk;
use oshelf_core::manifest::Hash;

/// Decrypted chunks kept in memory, so the many small NFS reads that land in
/// one 1 MiB chunk only decrypt it once.
const PLAIN_SLOTS: usize = 48;

#[derive(Clone, Copy)]
struct Entry {
    size: u64,
    used: u64,
}

pub struct Cache {
    dir: PathBuf,
    index: Mutex<Index>,
    plain: Mutex<VecDeque<(Hash, Arc<Vec<u8>>)>>,
}

#[derive(Default)]
struct Index {
    entries: HashMap<Hash, Entry>,
    bytes: u64,
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Cache {
    /// Opens the cache under `dir`, indexing what is already there.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let dir = dir.join("chunks");
        std::fs::create_dir_all(&dir)?;
        let mut index = Index::default();
        for shard in std::fs::read_dir(&dir)?.flatten() {
            let Ok(files) = std::fs::read_dir(shard.path()) else {
                continue;
            };
            for f in files.flatten() {
                let mut id = [0u8; 32];
                let name = f.file_name();
                if hex::decode_to_slice(name.to_string_lossy().as_bytes(), &mut id).is_err() {
                    let _ = std::fs::remove_file(f.path());
                    continue;
                }
                let Ok(meta) = f.metadata() else { continue };
                let used = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                index.bytes += meta.len();
                index.entries.insert(id, Entry { size: meta.len(), used });
            }
        }
        Ok(Self {
            dir,
            index: Mutex::new(index),
            plain: Mutex::new(VecDeque::new()),
        })
    }

    fn path(&self, id: &Hash) -> PathBuf {
        let h = hex::encode(id);
        self.dir.join(&h[..2]).join(h)
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.index.lock().expect("cache index").entries.contains_key(id)
    }

    /// Bytes on disk.
    pub fn bytes(&self) -> u64 {
        self.index.lock().expect("cache index").bytes
    }

    /// Stores a sealed chunk whose id the caller has already checked.
    pub fn put(&self, id: &Hash, stored: &[u8]) -> std::io::Result<()> {
        let path = self.path(id);
        std::fs::create_dir_all(path.parent().expect("sharded path"))?;
        let tmp = path.with_extension("part");
        std::fs::write(&tmp, stored)?;
        std::fs::rename(&tmp, &path)?;
        let mut idx = self.index.lock().expect("cache index");
        if idx
            .entries
            .insert(
                *id,
                Entry {
                    size: stored.len() as u64,
                    used: now_s(),
                },
            )
            .is_none()
        {
            idx.bytes += stored.len() as u64;
        }
        Ok(())
    }

    /// Reads a sealed chunk back, dropping it if it no longer matches its id.
    pub fn get(&self, id: &Hash) -> Option<Vec<u8>> {
        if !self.contains(id) {
            return None;
        }
        match std::fs::read(self.path(id)) {
            Ok(b) if chunk::chunk_id(&b) == *id => {
                if let Some(e) = self.index.lock().expect("cache index").entries.get_mut(id) {
                    e.used = now_s();
                }
                Some(b)
            }
            _ => {
                self.remove(id);
                None
            }
        }
    }

    pub fn remove(&self, id: &Hash) -> u64 {
        let freed = {
            let mut idx = self.index.lock().expect("cache index");
            match idx.entries.remove(id) {
                Some(e) => {
                    idx.bytes -= e.size;
                    e.size
                }
                None => 0,
            }
        };
        let _ = std::fs::remove_file(self.path(id));
        self.plain.lock().expect("plain cache").retain(|(k, _)| k != id);
        freed
    }

    pub fn plain(&self, id: &Hash) -> Option<Arc<Vec<u8>>> {
        let mut p = self.plain.lock().expect("plain cache");
        let pos = p.iter().position(|(k, _)| k == id)?;
        let hit = p.remove(pos).expect("position is valid");
        let data = hit.1.clone();
        p.push_back(hit);
        Some(data)
    }

    pub fn keep_plain(&self, id: Hash, data: Arc<Vec<u8>>) {
        let mut p = self.plain.lock().expect("plain cache");
        p.retain(|(k, _)| *k != id);
        p.push_back((id, data));
        while p.len() > PLAIN_SLOTS {
            p.pop_front();
        }
    }

    /// Drops least recently used chunks outside `keep` until the cache is
    /// at most `cap` bytes. Returns the bytes freed.
    pub fn trim(&self, cap: u64, keep: &HashSet<Hash>) -> u64 {
        let victims: Vec<Hash> = {
            let idx = self.index.lock().expect("cache index");
            if idx.bytes <= cap {
                return 0;
            }
            let mut all: Vec<(&Hash, &Entry)> = idx.entries.iter().filter(|(k, _)| !keep.contains(*k)).collect();
            all.sort_by_key(|(_, e)| e.used);
            let mut over = idx.bytes - cap;
            let mut out = Vec::new();
            for (k, e) in all {
                if over == 0 {
                    break;
                }
                over = over.saturating_sub(e.size);
                out.push(*k);
            }
            out
        };
        victims.iter().map(|v| self.remove(v)).sum()
    }

    /// Last time any of `ids` was read, in unix seconds (0 if none cached).
    pub fn last_used(&self, ids: &[Hash]) -> u64 {
        let idx = self.index.lock().expect("cache index");
        ids.iter()
            .filter_map(|i| idx.entries.get(i))
            .map(|e| e.used)
            .max()
            .unwrap_or(0)
    }

    /// Cached bytes among `ids`.
    pub fn cached_bytes(&self, ids: &[Hash]) -> u64 {
        let idx = self.index.lock().expect("cache index");
        ids.iter().filter_map(|i| idx.entries.get(i)).map(|e| e.size).sum()
    }
}

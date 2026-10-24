//! What the Swift app calls, through UniFFI. Paths here are shelf paths
//! like `Movies/Lisbon`, with `""` for the top of the shelf.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use oshelf::config::Home;
use oshelf::shelf::{self, Unlock};
use oshelf_core::manifest::{Id, Kind, ROOT};
use oshelf_core::vault::Kdf;

use crate::activity::Kind as EventKind;
use crate::engine::Engine;
use crate::mount::{self, Served};
use crate::settings::{Host, OffloadOrder};
use crate::sync::disk_space;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OffshelfError {
    #[error("{message}")]
    Failed { message: String },
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("no such file or folder: {path}")]
    NotFound { path: String },
}

impl From<anyhow::Error> for OffshelfError {
    fn from(e: anyhow::Error) -> Self {
        let message = format!("{e:#}");
        if message.contains("failed authentication") || message.contains("wrong passphrase") {
            return OffshelfError::WrongPassphrase;
        }
        OffshelfError::Failed { message }
    }
}

type R<T> = Result<T, OffshelfError>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct Paired {
    pub device_id: String,
    pub device_name: String,
    pub server_url: String,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum UnlockWith {
    Passphrase { passphrase: String },
    RecoveryWords { words: String },
    /// The master key kept in the Keychain from an earlier unlock.
    MasterKey { key: Vec<u8> },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ServerInfo {
    pub url: String,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HostRule {
    pub name: String,
    pub url: String,
    pub ssids: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Entry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Bytes of it on this Mac (sum over a folder's files).
    pub local_bytes: u64,
    pub mtime_ms: i64,
    pub pinned: bool,
    /// Not uploaded yet.
    pub uploading: bool,
    pub item_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StreamingFile {
    pub name: String,
    pub size: u64,
    pub fetched: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Status {
    pub online: bool,
    pub host_name: String,
    pub host_url: String,
    pub ssid: Option<String>,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
    pub revision: u64,
    pub last_verified_ms: i64,
    pub mounted_at: Option<String>,
    pub streaming: Vec<StreamingFile>,
    pub stream_rate: u64,
    pub uploading_files: u64,
    pub uploading_bytes: u64,
    pub cache_bytes: u64,
    pub mac_free: u64,
    pub mac_total: u64,
    pub fetched_total: u64,
    pub uploaded_total: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ShelfUsage {
    pub stored_bytes: u64,
    pub disk_total: Option<u64>,
    pub disk_free: Option<u64>,
    pub files: u64,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum EventKindFfi {
    Uploaded,
    Pinned,
    Offloaded,
    Switched,
    Synced,
    Conflict,
    Offline,
    Online,
    Error,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ActivityEvent {
    pub kind: EventKindFfi,
    pub title: String,
    pub detail: String,
    pub time_ms: i64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineSettings {
    pub cache_cap: u64,
    pub auto_offload: bool,
    pub threshold_pct: u8,
    pub offload_biggest_first: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub this_device: bool,
}

fn home(dir: &str) -> Home {
    Home::open(PathBuf::from(dir))
}

/// Times the unsigned health check of a server address.
#[uniffi::export]
pub fn probe_server(url: String) -> Option<ServerInfo> {
    crate::sync::probe(&url).map(|d| ServerInfo {
        url: url.trim_end_matches('/').to_string(),
        latency_ms: d.as_millis() as u32,
    })
}

/// Whether this Mac already has a paired device in `home_dir`.
#[uniffi::export]
pub fn is_paired(home_dir: String) -> bool {
    home(&home_dir).is_paired()
}

#[uniffi::export]
pub fn paired_device(home_dir: String) -> Option<Paired> {
    home(&home_dir).config().ok().map(|c| Paired {
        device_id: c.device_id,
        device_name: c.device_name,
        server_url: c.server_url,
    })
}

#[uniffi::export]
pub fn pair(home_dir: String, url: String, code: String, device_name: String) -> R<Paired> {
    let c = shelf::pair(&home(&home_dir), url.trim(), code.trim(), device_name.trim())?;
    Ok(Paired {
        device_id: c.device_id,
        device_name: c.device_name,
        server_url: c.server_url,
    })
}

/// Forgets the pairing on this Mac (the Pi side is revoked separately).
#[uniffi::export]
pub fn unpair(home_dir: String) -> R<()> {
    let h = home(&home_dir);
    for f in ["config.json", "device.key", "seen.json"] {
        let _ = std::fs::remove_file(h.dir().join(f));
    }
    Ok(())
}

/// Whether the paired Pi already holds a shelf (a vault).
#[uniffi::export]
pub fn has_vault(home_dir: String) -> R<bool> {
    let (_, client) = shelf::connect(&home(&home_dir))?;
    Ok(client.get("/v1/vault")?.status != 404)
}

/// Creates the shelf on a new Pi. Returns the 24 recovery words.
#[uniffi::export]
pub fn create_vault(home_dir: String, passphrase: String) -> R<String> {
    let (_, client) = shelf::connect(&home(&home_dir))?;
    Ok(shelf::init(&client, &passphrase, Kdf::new_default())?)
}

#[derive(uniffi::Object)]
pub struct OffshelfEngine {
    engine: Arc<Engine>,
    served: Mutex<Option<Served>>,
}

fn kind(k: EventKind) -> EventKindFfi {
    match k {
        EventKind::Uploaded => EventKindFfi::Uploaded,
        EventKind::Pinned => EventKindFfi::Pinned,
        EventKind::Offloaded => EventKindFfi::Offloaded,
        EventKind::Switched => EventKindFfi::Switched,
        EventKind::Synced => EventKindFfi::Synced,
        EventKind::Conflict => EventKindFfi::Conflict,
        EventKind::Offline => EventKindFfi::Offline,
        EventKind::Online => EventKindFfi::Online,
        EventKind::Error => EventKindFfi::Error,
    }
}

impl OffshelfEngine {
    fn resolve(&self, path: &str) -> R<Id> {
        self.engine.view().tree.resolve(path).ok_or_else(|| OffshelfError::NotFound { path: path.into() })
    }
}

#[uniffi::export]
impl OffshelfEngine {
    /// Unlocks the shelf and loads the verified tree. Slow with a
    /// passphrase (Argon2id, about a second); call it off the main thread.
    #[uniffi::constructor]
    pub fn open(home_dir: String, data_dir: String, unlock: UnlockWith) -> R<Arc<Self>> {
        let key: [u8; 32];
        let u = match &unlock {
            UnlockWith::Passphrase { passphrase } => Unlock::Passphrase(passphrase),
            UnlockWith::RecoveryWords { words } => Unlock::Recovery(words),
            UnlockWith::MasterKey { key: k } => {
                key = k
                    .as_slice()
                    .try_into()
                    .map_err(|_| OffshelfError::Failed { message: "stored key has the wrong length".into() })?;
                Unlock::MasterKey(key)
            }
        };
        let engine = Engine::open(home(&home_dir), PathBuf::from(data_dir), u)?;
        Ok(Arc::new(Self {
            engine,
            served: Mutex::new(None),
        }))
    }

    /// The master key, for the Keychain, so later launches skip the passphrase.
    pub fn master_key(&self) -> Vec<u8> {
        self.engine.master_key().to_vec()
    }

    /// Starts sync, uploads and the NFS server, and mounts at `mountpoint`.
    pub fn start(&self, mountpoint: String) -> R<()> {
        let mut served = self.served.lock().expect("served");
        if served.is_none() {
            self.engine.spawn_sync();
            self.engine.spawn_uploader();
            *served = Some(mount::serve(self.engine.clone())?);
        }
        let s = served.as_mut().expect("set above");
        if s.mountpoint.is_none() {
            s.mount(&PathBuf::from(&mountpoint), "")?;
        }
        Ok(())
    }

    pub fn unmount(&self) -> R<()> {
        if let Some(s) = self.served.lock().expect("served").as_mut() {
            s.unmount(true)?;
        }
        Ok(())
    }

    pub fn status(&self) -> Status {
        let e = &self.engine;
        let link = e.link.lock().expect("link").clone();
        let (streaming, rate) = e.activity.streaming();
        let (up_bytes, up_files) = e.upload_backlog();
        let (free, total) = disk_space(&e.staging).unwrap_or((0, 0));
        Status {
            online: link.online,
            host_name: link.host_name,
            host_url: link.host,
            ssid: link.ssid,
            latency_ms: link.latency_ms,
            error: link.error,
            revision: e.view().revision,
            last_verified_ms: link.last_verified_ms,
            mounted_at: self
                .served
                .lock()
                .expect("served")
                .as_ref()
                .and_then(|s| s.mountpoint.as_ref().map(|p| p.display().to_string())),
            streaming: streaming
                .into_iter()
                .map(|s| StreamingFile {
                    name: s.name,
                    size: s.size,
                    fetched: s.fetched,
                })
                .collect(),
            stream_rate: rate,
            uploading_files: up_files,
            uploading_bytes: up_bytes,
            cache_bytes: e.cache.bytes(),
            mac_free: free,
            mac_total: total,
            fetched_total: e.counters.fetched.load(Ordering::Relaxed),
            uploaded_total: e.counters.uploaded.load(Ordering::Relaxed),
        }
    }

    pub fn events(&self) -> Vec<ActivityEvent> {
        self.engine
            .activity
            .events()
            .into_iter()
            .map(|e| ActivityEvent {
                kind: kind(e.kind),
                title: e.title,
                detail: e.detail,
                time_ms: e.time_ms,
            })
            .collect()
    }

    /// A folder's contents, folders first, then by name.
    pub fn list(&self, path: String) -> R<Vec<Entry>> {
        let dir = self.resolve(&path)?;
        let v = self.engine.view();
        let pending = self.engine.pending_names();
        let mut out: Vec<Entry> = v
            .tree
            .list(&dir)
            .into_iter()
            .filter(|n| !crate::write::local_only(&n.name))
            .map(|n| {
                let files: Vec<_> = if n.kind == Kind::Dir {
                    v.tree.walk(&n.id).into_iter().filter(|c| c.kind == Kind::File).collect()
                } else {
                    vec![n]
                };
                let chunks: Vec<_> = files.iter().flat_map(|f| f.chunks.iter().copied()).collect();
                let p = if path.is_empty() { n.name.clone() } else { format!("{path}/{}", n.name) };
                Entry {
                    path: p,
                    name: n.name.clone(),
                    is_dir: n.kind == Kind::Dir,
                    size: files.iter().map(|f| f.size).sum(),
                    local_bytes: self.engine.cache.cached_bytes(&chunks),
                    mtime_ms: n.mtime_ns / 1_000_000,
                    pinned: self.engine.is_pinned(&n.id),
                    uploading: pending.contains_key(&crate::view::fileid(&n.id)),
                    item_count: if n.kind == Kind::Dir { v.tree.list(&n.id).len() as u64 } else { 0 },
                }
            })
            .collect();
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    /// Names matching `query` anywhere on the shelf (names only).
    pub fn search(&self, query: String, limit: u32) -> Vec<String> {
        let q = query.to_lowercase();
        let v = self.engine.view();
        let mut out: Vec<String> = v
            .tree
            .walk(&ROOT)
            .into_iter()
            .filter(|n| n.name.to_lowercase().contains(&q))
            .filter_map(|n| v.tree.path_of(&n.id))
            .take(limit as usize)
            .collect();
        out.sort();
        out
    }

    pub fn pin(&self, path: String) -> R<()> {
        let id = self.resolve(&path)?;
        Ok(self.engine.pin(id)?)
    }

    pub fn unpin(&self, path: String) -> R<()> {
        let id = self.resolve(&path)?;
        self.engine.unpin(&id);
        Ok(())
    }

    /// Drops this Mac's copy. Returns the bytes freed.
    pub fn offload(&self, path: String) -> R<u64> {
        let id = self.resolve(&path)?;
        let freed = self.engine.offload(&id);
        let name = if path.is_empty() { "everything not pinned".to_string() } else { path.clone() };
        self.engine.activity.push(
            EventKind::Offloaded,
            &format!("Offloaded {name}"),
            &format!("Freed {}", crate::engine::human(freed)),
        );
        Ok(freed)
    }

    /// Offloads everything that isn't pinned.
    pub fn offload_all(&self) -> u64 {
        let keep = self.engine.pinned_chunks();
        let v = self.engine.view();
        Engine::chunks_under(&v.tree, &ROOT)
            .iter()
            .filter(|c| !keep.contains(*c))
            .map(|c| self.engine.cache.remove(c))
            .sum()
    }

    /// Bytes of unpinned files on this Mac (what "Offload everything" frees).
    pub fn offloadable_bytes(&self) -> u64 {
        let keep = self.engine.pinned_chunks();
        let v = self.engine.view();
        let ids: Vec<_> = Engine::chunks_under(&v.tree, &ROOT).into_iter().filter(|c| !keep.contains(c)).collect();
        self.engine.cache.cached_bytes(&ids)
    }

    pub fn settings(&self) -> EngineSettings {
        let s = self.engine.settings.lock().expect("settings");
        EngineSettings {
            cache_cap: s.cache_cap,
            auto_offload: s.auto_offload,
            threshold_pct: s.threshold_pct,
            offload_biggest_first: s.offload_order == OffloadOrder::Biggest,
        }
    }

    pub fn set_settings(&self, settings: EngineSettings) {
        let mut s = self.engine.settings.lock().expect("settings");
        s.cache_cap = settings.cache_cap;
        s.auto_offload = settings.auto_offload;
        s.threshold_pct = settings.threshold_pct.clamp(1, 90);
        s.offload_order = if settings.offload_biggest_first { OffloadOrder::Biggest } else { OffloadOrder::Oldest };
        s.save();
    }

    pub fn hosts(&self) -> Vec<HostRule> {
        let s = self.engine.settings.lock().expect("settings");
        let hosts = if s.hosts.is_empty() {
            vec![Host {
                name: "Home".into(),
                url: self.engine.config.server_url.clone(),
                ssids: vec![],
            }]
        } else {
            s.hosts.clone()
        };
        hosts
            .into_iter()
            .map(|h| HostRule {
                name: h.name,
                url: h.url,
                ssids: h.ssids,
            })
            .collect()
    }

    pub fn set_hosts(&self, hosts: Vec<HostRule>) {
        self.engine.set_hosts(
            hosts
                .into_iter()
                .map(|h| Host {
                    name: h.name,
                    url: h.url.trim().trim_end_matches('/').to_string(),
                    ssids: h.ssids,
                })
                .collect(),
        );
        self.engine.select_host();
    }

    /// The Wi-Fi network the Mac is on, or `None` off Wi-Fi.
    pub fn set_network(&self, ssid: Option<String>) {
        self.engine.set_network(ssid);
    }

    /// Re-picks the host and re-verifies the tree (after wake, or "Try again").
    pub fn reconnect(&self) {
        self.engine.select_host();
        self.engine.health_check();
    }

    pub fn usage(&self) -> R<ShelfUsage> {
        let u = self.engine.client.get("/v1/usage")?.ok()?.json()?;
        let v = self.engine.view();
        Ok(ShelfUsage {
            stored_bytes: u["stored_bytes"].as_u64().unwrap_or(0),
            disk_total: u["disk_total"].as_u64(),
            disk_free: u["disk_free"].as_u64(),
            files: v.tree.walk(&ROOT).iter().filter(|n| n.kind == Kind::File).count() as u64,
        })
    }

    pub fn devices(&self) -> R<Vec<Device>> {
        let d = self.engine.client.get("/v1/devices")?.ok()?.json()?;
        Ok(d.as_array()
            .map(|a| {
                a.iter()
                    .map(|dev| {
                        let id = dev["id"].as_str().unwrap_or_default().to_string();
                        Device {
                            this_device: id == self.engine.config.device_id,
                            name: dev["name"].as_str().unwrap_or_default().to_string(),
                            id,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn change_passphrase(&self, new_passphrase: String) -> R<()> {
        let key = self.engine.master_key();
        Ok(shelf::change_passphrase(&self.engine.client, Unlock::MasterKey(key), &new_passphrase)?)
    }

    /// Copies a local file or folder onto the shelf under `to` (a shelf
    /// folder). Runs in the background; progress shows in the activity list.
    pub fn upload_local(&self, local_path: String, to: String) {
        let engine = self.engine.clone();
        std::thread::spawn(move || {
            let local = PathBuf::from(&local_path);
            let name = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            // A second session of the same shelf, so a long upload doesn't
            // hold up the mount's own commits; both rebase on the Pi's head
            // and the mount learns the new files from the event stream.
            let key = engine.master_key();
            let r = shelf::Shelf::open(&engine.home, &engine.config, &engine.client, Unlock::MasterKey(key))
                .and_then(|mut s| s.put(&local, &to));
            let _ = engine.refresh();
            match r {
                Ok(files) => {
                    let bytes: u64 = files.iter().map(|f| f.size).sum();
                    engine.activity.push(
                        EventKind::Uploaded,
                        &format!("Uploaded {} files", files.len()),
                        &format!("From {name} · {}", crate::engine::human(bytes)),
                    )
                }
                Err(e) => engine.activity.push(EventKind::Error, &format!("Upload of {name} stopped"), &format!("{e:#}")),
            }
        });
    }
}

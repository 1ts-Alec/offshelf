//! oshelfd: the Offshelf server. It stores sealed chunks and the sealed
//! manifest log, and never holds a key that can open either.

pub mod api;
pub mod auth;
pub mod config;
pub mod control;
pub mod db;
pub mod error;
pub mod storage;
pub mod store;
pub mod web;

use std::path::Path;
use std::sync::Arc;

use tokio::sync::broadcast;

pub use api::router;

/// Event pushed to connected clients whenever the manifest advances.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RevisionEvent {
    pub revision: u64,
    pub hash: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: db::Db,
    pub store: Arc<store::ChunkStore>,
    pub events: broadcast::Sender<RevisionEvent>,
    /// The Pi's identity, pinned by devices at pairing.
    pub server_key: Arc<ed25519_dalek::SigningKey>,
    pub replays: Arc<auth::ReplayCache>,
    /// The web app served at `/`, if any.
    pub web: Option<Arc<web::WebApp>>,
    pub presence: Arc<Presence>,
    pub started_at: std::time::Instant,
    /// The server's own folder (`--data-dir`), holding `location`.
    pub home: std::path::PathBuf,
    /// Where the shelf lives now: `home`, or a folder on a chosen drive.
    pub data_dir: std::path::PathBuf,
    /// Set while the shelf is being copied to another drive.
    pub moving: storage::MoveState,
}

/// When each device last made a request, and which hold the event stream
/// open, for "online now" in the admin.
#[derive(Default)]
pub struct Presence {
    seen: std::sync::Mutex<std::collections::HashMap<db::Id16, i64>>,
    streams: std::sync::Mutex<std::collections::HashMap<db::Id16, usize>>,
}

/// A device counts as online this long after its last request.
pub const ONLINE_WINDOW_MS: i64 = 120_000;

impl Presence {
    pub fn touch(&self, device: db::Id16, now_ms: i64) {
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(device, now_ms);
    }

    pub fn last_seen(&self, device: &db::Id16) -> Option<i64> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).get(device).copied()
    }

    pub fn streaming(&self, device: &db::Id16) -> bool {
        self.streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(device)
            .is_some_and(|n| *n > 0)
    }

    /// Marks an open event stream until the guard drops.
    pub fn stream(self: &Arc<Self>, device: db::Id16) -> StreamGuard {
        *self
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(device)
            .or_default() += 1;
        StreamGuard {
            presence: self.clone(),
            device,
        }
    }
}

pub struct StreamGuard {
    presence: Arc<Presence>,
    device: db::Id16,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut s = self.presence.streams.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = s.get_mut(&self.device) {
            *n = n.saturating_sub(1);
        }
    }
}

impl AppState {
    /// Opens the shelf wherever `home` says it lives (see `storage`).
    pub fn open_home(home: &Path) -> anyhow::Result<Self> {
        let data_dir = storage::resolve(home);
        let mut s = Self::open(&data_dir)?;
        s.home = home.to_path_buf();
        Ok(s)
    }

    /// Opens (or creates) the database and chunk store under `data_dir`.
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let db = db::Db::open(&data_dir.join("oshelf.db"))?;
        let store = Arc::new(store::ChunkStore::open(data_dir.join("chunks"))?);
        let (events, _) = broadcast::channel(256);
        let server_key = Arc::new(auth::load_or_create_server_key(data_dir)?);
        Ok(Self {
            db,
            store,
            events,
            server_key,
            replays: Arc::default(),
            web: web::WebApp::default_app().map(Arc::new),
            presence: Arc::default(),
            started_at: std::time::Instant::now(),
            home: data_dir.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
            moving: Arc::default(),
        })
    }
}

/// Deletes chunks no object references, plus orphans older than
/// `orphan_grace_secs`. Returns how many chunks were removed.
pub async fn gc(state: &AppState, orphan_grace_secs: i64) -> anyhow::Result<usize> {
    let ids = state
        .db
        .call(move |db| db.unreferenced_chunks(orphan_grace_secs))
        .await?;
    for id in &ids {
        state.store.delete(id).await?;
        let id = *id;
        state.db.call(move |db| db.delete_chunk(&id)).await?;
    }
    Ok(ids.len())
}

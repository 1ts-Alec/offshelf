//! oshelfd: the Offshelf server. It stores sealed chunks and the sealed
//! manifest log, and never holds a key that can open either.

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
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
}

impl AppState {
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

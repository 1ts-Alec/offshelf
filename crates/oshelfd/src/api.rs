//! HTTP API v1. Request signing (per device Ed25519 keys) lands with the
//! pairing work; until then oshelfd must only run on a trusted LAN.

use std::convert::Infallible;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use futures::{stream, Stream, StreamExt};
use oshelf_core::chunk::OVERHEAD;
use oshelf_core::CHUNK_SIZE;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;

use crate::db::{CommitResult, Id16, Id32, ObjectResult};
use crate::error::{ApiError, ApiResult};
use crate::{AppState, RevisionEvent};

/// Content type of framed binary responses: repeated `u32le len || bytes`
/// (chunks) or `u64le revision || u32le len || bytes` (log entries).
pub const FRAMED: &str = "application/x-oshelf-frames";
/// Most chunks one ranged read may ask for (64 MiB of plaintext).
pub const MAX_CHUNKS_PER_READ: u64 = 64;
const MAX_LOG_ENTRY: usize = 16 << 20;
const MAX_VAULT: usize = 64 << 10;
const MAX_LOG_PAGE: u32 = 1000;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/usage", get(usage))
        .route(
            "/v1/chunks/{id}",
            put(put_chunk)
                .get(get_chunk)
                .layer(DefaultBodyLimit::max(CHUNK_SIZE as usize + OVERHEAD)),
        )
        .route("/v1/objects", axum::routing::post(create_object))
        .route("/v1/objects/{id}", axum::routing::delete(delete_object))
        .route("/v1/objects/{id}/chunks", get(read_object_chunks))
        .route("/v1/manifest/head", get(manifest_head))
        .route(
            "/v1/manifest/log",
            get(manifest_log)
                .post(append_log)
                .layer(DefaultBodyLimit::max(MAX_LOG_ENTRY)),
        )
        .route(
            "/v1/vault",
            get(get_vault).put(put_vault).layer(DefaultBodyLimit::max(MAX_VAULT)),
        )
        .route("/v1/events", get(events))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

fn parse_hex<const N: usize>(s: &str, what: &str) -> ApiResult<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| ApiError::bad(format!("{what} must be {} hex characters", N * 2)))?;
    Ok(out)
}

fn if_match(headers: &HeaderMap) -> ApiResult<Option<String>> {
    headers
        .get(header::IF_MATCH)
        .map(|v| {
            v.to_str()
                .map(|s| s.trim().trim_matches('"').to_owned())
                .map_err(|_| ApiError::bad("bad If-Match"))
        })
        .transpose()
}

async fn usage(State(s): State<AppState>) -> ApiResult<Json<crate::db::Usage>> {
    Ok(Json(s.db.call(|db| db.usage()).await?))
}

// ---- chunks ----------------------------------------------------------------

async fn put_chunk(State(s): State<AppState>, Path(id): Path<String>, body: Bytes) -> ApiResult<StatusCode> {
    let id: Id32 = parse_hex(&id, "chunk id")?;
    if body.len() > CHUNK_SIZE as usize + OVERHEAD {
        return Err(ApiError::TooLarge);
    }
    oshelf_core::parse_header(&body).map_err(|e| ApiError::bad(format!("bad chunk: {e}")))?;
    if oshelf_core::chunk_id(&body) != id {
        return Err(ApiError::bad("chunk id does not match BLAKE3 of the body"));
    }
    let size = body.len() as u64;
    s.store.put(&id, body).await?;
    let created = s.db.call(move |db| db.insert_chunk(&id, size)).await?;
    Ok(if created { StatusCode::CREATED } else { StatusCode::OK })
}

async fn get_chunk(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let id: Id32 = parse_hex(&id, "chunk id")?;
    let bytes = s.store.get(&id).await?.ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

// ---- objects ---------------------------------------------------------------

#[derive(Deserialize)]
struct NewObject {
    id: String,
    chunks: Vec<String>,
}

async fn create_object(State(s): State<AppState>, Json(req): Json<NewObject>) -> ApiResult<StatusCode> {
    let object_id: Id16 = parse_hex(&req.id, "object id")?;
    let chunks = req
        .chunks
        .iter()
        .map(|c| parse_hex::<32>(c, "chunk id"))
        .collect::<ApiResult<Vec<_>>>()?;
    match s.db.call(move |db| db.insert_object(&object_id, &chunks)).await? {
        ObjectResult::Created => Ok(StatusCode::CREATED),
        ObjectResult::AlreadyExists => Err(ApiError::Conflict {
            message: "object exists".into(),
            detail: json!({}),
        }),
        ObjectResult::MissingChunks(m) => Err(ApiError::Conflict {
            message: "chunks not uploaded".into(),
            detail: json!({ "missing": m.iter().map(hex::encode).collect::<Vec<_>>() }),
        }),
    }
}

async fn delete_object(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let object_id: Id16 = parse_hex(&id, "object id")?;
    if s.db.call(move |db| db.delete_object(&object_id)).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

#[derive(Deserialize)]
struct ChunkRange {
    first: u64,
    last: u64,
}

/// Ranged read: the client maps a byte range to chunk indexes with
/// `oshelf_core::chunk_span` and asks for exactly those chunks, which come
/// back as one framed stream in index order.
async fn read_object_chunks(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(r): Query<ChunkRange>,
) -> ApiResult<Response> {
    let object_id: Id16 = parse_hex(&id, "object id")?;
    if r.first > r.last {
        return Err(ApiError::bad("first must be <= last"));
    }
    if r.last - r.first >= MAX_CHUNKS_PER_READ {
        return Err(ApiError::bad(format!("at most {MAX_CHUNKS_PER_READ} chunks per read")));
    }
    let (count, ids) =
        s.db.call(move |db| {
            let count = db.object_chunk_count(&object_id)?;
            let ids = if count.is_some() {
                db.object_chunks(&object_id, r.first, r.last)?
            } else {
                vec![]
            };
            Ok((count, ids))
        })
        .await?;
    let count = count.ok_or(ApiError::NotFound)?;
    if r.last >= count {
        return Err(ApiError::bad(format!("object has {count} chunks")));
    }

    let store = s.store.clone();
    let body = stream::iter(ids).then(move |id| {
        let store = store.clone();
        async move {
            let bytes = store
                .get(&id)
                .await?
                .ok_or_else(|| std::io::Error::other(format!("chunk {} missing from store", hex::encode(id))))?;
            let mut frame = Vec::with_capacity(4 + bytes.len());
            frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            frame.extend_from_slice(&bytes);
            Ok::<_, std::io::Error>(Bytes::from(frame))
        }
    });
    Ok((
        [
            (header::CONTENT_TYPE, FRAMED.to_string()),
            (
                header::HeaderName::from_static("x-oshelf-chunks"),
                (r.last - r.first + 1).to_string(),
            ),
        ],
        Body::from_stream(body),
    )
        .into_response())
}

// ---- manifest --------------------------------------------------------------

#[derive(Serialize)]
struct Head {
    revision: u64,
    hash: String,
}

async fn manifest_head(State(s): State<AppState>) -> ApiResult<Json<Head>> {
    let (revision, hash) = s.db.call(|db| db.head()).await?;
    Ok(Json(Head {
        revision,
        hash: hex::encode(hash),
    }))
}

#[derive(Deserialize)]
struct Since {
    since: u64,
    limit: Option<u32>,
}

async fn manifest_log(State(s): State<AppState>, Query(q): Query<Since>) -> ApiResult<Response> {
    let limit = q.limit.unwrap_or(MAX_LOG_PAGE).clamp(1, MAX_LOG_PAGE);
    let entries = s.db.call(move |db| db.log_since(q.since, limit)).await?;
    let mut out = Vec::new();
    for (rev, blob) in &entries {
        out.extend_from_slice(&rev.to_le_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        out.extend_from_slice(blob);
    }
    Ok(([(header::CONTENT_TYPE, FRAMED)], out).into_response())
}

/// Appends one sealed log entry. `If-Match` must carry the head revision the
/// client built on; a stale client gets 409 with the current head.
async fn append_log(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> ApiResult<Response> {
    let expected: u64 = if_match(&headers)?
        .ok_or_else(|| ApiError::bad("If-Match with the head revision is required"))?
        .parse()
        .map_err(|_| ApiError::bad("If-Match must be a revision number"))?;
    if body.len() < 4 || &body[0..4] != b"OSL1" {
        return Err(ApiError::bad("log entry must start with OSL1"));
    }
    match s.db.call(move |db| db.append_log(expected, &body)).await? {
        CommitResult::Committed { revision, hash } => {
            let hash = hex::encode(hash);
            let _ = s.events.send(RevisionEvent {
                revision,
                hash: hash.clone(),
            });
            Ok((StatusCode::CREATED, Json(Head { revision, hash })).into_response())
        }
        CommitResult::Stale { revision, hash } => Err(ApiError::Conflict {
            message: "stale head".into(),
            detail: json!({ "revision": revision, "hash": hex::encode(hash) }),
        }),
    }
}

// ---- vault header ----------------------------------------------------------

async fn get_vault(State(s): State<AppState>) -> ApiResult<Response> {
    let (hash, blob) = s.db.call(|db| db.vault()).await?.ok_or(ApiError::NotFound)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::ETAG, format!("\"{}\"", hex::encode(hash))),
        ],
        blob,
    )
        .into_response())
}

/// Creates the vault header (no If-Match) or replaces it after a passphrase
/// change (If-Match: hash of the current header).
async fn put_vault(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> ApiResult<Response> {
    let expected = if_match(&headers)?
        .map(|h| parse_hex::<32>(&h, "If-Match"))
        .transpose()?;
    if body.len() < 4 || &body[0..4] != b"OSVH" {
        return Err(ApiError::bad("vault header must start with OSVH"));
    }
    match s.db.call(move |db| db.put_vault(expected, &body)).await? {
        Some(hash) => Ok((StatusCode::OK, [(header::ETAG, format!("\"{}\"", hex::encode(hash)))]).into_response()),
        None => Err(ApiError::Conflict {
            message: "vault header changed or already exists".into(),
            detail: json!({}),
        }),
    }
}

// ---- events ----------------------------------------------------------------

/// Server-sent events: the current head on connect, then one `revision`
/// event per committed log entry. A client that sees a gap fetches the log.
async fn events(State(s): State<AppState>) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let rx = s.events.subscribe();
    let (revision, hash) = s.db.call(|db| db.head()).await?;
    let first = RevisionEvent {
        revision,
        hash: hex::encode(hash),
    };
    let live = BroadcastStream::new(rx).filter_map(|e| async move { e.ok() });
    let stream = stream::once(async { first }).chain(live).map(|ev| {
        Ok(Event::default()
            .event("revision")
            .json_data(ev)
            .expect("revision event serializes"))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

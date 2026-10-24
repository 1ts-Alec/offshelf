//! Device pairing and signed request checks (spec: "Device auth and pairing").

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oshelf_core::auth::{self, MAX_SKEW_MS, SCHEME};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::db::{self, Id16};
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Paths a device can call before it has a key.
const PUBLIC_PATHS: &[&str] = &["/v1/health", "/v1/pair"];
/// Largest body the signature check buffers; matches the biggest route limit.
const MAX_SIGNED_BODY: usize = 17 << 20;
pub const PAIRING_TTL_SECS: i64 = 600;
pub const PAIRING_ATTEMPTS: i64 = 5;
/// Crockford base32, without I, L, O, U, so codes read aloud cleanly.
const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Signatures seen inside the skew window, to reject replays.
#[derive(Default)]
pub struct ReplayCache(Mutex<HashMap<[u8; 64], i64>>);

impl ReplayCache {
    /// Records `sig`; false if it was already seen.
    fn insert(&self, sig: [u8; 64], now_ms: i64) -> bool {
        let mut seen = self.0.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, ts| now_ms - *ts <= 2 * MAX_SKEW_MS);
        seen.insert(sig, now_ms).is_none()
    }
}

/// Loads the server's Ed25519 identity from `server.key`, creating it on
/// first start (owner read/write only).
pub fn load_or_create_server_key(data_dir: &Path) -> anyhow::Result<SigningKey> {
    let path = data_dir.join("server.key");
    if let Ok(bytes) = std::fs::read(&path) {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a 32 byte key", path.display()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    std::io::Write::write_all(&mut opts.open(&path)?, &seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// A new random code like `7KQ2-M9XD`.
pub fn new_pairing_code() -> String {
    let mut raw = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter()
        .map(|b| CODE_ALPHABET[(*b as usize) % CODE_ALPHABET.len()] as char)
        .collect()
}

pub fn display_code(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct ParsedAuth {
    device: Id16,
    ts: i64,
    sig: [u8; 64],
}

fn parse_authorization(value: &str) -> Option<ParsedAuth> {
    let rest = value.strip_prefix(SCHEME)?.trim_start();
    let (mut device, mut ts, mut sig) = (None, None, None);
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        match k {
            "device" => {
                let mut id = [0u8; 16];
                hex::decode_to_slice(v, &mut id).ok()?;
                device = Some(id);
            }
            "ts" => ts = v.parse().ok(),
            "sig" => {
                let bytes = base64::engine::general_purpose::STANDARD.decode(v).ok()?;
                sig = bytes.try_into().ok();
            }
            _ => {}
        }
    }
    Some(ParsedAuth {
        device: device?,
        ts: ts?,
        sig: sig?,
    })
}

/// Middleware: every route except [`PUBLIC_PATHS`] needs a valid device
/// signature over method, path and query, timestamp and body.
pub async fn require_signature(State(s): State<AppState>, req: Request, next: Next) -> ApiResult<Response> {
    // Outside /v1 is the web app's static files.
    if PUBLIC_PATHS.contains(&req.uri().path()) || !req.uri().path().starts_with("/v1/") {
        return Ok(next.run(req).await);
    }
    let unauthorized = |m: &str| ApiError::Unauthorized(m.to_string());
    let parsed = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_authorization)
        .ok_or_else(|| unauthorized("missing or malformed Oshelf authorization"))?;
    let now = now_ms();
    if (now - parsed.ts).abs() > MAX_SKEW_MS {
        return Err(unauthorized("request timestamp too far from server time"));
    }
    let device = parsed.device;
    let pubkey =
        s.db.call(move |db| db.device_pubkey(&device))
            .await?
            .ok_or_else(|| unauthorized("unknown or revoked device"))?;
    let key = VerifyingKey::from_bytes(&pubkey).map_err(|_| unauthorized("bad device key"))?;

    let (parts, body) = req.into_parts();
    let body = to_bytes(body, MAX_SIGNED_BODY).await.map_err(|_| ApiError::TooLarge)?;
    let path_and_query = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if !auth::verify_request(
        &key,
        parts.method.as_str(),
        path_and_query,
        parsed.ts,
        &body,
        &parsed.sig,
    ) {
        return Err(unauthorized("bad signature"));
    }
    if !s.replays.insert(parsed.sig, now) {
        return Err(unauthorized("replayed request"));
    }
    s.presence.touch(device, now);
    let mut req = Request::from_parts(parts, Body::from(body));
    req.extensions_mut().insert(DeviceId(device));
    let res = next.run(req).await;
    sign_response(&s, &parsed.sig, res).await
}

/// Header carrying the server's signature over a response.
pub const RESPONSE_SIG_HEADER: &str = "x-oshelf-sig";

/// Signs buffered responses. Streams are left unsigned: chunk frames are
/// checked against their ids from the manifest, and revision events are
/// checked against the hash chain, so neither relies on this signature.
async fn sign_response(s: &AppState, request_sig: &[u8; 64], res: Response) -> ApiResult<Response> {
    let streaming = res.headers().contains_key(crate::api::CHUNKS_HEADER)
        || res
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
    if streaming {
        return Ok(res);
    }
    let (mut parts, body) = res.into_parts();
    let body = to_bytes(body, usize::MAX)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("buffering response: {e}")))?;
    let sig = auth::sign_response(&s.server_key, request_sig, parts.status.as_u16(), &body);
    parts.headers.insert(
        RESPONSE_SIG_HEADER,
        base64::engine::general_purpose::STANDARD
            .encode(sig)
            .parse()
            .expect("base64 is a valid header value"),
    );
    Ok(Response::from_parts(parts, Body::from(body)))
}

/// The authenticated device, available to handlers as an extension.
#[derive(Clone, Copy, Debug)]
pub struct DeviceId(pub Id16);

#[derive(Deserialize)]
pub struct PairRequest {
    name: String,
    pubkey: String,
    client_nonce: String,
    mac: String,
}

#[derive(Serialize)]
pub struct PairResponse {
    device_id: String,
    server_pubkey: String,
    mac: String,
}

fn hex_arr<const N: usize>(s: &str, what: &str) -> ApiResult<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| ApiError::bad(format!("{what} must be {} hex characters", N * 2)))?;
    Ok(out)
}

/// `POST /v1/pair`: trade a pairing code (proven by MAC, never sent) for a
/// device id, and get the server's key back with a MAC over it.
pub async fn pair(State(s): State<AppState>, Json(req): Json<PairRequest>) -> ApiResult<Json<PairResponse>> {
    let pubkey: [u8; 32] = hex_arr(&req.pubkey, "pubkey")?;
    let nonce: [u8; 16] = hex_arr(&req.client_nonce, "client_nonce")?;
    let mac: [u8; 32] = hex_arr(&req.mac, "mac")?;
    VerifyingKey::from_bytes(&pubkey).map_err(|_| ApiError::bad("pubkey is not a valid Ed25519 key"))?;
    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad("name must be 1 to 64 bytes"));
    }

    let codes = s.db.call(|db| db.live_pairing_codes()).await?;
    let Some(code) = codes
        .into_iter()
        .find(|c| auth::macs_equal(&auth::pairing_client_mac(c, &pubkey, &nonce), &mac))
    else {
        s.db.call(|db| db.record_failed_pairing()).await?;
        return Err(ApiError::Unauthorized("no matching pairing code".into()));
    };

    let mut device_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut device_id);
    let c = code.clone();
    let paired =
        s.db.call(move |db| db.pair_device(&c, &device_id, &name, &pubkey))
            .await
            .map_err(|e| match e.downcast_ref::<rusqlite::Error>() {
                Some(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    ApiError::Conflict {
                        message: "device key already paired".into(),
                        detail: serde_json::json!({}),
                    }
                }
                _ => ApiError::Internal(e),
            })?;
    if !paired {
        return Err(ApiError::Unauthorized("pairing code expired".into()));
    }
    let server_pubkey = s.server_key.verifying_key().to_bytes();
    Ok(Json(PairResponse {
        device_id: hex::encode(device_id),
        server_pubkey: hex::encode(server_pubkey),
        mac: hex::encode(auth::pairing_server_mac(&code, &server_pubkey, &device_id, &nonce)),
    }))
}

#[derive(Serialize)]
pub struct NewCode {
    code: String,
    expires_at: i64,
}

/// `POST /v1/pairing-codes`: a paired device (the web admin) makes a code.
pub async fn create_pairing_code(State(s): State<AppState>) -> ApiResult<Json<NewCode>> {
    let code = new_pairing_code();
    let c = code.clone();
    let expires_at =
        s.db.call(move |db| db.add_pairing_code(&c, PAIRING_TTL_SECS, PAIRING_ATTEMPTS))
            .await?;
    Ok(Json(NewCode {
        code: display_code(&code),
        expires_at,
    }))
}

#[derive(Serialize)]
pub struct DeviceView {
    #[serde(flatten)]
    device: db::Device,
    last_seen_ms: Option<i64>,
    online: bool,
    /// The device asking.
    current: bool,
}

pub async fn list_devices(
    State(s): State<AppState>,
    axum::Extension(DeviceId(me)): axum::Extension<DeviceId>,
) -> ApiResult<Json<Vec<DeviceView>>> {
    let now = now_ms();
    let devices = s.db.call(|db| db.devices()).await?;
    Ok(Json(
        devices
            .into_iter()
            .map(|d| {
                let last_seen_ms = s.presence.last_seen(&d.id);
                DeviceView {
                    online: s.presence.streaming(&d.id)
                        || last_seen_ms.is_some_and(|t| now - t < crate::ONLINE_WINDOW_MS),
                    current: d.id == me,
                    last_seen_ms,
                    device: d,
                }
            })
            .collect(),
    ))
}

/// `DELETE /v1/pairing-codes/{code}`: cancel a code before it's used.
pub async fn cancel_pairing_code(
    State(s): State<AppState>,
    axum::extract::Path(code): axum::extract::Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    let code = auth::normalize_code(&code);
    if s.db.call(move |db| db.delete_pairing_code(&code)).await? {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

pub async fn revoke_device(
    State(s): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    let id: Id16 = hex_arr(&id, "device id")?;
    if s.db.call(move |db| db.revoke_device(&id)).await? {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_use_the_readable_alphabet() {
        for _ in 0..100 {
            let c = new_pairing_code();
            assert_eq!(c.len(), 8);
            assert!(c.bytes().all(|b| CODE_ALPHABET.contains(&b)));
            assert_eq!(auth::normalize_code(&display_code(&c)), c);
        }
    }

    #[test]
    fn replay_cache() {
        let cache = ReplayCache::default();
        assert!(cache.insert([1; 64], 1000));
        assert!(!cache.insert([1; 64], 2000));
        assert!(
            cache.insert([1; 64], 1000 + 3 * MAX_SKEW_MS),
            "forgotten after the window"
        );
    }

    #[test]
    fn parses_header() {
        let sig = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
        let h = format!("Oshelf device={}, ts=123, sig={sig}", hex::encode([4u8; 16]));
        let p = parse_authorization(&h).unwrap();
        assert_eq!((p.device, p.ts, p.sig), ([4; 16], 123, [9; 64]));
        assert!(parse_authorization("Bearer abc").is_none());
        assert!(parse_authorization("Oshelf device=zz, ts=1, sig=").is_none());
    }
}

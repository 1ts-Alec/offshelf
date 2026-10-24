//! End to end: a client seals a file, uploads it, and reads a byte range back
//! through the API, with the server never seeing a key.

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use base64::Engine;
use ed25519_dalek::SigningKey;
use oshelf_core::auth;
use oshelf_core::{chunk_id, chunk_span, open_chunk, seal_chunk, CHUNK_SIZE};
use oshelfd::{router, AppState};
use tower::ServiceExt;

struct Server {
    app: Router,
    state: AppState,
    device: [u8; 16],
    key: SigningKey,
    _dir: tempfile::TempDir,
}

const CODE: &str = "7KQ2M9XD";

async fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::open(dir.path()).unwrap();
    let app = router(state.clone());
    let key = SigningKey::from_bytes(&[11; 32]);
    let mut srv = Server {
        app,
        state,
        device: [0; 16],
        key,
        _dir: dir,
    };
    srv.state.db.call(|db| db.add_pairing_code(CODE, 600, 5)).await.unwrap();
    let pubkey = srv.key.verifying_key().to_bytes();
    let (s, body) = srv.pair("7kq2-m9xd", &pubkey).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    hex::decode_to_slice(body["device_id"].as_str().unwrap(), &mut srv.device).unwrap();
    srv
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

impl Server {
    async fn pair(&self, code: &str, pubkey: &[u8; 32]) -> (StatusCode, serde_json::Value) {
        let nonce = [5u8; 16];
        let req = serde_json::json!({
            "name": "Test Mac",
            "pubkey": hex::encode(pubkey),
            "client_nonce": hex::encode(nonce),
            "mac": hex::encode(auth::pairing_client_mac(code, pubkey, &nonce)),
        });
        let res = self
            .raw(
                Request::post("/v1/pair")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await;
        (res.0, serde_json::from_slice(&res.1).unwrap_or_default())
    }

    async fn raw(&self, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (status, to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    fn signed(&self, method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request<Body> {
        let ts = now_ms();
        let sig = auth::sign_request(&self.key, method.as_str(), uri, ts, &body);
        let authz = format!(
            "Oshelf device={}, ts={ts}, sig={}",
            hex::encode(self.device),
            base64::engine::general_purpose::STANDARD.encode(sig)
        );
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, authz);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.body(Body::from(body)).unwrap()
    }

    async fn send(&self, method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        self.raw(self.signed(method, uri, headers, body)).await
    }

    async fn json(&self, method: Method, uri: &str, value: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let (s, b) = self
            .send(
                method,
                uri,
                &[(header::CONTENT_TYPE.as_str(), "application/json")],
                value.to_string().into_bytes(),
            )
            .await;
        (s, serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null))
    }
}

fn frames(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let len = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
        out.push(rest[4..4 + len].to_vec());
        rest = &rest[4 + len..];
    }
    out
}

#[tokio::test]
async fn upload_then_ranged_read() {
    let srv = server().await;
    let key = [42u8; 32];
    let file_id = [7u8; 16];
    let object_id = hex::encode([1u8; 16]);
    let cs = CHUNK_SIZE as usize;
    let plaintext: Vec<u8> = (0..cs * 2 + cs / 2).map(|i| (i % 251) as u8).collect();

    let mut ids = Vec::new();
    for (i, part) in plaintext.chunks(cs).enumerate() {
        let stored = seal_chunk(&key, &file_id, i as u64, part);
        let id = hex::encode(chunk_id(&stored));
        let (s, _) = srv
            .send(Method::PUT, &format!("/v1/chunks/{id}"), &[], stored.clone())
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, _) = srv.send(Method::PUT, &format!("/v1/chunks/{id}"), &[], stored).await;
        assert_eq!(s, StatusCode::OK, "re-upload is idempotent");
        ids.push(id);
    }

    let (s, _) = srv
        .json(
            Method::POST,
            "/v1/objects",
            serde_json::json!({ "id": object_id, "chunks": ids }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);

    // Read bytes straddling the chunk 0/1 and 1/2 boundaries.
    let (start, end) = (cs as u64 - 10, 2 * cs as u64 + 10);
    let span = chunk_span(start, end, plaintext.len() as u64, CHUNK_SIZE).unwrap();
    let (s, body) = srv
        .send(
            Method::GET,
            &format!("/v1/objects/{object_id}/chunks?first={}&last={}", span.first, span.last),
            &[],
            vec![],
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let mut out = Vec::new();
    for (i, stored) in frames(&body).into_iter().enumerate() {
        assert_eq!(
            hex::encode(chunk_id(&stored)),
            ids[span.first as usize + i],
            "client checks chunk ids"
        );
        out.extend(open_chunk(&key, &file_id, span.first + i as u64, &stored).unwrap());
    }
    let got: Vec<u8> = out
        .into_iter()
        .skip(span.skip as usize)
        .take(span.len as usize)
        .collect();
    assert_eq!(got, &plaintext[start as usize..end as usize]);

    let (s, _) = srv
        .send(
            Method::GET,
            &format!("/v1/objects/{object_id}/chunks?first=0&last=3"),
            &[],
            vec![],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "past the last chunk");
}

#[tokio::test]
async fn rejects_bad_chunks_and_missing_refs() {
    let srv = server().await;
    let stored = seal_chunk(&[1; 32], &[2; 16], 0, b"hello");
    let wrong = hex::encode([0u8; 32]);
    let (s, _) = srv
        .send(Method::PUT, &format!("/v1/chunks/{wrong}"), &[], stored.clone())
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "id must be the BLAKE3 of the body");

    let mut bad = stored.clone();
    bad[0] = b'X';
    let (s, _) = srv
        .send(
            Method::PUT,
            &format!("/v1/chunks/{}", hex::encode(chunk_id(&bad))),
            &[],
            bad,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "bad magic");

    let missing = hex::encode(chunk_id(&stored));
    let (s, body) = srv
        .json(
            Method::POST,
            "/v1/objects",
            serde_json::json!({ "id": hex::encode([3u8; 16]), "chunks": [missing] }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["detail"]["missing"][0], missing);
}

#[tokio::test]
async fn manifest_log_compare_and_swap() {
    let srv = server().await;
    let (_, head) = srv
        .json(Method::GET, "/v1/manifest/head", serde_json::Value::Null)
        .await;
    assert_eq!(head["revision"], 0);

    let (s, _) = srv
        .send(
            Method::POST,
            "/v1/manifest/log",
            &[("if-match", "0")],
            b"OSL1first".to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = srv
        .send(
            Method::POST,
            "/v1/manifest/log",
            &[("if-match", "0")],
            b"OSL1racer".to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "built on a stale head");
    let (s, _) = srv
        .send(
            Method::POST,
            "/v1/manifest/log",
            &[("if-match", "1")],
            b"OSL1second".to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = srv
        .send(Method::POST, "/v1/manifest/log", &[], b"OSL1nohead".to_vec())
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (_, body) = srv.send(Method::GET, "/v1/manifest/log?since=1", &[], vec![]).await;
    assert_eq!(u64::from_le_bytes(body[0..8].try_into().unwrap()), 2);
    let len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    assert_eq!(&body[12..12 + len], b"OSL1second");

    let (_, head) = srv
        .json(Method::GET, "/v1/manifest/head", serde_json::Value::Null)
        .await;
    assert_eq!(head["revision"], 2);
    assert_eq!(head["hash"], hex::encode(blake3::hash(b"OSL1second").as_bytes()));
}

#[tokio::test]
async fn gc_removes_chunks_after_object_delete() {
    let srv = server().await;
    let stored = seal_chunk(&[1; 32], &[2; 16], 0, b"bye");
    let id = hex::encode(chunk_id(&stored));
    srv.send(Method::PUT, &format!("/v1/chunks/{id}"), &[], stored).await;
    let obj = hex::encode([5u8; 16]);
    srv.json(
        Method::POST,
        "/v1/objects",
        serde_json::json!({ "id": obj, "chunks": [id] }),
    )
    .await;

    assert_eq!(oshelfd::gc(&srv.state, 0).await.unwrap(), 0, "referenced chunk stays");
    let (s, _) = srv
        .send(Method::DELETE, &format!("/v1/objects/{obj}"), &[], vec![])
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(oshelfd::gc(&srv.state, 0).await.unwrap(), 1);
    let (s, _) = srv.send(Method::GET, &format!("/v1/chunks/{id}"), &[], vec![]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn requests_must_be_signed_by_a_paired_device() {
    let srv = server().await;
    let (s, _) = srv.send(Method::GET, "/v1/usage", &[], vec![]).await;
    assert_eq!(s, StatusCode::OK);

    let (s, _) = srv.raw(Request::get("/v1/usage").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "unsigned");
    let (s, _) = srv.raw(Request::get("/v1/health").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK, "health is public");

    let req = srv.signed(Method::GET, "/v1/usage", &[], vec![]);
    let (parts, _) = req.into_parts();
    let replay = |p: &axum::http::request::Parts| {
        let mut r = Request::builder().method(p.method.clone()).uri(p.uri.clone());
        for (k, v) in &p.headers {
            r = r.header(k, v);
        }
        r.body(Body::empty()).unwrap()
    };
    assert_eq!(srv.raw(replay(&parts)).await.0, StatusCode::OK);
    assert_eq!(srv.raw(replay(&parts)).await.0, StatusCode::UNAUTHORIZED, "replay");

    // Signature over a different body.
    let mut req = srv.signed(
        Method::POST,
        "/v1/manifest/log",
        &[("if-match", "0")],
        b"OSL1a".to_vec(),
    );
    *req.body_mut() = Body::from(b"OSL1b".to_vec());
    assert_eq!(srv.raw(req).await.0, StatusCode::UNAUTHORIZED, "tampered body");

    // Signature for another path.
    let mut req = srv.signed(Method::GET, "/v1/usage", &[], vec![]);
    *req.uri_mut() = "/v1/devices".parse().unwrap();
    assert_eq!(srv.raw(req).await.0, StatusCode::UNAUTHORIZED, "path swapped");

    let (s, devices) = srv.json(Method::GET, "/v1/devices", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(devices[0]["name"], "Test Mac");
    let (s, _) = srv
        .send(
            Method::DELETE,
            &format!("/v1/devices/{}", hex::encode(srv.device)),
            &[],
            vec![],
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = srv.send(Method::GET, "/v1/usage", &[], vec![]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "revoked");
}

#[tokio::test]
async fn pairing_proves_both_sides_and_limits_guesses() {
    let srv = server().await;
    let (s, code) = srv
        .json(Method::POST, "/v1/pairing-codes", serde_json::Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK);
    let code = code["code"].as_str().unwrap().to_string();

    let new_key = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
    let (s, _) = srv.pair(CODE, &new_key).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "first code was already used");

    let (s, body) = srv.pair(&code, &new_key).await;
    assert_eq!(s, StatusCode::OK);
    let mut device_id = [0u8; 16];
    hex::decode_to_slice(body["device_id"].as_str().unwrap(), &mut device_id).unwrap();
    let server_pubkey = srv.state.server_key.verifying_key().to_bytes();
    assert_eq!(body["server_pubkey"], hex::encode(server_pubkey));
    let expected = auth::pairing_server_mac(&code, &server_pubkey, &device_id, &[5; 16]);
    assert_eq!(
        body["mac"],
        hex::encode(expected),
        "device can check it paired with this Pi"
    );

    // Five wrong guesses burn a fresh code.
    let (_, fresh) = srv
        .json(Method::POST, "/v1/pairing-codes", serde_json::Value::Null)
        .await;
    let fresh = fresh["code"].as_str().unwrap().to_string();
    let other = SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes();
    for _ in 0..5 {
        assert_eq!(srv.pair("WRONGWRG", &other).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(srv.pair(&fresh, &other).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn responses_are_signed_by_the_server() {
    let srv = server().await;
    let req = srv.signed(Method::GET, "/v1/manifest/head", &[], vec![]);
    let req_sig = sig_of(&req);
    let res = srv.app.clone().oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let sig = header_sig(res.headers()).expect("buffered responses carry a signature");
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let server_key = srv.state.server_key.verifying_key();
    assert!(auth::verify_response(&server_key, &req_sig, status, &body, &sig));
    assert!(
        !auth::verify_response(&server_key, &[0; 64], status, &body, &sig),
        "bound to the request"
    );

    // Errors from handlers are signed too, so a 409 can't be forged.
    let req = srv.signed(Method::POST, "/v1/manifest/log", &[("if-match", "7")], b"OSL1x".to_vec());
    let req_sig = sig_of(&req);
    let res = srv.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let sig = header_sig(res.headers()).unwrap();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert!(auth::verify_response(&server_key, &req_sig, 409, &body, &sig));
}

fn sig_of(req: &Request<Body>) -> [u8; 64] {
    let h = req.headers()[header::AUTHORIZATION].to_str().unwrap();
    let b64 = h.split("sig=").nth(1).unwrap();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
        .try_into()
        .unwrap()
}

fn header_sig(headers: &axum::http::HeaderMap) -> Option<[u8; 64]> {
    let v = headers.get("x-oshelf-sig")?.to_str().ok()?;
    base64::engine::general_purpose::STANDARD.decode(v).ok()?.try_into().ok()
}

#[tokio::test]
async fn snapshots_compact_the_log() {
    let srv = server().await;
    for i in 0..6u64 {
        let (s, _) = srv
            .send(
                Method::POST,
                "/v1/manifest/log",
                &[("if-match", &i.to_string())],
                format!("OSL1entry{i}").into_bytes(),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
    }
    let (s, _) = srv.send(Method::GET, "/v1/manifest/snapshot", &[], vec![]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Each snapshot's segments are one sealed chunk registered as an object.
    let mut put = |rev: u64, obj: [u8; 16]| {
        let srv = &srv;
        async move {
            let seg = seal_chunk(&[8; 32], &obj, 0, format!("tree at {rev}").as_bytes());
            let id = hex::encode(chunk_id(&seg));
            srv.send(Method::PUT, &format!("/v1/chunks/{id}"), &[], seg).await;
            let (s, _) = srv
                .json(
                    Method::POST,
                    "/v1/objects",
                    serde_json::json!({ "id": hex::encode(obj), "chunks": [id] }),
                )
                .await;
            assert_eq!(s, StatusCode::CREATED);
            srv.send(
                Method::PUT,
                &format!("/v1/manifest/snapshots/{rev}?object={}", hex::encode(obj)),
                &[],
                format!("OSN1header{rev}").into_bytes(),
            )
            .await
            .0
        }
    };
    assert_eq!(put(2, [1; 16]).await, StatusCode::CREATED);
    assert_eq!(put(9, [2; 16]).await, StatusCode::CONFLICT, "past the head");
    assert_eq!(put(4, [3; 16]).await, StatusCode::CREATED);
    assert_eq!(put(5, [4; 16]).await, StatusCode::CREATED);

    let res = srv
        .app
        .clone()
        .oneshot(srv.signed(Method::GET, "/v1/manifest/snapshot", &[], vec![]))
        .await
        .unwrap();
    assert_eq!(res.headers()["x-oshelf-revision"], "5");
    assert_eq!(res.headers()["x-oshelf-object"], hex::encode([4u8; 16]));
    assert_eq!(&to_bytes(res.into_body(), usize::MAX).await.unwrap()[..], b"OSN1header5");

    // Kept snapshots are 4 and 5, so the log starts after 4.
    let (s, body) = srv.send(Method::GET, "/v1/manifest/log?since=1", &[], vec![]).await;
    assert_eq!(s, StatusCode::GONE);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["detail"]["oldest_revision"], 5);
    let (s, body) = srv.send(Method::GET, "/v1/manifest/log?since=4", &[], vec![]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(u64::from_le_bytes(body[0..8].try_into().unwrap()), 5);

    // Snapshot 2's segments are no longer referenced.
    assert_eq!(oshelfd::gc(&srv.state, 0).await.unwrap(), 1);
}

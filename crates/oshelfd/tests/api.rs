//! End to end: a client seals a file, uploads it, and reads a byte range back
//! through the API, with the server never seeing a key.

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use oshelf_core::{chunk_id, chunk_span, open_chunk, seal_chunk, CHUNK_SIZE};
use oshelfd::{router, AppState};
use tower::ServiceExt;

struct Server {
    app: Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::open(dir.path()).unwrap();
    Server {
        app: router(state.clone()),
        state,
        _dir: dir,
    }
}

impl Server {
    async fn send(&self, method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let res = self
            .app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = res.status();
        (status, to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec())
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
    let srv = server();
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
    let srv = server();
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
    let srv = server();
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
    let srv = server();
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

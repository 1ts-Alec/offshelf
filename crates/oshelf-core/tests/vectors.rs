//! Checks `spec/vectors/*.json` against this implementation. Other
//! implementations (Swift wrapper, WebAssembly build) must pass the same files.
//!
//! To regenerate after an intentional format change:
//! `OSHELF_BLESS=1 cargo test -p oshelf-core --test vectors`

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use oshelf_core::{auth, chunk_id, chunk_span, open_chunk, seal_chunk_with_nonce, ChunkError};
use serde_json::{json, Value};

const KEY: [u8; 32] = [0x42; 32];
const FILE_ID: [u8; 16] = [0x07; 16];
const NONCE: [u8; 24] = [0x24; 24];

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

/// Compares `built` with the checked-in file, or rewrites it when blessing.
fn check(name: &str, built: Value) {
    let path = vectors_dir().join(name);
    if std::env::var_os("OSHELF_BLESS").is_some() {
        std::fs::create_dir_all(vectors_dir()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
        return;
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{} missing; run with OSHELF_BLESS=1", path.display()));
    let on_disk: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(on_disk, built, "{name} no longer matches the implementation");
}

/// Plaintext used by chunk vectors: byte i is i mod 251.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn chunk_vectors() {
    let mut cases = Vec::new();
    for (index, len) in [(0u64, 0usize), (1, 1), (2, 1 << 20), (3, (1 << 20) - 1)] {
        let pt = pattern(len);
        let stored = seal_chunk_with_nonce(&KEY, &FILE_ID, index, &pt, NONCE);
        assert_eq!(open_chunk(&KEY, &FILE_ID, index, &stored).unwrap(), pt);
        let mut case = json!({
            "chunk_index": index,
            "plaintext_len": len,
            "stored_len": stored.len(),
            "chunk_id": hex::encode(chunk_id(&stored)),
            "stored_prefix_hex": hex::encode(&stored[..stored.len().min(64)]),
            "tag_hex": hex::encode(&stored[stored.len() - 16..]),
        });
        if len <= 64 {
            case["stored_hex"] = json!(hex::encode(&stored));
        }
        cases.push(case);
    }

    let base = seal_chunk_with_nonce(&KEY, &FILE_ID, 5, b"offshelf", NONCE);
    let flip = |at: usize| {
        let mut b = base.clone();
        b[at] ^= 0x01;
        b
    };
    let rejects = [
        ("wrong chunk index", base.clone(), FILE_ID, 6u64, ChunkError::Auth),
        ("wrong file id", base.clone(), [0x08; 16], 5, ChunkError::Auth),
        ("flipped ciphertext bit", flip(32), FILE_ID, 5, ChunkError::Auth),
        ("flipped tag bit", flip(base.len() - 1), FILE_ID, 5, ChunkError::Auth),
        ("flipped nonce bit", flip(8), FILE_ID, 5, ChunkError::Auth),
        ("bad magic", flip(0), FILE_ID, 5, ChunkError::BadMagic),
        (
            "unsupported version",
            flip(4),
            FILE_ID,
            5,
            ChunkError::UnsupportedVersion(0),
        ),
        ("nonzero reserved", flip(6), FILE_ID, 5, ChunkError::ReservedNotZero),
        ("truncated", base[..47].to_vec(), FILE_ID, 5, ChunkError::TooShort),
    ];
    let rejects: Vec<Value> = rejects
        .into_iter()
        .map(|(name, stored, file_id, index, err)| {
            assert_eq!(open_chunk(&KEY, &file_id, index, &stored), Err(err.clone()), "{name}");
            json!({
                "name": name,
                "stored_hex": hex::encode(&stored),
                "file_id": hex::encode(file_id),
                "chunk_index": index,
                "error": format!("{err:?}"),
            })
        })
        .collect();

    check(
        "chunk.json",
        json!({
            "description": "Sealed chunk format v1. Plaintext byte i is i mod 251. Nonces are fixed here only to make vectors reproducible; real chunks use random nonces.",
            "key": hex::encode(KEY),
            "file_id": hex::encode(FILE_ID),
            "nonce": hex::encode(NONCE),
            "seal": cases,
            "reject": {
                "key": hex::encode(KEY),
                "sealed_for": { "file_id": hex::encode(FILE_ID), "chunk_index": 5, "plaintext": "offshelf" },
                "cases": rejects,
            },
        }),
    );
}

#[test]
fn range_vectors() {
    const MIB: u64 = 1 << 20;
    let inputs: [(u64, u64, u64); 9] = [
        (0, 0, 10),
        (0, 10, 10),
        (5, 3, 10),
        (20, 30, 10),
        (0, MIB, 3 * MIB),
        (MIB - 1, MIB + 1, 3 * MIB),
        (MIB, u64::MAX, 2 * MIB + 7),
        (2 * MIB, 2 * MIB + 7, 2 * MIB + 7),
        (12_345, 4 * MIB + 99, 10 * MIB),
    ];
    let cases: Vec<Value> = inputs
        .into_iter()
        .map(|(start, end, size)| {
            let span = chunk_span(start, end, size, 1 << 20);
            json!({
                "start": start,
                "end": end,
                "file_size": size,
                "span": span.map(|s| json!({ "first": s.first, "last": s.last, "skip": s.skip, "len": s.len })),
            })
        })
        .collect();
    check(
        "range.json",
        json!({
            "description": "Plaintext byte range [start, end) to chunk span, chunk size 1 MiB. end is clamped to file_size; null means an empty range.",
            "chunk_size": 1 << 20,
            "cases": cases,
        }),
    );
}

#[test]
fn auth_vectors() {
    let device = SigningKey::from_bytes(&[0x11; 32]);
    let server = SigningKey::from_bytes(&[0x22; 32]);
    let (method, path, ts, body) = ("PUT", "/v1/chunks/00ff?x=1", 1_761_329_400_000i64, b"sealed bytes");
    let req_sig = auth::sign_request(&device, method, path, ts, body);
    assert!(auth::verify_request(
        &device.verifying_key(),
        method,
        path,
        ts,
        body,
        &req_sig
    ));
    let res_body = br#"{"revision":7}"#;
    let res_sig = auth::sign_response(&server, &req_sig, 201, res_body);

    let code = "7KQ2-M9XD";
    let nonce = [0x33; 16];
    let device_id = [0x44; 16];
    let device_pub = device.verifying_key().to_bytes();
    let server_pub = server.verifying_key().to_bytes();

    check(
        "auth.json",
        json!({
            "description": "Ed25519 request and response signatures and pairing HMACs. Keys are Ed25519 seeds.",
            "request": {
                "device_seed": hex::encode(device.to_bytes()),
                "device_pubkey": hex::encode(device_pub),
                "method": method,
                "path_and_query": path,
                "ts_ms": ts,
                "body_hex": hex::encode(body),
                "message_hex": hex::encode(auth::signing_message(method, path, ts, body)),
                "sig": hex::encode(req_sig),
            },
            "response": {
                "server_seed": hex::encode(server.to_bytes()),
                "server_pubkey": hex::encode(server_pub),
                "request_sig": hex::encode(req_sig),
                "status": 201,
                "body_hex": hex::encode(res_body),
                "message_hex": hex::encode(auth::response_message(&req_sig, 201, res_body)),
                "sig": hex::encode(res_sig),
            },
            "pairing": {
                "code": code,
                "normalized_code": auth::normalize_code(code),
                "device_pubkey": hex::encode(device_pub),
                "client_nonce": hex::encode(nonce),
                "client_mac": hex::encode(auth::pairing_client_mac(code, &device_pub, &nonce)),
                "server_pubkey": hex::encode(server_pub),
                "device_id": hex::encode(device_id),
                "server_mac": hex::encode(auth::pairing_server_mac(code, &server_pub, &device_id, &nonce)),
            },
        }),
    );
}

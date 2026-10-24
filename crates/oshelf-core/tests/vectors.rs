//! Checks `spec/vectors/*.json` against this implementation. Other
//! implementations (Swift wrapper, WebAssembly build) must pass the same files.
//!
//! To regenerate after an intentional format change:
//! `OSHELF_BLESS=1 cargo test -p oshelf-core --test vectors`

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use oshelf_core::keys;
use oshelf_core::manifest::{self, Chain, LogEntry, Node, Op, ROOT};
use oshelf_core::vault::{self, Kdf, VaultHeader};
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

/// Small Argon2id cost so the vectors run fast; implementations must take
/// the parameters from the header, never assume the defaults.
fn test_kdf(salt: [u8; 16]) -> Kdf {
    Kdf {
        p: 1,
        t: 2,
        alg: "argon2id".into(),
        salt,
        m_kib: 1024,
    }
}

#[test]
fn kdf_vectors() {
    let kdf = test_kdf([0x5a; 16]);
    let pk = kdf.derive("correct horse battery staple").unwrap();
    let mk = [0x01; 32];
    let vault_id = [0x02; 16];
    check(
        "kdf.json",
        json!({
            "description": "Argon2id passphrase key (v1.3, 32 byte output) and HKDF-SHA256 subkeys (salt = vault id, ikm = master key).",
            "argon2id": {
                "passphrase": "correct horse battery staple",
                "salt": hex::encode(kdf.salt),
                "m_kib": kdf.m_kib, "t": kdf.t, "p": kdf.p,
                "key": hex::encode(pk),
            },
            "hkdf": {
                "master_key": hex::encode(mk),
                "vault_id": hex::encode(vault_id),
                "manifest_key": hex::encode(keys::manifest_key(&mk, &vault_id)),
                "snapshot_key_rev_7": hex::encode(keys::snapshot_key(&mk, &vault_id, 7)),
            },
            "recovery": {
                "key": hex::encode([0x7f; 32]),
                "words": vault::recovery_words(&[0x7f; 32]),
            },
        }),
    );
}

/// The vault header has random nonces, so this file is verified by opening
/// it rather than by rebuilding it.
#[test]
fn vault_vectors() {
    let path = vectors_dir().join("vault.json");
    if std::env::var_os("OSHELF_BLESS").is_some() {
        let v = VaultHeader::create_with(
            "hunter2 but longer",
            test_kdf([0x33; 16]),
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
        .unwrap();
        let mut tampered = v.header.encode();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let doc = json!({
            "description": "A sealed vault header (\"OSVH\" || 0x01 || deterministic CBOR). Open it with the passphrase or the recovery words to get master_key. The tampered header must fail.",
            "passphrase": "hunter2 but longer",
            "recovery_words": v.recovery_words,
            "master_key": hex::encode(v.master_key),
            "header_hex": hex::encode(v.header.encode()),
            "tampered_header_hex": hex::encode(tampered),
        });
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let s = |k: &str| doc[k].as_str().unwrap().to_string();
    let header = VaultHeader::decode(&hex::decode(s("header_hex")).unwrap()).unwrap();
    let mk = hex::encode(header.unlock(&s("passphrase")).unwrap());
    assert_eq!(mk, s("master_key"));
    assert_eq!(
        hex::encode(header.unlock_with_recovery(&s("recovery_words")).unwrap()),
        mk
    );
    assert!(header.unlock("not it").is_err());
    let tampered = VaultHeader::decode(&hex::decode(s("tampered_header_hex")).unwrap());
    assert!(tampered.map(|h| h.unlock(&s("passphrase")).is_err()).unwrap_or(true));
}

#[test]
fn manifest_vectors() {
    let km = keys::manifest_key(&[0x01; 32], &[0x02; 16]);
    let device = [0x09; 16];
    let file = |n: u8, name: &str| {
        Node::file(
            [n; 16],
            ROOT,
            name,
            11,
            1_700_000_000_000_000_000,
            [n; 32],
            [n + 100; 16],
            vec![[n; 32]],
        )
    };
    let batches: Vec<Vec<Op>> = vec![
        vec![Op::Put(Node::dir(
            [0x10; 16],
            ROOT,
            "Photos",
            1_700_000_000_000_000_000,
        ))],
        vec![Op::Put(file(0x11, "notes.txt"))],
        vec![Op::Move {
            id: [0x11; 16],
            name: "todo.txt".into(),
            parent: [0x10; 16],
        }],
        vec![Op::Put(file(0x12, "caf\u{e9}.md"))],
        vec![Op::Delete([0x12; 16])],
    ];
    let mut chain = Chain::GENESIS;
    let mut entries = Vec::new();
    let mut sealed_all = Vec::new();
    for (i, ops) in batches.into_iter().enumerate() {
        let entry: LogEntry = chain.next_entry(device, 1_761_330_000_000 + i as i64, ops);
        let sealed = manifest::seal_entry_with_nonce(&km, &entry, [i as u8 + 1; 24]);
        let (opened, next) = chain.open_next(&km, &sealed).unwrap();
        assert_eq!(opened, entry);
        entries.push(json!({
            "revision": entry.revision,
            "prev_hash": hex::encode(entry.prev_hash),
            "cbor_hex": hex::encode(keys::to_cbor(&entry)),
            "nonce": hex::encode([i as u8 + 1; 24]),
            "sealed_hex": hex::encode(&sealed),
            "entry_hash": hex::encode(next.hash),
        }));
        sealed_all.push(sealed);
        chain = next;
    }
    // Opening entry 3 right after entry 1 (skipping 2) must fail, as must
    // re-applying entry 2 on top of itself.
    let (_, after1) = Chain::GENESIS.open_next(&km, &sealed_all[0]).unwrap();
    assert!(after1.open_next(&km, &sealed_all[2]).is_err());
    let (_, after2) = after1.open_next(&km, &sealed_all[1]).unwrap();
    assert!(after2.open_next(&km, &sealed_all[1]).is_err());

    check(
        "manifest.json",
        json!({
            "description": "Five sealed log entries forming a chain from genesis (revision 0, all-zero hash). Each entry's CBOR is deterministic; sealed = \"OSL1\" || nonce || XChaCha20-Poly1305(manifest_key, zstd(cbor), aad = \"OSL1\" || u64le(revision) || prev_hash). zstd output may differ between libraries, so check cbor_hex by decoding sealed_hex, not by re-sealing.",
            "manifest_key": hex::encode(km),
            "entries": entries,
            "must_fail": [
                { "name": "skipped entry", "chain_after": 1, "open": 3 },
                { "name": "replayed entry", "chain_after": 2, "open": 2 },
            ],
            "final_tree": ["Photos/", "Photos/todo.txt"],
        }),
    );
}

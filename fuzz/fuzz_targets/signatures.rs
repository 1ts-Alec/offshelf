//! Signature and pairing checks on arbitrary input must not panic, and a
//! signature must never verify for a request it wasn't made for.
#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use oshelf_core::auth;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    method: &'a str,
    path: &'a str,
    ts: i64,
    body: &'a [u8],
    sig: [u8; 64],
    pubkey: [u8; 32],
    code: &'a str,
}

fuzz_target!(|i: Input| {
    let key = SigningKey::from_bytes(&[0x11; 32]);
    let vk = key.verifying_key();
    let _ = auth::verify_request(&vk, i.method, i.path, i.ts, i.body, &i.sig);
    if let Ok(other) = ed25519_dalek::VerifyingKey::from_bytes(&i.pubkey) {
        let _ = auth::verify_request(&other, i.method, i.path, i.ts, i.body, &i.sig);
    }

    let good = auth::sign_request(&key, i.method, i.path, i.ts, i.body);
    assert!(auth::verify_request(&vk, i.method, i.path, i.ts, i.body, &good));
    assert!(!auth::verify_request(&vk, i.method, i.path, i.ts.wrapping_add(1), i.body, &good));

    let normalized = auth::normalize_code(i.code);
    assert!(normalized.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
    assert_eq!(auth::normalize_code(&normalized), normalized);
    let mac = auth::pairing_client_mac(i.code, &i.pubkey, &[0; 16]);
    assert_eq!(mac, auth::pairing_client_mac(&normalized, &i.pubkey, &[0; 16]));
});

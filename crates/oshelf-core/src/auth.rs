//! Device request signing and pairing MACs (spec: "Device auth and pairing").

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Header scheme name: `Authorization: Oshelf device=<hex>, ts=<ms>, sig=<base64>`.
pub const SCHEME: &str = "Oshelf";
/// Largest allowed difference between a request's timestamp and the server clock.
pub const MAX_SKEW_MS: i64 = 60_000;

/// Bytes a device signs for one request.
pub fn signing_message(method: &str, path_and_query: &str, ts_ms: i64, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + path_and_query.len());
    m.extend_from_slice(b"OSR1");
    m.extend_from_slice(method.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(path_and_query.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(ts_ms.to_string().as_bytes());
    m.push(b'\n');
    m.extend_from_slice(blake3::hash(body).as_bytes());
    m
}

pub fn sign_request(key: &SigningKey, method: &str, path_and_query: &str, ts_ms: i64, body: &[u8]) -> [u8; 64] {
    key.sign(&signing_message(method, path_and_query, ts_ms, body))
        .to_bytes()
}

pub fn verify_request(
    key: &VerifyingKey,
    method: &str,
    path_and_query: &str,
    ts_ms: i64,
    body: &[u8],
    sig: &[u8; 64],
) -> bool {
    key.verify(
        &signing_message(method, path_and_query, ts_ms, body),
        &Signature::from_bytes(sig),
    )
    .is_ok()
}

/// Bytes the server signs for a response: tied to the request's signature so
/// an old response can't be replayed against a new request.
pub fn response_message(request_sig: &[u8; 64], status: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + 64 + 2 + 32);
    m.extend_from_slice(b"OSS1");
    m.extend_from_slice(request_sig);
    m.extend_from_slice(&status.to_le_bytes());
    m.extend_from_slice(blake3::hash(body).as_bytes());
    m
}

pub fn sign_response(key: &SigningKey, request_sig: &[u8; 64], status: u16, body: &[u8]) -> [u8; 64] {
    key.sign(&response_message(request_sig, status, body)).to_bytes()
}

/// Devices check every buffered response against the server key they
/// pinned at pairing.
pub fn verify_response(key: &VerifyingKey, request_sig: &[u8; 64], status: u16, body: &[u8], sig: &[u8; 64]) -> bool {
    key.verify(
        &response_message(request_sig, status, body),
        &Signature::from_bytes(sig),
    )
    .is_ok()
}

fn hmac(code: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(normalize_code(code).as_bytes()).expect("hmac takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Pairing codes are case-insensitive and ignore dashes and spaces.
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// MAC the new device sends to prove it knows the code.
pub fn pairing_client_mac(code: &str, device_pubkey: &[u8; 32], client_nonce: &[u8; 16]) -> [u8; 32] {
    hmac(code, &[b"OSP1client", device_pubkey, client_nonce])
}

/// MAC the server returns so the device knows it paired with the real Pi.
pub fn pairing_server_mac(
    code: &str,
    server_pubkey: &[u8; 32],
    device_id: &[u8; 16],
    client_nonce: &[u8; 16],
) -> [u8; 32] {
    hmac(code, &[b"OSP1server", server_pubkey, device_id, client_nonce])
}

/// Constant time comparison for MACs.
pub fn macs_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let sig = sign_request(&key, "PUT", "/v1/chunks/ab?x=1", 1_700_000_000_000, b"body");
        let vk = key.verifying_key();
        assert!(verify_request(
            &vk,
            "PUT",
            "/v1/chunks/ab?x=1",
            1_700_000_000_000,
            b"body",
            &sig
        ));
        assert!(!verify_request(
            &vk,
            "GET",
            "/v1/chunks/ab?x=1",
            1_700_000_000_000,
            b"body",
            &sig
        ));
        assert!(!verify_request(
            &vk,
            "PUT",
            "/v1/chunks/ab?x=2",
            1_700_000_000_000,
            b"body",
            &sig
        ));
        assert!(!verify_request(
            &vk,
            "PUT",
            "/v1/chunks/ab?x=1",
            1_700_000_000_001,
            b"body",
            &sig
        ));
        assert!(!verify_request(
            &vk,
            "PUT",
            "/v1/chunks/ab?x=1",
            1_700_000_000_000,
            b"bodY",
            &sig
        ));
    }

    #[test]
    fn response_signatures_bind_request_status_and_body() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let vk = key.verifying_key();
        let sig = sign_response(&key, &[1; 64], 200, b"ok");
        assert!(verify_response(&vk, &[1; 64], 200, b"ok", &sig));
        assert!(!verify_response(&vk, &[2; 64], 200, b"ok", &sig));
        assert!(!verify_response(&vk, &[1; 64], 201, b"ok", &sig));
        assert!(!verify_response(&vk, &[1; 64], 200, b"no", &sig));
    }

    #[test]
    fn pairing_macs_bind_their_inputs() {
        let a = pairing_client_mac("ab3d-k9qz", &[1; 32], &[2; 16]);
        assert_eq!(a, pairing_client_mac("AB3DK9QZ", &[1; 32], &[2; 16]));
        assert_ne!(a, pairing_client_mac("AB3DK9QX", &[1; 32], &[2; 16]));
        assert_ne!(a, pairing_client_mac("AB3DK9QZ", &[1; 32], &[3; 16]));
        let s = pairing_server_mac("AB3DK9QZ", &[1; 32], &[4; 16], &[2; 16]);
        assert!(!macs_equal(&a, &s), "client and server MACs are domain separated");
        assert!(macs_equal(&s, &s));
    }
}

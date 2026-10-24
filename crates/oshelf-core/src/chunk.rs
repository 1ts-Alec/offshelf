//! Sealed chunk format v1.
//!
//! ```text
//! stored = header (32) || ciphertext (pt_len) || tag (16)
//! header = "OSC1" || version 0x01 || alg 0x01 || reserved 0x0000 || nonce (24)
//! aad    = header[0..8] || file_id (16) || u64le(chunk_index)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

pub const MAGIC: [u8; 4] = *b"OSC1";
pub const VERSION: u8 = 1;
pub const ALG_XCHACHA20_POLY1305: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Bytes a stored chunk adds on top of its plaintext.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ChunkError {
    #[error("chunk shorter than header and tag")]
    TooShort,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported chunk version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported algorithm {0}")]
    UnsupportedAlg(u8),
    #[error("reserved bytes are not zero")]
    ReservedNotZero,
    #[error("chunk failed authentication")]
    Auth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub version: u8,
    pub alg: u8,
    pub nonce: [u8; 24],
}

impl ChunkHeader {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&MAGIC);
        h[4] = self.version;
        h[5] = self.alg;
        h[8..32].copy_from_slice(&self.nonce);
        h
    }
}

/// Parses and validates the header of a stored chunk. The server uses this to
/// reject malformed uploads; it does not need any key.
pub fn parse_header(stored: &[u8]) -> Result<ChunkHeader, ChunkError> {
    if stored.len() < OVERHEAD {
        return Err(ChunkError::TooShort);
    }
    if stored[0..4] != MAGIC {
        return Err(ChunkError::BadMagic);
    }
    if stored[4] != VERSION {
        return Err(ChunkError::UnsupportedVersion(stored[4]));
    }
    if stored[5] != ALG_XCHACHA20_POLY1305 {
        return Err(ChunkError::UnsupportedAlg(stored[5]));
    }
    if stored[6] != 0 || stored[7] != 0 {
        return Err(ChunkError::ReservedNotZero);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&stored[8..32]);
    Ok(ChunkHeader {
        version: stored[4],
        alg: stored[5],
        nonce,
    })
}

fn aad(header: &[u8], file_id: &[u8; 16], index: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..8].copy_from_slice(&header[0..8]);
    a[8..24].copy_from_slice(file_id);
    a[24..32].copy_from_slice(&index.to_le_bytes());
    a
}

/// Seals one plaintext chunk with a fresh random nonce.
pub fn seal_chunk(key: &[u8; 32], file_id: &[u8; 16], index: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    seal_chunk_with_nonce(key, file_id, index, plaintext, nonce)
}

/// Seals with a caller-chosen nonce. Only for test vectors: a nonce must never
/// be reused with the same key.
pub fn seal_chunk_with_nonce(
    key: &[u8; 32],
    file_id: &[u8; 16],
    index: u64,
    plaintext: &[u8],
    nonce: [u8; 24],
) -> Vec<u8> {
    let header = ChunkHeader {
        version: VERSION,
        alg: ALG_XCHACHA20_POLY1305,
        nonce,
    }
    .encode();
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(&header, file_id, index),
            },
        )
        .expect("xchacha20poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    out
}

/// Checks and decrypts a stored chunk for the given file and position.
pub fn open_chunk(key: &[u8; 32], file_id: &[u8; 16], index: u64, stored: &[u8]) -> Result<Vec<u8>, ChunkError> {
    let header = parse_header(stored)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &stored[HEADER_LEN..],
                aad: &aad(stored, file_id, index),
            },
        )
        .map_err(|_| ChunkError::Auth)
}

/// Content address of a stored chunk: BLAKE3-256 over all of its bytes.
pub fn chunk_id(stored: &[u8]) -> [u8; 32] {
    *blake3::hash(stored).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const FILE: [u8; 16] = [9; 16];

    #[test]
    fn round_trip_sizes() {
        for len in [0usize, 1, 4096, crate::CHUNK_SIZE as usize] {
            let pt = vec![0xAB; len];
            let stored = seal_chunk(&KEY, &FILE, 3, &pt);
            assert_eq!(stored.len(), len + OVERHEAD);
            assert_eq!(open_chunk(&KEY, &FILE, 3, &stored).unwrap(), pt);
        }
    }

    #[test]
    fn bound_to_file_and_index() {
        let stored = seal_chunk(&KEY, &FILE, 3, b"hello");
        assert_eq!(open_chunk(&KEY, &FILE, 4, &stored), Err(ChunkError::Auth));
        assert_eq!(open_chunk(&KEY, &[1; 16], 3, &stored), Err(ChunkError::Auth));
        assert_eq!(open_chunk(&[8; 32], &FILE, 3, &stored), Err(ChunkError::Auth));
    }

    #[test]
    fn tampering_is_caught() {
        let stored = seal_chunk(&KEY, &FILE, 0, b"hello world");
        for i in 0..stored.len() {
            let mut bad = stored.clone();
            bad[i] ^= 1;
            assert!(open_chunk(&KEY, &FILE, 0, &bad).is_err(), "flip at byte {i} accepted");
        }
    }

    #[test]
    fn header_validation() {
        let stored = seal_chunk(&KEY, &FILE, 0, b"x");
        assert_eq!(parse_header(&stored[..40]), Err(ChunkError::TooShort));
        let mut bad = stored.clone();
        bad[0] = b'X';
        assert_eq!(parse_header(&bad), Err(ChunkError::BadMagic));
        let mut bad = stored.clone();
        bad[4] = 2;
        assert_eq!(parse_header(&bad), Err(ChunkError::UnsupportedVersion(2)));
        let mut bad = stored.clone();
        bad[6] = 1;
        assert_eq!(parse_header(&bad), Err(ChunkError::ReservedNotZero));
    }

    #[test]
    fn fixed_nonce_is_deterministic() {
        let a = seal_chunk_with_nonce(&KEY, &FILE, 1, b"vector", [5; 24]);
        let b = seal_chunk_with_nonce(&KEY, &FILE, 1, b"vector", [5; 24]);
        assert_eq!(a, b);
        assert_eq!(&a[0..8], b"OSC1\x01\x01\x00\x00");
        assert_eq!(chunk_id(&a), chunk_id(&b));
    }
}

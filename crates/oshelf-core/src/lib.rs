//! Shared Offshelf logic: the sealed chunk format, chunk ids and byte range
//! mapping, device request signing, the vault and key hierarchy, and the
//! encrypted manifest. See `spec/crypto.md` for the normative description.

pub mod auth;
pub mod chunk;
pub mod keys;
pub mod manifest;
pub mod range;
pub mod vault;

pub use chunk::{chunk_id, open_chunk, parse_header, seal_chunk, seal_chunk_with_nonce, ChunkError, ChunkHeader};
pub use range::{chunk_span, ChunkSpan};

/// Plaintext bytes per chunk in format v1.
pub const CHUNK_SIZE: u32 = 1 << 20;

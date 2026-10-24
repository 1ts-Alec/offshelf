//! Key derivation from the master key, and small sealing helpers shared by
//! the vault, the manifest log and snapshots.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

pub type Key = [u8; 32];

/// HKDF-SHA256 with the vault id as salt and a fixed label as info.
pub fn derive(master_key: &Key, vault_id: &[u8; 16], info: &[u8]) -> Key {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(vault_id), master_key)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// KM: seals log entries.
pub fn manifest_key(master_key: &Key, vault_id: &[u8; 16]) -> Key {
    derive(master_key, vault_id, b"offshelf/v1/manifest")
}

/// Seals the snapshot at `revision` (its header and segments).
pub fn snapshot_key(master_key: &Key, vault_id: &[u8; 16], revision: u64) -> Key {
    let mut info = b"offshelf/v1/snapshot".to_vec();
    info.extend_from_slice(&revision.to_le_bytes());
    derive(master_key, vault_id, &info)
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// XChaCha20-Poly1305 seal; returns ciphertext || tag.
pub fn seal(key: &Key, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("xchacha20poly1305 encryption cannot fail for in-memory buffers")
}

/// XChaCha20-Poly1305 open; `None` if the tag doesn't verify.
pub fn open(key: &Key, nonce: &[u8; 24], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad })
        .ok()
}

/// Serde helper for fixed-size byte arrays as CBOR byte strings.
pub(crate) mod bytes_n {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let v: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        v.into_vec()
            .try_into()
            .map_err(|v: Vec<u8>| D::Error::invalid_length(v.len(), &"a fixed-size byte string"))
    }

    /// The same for `Option<[u8; N]>`.
    pub mod opt {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer, const N: usize>(v: &Option<[u8; N]>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(b) => s.serialize_some(&serde_bytes::Bytes::new(b)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Option<[u8; N]>, D::Error> {
            let v: Option<serde_bytes::ByteBuf> = Deserialize::deserialize(d)?;
            v.map(|b| {
                b.into_vec()
                    .try_into()
                    .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"a fixed-size byte string"))
            })
            .transpose()
        }
    }

    /// The same for `Vec<[u8; N]>`.
    pub mod vec {
        use serde::ser::SerializeSeq;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer, const N: usize>(v: &[[u8; N]], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&serde_bytes::Bytes::new(b))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Vec<[u8; N]>, D::Error> {
            let v: Vec<serde_bytes::ByteBuf> = Deserialize::deserialize(d)?;
            v.into_iter()
                .map(|b| {
                    b.into_vec()
                        .try_into()
                        .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"a fixed-size byte string"))
                })
                .collect()
        }
    }
}

/// Deterministic CBOR encoding. Struct fields are declared in RFC 8949 core
/// deterministic key order (shorter keys first, then bytewise), which the
/// tests check, so plain serde serialization is canonical.
pub fn to_cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("serializing to a Vec cannot fail");
    out
}

pub fn from_cbor<T: serde::de::DeserializeOwned>(b: &[u8]) -> Option<T> {
    ciborium::from_reader(b).ok()
}

#[cfg(test)]
pub(crate) fn assert_canonical_maps(bytes: &[u8]) {
    use ciborium::Value;
    fn walk(v: &Value) {
        match v {
            Value::Map(entries) => {
                let keys: Vec<Vec<u8>> = entries.iter().map(|(k, _)| to_cbor(k)).collect();
                let mut sorted = keys.clone();
                sorted.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
                assert_eq!(keys, sorted, "map keys not in deterministic order");
                entries.iter().for_each(|(_, v)| walk(v));
            }
            Value::Array(items) => items.iter().for_each(walk),
            Value::Tag(_, inner) => walk(inner),
            _ => {}
        }
    }
    let v: Value = ciborium::from_reader(bytes).unwrap();
    walk(&v);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_differ_by_label_vault_and_revision() {
        let mk = [1u8; 32];
        let v = [2u8; 16];
        assert_ne!(manifest_key(&mk, &v), manifest_key(&mk, &[3; 16]));
        assert_ne!(manifest_key(&mk, &v), snapshot_key(&mk, &v, 0));
        assert_ne!(snapshot_key(&mk, &v, 1), snapshot_key(&mk, &v, 2));
    }

    #[test]
    fn seal_open() {
        let sealed = seal(&[1; 32], &[2; 24], b"aad", b"hi");
        assert_eq!(open(&[1; 32], &[2; 24], b"aad", &sealed).unwrap(), b"hi");
        assert!(open(&[1; 32], &[2; 24], b"aaD", &sealed).is_none());
    }
}

//! The vault header: the master key wrapped by the passphrase and by the
//! recovery key (spec: "Key hierarchy").

use serde::{Deserialize, Serialize};

use crate::keys::{self, bytes_n, Key};

pub const MAGIC: [u8; 4] = *b"OSVH";
pub const VERSION: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("not a vault header")]
    BadHeader,
    #[error("wrong passphrase or recovery key")]
    WrongKey,
    #[error("recovery words are not a valid 24 word phrase")]
    BadRecoveryWords,
    #[error("unsupported key derivation parameters")]
    BadKdf,
}

/// Argon2id parameters, stored so they can be raised later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    // Field order is the deterministic CBOR key order.
    pub p: u32,
    pub t: u32,
    pub alg: String,
    #[serde(with = "bytes_n")]
    pub salt: [u8; 16],
    pub m_kib: u32,
}

impl Kdf {
    /// Spec defaults: m = 256 MiB, t = 3, p = 1.
    pub fn new_default() -> Self {
        Self {
            p: 1,
            t: 3,
            alg: "argon2id".into(),
            m_kib: 256 * 1024,
            salt: keys::random(),
        }
    }

    pub fn derive(&self, passphrase: &str) -> Result<Key, VaultError> {
        if self.alg != "argon2id" {
            return Err(VaultError::BadKdf);
        }
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(32)).map_err(|_| VaultError::BadKdf)?;
        let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &self.salt, &mut out)
            .map_err(|_| VaultError::BadKdf)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    pub kind: String,
    #[serde(with = "bytes_n")]
    pub nonce: [u8; 24],
    #[serde(with = "serde_bytes")]
    pub sealed_mk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    pub kdf: Kdf,
    pub slots: Vec<Slot>,
    #[serde(with = "bytes_n")]
    pub vault_id: [u8; 16],
}

/// What `create` hands back: the header to upload, the master key to keep in
/// the keychain, and the recovery words to show once.
pub struct NewVault {
    pub header: VaultHeader,
    pub master_key: Key,
    pub recovery_words: String,
}

fn slot_aad(vault_id: &[u8; 16], kind: &str) -> Vec<u8> {
    let mut a = b"offshelf/v1/vault".to_vec();
    a.extend_from_slice(vault_id);
    a.extend_from_slice(kind.as_bytes());
    a
}

fn wrap(key: &Key, vault_id: &[u8; 16], kind: &str, mk: &Key) -> Slot {
    let nonce = keys::random();
    Slot {
        kind: kind.into(),
        nonce,
        sealed_mk: keys::seal(key, &nonce, &slot_aad(vault_id, kind), mk),
    }
}

/// 24 BIP39 English words for a 32 byte recovery key.
pub fn recovery_words(rk: &Key) -> String {
    bip39::Mnemonic::from_entropy(rk)
        .expect("32 bytes is valid BIP39 entropy")
        .to_string()
}

/// Parses recovery words back into the key. Case and extra spaces don't matter.
pub fn recovery_key(words: &str) -> Result<Key, VaultError> {
    let normalized = words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let m = bip39::Mnemonic::parse_normalized(&normalized).map_err(|_| VaultError::BadRecoveryWords)?;
    m.to_entropy().try_into().map_err(|_| VaultError::BadRecoveryWords)
}

impl VaultHeader {
    /// Makes a new vault: random master key, passphrase slot, recovery slot.
    pub fn create(passphrase: &str, kdf: Kdf) -> Result<NewVault, VaultError> {
        Self::create_with(passphrase, kdf, keys::random(), keys::random(), keys::random())
    }

    /// Deterministic variant for test vectors.
    pub fn create_with(
        passphrase: &str,
        kdf: Kdf,
        vault_id: [u8; 16],
        master_key: Key,
        recovery: Key,
    ) -> Result<NewVault, VaultError> {
        let pk = kdf.derive(passphrase)?;
        let header = VaultHeader {
            slots: vec![
                wrap(&pk, &vault_id, "passphrase", &master_key),
                wrap(&recovery, &vault_id, "recovery", &master_key),
            ],
            kdf,
            vault_id,
        };
        Ok(NewVault {
            header,
            master_key,
            recovery_words: recovery_words(&recovery),
        })
    }

    fn unwrap_slot(&self, kind: &str, key: &Key) -> Result<Key, VaultError> {
        let slot = self
            .slots
            .iter()
            .find(|s| s.kind == kind)
            .ok_or(VaultError::BadHeader)?;
        let mk = keys::open(key, &slot.nonce, &slot_aad(&self.vault_id, kind), &slot.sealed_mk)
            .ok_or(VaultError::WrongKey)?;
        mk.try_into().map_err(|_| VaultError::BadHeader)
    }

    pub fn unlock(&self, passphrase: &str) -> Result<Key, VaultError> {
        self.unwrap_slot("passphrase", &self.kdf.derive(passphrase)?)
    }

    pub fn unlock_with_recovery(&self, words: &str) -> Result<Key, VaultError> {
        self.unwrap_slot("recovery", &recovery_key(words)?)
    }

    /// New passphrase (fresh salt), same master key and recovery slot.
    pub fn change_passphrase(&self, master_key: &Key, new_passphrase: &str) -> Result<VaultHeader, VaultError> {
        let kdf = Kdf {
            salt: keys::random(),
            ..self.kdf.clone()
        };
        let pk = kdf.derive(new_passphrase)?;
        let mut slots: Vec<Slot> = self.slots.iter().filter(|s| s.kind != "passphrase").cloned().collect();
        slots.insert(0, wrap(&pk, &self.vault_id, "passphrase", master_key));
        Ok(VaultHeader {
            kdf,
            slots,
            vault_id: self.vault_id,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend(keys::to_cbor(self));
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < 5 || bytes[0..4] != MAGIC || bytes[4] != VERSION {
            return Err(VaultError::BadHeader);
        }
        keys::from_cbor(&bytes[5..]).ok_or(VaultError::BadHeader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small Argon2 parameters so tests are fast.
    pub(crate) fn fast_kdf() -> Kdf {
        Kdf {
            m_kib: 64,
            t: 1,
            ..Kdf::new_default()
        }
    }

    #[test]
    fn create_unlock_recover_rewrap() {
        let v = VaultHeader::create("correct horse", fast_kdf()).unwrap();
        assert_eq!(v.recovery_words.split(' ').count(), 24);
        let decoded = VaultHeader::decode(&v.header.encode()).unwrap();
        crate::keys::assert_canonical_maps(&v.header.encode()[5..]);
        assert_eq!(decoded, v.header);
        assert_eq!(decoded.unlock("correct horse").unwrap(), v.master_key);
        assert_eq!(decoded.unlock("wrong"), Err(VaultError::WrongKey));
        let shouty = v.recovery_words.to_uppercase().replace(' ', "   ");
        assert_eq!(decoded.unlock_with_recovery(&shouty).unwrap(), v.master_key);

        let changed = decoded.change_passphrase(&v.master_key, "battery staple").unwrap();
        assert_eq!(changed.unlock("battery staple").unwrap(), v.master_key);
        assert_eq!(changed.unlock("correct horse"), Err(VaultError::WrongKey));
        assert_eq!(changed.unlock_with_recovery(&v.recovery_words).unwrap(), v.master_key);
    }

    #[test]
    fn bad_input() {
        assert_eq!(VaultHeader::decode(b"OSVH\x02"), Err(VaultError::BadHeader));
        assert_eq!(recovery_key("abandon abandon"), Err(VaultError::BadRecoveryWords));
        let words = recovery_words(&[7; 32]);
        let mut parts: Vec<&str> = words.split(' ').collect();
        parts[0] = if parts[0] == "abandon" { "ability" } else { "abandon" };
        assert_eq!(
            recovery_key(&parts.join(" ")),
            Err(VaultError::BadRecoveryWords),
            "checksum"
        );
    }
}

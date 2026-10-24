//! The shared host list: the Pi's addresses and the Wi-Fi names that pick
//! them, edited in the web admin and read by every Mac. Sealed like
//! everything else, so the Pi doesn't learn its users' network names.

use serde::{Deserialize, Serialize};

use crate::keys::{self, Key};

pub const MAGIC: [u8; 4] = *b"OSH1";

/// One address of the Pi. A host with no Wi-Fi names matches anywhere
/// (the tunnel). Field order is deterministic CBOR key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub url: String,
    pub name: String,
    #[serde(default)]
    pub ssids: Vec<String>,
}

/// Hosts in priority order: the first match wins, then down the list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostList {
    pub hosts: Vec<Host>,
}

pub fn hosts_key(master_key: &Key, vault_id: &[u8; 16]) -> Key {
    keys::derive(master_key, vault_id, b"offshelf/v1/hosts")
}

/// `"OSH1" || nonce || XChaCha20-Poly1305(hosts key, cbor(list), aad = "OSH1")`.
pub fn seal_hosts(master_key: &Key, vault_id: &[u8; 16], list: &HostList) -> Vec<u8> {
    let nonce: [u8; 24] = keys::random();
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend(keys::seal(
        &hosts_key(master_key, vault_id),
        &nonce,
        &MAGIC,
        &keys::to_cbor(list),
    ));
    out
}

pub fn open_hosts(master_key: &Key, vault_id: &[u8; 16], sealed: &[u8]) -> Option<HostList> {
    if sealed.len() < 4 + 24 + 16 || sealed[0..4] != MAGIC {
        return None;
    }
    let nonce: [u8; 24] = sealed[4..28].try_into().ok()?;
    let pt = keys::open(&hosts_key(master_key, vault_id), &nonce, &MAGIC, &sealed[28..])?;
    keys::from_cbor(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let list = HostList {
            hosts: vec![
                Host {
                    url: "http://192.168.1.20:8740".into(),
                    name: "Home".into(),
                    ssids: vec!["Home-5G".into()],
                },
                Host {
                    url: "https://shelf.example.net".into(),
                    name: "Away".into(),
                    ssids: vec![],
                },
            ],
        };
        let sealed = seal_hosts(&[1; 32], &[2; 16], &list);
        keys::assert_canonical_maps(&keys::to_cbor(&list));
        assert_eq!(open_hosts(&[1; 32], &[2; 16], &sealed), Some(list));
        assert_eq!(open_hosts(&[9; 32], &[2; 16], &sealed), None);
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(open_hosts(&[1; 32], &[2; 16], &bad), None);
    }
}

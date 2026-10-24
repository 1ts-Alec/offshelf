//! Arbitrary bytes as sealed log entries, snapshot headers, vault headers and
//! raw CBOR: decoding must never panic, and nothing forged may verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oshelf_core::keys;
use oshelf_core::manifest::{self, Chain, LogEntry, Node};
use oshelf_core::vault::VaultHeader;

const KM: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    assert!(Chain::GENESIS.open_next(&KM, data).is_err());
    assert!(manifest::open_snapshot_header(&KM, &[0; 16], 1, data).is_err());
    let _ = VaultHeader::decode(data);
    let _ = keys::from_cbor::<LogEntry>(data);
    let _ = keys::from_cbor::<Vec<Node>>(data);
});

//! Arbitrary bytes as a stored chunk: parsing and opening must never panic,
//! and nothing but a correctly sealed chunk may open.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oshelf_core::chunk::OVERHEAD;
use oshelf_core::{open_chunk, parse_header, seal_chunk};

const KEY: [u8; 32] = [0x42; 32];
const FILE_ID: [u8; 16] = [0x07; 16];

fuzz_target!(|data: &[u8]| {
    if parse_header(data).is_ok() {
        assert!(data.len() >= OVERHEAD);
    }
    // Bytes that weren't sealed with KEY must never open.
    assert!(open_chunk(&KEY, &FILE_ID, 0, data).is_err());

    // Round trip: whatever we seal opens to the same bytes at the same spot only.
    let stored = seal_chunk(&KEY, &FILE_ID, 3, data);
    assert_eq!(stored.len(), data.len() + OVERHEAD);
    assert_eq!(open_chunk(&KEY, &FILE_ID, 3, &stored).unwrap(), data);
    assert!(open_chunk(&KEY, &FILE_ID, 4, &stored).is_err());
});

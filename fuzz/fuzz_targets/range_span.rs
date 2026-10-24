//! The range mapper must cover exactly the requested bytes for any input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oshelf_core::chunk_span;

fuzz_target!(|input: (u64, u64, u64, u32)| {
    let (start, end, size, chunk_size) = input;
    if chunk_size == 0 {
        return;
    }
    let cs = u64::from(chunk_size);
    match chunk_span(start, end, size, chunk_size) {
        None => assert!(start >= end.min(size)),
        Some(s) => {
            let end = end.min(size);
            assert!(start < end);
            assert_eq!(s.len, end - start);
            assert!(s.first <= s.last);
            assert!(s.skip < cs);
            assert_eq!(s.first * cs + s.skip, start, "first byte is where the range starts");
            assert_eq!(s.last, (end - 1) / cs, "last chunk holds the last byte");
            assert!(s.last * cs < size, "never asks for a chunk past the end of the file");
        }
    }
});

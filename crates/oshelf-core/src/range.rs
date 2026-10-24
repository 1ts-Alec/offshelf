//! Maps a plaintext byte range onto the chunks that hold it.

/// The chunks covering a byte range and how to trim them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    /// Index of the first chunk to fetch.
    pub first: u64,
    /// Index of the last chunk to fetch (inclusive).
    pub last: u64,
    /// Bytes to drop from the start of the first chunk's plaintext.
    pub skip: u64,
    /// Total plaintext bytes to return after skipping.
    pub len: u64,
}

/// Chunks needed to serve `[start, end)` of a file of `file_size` bytes.
/// `end` is clamped to the file size. Returns `None` for an empty range.
pub fn chunk_span(start: u64, end: u64, file_size: u64, chunk_size: u32) -> Option<ChunkSpan> {
    let cs = u64::from(chunk_size);
    assert!(cs > 0, "chunk size must be positive");
    let end = end.min(file_size);
    if start >= end {
        return None;
    }
    Some(ChunkSpan {
        first: start / cs,
        last: (end - 1) / cs,
        skip: start % cs,
        len: end - start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn edges() {
        assert_eq!(chunk_span(0, 0, 10, 1 << 20), None);
        assert_eq!(chunk_span(5, 5, 10, 1 << 20), None);
        assert_eq!(chunk_span(20, 30, 10, 1 << 20), None);
        assert_eq!(
            chunk_span(0, MIB, 3 * MIB, 1 << 20),
            Some(ChunkSpan {
                first: 0,
                last: 0,
                skip: 0,
                len: MIB
            })
        );
        assert_eq!(
            chunk_span(MIB - 1, MIB + 1, 3 * MIB, 1 << 20),
            Some(ChunkSpan {
                first: 0,
                last: 1,
                skip: MIB - 1,
                len: 2
            })
        );
        assert_eq!(
            chunk_span(MIB, u64::MAX, 2 * MIB + 7, 1 << 20),
            Some(ChunkSpan {
                first: 1,
                last: 2,
                skip: 0,
                len: MIB + 7
            })
        );
    }

    /// Every byte of the range is covered exactly once, with a tiny chunk size
    /// so all the boundaries get exercised.
    #[test]
    fn exhaustive_small() {
        let cs = 4u32;
        let size = 23u64;
        for start in 0..=size + 2 {
            for end in 0..=size + 2 {
                let Some(span) = chunk_span(start, end, size, cs) else {
                    assert!(start >= end.min(size));
                    continue;
                };
                let mut got = Vec::new();
                for idx in span.first..=span.last {
                    let lo = idx * cs as u64;
                    let hi = (lo + cs as u64).min(size);
                    got.extend(lo..hi);
                }
                let got: Vec<u64> = got
                    .into_iter()
                    .skip(span.skip as usize)
                    .take(span.len as usize)
                    .collect();
                let want: Vec<u64> = (start..end.min(size)).collect();
                assert_eq!(got, want, "start={start} end={end}");
            }
        }
    }
}

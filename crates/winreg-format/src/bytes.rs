//! Bounds-checked little-endian readers (panic-free on crafted offsets).
//!
//! Registry cells are untrusted input; an out-of-range read yields a zero value
//! instead of an out-of-bounds slice panic, keeping the parser panic-free even
//! if a caller's bounds guard is ever broken (defence-in-depth).

/// Read a little-endian `u32` at `off`, or `0` if `off..off+4` is out of range.
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    data.get(off..off.wrapping_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Read 4 raw bytes at `off`, or `[0; 4]` if `off..off+4` is out of range.
#[must_use]
pub fn read4(data: &[u8], off: usize) -> [u8; 4] {
    data.get(off..off.wrapping_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .unwrap_or([0; 4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_u32_reads_and_guards() {
        assert_eq!(le_u32(&[1, 0, 0, 0], 0), 1);
        assert_eq!(le_u32(&[1, 2, 3], 0), 0);
        assert_eq!(le_u32(&[0; 4], usize::MAX), 0);
    }

    #[test]
    fn read4_reads_and_guards() {
        assert_eq!(read4(&[1, 2, 3, 4, 5], 1), [2, 3, 4, 5]);
        assert_eq!(read4(&[1, 2], 0), [0; 4]);
        assert_eq!(read4(&[0; 4], usize::MAX), [0; 4]);
    }
}

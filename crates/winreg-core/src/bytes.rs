//! Bounds-checked little-endian integer readers.
//!
//! Registry hives are untrusted, attacker-controllable input. These helpers
//! read fixed-width integers without ever panicking on a crafted offset/length:
//! an out-of-range read yields `0` rather than an out-of-bounds slice panic.
//! Using them (instead of `data[a..b].try_into().unwrap()`) keeps the parser
//! panic-free even if a future change breaks a caller's bounds guard — the
//! defence-in-depth the Paranoid-Gatekeeper standard requires.

/// Read a little-endian `u32` at `off`, or `0` if `off..off+4` is out of range.
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    data.get(off..off.wrapping_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Read a little-endian `u64` at `off`, or `0` if `off..off+8` is out of range.
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    data.get(off..off.wrapping_add(8))
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map_or(0, u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_u32_reads_value() {
        assert_eq!(le_u32(&[0x01, 0x02, 0x03, 0x04], 0), 0x0403_0201);
        assert_eq!(le_u32(&[0xFF, 0x01, 0x02, 0x03, 0x04], 1), 0x0403_0201);
    }

    #[test]
    fn le_u32_out_of_range_is_zero_not_panic() {
        assert_eq!(le_u32(&[1, 2, 3], 0), 0); // too short
        assert_eq!(le_u32(&[1, 2, 3, 4], 2), 0); // off+4 overruns
        assert_eq!(le_u32(&[], 0), 0);
        assert_eq!(le_u32(&[1, 2, 3, 4], usize::MAX), 0); // no overflow panic
    }

    #[test]
    fn le_u64_reads_value_and_guards() {
        assert_eq!(le_u64(&[1, 0, 0, 0, 0, 0, 0, 0], 0), 1);
        assert_eq!(le_u64(&[1, 2, 3, 4, 5, 6, 7], 0), 0); // too short
        assert_eq!(le_u64(&[0; 8], usize::MAX), 0); // no overflow panic
    }
}

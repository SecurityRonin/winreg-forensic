//! Hive bin (hbin) header — 32-byte container header within a hive file.

use binrw::BinRead;

/// Hive bin header (32 bytes). Hive bins immediately follow the 4096-byte
/// base block and contain all cells (keys, values, security descriptors, etc.).
///
/// Reference: research/regf-binary-format-specification.md Section 2.1
#[derive(Debug, Clone, BinRead)]
#[br(little, magic = b"hbin")]
pub struct HbinHeader {
    /// Offset of this hbin from the start of hive bins data (NOT file start).
    /// First hbin has offset 0.
    pub offset: u32,
    /// Size of this hbin in bytes (including 32-byte header). Always multiple of 4096.
    pub size: u32,
    /// Reserved (8 bytes). Typically zero.
    pub reserved: u64,
    /// FILETIME timestamp. Only meaningful for the first hbin.
    pub timestamp: u64,
    /// Runtime spare/memory allocation field. No meaning on disk.
    pub spare: u32,
}

impl HbinHeader {
    /// Size of the hbin header in bytes.
    pub const SIZE: u32 = 32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_test_hbin(offset: u32, size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(b"hbin");
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
        buf[8..12].copy_from_slice(&size.to_le_bytes());
        buf
    }

    #[test]
    fn parse_hbin_header() {
        let buf = build_test_hbin(0, 4096);
        let mut cursor = Cursor::new(&buf[..]);
        let hbin = HbinHeader::read(&mut cursor).unwrap();
        assert_eq!(hbin.offset, 0);
        assert_eq!(hbin.size, 4096);
    }

    #[test]
    fn parse_second_hbin_with_offset() {
        let buf = build_test_hbin(4096, 8192);
        let mut cursor = Cursor::new(&buf[..]);
        let hbin = HbinHeader::read(&mut cursor).unwrap();
        assert_eq!(hbin.offset, 4096);
        assert_eq!(hbin.size, 8192);
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut buf = build_test_hbin(0, 4096);
        buf[0..4].copy_from_slice(b"nope");
        let mut cursor = Cursor::new(&buf[..]);
        assert!(HbinHeader::read(&mut cursor).is_err());
    }
}

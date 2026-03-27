//! REGF base block (header) — first 4096 bytes of a hive file.

use binrw::BinRead;

/// REGF base block header (first 512 bytes of the 4096-byte header block).
///
/// Reference: research/regf-binary-format-specification.md Section 1.1
#[derive(Debug, Clone, BinRead)]
#[br(little, magic = b"regf")]
pub struct BaseBlock {
    /// Incremented on each write; must match secondary if hive was properly synced.
    pub primary_sequence: u32,
    /// Updated after successful write; mismatch = dirty hive.
    pub secondary_sequence: u32,
    /// FILETIME (UTC). Not updated as of Windows 8.1.
    pub last_written: u64,
    /// Always 1 for all known Windows versions.
    pub major_version: u32,
    /// 0-2 (NT 3.x), 3 (NT 4.0), 5 (XP+), 6 (Win10+ differencing).
    pub minor_version: u32,
    /// 0 = primary, 1 = transaction log, 2 = alternate (Win2000 SYSTEM.ALT).
    pub file_type: u32,
    /// Always 1 (direct memory load).
    pub format: u32,
    /// Offset to root key node cell, relative to hive bins data start.
    pub root_cell_offset: u32,
    /// Total size of all hive bins in bytes.
    pub hive_bins_data_size: u32,
    /// Logical sector size / 512. Typically 1 or 8.
    pub clustering_factor: u32,
    /// Internal hive path, UTF-16LE, 64 bytes. May contain remnant data.
    pub file_name: [u8; 64],
    /// Resource Manager GUID (Vista+). Null if CLFS not used.
    pub rm_id: [u8; 16],
    /// Log GUID. Usually same as `rm_id`.
    pub log_id: [u8; 16],
    /// Bit mask: 0x1 = pending txns, 0x2 = differencing hive.
    pub flags: u32,
    /// Transaction Manager GUID.
    pub tm_id: [u8; 16],
    /// "rmtm" signature validating GUID fields are present.
    pub guid_signature: u32,
    /// FILETIME of latest hive reorganization (Win8+).
    pub last_reorganize_time: u64,
    /// Reserved (332 bytes = 83 DWORDs).
    #[br(count = 332)]
    pub reserved1: Vec<u8>,
    /// XOR-32 checksum of first 508 bytes (offsets 0x000-0x1FB).
    pub checksum: u32,
}

impl BaseBlock {
    /// Size of the base block in the file (always 4096 bytes).
    pub const SIZE: usize = 4096;

    /// Validate the XOR-32 checksum.
    ///
    /// Algorithm: XOR all 127 u32 LE words from offsets 0x000-0x1FB.
    /// Special cases: result 0 becomes 1, result 0xFFFFFFFF becomes 0xFFFFFFFE.
    pub fn validate_checksum(header_bytes: &[u8]) -> bool {
        if header_bytes.len() < 512 {
            return false;
        }
        let computed = Self::compute_checksum(header_bytes);
        let stored = u32::from_le_bytes([
            header_bytes[0x1FC],
            header_bytes[0x1FD],
            header_bytes[0x1FE],
            header_bytes[0x1FF],
        ]);
        computed == stored
    }

    /// Compute the XOR-32 checksum over the first 508 bytes.
    pub fn compute_checksum(header_bytes: &[u8]) -> u32 {
        let mut checksum: u32 = 0;
        for i in 0..127 {
            let offset = i * 4;
            let word = u32::from_le_bytes([
                header_bytes[offset],
                header_bytes[offset + 1],
                header_bytes[offset + 2],
                header_bytes[offset + 3],
            ]);
            checksum ^= word;
        }
        if checksum == 0 {
            checksum = 1;
        }
        if checksum == 0xFFFF_FFFF {
            checksum = 0xFFFF_FFFE;
        }
        checksum
    }

    /// Check if primary and secondary sequence numbers match (clean hive).
    pub fn is_clean(&self) -> bool {
        self.primary_sequence == self.secondary_sequence
    }

    /// Decode the internal file name from UTF-16LE.
    pub fn file_name_string(&self) -> String {
        let u16s: Vec<u16> = self
            .file_name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&u16s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal valid 512-byte base block header for testing.
    fn build_test_header() -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        // Signature "regf"
        buf[0..4].copy_from_slice(b"regf");
        // Primary sequence = 1
        buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        // Secondary sequence = 1
        buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
        // Major version = 1
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        // Minor version = 5
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
        // Format = 1
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        // Root cell offset = 32 (0x20)
        buf[0x24..0x28].copy_from_slice(&32u32.to_le_bytes());
        // Hive bins data size = 4096
        buf[0x28..0x2C].copy_from_slice(&4096u32.to_le_bytes());
        // Clustering factor = 1
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        // Compute and store checksum
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    #[test]
    fn parse_base_block_from_bytes() {
        let buf = build_test_header();
        let mut cursor = Cursor::new(&buf[..]);
        let header = BaseBlock::read(&mut cursor).expect("should parse valid header");
        assert_eq!(header.major_version, 1);
        assert_eq!(header.minor_version, 5);
        assert_eq!(header.root_cell_offset, 32);
        assert_eq!(header.hive_bins_data_size, 4096);
        assert!(header.is_clean());
    }

    #[test]
    fn checksum_validates_on_clean_header() {
        let buf = build_test_header();
        assert!(BaseBlock::validate_checksum(&buf));
    }

    #[test]
    fn checksum_fails_on_corrupt_header() {
        let mut buf = build_test_header();
        buf[0x14] = 0xFF; // corrupt major version
        assert!(!BaseBlock::validate_checksum(&buf));
    }

    #[test]
    fn checksum_special_case_zero_becomes_one() {
        // Construct a header where XOR of all 127 words would be 0 before adjustment.
        // Word 0 = b"regf" = 0x66676572.
        // Place the same value at word 1 (offset 4) so they cancel: 0x66676572 ^ 0x66676572 = 0.
        // All other words are zero, so total XOR = 0 → special case returns 1.
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(b"regf");
        let checksum = BaseBlock::compute_checksum(&buf);
        assert_eq!(checksum, 1, "zero checksum should become 1");
    }

    #[test]
    fn dirty_hive_detection() {
        let mut buf = build_test_header();
        // Make primary != secondary
        buf[0x04..0x08].copy_from_slice(&2u32.to_le_bytes());
        // Recompute checksum
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        let mut cursor = Cursor::new(&buf[..]);
        let header = BaseBlock::read(&mut cursor).unwrap();
        assert!(!header.is_clean());
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut buf = build_test_header();
        buf[0..4].copy_from_slice(b"nope");
        let mut cursor = Cursor::new(&buf[..]);
        assert!(BaseBlock::read(&mut cursor).is_err());
    }
}

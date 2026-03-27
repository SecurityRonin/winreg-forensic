//! `Hive` — the entry point for reading a Windows Registry hive.

use std::io::{Cursor, Read, Seek};

use winreg_format::header::BaseBlock;
use winreg_format::version::RegfVersion;

use crate::error::{HiveError, Result};

use binrw::BinRead;

/// `ReadSeek` trait alias for convenience.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Descriptor for a cataloged hive bin.
#[derive(Debug, Clone)]
pub struct HbinDescriptor {
    /// Offset of this hbin from start of hive bins data.
    pub offset: u32,
    /// Size of this hbin in bytes.
    pub size: u32,
    /// File offset where this hbin starts.
    pub file_offset: u64,
}

/// A parsed Windows Registry hive file.
///
/// Generic over `R: ReadSeek` to support mmap, in-memory buffers, and overlays.
pub struct Hive<R: ReadSeek> {
    // Used by CellReader (Task 8) and future I/O methods.
    #[allow(dead_code)]
    pub(crate) reader: R,
    pub(crate) header: BaseBlock,
    pub(crate) version: RegfVersion,
    pub(crate) bins: Vec<HbinDescriptor>,
    /// Raw header bytes (first 4096) — kept for checksum validation and transaction log replay.
    #[allow(dead_code)]
    pub(crate) header_bytes: Vec<u8>,
}

impl Hive<Cursor<Vec<u8>>> {
    /// Open a hive from an in-memory byte buffer.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < BaseBlock::SIZE {
            return Err(HiveError::TruncatedHive {
                expected: BaseBlock::SIZE as u64,
                actual: data.len() as u64,
            });
        }

        // Parse base block.
        let mut cursor = Cursor::new(data.clone());
        let header = BaseBlock::read(&mut cursor).map_err(|_| HiveError::InvalidSignature)?;

        // Validate checksum.
        if !BaseBlock::validate_checksum(&data) {
            let computed = BaseBlock::compute_checksum(&data);
            let expected = u32::from_le_bytes([data[0x1FC], data[0x1FD], data[0x1FE], data[0x1FF]]);
            return Err(HiveError::ChecksumMismatch { expected, computed });
        }

        // Determine version.
        let version =
            RegfVersion::from_minor(header.minor_version).ok_or(HiveError::UnsupportedVersion {
                major: header.major_version,
                minor: header.minor_version,
            })?;

        // Catalog hive bins.
        let header_bytes = data[..BaseBlock::SIZE].to_vec();
        let bins_data_start = BaseBlock::SIZE as u64;
        let bins_data_size = u64::from(header.hive_bins_data_size);
        let bins = catalog_hbins(&data, bins_data_start, bins_data_size)?;

        let reader = Cursor::new(data);
        Ok(Self {
            reader,
            header,
            version,
            bins,
            header_bytes,
        })
    }

    /// Open a hive from a file path.
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }
}

impl<R: ReadSeek> Hive<R> {
    /// The REGF format version of this hive.
    pub fn version(&self) -> RegfVersion {
        self.version
    }

    /// Whether the hive was cleanly synchronized (primary == secondary sequence).
    pub fn is_clean(&self) -> bool {
        self.header.is_clean()
    }

    /// Root cell offset (relative to hive bins data start).
    pub fn root_cell_offset(&self) -> winreg_format::cells::CellOffset {
        winreg_format::cells::CellOffset(self.header.root_cell_offset)
    }

    /// Total hive bins data size in bytes.
    pub fn hive_bins_data_size(&self) -> u32 {
        self.header.hive_bins_data_size
    }

    /// Number of hive bins.
    pub fn bin_count(&self) -> usize {
        self.bins.len()
    }

    /// Internal file name from the header.
    pub fn file_name(&self) -> String {
        self.header.file_name_string()
    }

    /// The hbin descriptors.
    pub fn bins(&self) -> &[HbinDescriptor] {
        &self.bins
    }
}

/// Walk the hive bins data and build a catalog of all hbins.
fn catalog_hbins(data: &[u8], start: u64, expected_size: u64) -> Result<Vec<HbinDescriptor>> {
    let mut bins = Vec::new();
    let mut pos = start;
    let end = start + expected_size;

    while pos < end {
        let file_offset = pos;
        let pos_usize = usize::try_from(pos).unwrap_or(usize::MAX);

        if pos_usize.saturating_add(32) > data.len() {
            break; // Truncated — stop cataloging
        }

        // Check hbin signature.
        let sig = &data[pos_usize..pos_usize + 4];
        if sig != b"hbin" {
            return Err(HiveError::InvalidHbin { file_offset });
        }

        let offset = u32::from_le_bytes(data[pos_usize + 4..pos_usize + 8].try_into().unwrap());
        let size = u32::from_le_bytes(data[pos_usize + 8..pos_usize + 12].try_into().unwrap());

        if size == 0 || size % 4096 != 0 {
            break; // Invalid size — stop
        }

        bins.push(HbinDescriptor {
            offset,
            size,
            file_offset,
        });

        pos += u64::from(size);
    }

    Ok(bins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg_format::header::BaseBlock;

    /// Build a minimal valid hive with one hbin containing a root NK cell.
    fn build_minimal_hive() -> Vec<u8> {
        let hbin_size: u32 = 4096;
        let total_size = BaseBlock::SIZE + hbin_size as usize;
        let mut buf = vec![0u8; total_size];

        // Base block header
        buf[0..4].copy_from_slice(b"regf");
        buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes()); // primary seq
        buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes()); // secondary seq
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version = 1.5
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // format = 1
        buf[0x24..0x28].copy_from_slice(&32u32.to_le_bytes()); // root cell offset = 32
        buf[0x28..0x2C].copy_from_slice(&hbin_size.to_le_bytes()); // hive bins data size
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor

        // Compute checksum
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        // Hbin header at offset 4096
        let hbin_start = BaseBlock::SIZE;
        buf[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");
        buf[hbin_start + 4..hbin_start + 8].copy_from_slice(&0u32.to_le_bytes()); // offset = 0
        buf[hbin_start + 8..hbin_start + 12].copy_from_slice(&hbin_size.to_le_bytes()); // size

        // Root NK cell at hbin offset 32 (= file offset 4096 + 32 = 4128)
        let cell_start = hbin_start + 32;
        let cell_size: i32 = -128; // allocated, 128 bytes
        buf[cell_start..cell_start + 4].copy_from_slice(&cell_size.to_le_bytes());
        buf[cell_start + 4..cell_start + 6].copy_from_slice(b"nk");
        // flags: HIVE_ENTRY | COMP_NAME = 0x0024
        buf[cell_start + 6..cell_start + 8].copy_from_slice(&0x0024u16.to_le_bytes());

        // Fill remaining hbin space with a free cell
        let free_start = cell_start + 128;
        let free_size = (hbin_size as usize) - 32 - 128;
        buf[free_start..free_start + 4].copy_from_slice(&(free_size as i32).to_le_bytes());

        buf
    }

    #[test]
    fn open_minimal_hive() {
        let data = build_minimal_hive();
        let hive = Hive::from_bytes(data).expect("should open minimal hive");
        assert_eq!(hive.version(), RegfVersion::V1_5);
        assert!(hive.is_clean());
        assert_eq!(hive.bin_count(), 1);
        assert_eq!(hive.hive_bins_data_size(), 4096);
    }

    #[test]
    fn rejects_truncated_file() {
        let data = vec![0u8; 100];
        assert!(matches!(
            Hive::from_bytes(data),
            Err(HiveError::TruncatedHive { .. })
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut data = build_minimal_hive();
        data[0..4].copy_from_slice(b"nope");
        assert!(matches!(
            Hive::from_bytes(data),
            Err(HiveError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut data = build_minimal_hive();
        data[0x14] = 0xFF;
        assert!(matches!(
            Hive::from_bytes(data),
            Err(HiveError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn catalogs_hbin_descriptors() {
        let hive = Hive::from_bytes(build_minimal_hive()).unwrap();
        let bins = hive.bins();
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].offset, 0);
        assert_eq!(bins[0].size, 4096);
        assert_eq!(bins[0].file_offset, 4096);
    }
}

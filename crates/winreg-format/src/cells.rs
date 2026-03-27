//! Cell types and the `CellOffset` newtype.

use binrw::BinRead;

/// Offset to a cell within hive bins data.
///
/// All cell offsets in the REGF format are relative to the start of the hive
/// bins data area (which begins at file offset 4096). This newtype prevents
/// accidentally mixing cell offsets with file offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BinRead)]
#[br(little)]
pub struct CellOffset(pub u32);

impl CellOffset {
    /// Null/empty sentinel value (0xFFFFFFFF).
    pub const NULL: Self = Self(0xFFFF_FFFF);

    /// Convert a cell offset to an absolute file offset.
    ///
    /// `file_offset = 4096 + cell_offset`
    pub fn file_offset(self) -> u64 {
        4096 + u64::from(self.0)
    }

    /// Check if this is a null/empty reference.
    pub fn is_null(self) -> bool {
        self.0 == 0xFFFF_FFFF
    }
}

impl std::fmt::Display for CellOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_null() {
            write!(f, "NULL")
        } else {
            write!(f, "0x{:08X}", self.0)
        }
    }
}

/// Raw cell header — the first 4 bytes of every cell.
///
/// Cell size is a signed i32:
/// - **Negative** = allocated cell (use absolute value for size)
/// - **Positive** = free/unallocated cell
///
/// All cell sizes are 8-byte aligned.
#[derive(Debug, Clone, Copy)]
pub struct CellHeader {
    /// Raw size field (negative = allocated, positive = free).
    pub raw_size: i32,
}

impl CellHeader {
    /// Parse cell header from 4 bytes.
    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        Self {
            raw_size: i32::from_le_bytes(*bytes),
        }
    }

    /// Whether this cell is allocated.
    pub fn is_allocated(&self) -> bool {
        self.raw_size < 0
    }

    /// Absolute cell size in bytes (including the 4-byte size field).
    pub fn size(&self) -> u32 {
        self.raw_size.unsigned_abs()
    }
}

/// Two-byte cell signature identifying the cell type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellSignature {
    /// `nk` — Key Node
    KeyNode,
    /// `vk` — Key Value
    KeyValue,
    /// `sk` — Security Key
    SecurityKey,
    /// `lf` — Fast Leaf (subkey index with name hints)
    FastLeaf,
    /// `lh` — Hash Leaf (subkey index with name hashes)
    HashLeaf,
    /// `li` — Index Leaf (simple subkey index)
    IndexLeaf,
    /// `ri` — Root Index (index of subkey indices)
    RootIndex,
    /// `db` — Big Data
    BigData,
}

impl CellSignature {
    /// Parse a 2-byte signature.
    pub fn from_bytes(bytes: &[u8; 2]) -> Option<Self> {
        match bytes {
            b"nk" => Some(Self::KeyNode),
            b"vk" => Some(Self::KeyValue),
            b"sk" => Some(Self::SecurityKey),
            b"lf" => Some(Self::FastLeaf),
            b"lh" => Some(Self::HashLeaf),
            b"li" => Some(Self::IndexLeaf),
            b"ri" => Some(Self::RootIndex),
            b"db" => Some(Self::BigData),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_offset_file_conversion() {
        let offset = CellOffset(0x20);
        assert_eq!(offset.file_offset(), 4096 + 0x20);
    }

    #[test]
    fn cell_offset_null() {
        assert!(CellOffset::NULL.is_null());
        assert!(!CellOffset(0).is_null());
    }

    #[test]
    fn cell_offset_display() {
        assert_eq!(format!("{}", CellOffset::NULL), "NULL");
        assert_eq!(format!("{}", CellOffset(0x20)), "0x00000020");
    }

    #[test]
    fn cell_header_allocated() {
        let bytes = (-128i32).to_le_bytes();
        let header = CellHeader::from_bytes(&bytes);
        assert!(header.is_allocated());
        assert_eq!(header.size(), 128);
    }

    #[test]
    fn cell_header_free() {
        let bytes = 64i32.to_le_bytes();
        let header = CellHeader::from_bytes(&bytes);
        assert!(!header.is_allocated());
        assert_eq!(header.size(), 64);
    }

    #[test]
    fn cell_signatures() {
        assert_eq!(CellSignature::from_bytes(b"nk"), Some(CellSignature::KeyNode));
        assert_eq!(CellSignature::from_bytes(b"vk"), Some(CellSignature::KeyValue));
        assert_eq!(CellSignature::from_bytes(b"sk"), Some(CellSignature::SecurityKey));
        assert_eq!(CellSignature::from_bytes(b"lf"), Some(CellSignature::FastLeaf));
        assert_eq!(CellSignature::from_bytes(b"lh"), Some(CellSignature::HashLeaf));
        assert_eq!(CellSignature::from_bytes(b"li"), Some(CellSignature::IndexLeaf));
        assert_eq!(CellSignature::from_bytes(b"ri"), Some(CellSignature::RootIndex));
        assert_eq!(CellSignature::from_bytes(b"db"), Some(CellSignature::BigData));
        assert_eq!(CellSignature::from_bytes(b"xx"), None);
    }
}

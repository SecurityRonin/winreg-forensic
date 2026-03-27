//! Cell types and the `CellOffset` newtype.

use binrw::BinRead;
use crate::flags::{KeyFlags, ValueFlags, ValueType};

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

/// Raw NK (Key Node) cell data — parsed from bytes after the cell size field.
///
/// Fixed header: 76 bytes (0x4C) + variable-length key name.
#[derive(Debug, Clone)]
pub struct RawKeyNode {
    pub flags: KeyFlags,
    pub last_written: u64,
    pub access_bits: u32,
    pub parent: CellOffset,
    pub subkey_count: u32,
    pub volatile_subkey_count: u32,
    pub subkeys_list_offset: CellOffset,
    pub volatile_subkeys_list_offset: CellOffset,
    pub value_count: u32,
    pub values_list_offset: CellOffset,
    pub security_offset: CellOffset,
    pub class_name_offset: CellOffset,
    pub max_subkey_name_compound: u32,
    pub max_subkey_class_len: u32,
    pub max_value_name_len: u32,
    pub max_value_data_size: u32,
    pub work_var: u32,
    pub key_name_len: u16,
    pub class_name_len: u16,
    pub key_name_raw: Vec<u8>,
}

impl RawKeyNode {
    pub const HEADER_SIZE: usize = 0x4C;

    /// Parse an NK cell from a byte slice (starting after the 2-byte "nk" signature).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE - 2 {
            return None;
        }
        let flags = KeyFlags::from_bits_truncate(u16::from_le_bytes([data[0], data[1]]));
        let last_written = u64::from_le_bytes(data[2..10].try_into().ok()?);
        let access_bits = u32::from_le_bytes(data[10..14].try_into().ok()?);
        let parent = CellOffset(u32::from_le_bytes(data[14..18].try_into().ok()?));
        let subkey_count = u32::from_le_bytes(data[18..22].try_into().ok()?);
        let volatile_subkey_count = u32::from_le_bytes(data[22..26].try_into().ok()?);
        let subkeys_list_offset = CellOffset(u32::from_le_bytes(data[26..30].try_into().ok()?));
        let volatile_subkeys_list_offset = CellOffset(u32::from_le_bytes(data[30..34].try_into().ok()?));
        let value_count = u32::from_le_bytes(data[34..38].try_into().ok()?);
        let values_list_offset = CellOffset(u32::from_le_bytes(data[38..42].try_into().ok()?));
        let security_offset = CellOffset(u32::from_le_bytes(data[42..46].try_into().ok()?));
        let class_name_offset = CellOffset(u32::from_le_bytes(data[46..50].try_into().ok()?));
        let max_subkey_name_compound = u32::from_le_bytes(data[50..54].try_into().ok()?);
        let max_subkey_class_len = u32::from_le_bytes(data[54..58].try_into().ok()?);
        let max_value_name_len = u32::from_le_bytes(data[58..62].try_into().ok()?);
        let max_value_data_size = u32::from_le_bytes(data[62..66].try_into().ok()?);
        let work_var = u32::from_le_bytes(data[66..70].try_into().ok()?);
        let key_name_len = u16::from_le_bytes([data[70], data[71]]);
        let class_name_len = u16::from_le_bytes([data[72], data[73]]);

        let name_start = 74;
        let name_end = name_start + usize::from(key_name_len);
        if data.len() < name_end {
            return None;
        }
        let key_name_raw = data[name_start..name_end].to_vec();

        Some(Self {
            flags, last_written, access_bits, parent, subkey_count,
            volatile_subkey_count, subkeys_list_offset, volatile_subkeys_list_offset,
            value_count, values_list_offset, security_offset, class_name_offset,
            max_subkey_name_compound, max_subkey_class_len, max_value_name_len,
            max_value_data_size, work_var, key_name_len, class_name_len, key_name_raw,
        })
    }

    pub fn key_name(&self) -> String {
        if self.flags.contains(KeyFlags::COMP_NAME) {
            self.key_name_raw.iter().map(|&b| b as char).collect()
        } else {
            let u16s: Vec<u16> = self.key_name_raw.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u16s)
        }
    }

    pub fn is_root(&self) -> bool {
        self.flags.contains(KeyFlags::HIVE_ENTRY)
    }
}

/// Raw VK (Key Value) cell data — parsed from bytes after the cell size field.
///
/// Fixed header: 20 bytes (0x14) + variable-length value name.
#[derive(Debug, Clone)]
pub struct RawKeyValue {
    pub name_len: u16,
    pub data_size_raw: u32,
    pub data_offset_raw: u32,
    pub data_type: ValueType,
    pub flags: ValueFlags,
    pub name_raw: Vec<u8>,
}

impl RawKeyValue {
    pub const HEADER_SIZE: usize = 0x14;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE - 2 {
            return None;
        }
        let name_len = u16::from_le_bytes([data[0], data[1]]);
        let data_size_raw = u32::from_le_bytes(data[2..6].try_into().ok()?);
        let data_offset_raw = u32::from_le_bytes(data[6..10].try_into().ok()?);
        let data_type = ValueType::from_raw(u32::from_le_bytes(data[10..14].try_into().ok()?));
        let flags = ValueFlags::from_bits_truncate(u16::from_le_bytes([data[14], data[15]]));

        let name_start = 18;
        let name_end = name_start + usize::from(name_len);
        if data.len() < name_end {
            return None;
        }
        let name_raw = data[name_start..name_end].to_vec();

        Some(Self { name_len, data_size_raw, data_offset_raw, data_type, flags, name_raw })
    }

    pub fn is_resident(&self) -> bool {
        self.data_size_raw & 0x8000_0000 != 0
    }

    pub fn data_size(&self) -> u32 {
        self.data_size_raw & 0x7FFF_FFFF
    }

    pub fn data_offset(&self) -> CellOffset {
        CellOffset(self.data_offset_raw)
    }

    pub fn inline_data(&self) -> Vec<u8> {
        let size = self.data_size() as usize;
        let bytes = self.data_offset_raw.to_le_bytes();
        bytes[..size.min(4)].to_vec()
    }

    pub fn value_name(&self) -> String {
        if self.name_len == 0 {
            return String::new();
        }
        if self.flags.contains(ValueFlags::COMP_NAME) {
            self.name_raw.iter().map(|&b| b as char).collect()
        } else {
            let u16s: Vec<u16> = self.name_raw.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u16s)
        }
    }
}

#[cfg(test)]
mod nk_vk_tests {
    use super::*;
    use crate::flags::KeyFlags;

    fn build_nk_bytes(name: &str, flags: KeyFlags, subkey_count: u32, value_count: u32) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut buf = vec![0u8; 74 + name_bytes.len()];
        buf[0..2].copy_from_slice(&flags.bits().to_le_bytes());
        buf[2..10].copy_from_slice(&1000u64.to_le_bytes());
        buf[14..18].copy_from_slice(&0x20u32.to_le_bytes());
        buf[18..22].copy_from_slice(&subkey_count.to_le_bytes());
        let sk_offset = if subkey_count > 0 { 0x100u32 } else { 0xFFFF_FFFFu32 };
        buf[26..30].copy_from_slice(&sk_offset.to_le_bytes());
        buf[34..38].copy_from_slice(&value_count.to_le_bytes());
        let vl_offset = if value_count > 0 { 0x200u32 } else { 0xFFFF_FFFFu32 };
        buf[38..42].copy_from_slice(&vl_offset.to_le_bytes());
        buf[42..46].copy_from_slice(&0x300u32.to_le_bytes());
        buf[46..50].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf[70..72].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf[74..74 + name_bytes.len()].copy_from_slice(name_bytes);
        buf
    }

    #[test]
    fn parse_nk_root_key() {
        let data = build_nk_bytes("CMI-CreateHive{2A7FB991}", KeyFlags::HIVE_ENTRY | KeyFlags::COMP_NAME, 3, 0);
        let nk = RawKeyNode::parse(&data).unwrap();
        assert!(nk.is_root());
        assert_eq!(nk.key_name(), "CMI-CreateHive{2A7FB991}");
        assert_eq!(nk.subkey_count, 3);
        assert_eq!(nk.value_count, 0);
        assert!(nk.flags.contains(KeyFlags::COMP_NAME));
    }

    #[test]
    fn parse_nk_child_key() {
        let data = build_nk_bytes("Software", KeyFlags::COMP_NAME, 0, 2);
        let nk = RawKeyNode::parse(&data).unwrap();
        assert!(!nk.is_root());
        assert_eq!(nk.key_name(), "Software");
        assert_eq!(nk.value_count, 2);
    }

    #[test]
    fn nk_rejects_truncated_data() {
        let data = vec![0u8; 10];
        assert!(RawKeyNode::parse(&data).is_none());
    }

    fn build_vk_bytes(name: &str, data_type: u32, data_size: u32, data_offset: u32) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let comp_flag: u16 = if name.is_empty() { 0 } else { 0x0001 };
        let mut buf = vec![0u8; 18 + name_bytes.len()];
        buf[0..2].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf[2..6].copy_from_slice(&data_size.to_le_bytes());
        buf[6..10].copy_from_slice(&data_offset.to_le_bytes());
        buf[10..14].copy_from_slice(&data_type.to_le_bytes());
        buf[14..16].copy_from_slice(&comp_flag.to_le_bytes());
        buf[18..18 + name_bytes.len()].copy_from_slice(name_bytes);
        buf
    }

    #[test]
    fn parse_vk_dword_resident() {
        let data = build_vk_bytes("Start", 4, 0x8000_0004, 0x0000_0003);
        let vk = RawKeyValue::parse(&data).unwrap();
        assert_eq!(vk.value_name(), "Start");
        assert!(matches!(vk.data_type, ValueType::Dword));
        assert!(vk.is_resident());
        assert_eq!(vk.data_size(), 4);
        assert_eq!(vk.inline_data(), vec![3, 0, 0, 0]);
    }

    #[test]
    fn parse_vk_string_non_resident() {
        let data = build_vk_bytes("ImagePath", 1, 42, 0x500);
        let vk = RawKeyValue::parse(&data).unwrap();
        assert_eq!(vk.value_name(), "ImagePath");
        assert!(matches!(vk.data_type, ValueType::Sz));
        assert!(!vk.is_resident());
        assert_eq!(vk.data_size(), 42);
        assert_eq!(vk.data_offset(), CellOffset(0x500));
    }

    #[test]
    fn parse_vk_unnamed_default_value() {
        let data = build_vk_bytes("", 1, 10, 0x600);
        let vk = RawKeyValue::parse(&data).unwrap();
        assert_eq!(vk.value_name(), "");
        assert_eq!(vk.name_len, 0);
    }

    #[test]
    fn vk_rejects_truncated_data() {
        let data = vec![0u8; 5];
        assert!(RawKeyValue::parse(&data).is_none());
    }
}

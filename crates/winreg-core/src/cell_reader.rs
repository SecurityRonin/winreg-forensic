//! Cell reading — read typed cells from a hive by offset.

use std::io::Cursor;

use winreg_format::cells::{
    CellHeader, CellOffset, CellSignature, RawBigData, RawKeyNode, RawKeyValue, RawSecurityKey,
    SubkeyIndex,
};

use crate::error::{HiveError, Result};
use crate::hive::Hive;

/// Typed cell content after dispatching on signature.
#[derive(Debug)]
pub enum Cell {
    KeyNode(RawKeyNode),
    KeyValue(RawKeyValue),
    SecurityKey(RawSecurityKey),
    Index(SubkeyIndex),
    BigData(RawBigData),
    /// Raw data cell (no recognized signature — value data, class name, etc.).
    Data(Vec<u8>),
}

impl Hive<Cursor<Vec<u8>>> {
    /// Read raw bytes at a cell offset. Returns (`cell_header`, `cell_body_bytes`).
    pub fn read_cell_raw(&self, offset: CellOffset) -> Result<(CellHeader, Vec<u8>)> {
        if offset.is_null() {
            return Err(HiveError::NullOffset);
        }

        #[allow(clippy::cast_possible_truncation)]
        let file_offset = offset.file_offset() as usize;
        let data = self.reader.get_ref();

        if file_offset + 4 > data.len() {
            return Err(HiveError::CellOverflow {
                offset,
                cell_size: 0,
                hbin_end: data.len() as u64,
            });
        }

        let header_bytes: [u8; 4] = data[file_offset..file_offset + 4]
            .try_into()
            .unwrap();
        let header = CellHeader::from_bytes(&header_bytes);

        if !header.is_allocated() {
            return Err(HiveError::UnallocatedCell { offset });
        }

        let size = header.size() as usize;
        let end = file_offset + size;
        if end > data.len() {
            return Err(HiveError::CellOverflow {
                offset,
                cell_size: header.size(),
                hbin_end: data.len() as u64,
            });
        }

        let body = data[file_offset + 4..end].to_vec();
        Ok((header, body))
    }

    /// Read and parse a typed cell at the given offset.
    pub fn read_cell(&self, offset: CellOffset) -> Result<Cell> {
        let (_header, body) = self.read_cell_raw(offset)?;

        if body.len() < 2 {
            return Ok(Cell::Data(body));
        }

        let sig_bytes: [u8; 2] = [body[0], body[1]];
        let after_sig = &body[2..];

        match CellSignature::from_bytes(&sig_bytes) {
            Some(CellSignature::KeyNode) => {
                let nk = RawKeyNode::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                    offset,
                    expected: "nk (valid key node)",
                    byte0: sig_bytes[0],
                    byte1: sig_bytes[1],
                })?;
                Ok(Cell::KeyNode(nk))
            }
            Some(CellSignature::KeyValue) => {
                let vk = RawKeyValue::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                    offset,
                    expected: "vk (valid key value)",
                    byte0: sig_bytes[0],
                    byte1: sig_bytes[1],
                })?;
                Ok(Cell::KeyValue(vk))
            }
            Some(CellSignature::SecurityKey) => {
                let sk = RawSecurityKey::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                    offset,
                    expected: "sk (valid security key)",
                    byte0: sig_bytes[0],
                    byte1: sig_bytes[1],
                })?;
                Ok(Cell::SecurityKey(sk))
            }
            Some(CellSignature::FastLeaf) => {
                let idx =
                    SubkeyIndex::parse_lf(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "lf (valid fast leaf)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::HashLeaf) => {
                let idx =
                    SubkeyIndex::parse_lh(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "lh (valid hash leaf)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::IndexLeaf) => {
                let idx =
                    SubkeyIndex::parse_li(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "li (valid index leaf)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::RootIndex) => {
                let idx =
                    SubkeyIndex::parse_ri(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "ri (valid root index)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::BigData) => {
                let db = RawBigData::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                    offset,
                    expected: "db (valid big data)",
                    byte0: sig_bytes[0],
                    byte1: sig_bytes[1],
                })?;
                Ok(Cell::BigData(db))
            }
            None => Ok(Cell::Data(body)),
        }
    }

    /// Read raw data bytes at a cell offset (no signature dispatch).
    /// Used for value data cells, class names, etc.
    pub fn read_data_cell(&self, offset: CellOffset) -> Result<Vec<u8>> {
        let (_header, body) = self.read_cell_raw(offset)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_hive() -> Vec<u8> {
        use winreg_format::header::BaseBlock;

        let hbin_size: u32 = 4096;
        let total_size = BaseBlock::SIZE + hbin_size as usize;
        let mut buf = vec![0u8; total_size];

        buf[0..4].copy_from_slice(b"regf");
        buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        buf[0x24..0x28].copy_from_slice(&32u32.to_le_bytes()); // root at cell offset 32
        buf[0x28..0x2C].copy_from_slice(&hbin_size.to_le_bytes());
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        let hbin_start = BaseBlock::SIZE;
        buf[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");
        buf[hbin_start + 4..hbin_start + 8].copy_from_slice(&0u32.to_le_bytes());
        buf[hbin_start + 8..hbin_start + 12].copy_from_slice(&hbin_size.to_le_bytes());

        // Root NK cell at hbin offset 32
        let cell_start = hbin_start + 32;
        let cell_size: i32 = -128;
        buf[cell_start..cell_start + 4].copy_from_slice(&cell_size.to_le_bytes());
        buf[cell_start + 4..cell_start + 6].copy_from_slice(b"nk");
        buf[cell_start + 6..cell_start + 8].copy_from_slice(&0x0024u16.to_le_bytes()); // HIVE_ENTRY | COMP_NAME
        // key_name_len = 4 at offset +74 from cell body sig
        let name_len_offset = cell_start + 4 + 2 + 70; // size(4) + sig(2) + header fields(70)
        buf[name_len_offset..name_len_offset + 2].copy_from_slice(&4u16.to_le_bytes());
        // key name "root" at offset +76 from sig
        let name_offset = name_len_offset + 4; // +2 for class_name_len
        buf[name_offset..name_offset + 4].copy_from_slice(b"root");

        // Free cell after NK
        let free_start = cell_start + 128;
        let free_size = (hbin_size as usize) - 32 - 128;
        buf[free_start..free_start + 4].copy_from_slice(&(free_size as i32).to_le_bytes());

        buf
    }

    #[test]
    fn read_root_nk_cell() {
        let hive = Hive::from_bytes(build_minimal_hive()).unwrap();
        let root_offset = hive.root_cell_offset();
        let cell = hive.read_cell(root_offset).unwrap();
        match cell {
            Cell::KeyNode(nk) => {
                assert!(nk.is_root());
            }
            other => panic!("expected KeyNode, got {other:?}"),
        }
    }

    #[test]
    fn null_offset_returns_error() {
        let hive = Hive::from_bytes(build_minimal_hive()).unwrap();
        assert!(matches!(
            hive.read_cell(CellOffset::NULL),
            Err(HiveError::NullOffset)
        ));
    }

    #[test]
    fn out_of_bounds_offset_returns_error() {
        let hive = Hive::from_bytes(build_minimal_hive()).unwrap();
        let bad_offset = CellOffset(0xFFFFFE); // way beyond data
        assert!(matches!(
            hive.read_cell(bad_offset),
            Err(HiveError::CellOverflow { .. })
        ));
    }
}

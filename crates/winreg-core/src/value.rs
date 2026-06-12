//! Value struct — decode registry value data.

use std::io::Cursor;

use winreg_format::cells::{CellOffset, RawKeyValue};
use winreg_format::flags::ValueType;

use crate::error::Result;
use crate::hive::Hive;

/// Values larger than this are stored as a `db` big-data record (a list of
/// segment cells) rather than inline in a single data cell.
const BIG_DATA_THRESHOLD: usize = 16344;
/// Maximum bytes contributed by one big-data segment cell.
const BIG_DATA_SEGMENT_SIZE: usize = 16344;

/// A registry value within a key.
pub struct Value<'h> {
    pub(crate) hive: &'h Hive<Cursor<Vec<u8>>>,
    pub(crate) vk: RawKeyValue,
    pub(crate) offset: CellOffset,
}

impl Value<'_> {
    /// Value name. Empty string for the unnamed (default) value.
    pub fn name(&self) -> String {
        self.vk.value_name()
    }

    /// Data type.
    pub fn data_type(&self) -> ValueType {
        self.vk.data_type
    }

    /// Raw data size in bytes.
    pub fn data_size(&self) -> u32 {
        self.vk.data_size()
    }

    /// Whether data is resident (stored inline in the VK cell).
    pub fn is_resident(&self) -> bool {
        self.vk.is_resident()
    }

    /// Cell offset of this value.
    pub fn offset(&self) -> CellOffset {
        self.offset
    }

    /// Read raw data bytes.
    pub fn raw_data(&self) -> Result<Vec<u8>> {
        let size = self.vk.data_size() as usize;
        if size == 0 {
            return Ok(Vec::new());
        }

        if self.vk.is_resident() {
            return Ok(self.vk.inline_data());
        }

        let data_offset = self.vk.data_offset();

        // Values larger than a single cell (> 16344 B) are split into a "big
        // data" (`db`) record: a list of segment cells, each holding up to
        // 16344 bytes. Reassemble them. (Real Win10 AppCompatCache lives here.)
        if size > BIG_DATA_THRESHOLD {
            return self.read_big_data(data_offset, size);
        }

        // Non-resident, single cell.
        let (_header, body) = self.hive.read_cell_raw(data_offset)?;
        Ok(body[..size.min(body.len())].to_vec())
    }

    /// Reassemble a `db` big-data record into its full `size`-byte value.
    fn read_big_data(&self, db_offset: CellOffset, size: usize) -> Result<Vec<u8>> {
        let (_h, db_body) = self.hive.read_cell_raw(db_offset)?;
        // db body: "db"(2) | segment_count(u16) | segment_list_offset(u32).
        if db_body.len() < 8 || &db_body[0..2] != b"db" {
            // Not actually a db record — return what we have rather than fail.
            return Ok(db_body[..size.min(db_body.len())].to_vec());
        }
        let segment_count = u16::from_le_bytes([db_body[2], db_body[3]]) as usize;
        let list_offset = CellOffset(u32::from_le_bytes([
            db_body[4], db_body[5], db_body[6], db_body[7],
        ]));
        let (_h2, list_body) = self.hive.read_cell_raw(list_offset)?;

        let mut out = Vec::with_capacity(size);
        for i in 0..segment_count {
            if out.len() >= size {
                break;
            }
            let pos = i * 4;
            let Some(off_bytes) = list_body.get(pos..pos + 4) else {
                break;
            };
            let seg_off = CellOffset(u32::from_le_bytes([
                off_bytes[0], off_bytes[1], off_bytes[2], off_bytes[3],
            ]));
            let Ok((_h3, seg_body)) = self.hive.read_cell_raw(seg_off) else {
                break;
            };
            // Each segment contributes up to 16344 bytes; the value is truncated
            // to the declared `size` (segment cells may be padded).
            let take = (size - out.len()).min(BIG_DATA_SEGMENT_SIZE).min(seg_body.len());
            out.extend_from_slice(&seg_body[..take]);
        }
        Ok(out)
    }

    /// Decode as a string (`REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`).
    pub fn as_string(&self) -> Result<String> {
        let data = self.raw_data()?;
        Ok(decode_utf16le(&data))
    }

    /// Decode as u32 (`REG_DWORD`).
    pub fn as_u32(&self) -> Result<u32> {
        let data = self.raw_data()?;
        if data.len() < 4 {
            return Ok(0);
        }
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Decode as u32 big-endian (`REG_DWORD_BIG_ENDIAN`).
    pub fn as_u32_be(&self) -> Result<u32> {
        let data = self.raw_data()?;
        if data.len() < 4 {
            return Ok(0);
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Decode as u64 (`REG_QWORD`).
    pub fn as_u64(&self) -> Result<u64> {
        let data = self.raw_data()?;
        if data.len() < 8 {
            return Ok(0);
        }
        Ok(crate::bytes::le_u64(&data, 0))
    }

    /// Decode as multi-string (`REG_MULTI_SZ`).
    pub fn as_multi_string(&self) -> Result<Vec<String>> {
        let data = self.raw_data()?;
        Ok(decode_multi_sz(&data))
    }
}

/// Decode UTF-16LE bytes to a String.
pub fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed: &[u16] = match u16s.iter().position(|&c| c == 0) {
        Some(pos) => &u16s[..pos],
        None => &u16s,
    };
    String::from_utf16_lossy(trimmed)
}

/// Decode `REG_MULTI_SZ`: sequence of null-terminated UTF-16LE strings,
/// terminated by an empty string (double null).
pub fn decode_multi_sz(data: &[u8]) -> Vec<String> {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let mut strings = Vec::new();
    let mut start = 0;

    for (i, &ch) in u16s.iter().enumerate() {
        if ch == 0 {
            if i == start {
                break;
            }
            strings.push(String::from_utf16_lossy(&u16s[start..i]));
            start = i + 1;
        }
    }

    if start < u16s.len() {
        let remaining: Vec<u16> = u16s[start..]
            .iter()
            .copied()
            .take_while(|&c| c != 0)
            .collect();
        if !remaining.is_empty() {
            strings.push(String::from_utf16_lossy(&remaining));
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_utf16le_normal() {
        let data = b"H\x00e\x00l\x00l\x00o\x00\x00\x00";
        assert_eq!(decode_utf16le(data), "Hello");
    }

    #[test]
    fn decode_utf16le_no_null() {
        let data = b"H\x00i\x00";
        assert_eq!(decode_utf16le(data), "Hi");
    }

    #[test]
    fn decode_utf16le_empty() {
        assert_eq!(decode_utf16le(b""), "");
    }

    #[test]
    fn decode_multi_sz_normal() {
        let data = b"f\x00o\x00o\x00\x00\x00b\x00a\x00r\x00\x00\x00\x00\x00";
        let result = decode_multi_sz(data);
        assert_eq!(result, vec!["foo", "bar"]);
    }

    #[test]
    fn decode_multi_sz_single() {
        let data = b"o\x00n\x00e\x00\x00\x00\x00\x00";
        let result = decode_multi_sz(data);
        assert_eq!(result, vec!["one"]);
    }

    #[test]
    fn decode_multi_sz_empty() {
        let data = b"\x00\x00";
        let result = decode_multi_sz(data);
        assert!(result.is_empty());
    }

    #[test]
    fn decode_multi_sz_missing_terminator() {
        let data = b"a\x00b\x00c\x00\x00\x00d\x00e\x00f\x00";
        let result = decode_multi_sz(data);
        assert_eq!(result, vec!["abc", "def"]);
    }
}

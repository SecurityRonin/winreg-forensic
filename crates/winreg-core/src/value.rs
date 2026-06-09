//! Value struct — decode registry value data.

use std::io::Cursor;

use winreg_format::cells::{CellOffset, RawKeyValue};
use winreg_format::flags::ValueType;

use crate::error::Result;
use crate::hive::Hive;

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
        if self.vk.data_size() == 0 {
            return Ok(Vec::new());
        }

        if self.vk.is_resident() {
            return Ok(self.vk.inline_data());
        }

        // Non-resident: read data from separate cell.
        let data_offset = self.vk.data_offset();
        let (_header, body) = self.hive.read_cell_raw(data_offset)?;

        let size = self.vk.data_size() as usize;
        Ok(body[..size.min(body.len())].to_vec())
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

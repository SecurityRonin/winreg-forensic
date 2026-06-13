//! Key struct — high-level interface for navigating registry keys.

use std::io::Cursor;

use winreg_format::cells::{CellOffset, RawKeyNode, SubkeyIndex};
use winreg_format::flags::KeyFlags;

use crate::cell_reader::Cell;
use crate::error::{HiveError, Result};
use crate::hive::Hive;
use crate::value::Value;

/// Difference between the Windows FILETIME epoch (1601-01-01) and
/// the Unix epoch (1970-01-01) expressed in 100-nanosecond intervals.
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// A registry key within a hive.
pub struct Key<'h> {
    pub(crate) hive: &'h Hive<Cursor<Vec<u8>>>,
    pub(crate) node: RawKeyNode,
    pub(crate) offset: CellOffset,
}

impl<'h> Key<'h> {
    pub fn name(&self) -> String {
        self.node.key_name()
    }

    pub fn last_written_raw(&self) -> u64 {
        self.node.last_written
    }

    pub fn last_written(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        filetime_to_datetime(self.node.last_written)
    }

    pub fn flags(&self) -> KeyFlags {
        self.node.flags
    }

    pub fn is_root(&self) -> bool {
        self.node.is_root()
    }

    pub fn subkey_count(&self) -> u32 {
        self.node.subkey_count
    }

    pub fn value_count(&self) -> u32 {
        self.node.value_count
    }

    pub fn offset(&self) -> CellOffset {
        self.offset
    }

    pub fn subkeys(&self) -> Result<Vec<Key<'h>>> {
        if self.node.subkey_count == 0 || self.node.subkeys_list_offset.is_null() {
            return Ok(Vec::new());
        }
        let offsets = self.collect_subkey_offsets(self.node.subkeys_list_offset)?;
        let mut keys = Vec::with_capacity(offsets.len());
        for offset in offsets {
            let cell = self.hive.read_cell(offset)?;
            if let Cell::KeyNode(nk) = cell {
                keys.push(Key {
                    hive: self.hive,
                    node: nk,
                    offset,
                });
            }
        }
        Ok(keys)
    }

    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h>>> {
        let target = name.to_ascii_uppercase();
        for key in self.subkeys()? {
            if key.name().to_ascii_uppercase() == target {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    pub fn subkey_path(&self, path: &str) -> Result<Option<Key<'h>>> {
        let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(None);
        }

        // Walk the path one level at a time, owning each intermediate key.
        let Some(first) = self.subkey(parts[0])? else {
            return Ok(None);
        };

        let mut current = first;
        for part in &parts[1..] {
            let Some(next) = current.subkey(part)? else {
                return Ok(None);
            };
            current = next;
        }
        Ok(Some(current))
    }

    pub fn values(&self) -> Result<Vec<Value<'h>>> {
        if self.node.value_count == 0 || self.node.values_list_offset.is_null() {
            return Ok(Vec::new());
        }
        let (_header, body) = self.hive.read_cell_raw(self.node.values_list_offset)?;
        let count = self.node.value_count as usize;
        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            let base = i * 4;
            if base + 4 > body.len() {
                break;
            }
            let vk_offset = CellOffset(crate::bytes::le_u32(&body, base));
            let cell = self.hive.read_cell(vk_offset)?;
            if let Cell::KeyValue(vk) = cell {
                values.push(Value {
                    hive: self.hive,
                    vk,
                    offset: vk_offset,
                });
            }
        }
        Ok(values)
    }

    pub fn value(&self, name: &str) -> Result<Option<Value<'h>>> {
        let target = name.to_ascii_uppercase();
        for val in self.values()? {
            if val.name().to_ascii_uppercase() == target {
                return Ok(Some(val));
            }
        }
        Ok(None)
    }

    fn collect_subkey_offsets(&self, index_offset: CellOffset) -> Result<Vec<CellOffset>> {
        let cell = self.hive.read_cell(index_offset)?;
        match cell {
            Cell::Index(SubkeyIndex::HashLeaf(elements)) => {
                Ok(elements.iter().map(|e| e.key_offset).collect())
            }
            Cell::Index(SubkeyIndex::FastLeaf(elements)) => {
                Ok(elements.iter().map(|e| e.key_offset).collect())
            }
            Cell::Index(SubkeyIndex::IndexLeaf(offsets)) => Ok(offsets),
            Cell::Index(SubkeyIndex::RootIndex(sub_indices)) => {
                let mut all = Vec::new();
                for sub_offset in sub_indices {
                    all.extend(self.collect_subkey_offsets(sub_offset)?);
                }
                Ok(all)
            }
            _ => Ok(Vec::new()),
        }
    }
}

impl Hive<Cursor<Vec<u8>>> {
    pub fn root_key(&self) -> Result<Key<'_>> {
        let offset = self.root_cell_offset();
        let cell = self.read_cell(offset)?;
        match cell {
            Cell::KeyNode(nk) => Ok(Key {
                hive: self,
                node: nk,
                offset,
            }),
            _ => Err(HiveError::InvalidCellSignature {
                offset,
                expected: "nk (root key node)",
                byte0: 0,
                byte1: 0,
            }),
        }
    }

    pub fn open_key(&self, path: &str) -> Result<Option<Key<'_>>> {
        self.root_key()?.subkey_path(path)
    }
}

/// Convert a Windows FILETIME value to a chrono [`chrono::DateTime`].
///
/// Returns `None` if `filetime` is zero or predates the Unix epoch.
pub fn filetime_to_datetime(filetime: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    if filetime == 0 || filetime < FILETIME_EPOCH_DIFF {
        return None;
    }
    let unix_100ns = filetime - FILETIME_EPOCH_DIFF;
    #[allow(clippy::cast_possible_wrap)]
    let secs = (unix_100ns / 10_000_000) as i64;
    #[allow(clippy::cast_possible_truncation)]
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn filetime_epoch() {
        let dt = filetime_to_datetime(133_485_408_000_000_000).unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn filetime_zero_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
    }
}

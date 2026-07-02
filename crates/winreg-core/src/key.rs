//! Key struct — high-level interface for navigating registry keys.

use std::io::Cursor;

use winreg_format::cells::{CellOffset, RawKeyNode, SubkeyIndex};
use winreg_format::flags::KeyFlags;

use crate::cell_reader::{Cell, CellReader};
use crate::error::{HiveError, Result};
use crate::hive::Hive;
use crate::value::Value;

/// Difference between the Windows FILETIME epoch (1601-01-01) and
/// the Unix epoch (1970-01-01) expressed in 100-nanosecond intervals.
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// A registry key within a hive.
///
/// Generic over the [`CellReader`] backend; defaults to the flat-file hive so
/// existing call sites keep using `Key<'_>` unchanged.
pub struct Key<'h, R: CellReader = Hive<Cursor<Vec<u8>>>> {
    pub(crate) hive: &'h R,
    pub(crate) node: RawKeyNode,
    pub(crate) offset: CellOffset,
}

impl<'h, R: CellReader> Key<'h, R> {
    /// Mint a root (or any) [`Key`] directly from a cell offset on an arbitrary
    /// [`CellReader`] backend.
    ///
    /// This is the public bootstrap seam for out-of-crate backends: a foreign
    /// `R: CellReader` (e.g. a live-memory hive walked through the HMAP cell
    /// map) computes its own root cell offset and calls this to obtain the
    /// first `Key`, from which all generic navigation
    /// ([`subkeys`](Key::subkeys), [`values`](Key::values), …) follows. The
    /// cell at `offset` is read through the trait and its `nk` signature
    /// validated; a non-`nk` (or missing) cell is rejected loudly.
    pub fn from_cell_offset(reader: &'h R, offset: CellOffset) -> Result<Self> {
        match reader.read_cell(offset)? {
            Cell::KeyNode(node) => Ok(Key {
                hive: reader,
                node,
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

    pub fn name(&self) -> String {
        self.node.key_name()
    }

    pub fn last_written_raw(&self) -> u64 {
        self.node.last_written
    }

    pub fn last_written(&self) -> Option<jiff::Timestamp> {
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

    pub fn subkeys(&self) -> Result<Vec<Key<'h, R>>> {
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

    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h, R>>> {
        let target = name.to_ascii_uppercase();
        for key in self.subkeys()? {
            if key.name().to_ascii_uppercase() == target {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    pub fn subkey_path(&self, path: &str) -> Result<Option<Key<'h, R>>> {
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

    pub fn values(&self) -> Result<Vec<Value<'h, R>>> {
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

    pub fn value(&self, name: &str) -> Result<Option<Value<'h, R>>> {
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
        Key::from_cell_offset(self, self.root_cell_offset())
    }

    pub fn open_key(&self, path: &str) -> Result<Option<Key<'_>>> {
        self.root_key()?.subkey_path(path)
    }
}

/// Convert a Windows FILETIME value to a [`jiff::Timestamp`].
///
/// Returns `None` if `filetime` is zero, predates the Unix epoch, or lands
/// outside the range representable by a `Timestamp`.
pub fn filetime_to_datetime(filetime: u64) -> Option<jiff::Timestamp> {
    if filetime == 0 || filetime < FILETIME_EPOCH_DIFF {
        return None;
    }
    let unix_100ns = i128::from(filetime - FILETIME_EPOCH_DIFF);
    let unix_nanos = unix_100ns * 100;
    jiff::Timestamp::from_nanosecond(unix_nanos).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch() {
        // FILETIME 133_485_408_000_000_000 == 2024-01-01T00:00:00Z.
        // Pin the exact Unix-nanosecond instant so the jiff conversion is
        // checked against a value derived from the documented FILETIME math,
        // not merely against a coarse year/month/day.
        let ts = filetime_to_datetime(133_485_408_000_000_000).unwrap();
        assert_eq!(ts.as_nanosecond(), 1_704_067_200_000_000_000_i128);
        assert_eq!(ts.as_second(), 1_704_067_200);
        assert_eq!(ts.to_string(), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn filetime_zero_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn filetime_pre_epoch_returns_none() {
        // Any FILETIME below the 1601->1970 epoch difference predates the Unix
        // epoch and must yield None (preserving the pre-migration guard).
        assert!(filetime_to_datetime(FILETIME_EPOCH_DIFF - 1).is_none());
    }
}

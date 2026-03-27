//! Value decoding for all REG_* types.

use std::io::Cursor;
use winreg_format::cells::{CellOffset, RawKeyValue};
use crate::hive::Hive;

/// A registry value within a hive.
pub struct Value<'h> {
    #[allow(dead_code)]
    pub(crate) hive: &'h Hive<Cursor<Vec<u8>>>,
    pub(crate) vk: RawKeyValue,
    #[allow(dead_code)]
    pub(crate) offset: CellOffset,
}

impl Value<'_> {
    /// Value name. Empty string for the default (unnamed) value.
    pub fn name(&self) -> String {
        self.vk.value_name()
    }
}

//! Key path reconstruction — walk the parent chain to build full paths.

use crate::cell_reader::{Cell, CellReader};
use crate::error::Result;
use crate::key::Key;

impl<R: CellReader> Key<'_, R> {
    /// Reconstruct the full path from root to this key.
    ///
    /// Walks the parent chain upward until the root key (`KEY_HIVE_ENTRY`) is found.
    pub fn path(&self) -> Result<String> {
        let mut parts: Vec<String> = vec![self.name()];
        let mut current_parent = self.node.parent;

        // Walk up to root (max 512 levels to prevent infinite loops on corrupt hives).
        for _ in 0..512 {
            if current_parent.is_null() {
                break;
            }

            let cell = self.hive.read_cell(current_parent)?;
            match cell {
                Cell::KeyNode(nk) => {
                    if nk.is_root() {
                        break; // Don't include root key name in path
                    }
                    parts.push(nk.key_name());
                    current_parent = nk.parent;
                }
                _ => break,
            }
        }

        parts.reverse();
        Ok(parts.join("\\"))
    }
}

#[cfg(test)]
mod tests {
    // Path reconstruction tests require TestHiveBuilder with nested keys.
    //
    // #[test]
    // fn path_of_root_key() { ... }
    //
    // #[test]
    // fn path_of_nested_key() { ... }
}

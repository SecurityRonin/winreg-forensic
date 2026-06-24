#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

use std::collections::HashMap;

use common::hive_builder::TestHiveBuilder;
use winreg_core::cell_reader::CellReader;
use winreg_core::error::{HiveError, Result};
use winreg_core::hive::Hive;
use winreg_core::key::Key;
use winreg_format::cells::{CellHeader, CellOffset};
use winreg_format::header::BaseBlock;

#[test]
fn root_key_from_hive() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    assert!(root.is_root());
}

#[test]
fn navigate_to_subkey() {
    let data = TestHiveBuilder::new().add_key("Software").build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    let software = root.subkey("Software").unwrap();
    assert!(software.is_some());
    assert_eq!(software.unwrap().name(), "Software");
}

#[test]
fn case_insensitive_lookup() {
    let data = TestHiveBuilder::new().add_key("Software").build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    // Case-insensitive: "software" should find "Software"
    let found = root.subkey("software").unwrap();
    assert!(found.is_some());
}

#[test]
fn subkey_path_navigation() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .add_key("Software\\Microsoft\\Windows")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    let windows = root.subkey_path("Software\\Microsoft\\Windows").unwrap();
    assert!(windows.is_some());
    assert_eq!(windows.unwrap().name(), "Windows");
}

#[test]
fn open_key_convenience() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let microsoft = hive.open_key("Software\\Microsoft").unwrap();
    assert!(microsoft.is_some());
    assert_eq!(microsoft.unwrap().name(), "Microsoft");
}

#[test]
fn missing_subkey_returns_none() {
    let data = TestHiveBuilder::new().add_key("Software").build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    let nope = root.subkey("NonExistent").unwrap();
    assert!(nope.is_none());
}

/// A foreign-style `CellReader` backend mirroring the out-of-crate case
/// (e.g. memf's HMAP cell map): an in-memory `offset -> cell bytes` map with
/// NO 4096-base, NO checksum, NO `Cursor`. It implements only
/// `read_cell_raw` and reuses every shared navigation routine.
struct MapBackend {
    cells: HashMap<u32, (CellHeader, Vec<u8>)>,
    root: CellOffset,
}

impl MapBackend {
    /// Build a map backend from a flat-file hive by walking each allocated
    /// cell in the hbin data and indexing it by its hive-relative offset.
    fn from_hive(hive: &Hive<std::io::Cursor<Vec<u8>>>) -> Self {
        let bytes = hive.raw_bytes();
        let hbin_base = BaseBlock::SIZE;
        let mut cells = HashMap::new();

        // Each hbin starts with a 32-byte header; cells follow back-to-back.
        let mut pos = hbin_base + 32;
        while pos + 4 <= bytes.len() {
            let header = CellHeader::from_bytes(&[
                bytes[pos],
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
            ]);
            let size = header.size() as usize;
            if size == 0 {
                break;
            }
            if header.is_allocated() && pos + size <= bytes.len() {
                let body = bytes[pos + 4..pos + size].to_vec();
                let rel = (pos - hbin_base) as u32;
                cells.insert(rel, (header, body));
            }
            pos += size;
        }

        Self {
            cells,
            root: hive.root_cell_offset(),
        }
    }
}

impl CellReader for MapBackend {
    fn read_cell_raw(&self, offset: CellOffset) -> Result<(CellHeader, Vec<u8>)> {
        self.cells
            .get(&offset.0)
            .cloned()
            .ok_or(HiveError::NullOffset)
    }
}

#[test]
fn foreign_backend_bootstraps_root_via_public_ctor() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .add_value("Software", "Version", 1, b"1\x00.\x000\x00\0\0")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let backend = MapBackend::from_hive(&hive);

    // The out-of-crate backend mints its root Key through the PUBLIC ctor —
    // no pub(crate) field access.
    let root: Key<'_, MapBackend> = Key::from_cell_offset(&backend, backend.root).unwrap();
    assert!(root.is_root());

    // name()/subkeys()/values() all work over the foreign backend.
    let software = root.subkey("Software").unwrap().unwrap();
    assert_eq!(software.name(), "Software");

    let names: Vec<String> = root.subkeys().unwrap().iter().map(Key::name).collect();
    assert!(names.contains(&"Software".to_string()));

    let values = software.values().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name(), "Version");
}

#[test]
fn from_cell_offset_rejects_non_nk_cell() {
    let data = TestHiveBuilder::new().add_key("Software").build();
    let hive = Hive::from_bytes(data).unwrap();
    let backend = MapBackend::from_hive(&hive);

    // An absent offset must fail loudly, not silently mint a bogus root.
    let bad = CellOffset(0xFFFF_FFFE);
    assert!(Key::from_cell_offset(&backend, bad).is_err());
}

#[test]
fn list_values_on_key() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_value("Software", "Version", 1, b"1\x00.\x000\x00\0\0")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let software = hive.open_key("Software").unwrap().unwrap();
    let values = software.values().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name(), "Version");
}

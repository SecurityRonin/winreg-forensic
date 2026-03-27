//! Integration tests for `TestHiveBuilder`.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_core::cell_reader::Cell;
use winreg_core::hive::Hive;

#[test]
fn build_empty_hive() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).expect("empty hive should be valid");
    assert_eq!(hive.bin_count(), 1);
}

#[test]
fn build_hive_with_keys() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    assert!(hive.bin_count() >= 1);

    // Verify root NK has subkeys
    let root_offset = hive.root_cell_offset();
    let cell = hive.read_cell(root_offset).unwrap();
    if let Cell::KeyNode(nk) = cell {
        assert!(nk.is_root());
        assert_eq!(nk.subkey_count, 1); // "Software"
    } else {
        panic!("expected root NK");
    }
}

#[test]
fn build_hive_with_values() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_value("Software", "Version", 1, b"1\x00.\x000\x00\0\0")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    assert!(hive.bin_count() >= 1);
}

#[test]
fn build_hive_with_nested_keys() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .add_key("Software\\Microsoft\\Windows")
        .add_key("System")
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    // Root should have 2 direct subkeys: Software and System
    let root_offset = hive.root_cell_offset();
    let cell = hive.read_cell(root_offset).unwrap();
    if let Cell::KeyNode(nk) = cell {
        assert!(nk.is_root());
        assert_eq!(nk.subkey_count, 2);
    } else {
        panic!("expected root NK");
    }
}

#[test]
fn build_hive_with_resident_value() {
    // DWORD value (4 bytes) should be stored inline (resident)
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_value("Software", "Start", 4, &42u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    assert!(hive.bin_count() >= 1);
}

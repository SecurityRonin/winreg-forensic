//! Integration tests for `winreg_diff::snapshot`.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_diff::snapshot::value_to_snapshot;

#[test]
fn snapshot_from_dword_value() {
    let hive_data = TestHiveBuilder::new()
        .add_key("TestKey")
        .add_value("TestKey", "Count", 4, &42u32.to_le_bytes())
        .build();
    let hive = winreg_core::hive::Hive::from_bytes(hive_data).unwrap();
    let root = hive.root_key().unwrap();
    let key = root.subkey("TestKey").unwrap().unwrap();
    let val = key.value("Count").unwrap().unwrap();

    let snap = value_to_snapshot(&val);
    assert_eq!(snap.data_type, "REG_DWORD");
    assert_eq!(snap.display, "0x0000002A");
    assert_eq!(snap.raw, 42u32.to_le_bytes());
}

#[test]
fn snapshot_from_string_value() {
    let text = "Hello";
    let mut utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    utf16.extend_from_slice(&[0, 0]); // null terminator

    let hive_data = TestHiveBuilder::new()
        .add_key("TestKey")
        .add_value("TestKey", "Greeting", 1, &utf16)
        .build();
    let hive = winreg_core::hive::Hive::from_bytes(hive_data).unwrap();
    let root = hive.root_key().unwrap();
    let key = root.subkey("TestKey").unwrap().unwrap();
    let val = key.value("Greeting").unwrap().unwrap();

    let snap = value_to_snapshot(&val);
    assert_eq!(snap.data_type, "REG_SZ");
    assert_eq!(snap.display, "Hello");
}

#[test]
fn snapshot_from_binary_value() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let hive_data = TestHiveBuilder::new()
        .add_key("TestKey")
        .add_value("TestKey", "Blob", 3, &data)
        .build();
    let hive = winreg_core::hive::Hive::from_bytes(hive_data).unwrap();
    let root = hive.root_key().unwrap();
    let key = root.subkey("TestKey").unwrap().unwrap();
    let val = key.value("Blob").unwrap().unwrap();

    let snap = value_to_snapshot(&val);
    assert_eq!(snap.data_type, "REG_BINARY");
    assert_eq!(snap.display, "DE AD BE EF");
}

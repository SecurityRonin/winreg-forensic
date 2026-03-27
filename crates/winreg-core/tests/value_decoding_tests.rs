mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_core::hive::Hive;

#[test]
fn read_resident_dword() {
    // DWORD value with data <= 4 bytes should be resident
    let data = TestHiveBuilder::new()
        .add_key("Test")
        .add_value("Test", "Count", 4, &42u32.to_le_bytes()) // REG_DWORD = 4
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let key = hive.open_key("Test").unwrap().unwrap();
    let val = key.value("Count").unwrap().unwrap();
    assert_eq!(val.as_u32().unwrap(), 42);
}

#[test]
fn read_non_resident_string() {
    // String value > 4 bytes should be non-resident
    let utf16 = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"; // "Hello\0" in UTF-16LE
    let data = TestHiveBuilder::new()
        .add_key("Test")
        .add_value("Test", "Greeting", 1, utf16) // REG_SZ = 1
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let key = hive.open_key("Test").unwrap().unwrap();
    let val = key.value("Greeting").unwrap().unwrap();
    assert_eq!(val.as_string().unwrap(), "Hello");
}

#[test]
fn value_metadata() {
    let data = TestHiveBuilder::new()
        .add_key("Test")
        .add_value("Test", "Name", 1, b"V\x00\x00\x00")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let key = hive.open_key("Test").unwrap().unwrap();
    let val = key.value("Name").unwrap().unwrap();
    assert_eq!(val.name(), "Name");
    assert!(val.data_size() > 0);
}

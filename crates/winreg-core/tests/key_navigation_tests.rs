#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_core::hive::Hive;

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

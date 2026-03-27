//! Integration tests for `winreg_diff::engine`.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_core::hive::Hive;
use winreg_diff::engine::diff_hives;
use winreg_diff::types::DiffKind;

#[test]
fn diff_identical_hives() {
    let data = TestHiveBuilder::new()
        .add_key("Key1")
        .add_value("Key1", "Val1", 4, &100u32.to_le_bytes())
        .build();
    let left = Hive::from_bytes(data.clone()).unwrap();
    let right = Hive::from_bytes(data).unwrap();

    let result = diff_hives(&left, &right, "left", "right").unwrap();
    assert!(
        result.entries.is_empty(),
        "Identical hives should have no diff entries"
    );
    assert_eq!(result.stats.keys_added, 0);
    assert_eq!(result.stats.keys_removed, 0);
    assert_eq!(result.stats.keys_modified, 0);
}

#[test]
fn diff_added_key() {
    let left_data = TestHiveBuilder::new().add_key("Key1").build();
    let right_data = TestHiveBuilder::new()
        .add_key("Key1")
        .add_key("Key2")
        .build();

    let left = Hive::from_bytes(left_data).unwrap();
    let right = Hive::from_bytes(right_data).unwrap();

    let result = diff_hives(&left, &right, "left", "right").unwrap();
    assert_eq!(result.stats.keys_added, 1);
    let added = result
        .entries
        .iter()
        .find(|e| e.kind == DiffKind::KeyAdded)
        .unwrap();
    assert_eq!(added.path, "Key2");
}

#[test]
fn diff_removed_key() {
    let left_data = TestHiveBuilder::new()
        .add_key("Key1")
        .add_key("Key2")
        .build();
    let right_data = TestHiveBuilder::new().add_key("Key1").build();

    let left = Hive::from_bytes(left_data).unwrap();
    let right = Hive::from_bytes(right_data).unwrap();

    let result = diff_hives(&left, &right, "left", "right").unwrap();
    assert_eq!(result.stats.keys_removed, 1);
    let removed = result
        .entries
        .iter()
        .find(|e| e.kind == DiffKind::KeyRemoved)
        .unwrap();
    assert_eq!(removed.path, "Key2");
}

#[test]
fn diff_modified_value() {
    let left_data = TestHiveBuilder::new()
        .add_key("Key1")
        .add_value("Key1", "Count", 4, &10u32.to_le_bytes())
        .build();
    let right_data = TestHiveBuilder::new()
        .add_key("Key1")
        .add_value("Key1", "Count", 4, &20u32.to_le_bytes())
        .build();

    let left = Hive::from_bytes(left_data).unwrap();
    let right = Hive::from_bytes(right_data).unwrap();

    let result = diff_hives(&left, &right, "left", "right").unwrap();
    assert_eq!(result.stats.keys_modified, 1);
    assert_eq!(result.stats.values_changed, 1);
    let modified = result
        .entries
        .iter()
        .find(|e| e.kind == DiffKind::KeyModified)
        .unwrap();
    assert_eq!(modified.details.len(), 1);
    assert_eq!(modified.details[0].name, "Count");
}

#[test]
fn diff_added_value() {
    let left_data = TestHiveBuilder::new().add_key("Key1").build();
    let right_data = TestHiveBuilder::new()
        .add_key("Key1")
        .add_value("Key1", "NewVal", 4, &99u32.to_le_bytes())
        .build();

    let left = Hive::from_bytes(left_data).unwrap();
    let right = Hive::from_bytes(right_data).unwrap();

    let result = diff_hives(&left, &right, "left", "right").unwrap();
    assert_eq!(result.stats.values_added, 1);
    assert_eq!(result.stats.keys_modified, 1);
}

#[test]
fn diff_empty_hives() {
    let left_data = TestHiveBuilder::new().build();
    let right_data = TestHiveBuilder::new().build();

    let left = Hive::from_bytes(left_data).unwrap();
    let right = Hive::from_bytes(right_data).unwrap();

    let result = diff_hives(&left, &right, "left", "right").unwrap();
    assert!(result.entries.is_empty());
}

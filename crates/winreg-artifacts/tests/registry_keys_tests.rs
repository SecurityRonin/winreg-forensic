#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::registry_keys`.
//!
//! RED phase: all tests should FAIL until the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::registry_keys::{walk_all_values, walk_keys, walk_values};
use winreg_core::hive::Hive;

// ── Test 1: empty hive returns at least the root key ──────────────────

#[test]
fn walk_keys_empty_hive_returns_root() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys = walk_keys(&hive);
    assert!(
        !keys.is_empty(),
        "empty hive should still return the root key"
    );
    assert_eq!(keys[0].subkey_count, 0);
    assert_eq!(keys[0].value_count, 0);
}

// ── Test 2: nested keys are all returned ─────────────────────────────

#[test]
fn walk_keys_nested_returns_all() {
    let data = TestHiveBuilder::new()
        .add_key("Control Panel")
        .add_key("Control Panel\\Desktop")
        .add_key("Control Panel\\Desktop\\Colors")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys = walk_keys(&hive);
    // Root + Control Panel + Desktop + Colors = 4
    assert_eq!(
        keys.len(),
        4,
        "expected 4 keys (root + 3 nested), got {}",
        keys.len()
    );
}

// ── Test 3: last_written is populated when set ────────────────────────

#[test]
fn walk_keys_captures_last_written() {
    // TestHiveBuilder writes zero FILETIME for all keys (→ last_written = None).
    // Verify that the field is at least Some/None consistently.
    let data = TestHiveBuilder::new().add_key("Software").build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys = walk_keys(&hive);
    // All keys have zero FILETIME so last_written should be None
    for key in &keys {
        assert!(
            key.last_written.is_none(),
            "TestHiveBuilder keys have zero FILETIME so last_written must be None"
        );
    }
}

// ── Test 4: subkey_count and value_count match the actual structure ───

#[test]
fn walk_keys_counts_are_correct() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .add_value("Software", "Version", 1, b"1\x00.\x000\x00\x00\x00")
        .add_value("Software", "Build", 4, &42u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys = walk_keys(&hive);
    // Find the "Software" key
    let software = keys
        .iter()
        .find(|k| k.name == "Software")
        .expect("Software key not found");
    assert_eq!(
        software.subkey_count, 1,
        "Software should have 1 subkey (Microsoft)"
    );
    assert_eq!(software.value_count, 2, "Software should have 2 values");
}

// ── Test 5: walk_values at a known path returns values ────────────────

#[test]
fn walk_values_at_path_returns_values() {
    let data = TestHiveBuilder::new()
        .add_key("Control Panel")
        .add_key("Control Panel\\Desktop")
        .add_value(
            "Control Panel\\Desktop",
            "Wallpaper",
            1,
            b"C\x00:\x00\\\x00w\x00a\x00l\x00l\x00.\x00b\x00m\x00p\x00\x00\x00",
        )
        .add_value(
            "Control Panel\\Desktop",
            "WallpaperStyle",
            4,
            &2u32.to_le_bytes(),
        )
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let values = walk_values(&hive, "Control Panel\\Desktop");
    assert_eq!(
        values.len(),
        2,
        "expected 2 values at Control Panel\\Desktop"
    );
    let names: Vec<&str> = values.iter().map(|v| v.name.as_str()).collect();
    assert!(names.contains(&"Wallpaper"), "expected Wallpaper value");
    assert!(
        names.contains(&"WallpaperStyle"),
        "expected WallpaperStyle value"
    );
}

// ── Test 6: nonexistent path returns empty vec ────────────────────────

#[test]
fn walk_values_missing_path_returns_empty() {
    let data = TestHiveBuilder::new().add_key("Software").build();
    let hive = Hive::from_bytes(data).unwrap();
    let values = walk_values(&hive, "NoSuchKey\\Nowhere");
    assert!(
        values.is_empty(),
        "missing key path should return empty Vec"
    );
}

// ── Test 7: DWORD value shows numeric preview ─────────────────────────

#[test]
fn walk_values_dword_preview() {
    let data = TestHiveBuilder::new()
        .add_key("System")
        .add_value("System", "Start", 4, &42u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let values = walk_values(&hive, "System");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].data_type, "REG_DWORD");
    assert!(
        values[0].data_preview.contains("42"),
        "DWORD preview should contain the decimal value '42', got: {}",
        values[0].data_preview
    );
}

// ── Test 8: REG_SZ shows string preview (truncated at 256) ───────────

#[test]
fn walk_values_sz_preview() {
    // "Hello" in UTF-16LE with null terminator
    let hello_utf16 = b"H\x00e\x00l\x00l\x00o\x00\x00\x00";
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_value("Software", "Name", 1, hello_utf16)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let values = walk_values(&hive, "Software");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].data_type, "REG_SZ");
    assert_eq!(
        values[0].data_preview, "Hello",
        "REG_SZ preview should decode the string"
    );

    // Also verify truncation for long strings (> 256 chars)
    let long_str: String = "A".repeat(300);
    let long_utf16: Vec<u8> = long_str
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let data2 = TestHiveBuilder::new()
        .add_key("Long")
        .add_value("Long", "LongVal", 1, &long_utf16)
        .build();
    let hive2 = Hive::from_bytes(data2).unwrap();
    let values2 = walk_values(&hive2, "Long");
    assert_eq!(values2.len(), 1);
    assert!(
        values2[0].data_preview.len() <= 256,
        "REG_SZ preview must be truncated to 256 chars, got {}",
        values2[0].data_preview.len()
    );
}

// ── Test 9: walk_all_values returns values from every key ─────────────

#[test]
fn walk_all_values_traverses_all_keys() {
    let data = TestHiveBuilder::new()
        .add_key("KeyA")
        .add_key("KeyB")
        .add_value("KeyA", "ValA", 4, &1u32.to_le_bytes())
        .add_value("KeyB", "ValB", 4, &2u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let values = walk_all_values(&hive);
    // Should find both ValA and ValB
    let names: Vec<&str> = values.iter().map(|v| v.name.as_str()).collect();
    assert!(names.contains(&"ValA"), "should find ValA across all keys");
    assert!(names.contains(&"ValB"), "should find ValB across all keys");
}

// ── Test 10: path field is full path from root (not just the name) ────

#[test]
fn walk_keys_path_is_full_from_root() {
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Microsoft")
        .add_key("Software\\Microsoft\\Windows")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys = walk_keys(&hive);
    // Find the "Windows" key — its path should be the full path
    let windows = keys
        .iter()
        .find(|k| k.name == "Windows")
        .expect("Windows key not found");
    assert_eq!(
        windows.path, "Software\\Microsoft\\Windows",
        "path should be full path from root, not just the key name"
    );
}

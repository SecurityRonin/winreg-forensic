#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::amcache`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::amcache::{parse, AmcacheEntry};
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Base path for `InventoryApplicationFile` entries.
const IAF_PATH: &str = "Root\\InventoryApplicationFile";

/// Encode a string as UTF-16LE bytes (with null terminator).
fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.push(0);
    out.push(0);
    out
}

/// Build a u32 as little-endian bytes.
fn dword(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

// REG_SZ = 1, REG_DWORD = 4
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

// ---------------------------------------------------------------------------
// Test 1: parse_empty_hive_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "empty hive (no InventoryApplicationFile key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_single_entry_returns_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_single_entry_returns_entry() {
    let subkey = format!("{IAF_PATH}\\abc123");
    let data = TestHiveBuilder::new()
        .add_key(&subkey)
        .add_value(
            &subkey,
            "LowerCaseLongPath",
            REG_SZ,
            &utf16le("C:\\windows\\system32\\foo.exe"),
        )
        .add_value(&subkey, "FileId", REG_SZ, &utf16le("00001234567890abcdef"))
        .add_value(&subkey, "Size", REG_DWORD, &dword(12345))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "should return one entry");
}

// ---------------------------------------------------------------------------
// Test 3: parse_file_path_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_file_path_extracted() {
    let subkey = format!("{IAF_PATH}\\entry1");
    let expected_path = "C:\\windows\\system32\\notepad.exe";
    let data = TestHiveBuilder::new()
        .add_key(&subkey)
        .add_value(
            &subkey,
            "LowerCaseLongPath",
            REG_SZ,
            &utf16le(expected_path),
        )
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].file_path, expected_path,
        "file_path should match LowerCaseLongPath value"
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_sha1_strips_0000_prefix
// ---------------------------------------------------------------------------

#[test]
fn parse_sha1_strips_0000_prefix() {
    let subkey = format!("{IAF_PATH}\\sha1test");
    let file_id = "0000aabbccddeeff00112233445566778899aabb";
    let data = TestHiveBuilder::new()
        .add_key(&subkey)
        .add_value(&subkey, "FileId", REG_SZ, &utf16le(file_id))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].sha1, "aabbccddeeff00112233445566778899aabb",
        "sha1 should have '0000' prefix stripped"
    );
}

// ---------------------------------------------------------------------------
// Test 5: parse_sha1_absent_gives_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_sha1_absent_gives_empty() {
    let subkey = format!("{IAF_PATH}\\nosha1");
    let data = TestHiveBuilder::new()
        .add_key(&subkey)
        .add_value(
            &subkey,
            "LowerCaseLongPath",
            REG_SZ,
            &utf16le("C:\\foo.exe"),
        )
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].sha1.is_empty(),
        "sha1 should be empty string when FileId is absent"
    );
}

// ---------------------------------------------------------------------------
// Test 6: parse_size_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_size_extracted() {
    let subkey = format!("{IAF_PATH}\\sizetest");
    let data = TestHiveBuilder::new()
        .add_key(&subkey)
        .add_value(&subkey, "Size", REG_DWORD, &dword(98765))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, 98765, "size should match REG_DWORD value");
}

// ---------------------------------------------------------------------------
// Test 7: parse_publisher_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_publisher_extracted() {
    let subkey = format!("{IAF_PATH}\\pubtest");
    let data = TestHiveBuilder::new()
        .add_key(&subkey)
        .add_value(
            &subkey,
            "Publisher",
            REG_SZ,
            &utf16le("Microsoft Corporation"),
        )
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].publisher, "Microsoft Corporation",
        "publisher should match Publisher value"
    );
}

// ---------------------------------------------------------------------------
// Test 8: parse_missing_values_default_to_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_values_default_to_empty() {
    // Subkey with no values at all
    let subkey = format!("{IAF_PATH}\\emptyentry");
    let data = TestHiveBuilder::new().add_key(&subkey).build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert!(e.file_path.is_empty(), "file_path should be empty");
    assert!(e.sha1.is_empty(), "sha1 should be empty");
    assert_eq!(e.size, 0, "size should be 0");
    assert!(e.publisher.is_empty(), "publisher should be empty");
    assert!(e.product_name.is_empty(), "product_name should be empty");
    assert!(
        e.product_version.is_empty(),
        "product_version should be empty"
    );
    assert!(
        e.bin_file_version.is_empty(),
        "bin_file_version should be empty"
    );
}

// ---------------------------------------------------------------------------
// Test 9: parse_last_written_populated
// ---------------------------------------------------------------------------

#[test]
fn parse_last_written_populated() {
    // Even with no special setup, last_written field should be Some or None
    // (it comes from the key's metadata — builder sets last_written to 0
    // so we expect None, but the field must exist and be accessible)
    let subkey = format!("{IAF_PATH}\\lwtest");
    let data = TestHiveBuilder::new().add_key(&subkey).build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    // last_written is None when builder writes 0 filetime (which is the case in TestHiveBuilder)
    // The important thing: the field exists and is Option<String>
    let _ = entries[0].last_written.as_deref();
}

// ---------------------------------------------------------------------------
// Test 10: parse_key_name_populated
// ---------------------------------------------------------------------------

#[test]
fn parse_key_name_populated() {
    let subkey_name = "deadbeef1234";
    let subkey = format!("{IAF_PATH}\\{subkey_name}");
    let data = TestHiveBuilder::new().add_key(&subkey).build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].key_name, subkey_name,
        "key_name should be the subkey name (hash identifier)"
    );
}

// ---------------------------------------------------------------------------
// Test 11: parse_multiple_entries
// ---------------------------------------------------------------------------

#[test]
fn parse_multiple_entries() {
    let sub1 = format!("{IAF_PATH}\\entry_a");
    let sub2 = format!("{IAF_PATH}\\entry_b");
    let data = TestHiveBuilder::new()
        .add_key(&sub1)
        .add_value(&sub1, "LowerCaseLongPath", REG_SZ, &utf16le("C:\\a.exe"))
        .add_key(&sub2)
        .add_value(&sub2, "LowerCaseLongPath", REG_SZ, &utf16le("C:\\b.exe"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 2, "should return an entry per subkey");
}

// ---------------------------------------------------------------------------
// Test 12: AmcacheEntry struct accessible
// ---------------------------------------------------------------------------

#[test]
fn amcache_entry_struct_fields_accessible() {
    let entry = AmcacheEntry {
        file_path: "C:\\foo.exe".to_string(),
        sha1: "abc123".to_string(),
        size: 1024,
        link_date: Some("01/15/2023 10:30:00".to_string()),
        publisher: "Acme".to_string(),
        product_name: "FooApp".to_string(),
        product_version: "1.0.0".to_string(),
        bin_file_version: "1.0.0.0".to_string(),
        key_name: "deadbeef".to_string(),
        last_written: None,
    };
    assert_eq!(entry.file_path, "C:\\foo.exe");
    assert_eq!(entry.sha1, "abc123");
    assert_eq!(entry.size, 1024);
    assert_eq!(entry.publisher, "Acme");
    assert_eq!(entry.key_name, "deadbeef");
}

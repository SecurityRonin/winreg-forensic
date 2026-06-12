#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::shimcache`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::shimcache::{parse, ShimcacheEntry};
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Correct key path relative to the hive root.
const APPCOMPAT_KEY: &str = "CurrentControlSet\\Control\\Session Manager\\AppCompatCache";

/// Value name holding the binary blob.
const APPCOMPAT_VALUE: &str = "AppCompatCache";

// REG_BINARY = 3
const REG_BINARY: u32 = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal but recognisable AppCompatCache blob.
/// The blob starts with the Win10 "10ts" signature (little-endian 0x73743031),
/// followed by a u32 entry count of 0, so no entries should be parsed.
fn empty_appcompat_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    // Signature: "10ts" = 0x30 0x31 0x74 0x73 (little-endian for 0x73743031)
    blob.extend_from_slice(&0x73743031u32.to_le_bytes());
    // Entry count = 0
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob
}

/// Build a blob with an unrecognised signature.
fn unknown_signature_blob() -> Vec<u8> {
    // Something that is definitely not a known shimcache signature.
    vec![0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x00, 0x00, 0x00]
}

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
        "empty hive (no AppCompatCache key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_missing_key_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_key_returns_empty() {
    // Hive with an unrelated key, not the AppCompatCache path.
    let data = TestHiveBuilder::new().add_key("SomeOtherKey\\Foo").build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "hive without AppCompatCache key should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 3: parse_present_blob_returns_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_present_blob_returns_entry() {
    let blob = unknown_signature_blob();
    let data = TestHiveBuilder::new()
        .add_key(APPCOMPAT_KEY)
        .add_value(APPCOMPAT_KEY, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        !entries.is_empty(),
        "hive with AppCompatCache blob should return at least one entry"
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_entry_raw_size_matches_blob
// ---------------------------------------------------------------------------

#[test]
fn parse_entry_raw_size_matches_blob() {
    let blob = unknown_signature_blob();
    let expected_size = blob.len();
    let data = TestHiveBuilder::new()
        .add_key(APPCOMPAT_KEY)
        .add_value(APPCOMPAT_KEY, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].raw_size, expected_size,
        "raw_size should equal the byte length of the AppCompatCache blob"
    );
}

// ---------------------------------------------------------------------------
// Test 5: parse_entry_index_is_zero_for_first
// ---------------------------------------------------------------------------

#[test]
fn parse_entry_index_is_zero_for_first() {
    let blob = unknown_signature_blob();
    let data = TestHiveBuilder::new()
        .add_key(APPCOMPAT_KEY)
        .add_value(APPCOMPAT_KEY, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].entry_index, 0,
        "first entry should have entry_index == 0"
    );
}

// ---------------------------------------------------------------------------
// Test 6: parse_multiple_format_graceful (short blob < 4 bytes → empty vec)
// ---------------------------------------------------------------------------

#[test]
fn parse_multiple_format_graceful() {
    // A blob shorter than 4 bytes cannot contain a valid signature.
    let blob: Vec<u8> = vec![0x01, 0x02, 0x03];
    let data = TestHiveBuilder::new()
        .add_key(APPCOMPAT_KEY)
        .add_value(APPCOMPAT_KEY, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    // Must not panic; should return empty vec for blobs too short to parse.
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "blob shorter than 4 bytes should return empty vec, not panic"
    );
}

// ---------------------------------------------------------------------------
// Test 7: parse_result_is_serializable
// ---------------------------------------------------------------------------

#[test]
fn parse_result_is_serializable() {
    let blob = unknown_signature_blob();
    let data = TestHiveBuilder::new()
        .add_key(APPCOMPAT_KEY)
        .add_value(APPCOMPAT_KEY, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    let json = serde_json::to_string(&entries);
    assert!(
        json.is_ok(),
        "parse result should be JSON-serializable: {:?}",
        json.err()
    );
}

// ---------------------------------------------------------------------------
// Test 8: parse_key_path_is_correct
// ---------------------------------------------------------------------------

#[test]
fn parse_key_path_is_correct() {
    let blob = unknown_signature_blob();

    // Build hive with blob at the CORRECT path.
    let correct_data = TestHiveBuilder::new()
        .add_key(APPCOMPAT_KEY)
        .add_value(APPCOMPAT_KEY, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();

    // Build hive with blob at a WRONG path.
    let wrong_path = "CurrentControlSet\\Control\\Session Manager\\NotShimCache";
    let wrong_data = TestHiveBuilder::new()
        .add_key(wrong_path)
        .add_value(wrong_path, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .build();

    let correct_hive = Hive::from_bytes(correct_data).unwrap();
    let wrong_hive = Hive::from_bytes(wrong_data).unwrap();

    let correct_entries = parse(&correct_hive);
    let wrong_entries = parse(&wrong_hive);

    assert!(
        !correct_entries.is_empty(),
        "correct key path should yield entries"
    );
    assert!(
        wrong_entries.is_empty(),
        "wrong key path should yield no entries"
    );
}

// ---------------------------------------------------------------------------
// Test: offline-hive ControlSet resolution (real-world quirk)
// ---------------------------------------------------------------------------

/// REG_DWORD = 4
const REG_DWORD: u32 = 4;

/// Real OFFLINE SYSTEM hives have NO `CurrentControlSet` key — that is a volatile
/// runtime symlink the kernel materialises. Offline they carry `ControlSet001`
/// (and maybe `002`) plus a `Select` key whose `Current` REG_DWORD names the
/// active set. The decoder must resolve AppCompatCache through `Select\Current`,
/// not the absent `CurrentControlSet`. (This is why shimcache returned 0 on the
/// Case-001 SYSTEM hive while the synthetic `CurrentControlSet` tests passed.)
#[test]
fn parse_resolves_controlset_from_select_on_offline_hive() {
    let blob = unknown_signature_blob();
    let key = "ControlSet001\\Control\\Session Manager\\AppCompatCache";
    let data = TestHiveBuilder::new()
        .add_key(key)
        .add_value(key, APPCOMPAT_VALUE, REG_BINARY, &blob)
        .add_key("Select")
        .add_value("Select", "Current", REG_DWORD, &1u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        !entries.is_empty(),
        "must resolve AppCompatCache via Select\\Current → ControlSet001 on an \
         offline hive that has no CurrentControlSet"
    );
}

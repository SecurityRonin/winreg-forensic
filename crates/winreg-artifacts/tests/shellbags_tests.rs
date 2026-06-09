#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::shellbags`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::shellbags::{parse, ShellbagEntry};
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Primary BagMRU path (NTUSER.DAT / modern Windows).
const BAGMRU_PATH: &str = "Software\\Microsoft\\Windows\\Shell\\BagMRU";

// REG_BINARY = 3, REG_SZ = 1
const REG_BINARY: u32 = 3;

// ---------------------------------------------------------------------------
// Helper: build a MRUListEx binary value for given slot indices.
// Terminated with 0xFFFF_FFFF.
// ---------------------------------------------------------------------------

fn mrulistex(indices: &[u32]) -> Vec<u8> {
    let mut data: Vec<u8> = indices
        .iter()
        .flat_map(|&i| i.to_le_bytes())
        .collect();
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data
}

// ---------------------------------------------------------------------------
// Helper: a minimal ShellItem binary blob (just some bytes, not parsed).
// ---------------------------------------------------------------------------

fn shell_item_blob(tag: u8) -> Vec<u8> {
    vec![tag, 0x00, 0x1F, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]
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
        "empty hive (no BagMRU key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_bagmru_key_returns_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_bagmru_key_returns_entry() {
    // BagMRU key with one slot value "0"
    let blob = shell_item_blob(0xAA);
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .add_value(BAGMRU_PATH, "0", REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        !entries.is_empty(),
        "BagMRU key with slot values should produce at least one entry"
    );
}

// ---------------------------------------------------------------------------
// Test 3: parse_entry_key_path_is_correct
// ---------------------------------------------------------------------------

#[test]
fn parse_entry_key_path_is_correct() {
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    // The BagMRU key itself should appear (even with no slot values)
    assert_eq!(entries.len(), 1, "should have one entry for the BagMRU key");
    assert!(
        entries[0].key_path.contains("BagMRU"),
        "key_path should contain 'BagMRU', got: {}",
        entries[0].key_path
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_last_written_populated
// ---------------------------------------------------------------------------

#[test]
fn parse_last_written_populated() {
    // last_written comes from key metadata. Builder writes 0 filetime → None.
    // Field must exist and be Option<String>.
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    // Access the field — it should be None (builder sets last_written=0)
    let _lw: Option<&str> = entries[0].last_written.as_deref();
}

// ---------------------------------------------------------------------------
// Test 5: parse_mru_order_decoded
// ---------------------------------------------------------------------------

#[test]
fn parse_mru_order_decoded() {
    // MRUListEx = [2, 0, 1, 0xFFFFFFFF]
    let mru = mrulistex(&[2, 0, 1]);
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .add_value(BAGMRU_PATH, "MRUListEx", REG_BINARY, &mru)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    let order = &entries[0].mru_order;
    assert_eq!(order.len(), 3, "MRUListEx [2,0,1,term] should decode to 3 items");
    assert_eq!(order[0], "2", "first MRU slot should be '2'");
    assert_eq!(order[1], "0", "second MRU slot should be '0'");
    assert_eq!(order[2], "1", "third MRU slot should be '1'");
}

// ---------------------------------------------------------------------------
// Test 6: parse_subkey_creates_separate_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_subkey_creates_separate_entry() {
    let subkey = format!("{BAGMRU_PATH}\\0");
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .add_key(&subkey)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(
        entries.len(),
        2,
        "BagMRU key + one subkey should produce 2 entries (recursive walk)"
    );
}

// ---------------------------------------------------------------------------
// Test 7: parse_missing_mrulistex_gives_empty_order
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_mrulistex_gives_empty_order() {
    // BagMRU key with no MRUListEx value
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].mru_order.is_empty(),
        "mru_order should be empty when MRUListEx is absent"
    );
}

// ---------------------------------------------------------------------------
// Test 8: parse_path_field_contains_slot_preview
// ---------------------------------------------------------------------------

#[test]
fn parse_path_field_contains_slot_preview() {
    // When slot "0" is present, path should contain a descriptive preview
    let blob = shell_item_blob(0x1F);
    let data = TestHiveBuilder::new()
        .add_key(BAGMRU_PATH)
        .add_value(BAGMRU_PATH, "0", REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    // Path field should show something about the slots
    // (e.g., "BagMRU[slot=0, size=8 bytes]" or similar)
    assert!(
        !entries[0].path.is_empty(),
        "path should not be empty when slot values are present"
    );
}

// ---------------------------------------------------------------------------
// Test 9: ShellbagEntry struct accessible
// ---------------------------------------------------------------------------

#[test]
fn shellbag_entry_struct_fields_accessible() {
    let entry = ShellbagEntry {
        path: "BagMRU[slot=0, size=8 bytes]".to_string(),
        key_path: "Software\\Microsoft\\Windows\\Shell\\BagMRU".to_string(),
        last_written: None,
        mru_order: vec!["2".to_string(), "0".to_string()],
    };
    assert_eq!(entry.path, "BagMRU[slot=0, size=8 bytes]");
    assert_eq!(entry.key_path, "Software\\Microsoft\\Windows\\Shell\\BagMRU");
    assert!(entry.last_written.is_none());
    assert_eq!(entry.mru_order.len(), 2);
}

#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::lsadump`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::lsadump::{is_interesting_secret, parse_dcc2_slots, parse_secrets};
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECRETS_KEY: &str = "Policy\\Secrets";
const CACHE_KEY: &str = "Cache";

/// REG_BINARY type
const REG_BINARY: u32 = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a full key path under Policy\Secrets\<name>.
fn secret_key(name: &str) -> String {
    format!("{SECRETS_KEY}\\{name}")
}

/// Build a key path for a CurrVal subkey under a named secret.
fn currval_key(name: &str) -> String {
    format!("{SECRETS_KEY}\\{name}\\CurrVal")
}

/// Build a key path for an OldVal subkey under a named secret.
fn oldval_key(name: &str) -> String {
    format!("{SECRETS_KEY}\\{name}\\OldVal")
}

/// Build a key path for a DCC2 slot under Cache.
fn cache_slot_key(slot: &str) -> String {
    format!("{CACHE_KEY}\\{slot}")
}

/// Generate `n` arbitrary bytes to simulate encrypted blob data.
fn fake_blob(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xFF) as u8).collect()
}

// ---------------------------------------------------------------------------
// Test 1: parse_secrets_empty_hive_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_secrets_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse_secrets(&hive);
    assert!(
        entries.is_empty(),
        "empty hive (no Policy\\Secrets key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_secrets_returns_entry_for_each_subkey
// ---------------------------------------------------------------------------

#[test]
fn parse_secrets_returns_entry_for_each_subkey() {
    let s1 = secret_key("$MACHINE.ACC");
    let s2 = secret_key("DPAPI_SYSTEM");
    let data = TestHiveBuilder::new().add_key(&s1).add_key(&s2).build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse_secrets(&hive);
    assert_eq!(
        entries.len(),
        2,
        "two secret subkeys should produce two entries"
    );
}

// ---------------------------------------------------------------------------
// Test 3: parse_secrets_name_captured
// ---------------------------------------------------------------------------

#[test]
fn parse_secrets_name_captured() {
    let key = secret_key("DefaultPassword");
    let data = TestHiveBuilder::new().add_key(&key).build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse_secrets(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].name, "DefaultPassword",
        "secret name should match the subkey name"
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_secrets_has_current_true_when_currval_present
// ---------------------------------------------------------------------------

#[test]
fn parse_secrets_has_current_true_when_currval_present() {
    let secret = secret_key("DPAPI_SYSTEM");
    let currval = currval_key("DPAPI_SYSTEM");
    let blob = fake_blob(32);
    let data = TestHiveBuilder::new()
        .add_key(&secret)
        .add_key(&currval)
        .add_value(&currval, "(default)", REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse_secrets(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].has_current,
        "has_current should be true when CurrVal value is present and non-empty"
    );
}

// ---------------------------------------------------------------------------
// Test 5: parse_secrets_has_old_false_when_oldval_absent
// ---------------------------------------------------------------------------

#[test]
fn parse_secrets_has_old_false_when_oldval_absent() {
    let secret = secret_key("NL$KM");
    let currval = currval_key("NL$KM");
    let blob = fake_blob(16);
    let data = TestHiveBuilder::new()
        .add_key(&secret)
        .add_key(&currval)
        .add_value(&currval, "(default)", REG_BINARY, &blob)
        // No OldVal key
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse_secrets(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        !entries[0].has_old,
        "has_old should be false when OldVal is absent"
    );
}

// ---------------------------------------------------------------------------
// Test 6: parse_secrets_curr_size_matches_data_length
// ---------------------------------------------------------------------------

#[test]
fn parse_secrets_curr_size_matches_data_length() {
    let secret = secret_key("_SC_TestService");
    let currval = currval_key("_SC_TestService");
    let blob = fake_blob(64);
    let data = TestHiveBuilder::new()
        .add_key(&secret)
        .add_key(&currval)
        .add_value(&currval, "(default)", REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse_secrets(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].curr_size, 64,
        "curr_size should match the byte length of the CurrVal data"
    );
}

// ---------------------------------------------------------------------------
// Test 7: classify_machine_acc_is_interesting
// ---------------------------------------------------------------------------

#[test]
fn classify_machine_acc_is_interesting() {
    assert!(
        is_interesting_secret("$MACHINE.ACC"),
        "$MACHINE.ACC should be classified as interesting"
    );
}

// ---------------------------------------------------------------------------
// Test 8: classify_default_password_is_interesting
// ---------------------------------------------------------------------------

#[test]
fn classify_default_password_is_interesting() {
    assert!(
        is_interesting_secret("DefaultPassword"),
        "DefaultPassword should be classified as interesting"
    );
}

// ---------------------------------------------------------------------------
// Test 9: classify_sc_prefix_is_interesting
// ---------------------------------------------------------------------------

#[test]
fn classify_sc_prefix_is_interesting() {
    assert!(
        is_interesting_secret("_SC_MyService"),
        "_SC_ prefix secrets should be classified as interesting"
    );
}

// ---------------------------------------------------------------------------
// Test 10: classify_unknown_name_is_not_interesting
// ---------------------------------------------------------------------------

#[test]
fn classify_unknown_name_is_not_interesting() {
    assert!(
        !is_interesting_secret("SomeRandomKey"),
        "unknown secret names should NOT be classified as interesting"
    );
}

// ---------------------------------------------------------------------------
// Test 11: parse_dcc2_slots_empty_hive_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_dcc2_slots_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let slots = parse_dcc2_slots(&hive);
    assert!(
        slots.is_empty(),
        "empty hive (no Cache key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 12: parse_dcc2_slots_populated_slot_detected
// ---------------------------------------------------------------------------

#[test]
fn parse_dcc2_slots_populated_slot_detected() {
    let slot_path = cache_slot_key("NL$1");
    let blob = fake_blob(72); // typical DCC2 credential size
    let data = TestHiveBuilder::new()
        .add_key(&slot_path)
        .add_value(&slot_path, "(default)", REG_BINARY, &blob)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let slots = parse_dcc2_slots(&hive);
    assert!(!slots.is_empty(), "should return at least one slot entry");
    let nl1 = slots.iter().find(|s| s.slot_name == "NL$1");
    assert!(nl1.is_some(), "NL$1 should be present in results");
    let nl1 = nl1.unwrap();
    assert!(
        nl1.is_populated,
        "NL$1 with non-empty data should be is_populated=true"
    );
    assert_eq!(nl1.data_size, 72, "data_size should match blob length");
}

// ---------------------------------------------------------------------------
// Test 13: parse_dcc2_slots_empty_slot_not_populated
// ---------------------------------------------------------------------------

#[test]
fn parse_dcc2_slots_empty_slot_not_populated() {
    let slot_path = cache_slot_key("NL$2");
    let data = TestHiveBuilder::new()
        .add_key(&slot_path)
        // Empty blob — 0 bytes
        .add_value(&slot_path, "(default)", REG_BINARY, &[])
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let slots = parse_dcc2_slots(&hive);
    assert!(!slots.is_empty(), "should return the slot even when empty");
    let nl2 = slots.iter().find(|s| s.slot_name == "NL$2");
    assert!(nl2.is_some(), "NL$2 should be present in results");
    let nl2 = nl2.unwrap();
    assert!(
        !nl2.is_populated,
        "NL$2 with empty (0-byte) data should be is_populated=false"
    );
    assert_eq!(nl2.data_size, 0);
}

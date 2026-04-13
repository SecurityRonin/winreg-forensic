//! Integration tests for `winreg_artifacts::sam`.
//!
//! RED phase: tests define expected behaviour and must FAIL until the
//! `parse` function is implemented.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::sam::parse;
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REG_BINARY: u32 = 3;

/// Build the F record binary for a SAM user.
///
/// Layout (72 bytes minimum):
///   0-1:   version (u16 LE) = 2
///   2-7:   padding
///   8-15:  last login FILETIME (u64 LE)
///  16-23:  password last set FILETIME (u64 LE)
///  24-31:  account expires FILETIME (u64 LE)  — 0 = never
///  32-55:  padding
///  56-59:  account flags (u32 LE)
///  60-65:  padding
///  66-67:  login count (u16 LE)
///  68-71:  padding
fn build_f_record(
    last_login: u64,
    password_last_set: u64,
    account_expires: u64,
    account_flags: u32,
    login_count: u16,
) -> Vec<u8> {
    let mut f = vec![0u8; 72];
    // version = 2
    f[0..2].copy_from_slice(&2u16.to_le_bytes());
    // last login (bytes 8-15)
    f[8..16].copy_from_slice(&last_login.to_le_bytes());
    // password last set (bytes 16-23)
    f[16..24].copy_from_slice(&password_last_set.to_le_bytes());
    // account expires (bytes 24-31)
    f[24..32].copy_from_slice(&account_expires.to_le_bytes());
    // account flags (bytes 56-59)
    f[56..60].copy_from_slice(&account_flags.to_le_bytes());
    // login count (bytes 66-67)
    f[66..68].copy_from_slice(&login_count.to_le_bytes());
    f
}

/// A non-zero FILETIME value corresponding to 2024-01-01 00:00:00 UTC.
const FILETIME_2024: u64 = 133_485_408_000_000_000;

/// Build a SAM hive with one user.
///
/// `rid_hex` should be an 8-digit uppercase hex string, e.g. `"000001F4"` for RID 500.
fn build_sam_hive_one_user(
    username: &str,
    rid_hex: &str,
    f_record: &[u8],
) -> Vec<u8> {
    let names_path = format!("SAM\\Domains\\Account\\Users\\Names\\{username}");
    let rid_path = format!("SAM\\Domains\\Account\\Users\\{rid_hex}");

    TestHiveBuilder::new()
        .add_key(&names_path)
        .add_key(&rid_path)
        .add_value(&rid_path, "F", REG_BINARY, f_record)
        .build()
}

/// Build a SAM hive with two users.
fn build_sam_hive_two_users(
    username1: &str,
    rid_hex1: &str,
    f1: &[u8],
    username2: &str,
    rid_hex2: &str,
    f2: &[u8],
) -> Vec<u8> {
    let names_path1 = format!("SAM\\Domains\\Account\\Users\\Names\\{username1}");
    let names_path2 = format!("SAM\\Domains\\Account\\Users\\Names\\{username2}");
    let rid_path1 = format!("SAM\\Domains\\Account\\Users\\{rid_hex1}");
    let rid_path2 = format!("SAM\\Domains\\Account\\Users\\{rid_hex2}");

    TestHiveBuilder::new()
        .add_key(&names_path1)
        .add_key(&names_path2)
        .add_key(&rid_path1)
        .add_value(&rid_path1, "F", REG_BINARY, f1)
        .add_key(&rid_path2)
        .add_value(&rid_path2, "F", REG_BINARY, f2)
        .build()
}

// ---------------------------------------------------------------------------
// Test 1: parse_empty_hive_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert!(
        results.is_empty(),
        "empty hive (no SAM\\Domains key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_sam_user_returns_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_sam_user_returns_entry() {
    let f = build_f_record(0, 0, 0, 0, 0);
    let data = build_sam_hive_one_user("Administrator", "000001F4", &f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1, "should return one entry");
}

// ---------------------------------------------------------------------------
// Test 3: parse_username_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_username_extracted() {
    let f = build_f_record(0, 0, 0, 0, 0);
    let data = build_sam_hive_one_user("TestUser", "000003E9", &f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].username, "TestUser",
        "username should match the Names subkey"
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_disabled_flag_detected
// ---------------------------------------------------------------------------

#[test]
fn parse_disabled_flag_detected() {
    // account_flags bit 0x0001 = disabled
    let f = build_f_record(0, 0, 0, 0x0001, 0);
    let data = build_sam_hive_one_user("DisabledUser", "000003EA", &f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1);
    assert!(results[0].is_disabled, "is_disabled should be true when flag 0x0001 is set");
    assert_eq!(results[0].account_flags & 0x0001, 0x0001);
}

// ---------------------------------------------------------------------------
// Test 5: parse_login_count_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_login_count_extracted() {
    let f = build_f_record(0, 0, 0, 0, 42);
    let data = build_sam_hive_one_user("CountUser", "000003EB", &f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].login_count, 42, "login_count should be extracted from F record bytes 66-67");
}

// ---------------------------------------------------------------------------
// Test 6: parse_last_login_filetime_converted
// ---------------------------------------------------------------------------

#[test]
fn parse_last_login_filetime_converted() {
    let f = build_f_record(FILETIME_2024, 0, 0, 0, 0);
    let data = build_sam_hive_one_user("LoginUser", "000003EC", &f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1);
    let last_login = results[0].last_login.as_deref().unwrap_or("");
    assert!(
        last_login.contains("2024"),
        "last_login should be an ISO 8601 string containing '2024', got: {last_login:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 7: parse_zero_filetime_gives_none
// ---------------------------------------------------------------------------

#[test]
fn parse_zero_filetime_gives_none() {
    let f = build_f_record(0, 0, 0, 0, 0);
    let data = build_sam_hive_one_user("ZeroUser", "000003ED", &f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].last_login.is_none(),
        "zero FILETIME should produce None for last_login"
    );
    assert!(
        results[0].password_last_set.is_none(),
        "zero FILETIME should produce None for password_last_set"
    );
}

// ---------------------------------------------------------------------------
// Test 8: parse_short_f_record_returns_defaults
// ---------------------------------------------------------------------------

#[test]
fn parse_short_f_record_returns_defaults() {
    // F record is only 4 bytes — too short for any fields
    let short_f = vec![0u8; 4];
    let data = build_sam_hive_one_user("ShortUser", "000003EE", &short_f);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 1);
    let entry = &results[0];
    assert!(entry.last_login.is_none(), "short F record: last_login should be None");
    assert_eq!(entry.login_count, 0, "short F record: login_count should default to 0");
    assert_eq!(entry.account_flags, 0, "short F record: account_flags should default to 0");
    assert!(!entry.is_disabled);
    assert!(!entry.is_locked);
}

// ---------------------------------------------------------------------------
// Test 9: parse_multiple_users_returns_all
// ---------------------------------------------------------------------------

#[test]
fn parse_multiple_users_returns_all() {
    let f1 = build_f_record(0, 0, 0, 0, 5);
    let f2 = build_f_record(0, 0, 0, 0x0001, 10);
    let data = build_sam_hive_two_users(
        "AdminUser", "000001F4", &f1,
        "GuestUser", "000001F5", &f2,
    );
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse(&hive);
    assert_eq!(results.len(), 2, "should return one entry per username");

    let names: Vec<&str> = results.iter().map(|e| e.username.as_str()).collect();
    assert!(names.contains(&"AdminUser"), "AdminUser should be present");
    assert!(names.contains(&"GuestUser"), "GuestUser should be present");
}

//! Integration tests for `winreg_artifacts::typed_urls`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::typed_urls::{parse, TypedUrl};
use winreg_core::hive::Hive;

// ── Helper: encode a string as UTF-16LE with null terminator ─────────────────

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.extend_from_slice(&[0x00, 0x00]); // null terminator
    out
}

/// Build a FILETIME (u64 LE) for a known timestamp.
/// Using Windows FILETIME for 2023-01-15 12:00:00 UTC:
/// (2023-01-15 12:00:00 UTC) = 133_183_968_000_000_000 in FILETIME units
fn sample_filetime() -> Vec<u8> {
    133_183_968_000_000_000u64.to_le_bytes().to_vec()
}

// ── Test 1: empty hive returns empty ─────────────────────────────────────────

#[test]
fn parse_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "empty hive (no TypedURLs key) should return empty Vec"
    );
}

// ── Test 2: typed URL returns entry ──────────────────────────────────────────

#[test]
fn parse_typed_url_returns_entry() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://www.google.com";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "expected 1 entry");
    assert_eq!(entries[0].url, url);
}

// ── Test 3: URL with time entry sets last_visited ────────────────────────────

#[test]
fn parse_url_with_time_sets_last_visited() {
    let urls_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let time_path = "Software\\Microsoft\\Internet Explorer\\TypedURLsTime";
    let url = "https://www.example.com";
    let data = TestHiveBuilder::new()
        .add_key(urls_path)
        .add_value(urls_path, "url1", 1, &utf16le(url))
        .add_key(time_path)
        .add_value(time_path, "url1", 3, &sample_filetime()) // REG_BINARY = 3
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "expected 1 entry");
    assert!(
        entries[0].last_visited.is_some(),
        "last_visited should be Some when TypedURLsTime has matching entry"
    );
    // Should be a valid ISO 8601 string
    let ts = entries[0].last_visited.as_ref().unwrap();
    assert!(ts.contains("2023"), "ISO timestamp should include year 2023");
}

// ── Test 4: URL without time entry has None ───────────────────────────────────

#[test]
fn parse_url_without_time_entry_has_none() {
    let urls_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://www.example.com";
    let data = TestHiveBuilder::new()
        .add_key(urls_path)
        .add_value(urls_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].last_visited.is_none(),
        "last_visited should be None when no TypedURLsTime entry exists"
    );
}

// ── Test 5: pastebin.com is suspicious ───────────────────────────────────────

#[test]
fn classify_pastebin_is_suspicious() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://pastebin.com/abc123";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_suspicious, "pastebin.com should be suspicious");
    assert!(
        entries[0].suspicious_reason.is_some(),
        "suspicious_reason should be set"
    );
}

// ── Test 6: ngrok.io is suspicious ───────────────────────────────────────────

#[test]
fn classify_ngrok_is_suspicious() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://abc123.ngrok.io/shell";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_suspicious, "ngrok.io should be suspicious");
}

// ── Test 7: normal URL is benign ─────────────────────────────────────────────

#[test]
fn classify_normal_url_is_benign() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://www.microsoft.com/en-us";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].is_suspicious, "microsoft.com should not be suspicious");
    assert!(entries[0].suspicious_reason.is_none());
}

// ── Test 8: raw IP address URL is suspicious ──────────────────────────────────

#[test]
fn classify_raw_ip_is_suspicious() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "http://192.168.1.100/payload";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_suspicious, "raw IP URL should be suspicious");
    assert!(entries[0].suspicious_reason.is_some());
}

// ── Test 9: suspicious URL sets flag ─────────────────────────────────────────

#[test]
fn parse_suspicious_url_sets_flag() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://transfer.sh/malware.exe";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_suspicious, "transfer.sh should be suspicious");
    assert!(
        entries[0].suspicious_reason.as_deref().unwrap_or("").contains("transfer.sh"),
        "reason should mention transfer.sh"
    );
}

// ── Test 10: multiple URLs are all returned ───────────────────────────────────

#[test]
fn parse_multiple_urls_returned() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le("https://www.google.com"))
        .add_value(key_path, "url2", 1, &utf16le("https://pastebin.com/xyz"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 2, "should return 2 URL entries");
    let suspicious_count = entries.iter().filter(|e| e.is_suspicious).count();
    assert_eq!(suspicious_count, 1, "only pastebin.com should be suspicious");
}

// ── Test 11: trycloudflare.com is suspicious ──────────────────────────────────

#[test]
fn classify_trycloudflare_is_suspicious() {
    let key_path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let url = "https://abc123.trycloudflare.com/cmd";
    let data = TestHiveBuilder::new()
        .add_key(key_path)
        .add_value(key_path, "url1", 1, &utf16le(url))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].is_suspicious,
        "trycloudflare.com should be suspicious"
    );
}

// ── Test 12: TypedUrl struct fields are accessible ───────────────────────────

#[test]
fn typed_url_struct_fields_accessible() {
    let entry = TypedUrl {
        url: "https://example.com".to_string(),
        last_visited: None,
        is_suspicious: false,
        suspicious_reason: None,
    };
    assert_eq!(entry.url, "https://example.com");
    assert!(!entry.is_suspicious);
}

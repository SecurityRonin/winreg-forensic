#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::catalog_scan`.
//!
//! The catalog scanner is driven entirely by `forensicnomicon`'s registry
//! artifact catalog: it enumerates every registry descriptor whose hive matches
//! the hive under analysis, resolves the descriptor's key path, and emits the
//! decoded value(s). This proves coverage of artifacts winreg never hardcoded a
//! module for.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! `catalog_scan` exists.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::catalog_scan::{scan, CatalogHit};
use winreg_core::hive::Hive;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.extend_from_slice(&[0x00, 0x00]); // NUL terminator
    out
}

const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

/// Add the root subkeys that make `detect_hive_type` classify a hive as SOFTWARE
/// (it looks for `Microsoft` + `Classes` at the root).
fn software_root(b: TestHiveBuilder) -> TestHiveBuilder {
    b.add_key("Classes")
}

/// Find the hit whose catalog id matches.
fn find<'a>(hits: &'a [CatalogHit], id: &str) -> Option<&'a CatalogHit> {
    hits.iter().find(|h| h.catalog_id == id)
}

// ── Test 1: NEW COVERAGE — AppInit_DLLs (never had a winreg module) ──────────

#[test]
fn scan_surfaces_appinit_dlls_a_new_catalog_artifact() {
    // `appinit_dlls`: HklmSoftware, key `Microsoft\Windows NT\CurrentVersion\Windows`,
    // value `AppInit_DLLs`. winreg-artifacts has NO dedicated module for this —
    // it comes purely from the forensicnomicon catalog.
    let key = r"Microsoft\Windows NT\CurrentVersion\Windows";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(key)
        .add_value(key, "AppInit_DLLs", REG_SZ, &utf16le(r"C:\evil\inject.dll"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let hit = find(&hits, "appinit_dlls")
        .expect("catalog-driven scan must surface the AppInit_DLLs artifact");

    assert_eq!(hit.value_name.as_deref(), Some("AppInit_DLLs"));
    assert_eq!(hit.value_data, r"C:\evil\inject.dll");
    assert_eq!(hit.key_path, key);
}

// ── Test 2: empty hive yields no hits ────────────────────────────────────────

#[test]
fn scan_empty_software_hive_returns_no_hits() {
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    assert!(scan(&hive).is_empty());
}

// ── Test 3: regression — Run key still surfaces via the catalog ──────────────

#[test]
fn scan_still_surfaces_run_key_values() {
    let run = r"Microsoft\Windows\CurrentVersion\Run";
    let cmd = r"C:\Program Files\App\app.exe";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(run)
        .add_value(run, "MyApp", REG_SZ, &utf16le(cmd))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    // The Run key is a key-level descriptor (value_name: None) — its child values
    // must each become a hit.
    let run_hit = hits
        .iter()
        .find(|h| h.key_path == run && h.value_name.as_deref() == Some("MyApp"))
        .expect("Run-key value must surface via the catalog scan");
    assert_eq!(run_hit.value_data, cmd);
    assert_eq!(run_hit.catalog_id, "run_key_hklm");
}

// ── Test 4: DWORD decoder via catalog (InstallDate) ──────────────────────────

#[test]
fn scan_decodes_dword_value() {
    // `windows_install_date`: HklmSoftware, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
    // value `InstallDate`, decoder DwordLe. Catalog key_path carries an extra
    // leading `SOFTWARE\` (catalog quirk) — see notes.
    let key = r"Microsoft\Windows NT\CurrentVersion";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(key)
        .add_value(key, "InstallDate", REG_DWORD, &0x1234_5678u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    // Find any hit whose value_name is InstallDate under this key.
    let hit = hits
        .iter()
        .find(|h| h.value_name.as_deref() == Some("InstallDate"))
        .expect("InstallDate DWORD must surface via the catalog scan");
    assert_eq!(hit.value_data, "305419896"); // 0x12345678
}

// ── Test 5: hive-mismatched descriptors are not resolved ─────────────────────

#[test]
fn scan_only_resolves_matching_hive_descriptors() {
    // A SOFTWARE hive must never emit an NtUser-only artifact like `typed_urls`,
    // even if the key happens to exist.
    let key = r"Software\Microsoft\Internet Explorer\TypedURLs";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(key)
        .add_value(key, "url1", REG_SZ, &utf16le("https://example.com"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    assert!(
        find(&hits, "typed_urls").is_none(),
        "NtUser-only descriptor must not be resolved against a SOFTWARE hive"
    );
}

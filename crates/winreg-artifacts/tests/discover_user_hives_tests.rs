#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration test for `winreg_artifacts::catalog_scan::discover_user_hives`.
//!
//! The discovery helper walks a mounted-image profile root (`Users/<name>/…`)
//! via `winreg-discover`, opening every `NTUSER.DAT` / `UsrClass.dat` into a
//! [`UserHive`] tagged with the profile name. Feeding the result into
//! `scan_users` attributes per-user artifacts back to each account.

mod common;

use std::fs;
use std::io::Write;
use std::path::Path;

use common::hive_builder::TestHiveBuilder;
use tempfile::TempDir;
use winreg_artifacts::catalog_scan::{discover_user_hives, scan_users};

const REG_SZ: u32 = 1;

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

/// Write an NTUSER hive carrying one HKCU Run-key value to `path`.
fn write_ntuser(path: &Path, run_value: &str, cmd: &str) {
    let run = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let data = TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Environment")
        .add_key(r"Software\Microsoft")
        .add_key(r"Software\Microsoft\Windows")
        .add_key(r"Software\Microsoft\Windows\CurrentVersion")
        .add_key(run)
        .add_value(run, run_value, REG_SZ, &utf16le(cmd))
        .build();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = fs::File::create(path).unwrap();
    f.write_all(&data).unwrap();
}

#[test]
fn discover_user_hives_finds_both_profiles_and_tags_them() {
    let tmp = TempDir::new().unwrap();
    let users = tmp.path().join("Users");
    write_ntuser(
        &users.join("alice").join("NTUSER.DAT"),
        "AlicePersist",
        r"C:\Users\alice\evil.exe",
    );
    write_ntuser(
        &users.join("bob").join("NTUSER.DAT"),
        "BobPersist",
        r"C:\Users\bob\backdoor.exe",
    );

    let hives = discover_user_hives(tmp.path());
    assert_eq!(hives.len(), 2, "must discover both user NTUSER hives");

    // The profile name must be derived from the `Users/<name>/…` path.
    let mut profiles: Vec<String> = hives
        .iter()
        .filter_map(|h| h.identity.profile.clone())
        .collect();
    profiles.sort();
    assert_eq!(profiles, vec!["alice".to_string(), "bob".to_string()]);

    // Feeding into scan_users attributes each Run value to its owner.
    let hits = scan_users(&hives);
    let alice_hit = hits
        .iter()
        .find(|h| h.value_name.as_deref() == Some("AlicePersist"))
        .expect("alice's Run value must surface");
    assert_eq!(
        alice_hit.user.as_ref().and_then(|u| u.profile.as_deref()),
        Some("alice")
    );
}

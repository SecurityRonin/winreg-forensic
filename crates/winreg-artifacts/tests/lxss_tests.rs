#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::lxss`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.
//!
//! Registry path: NTUSER.DAT → Software\Microsoft\Windows\CurrentVersion\Lxss
//! One subkey per distro (GUID-named); root key holds `DefaultDistribution`.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::lxss::{parse, DistroState, DistroVersion};
use winreg_core::hive::Hive;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

fn dword_le(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

const LXSS_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";
const DISTRO_GUID: &str = "{12345678-1234-1234-1234-123456789012}";
const DISTRO_GUID2: &str = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}";

fn distro_key_path(guid: &str) -> String {
    format!("{LXSS_PATH}\\{guid}")
}

// ── Test 1: no Lxss key → empty result ───────────────────────────────────────

#[test]
fn parse_no_lxss_key_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert!(distros.is_empty(), "no Lxss key should yield empty Vec");
}

// ── Test 2: Lxss key present but no subkeys → empty ──────────────────────────

#[test]
fn parse_lxss_key_no_distros_returns_empty() {
    let data = TestHiveBuilder::new().add_key(LXSS_PATH).build();
    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert!(
        distros.is_empty(),
        "Lxss key with no subkeys should yield empty Vec"
    );
}

// ── Test 3: single distro, all fields present ─────────────────────────────────

#[test]
fn parse_single_distro_all_fields() {
    let key = distro_key_path(DISTRO_GUID);
    let base_path = r"C:\Users\alice\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc\LocalState";
    let pkg_name = "CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc";
    let dist_name = "Ubuntu-22.04";

    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le(dist_name))
        .add_value(&key, "PackageFamilyName", 1, &utf16le(pkg_name))
        .add_value(&key, "BasePath", 1, &utf16le(base_path))
        .add_value(&key, "State", 4, &dword_le(1)) // 1 = Installed
        .add_value(&key, "Version", 4, &dword_le(2)) // 2 = WSL2
        .add_value(&key, "DefaultUid", 4, &dword_le(1000))
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);

    assert_eq!(distros.len(), 1, "expected 1 distro");
    let d = &distros[0];
    assert_eq!(d.guid, DISTRO_GUID);
    assert_eq!(d.distribution_name, dist_name);
    assert_eq!(d.package_family_name.as_deref(), Some(pkg_name));
    assert_eq!(d.base_path, base_path);
    assert_eq!(d.state, DistroState::Installed);
    assert_eq!(d.version, DistroVersion::Wsl2);
    assert_eq!(d.default_uid, Some(1000));
    assert!(
        d.vhdx_path().is_some(),
        "vhdx_path() should derive path from BasePath"
    );
    let vhdx = d.vhdx_path().unwrap();
    assert!(
        vhdx.ends_with("ext4.vhdx"),
        "vhdx_path should end in ext4.vhdx, got {vhdx:?}"
    );
}

// ── Test 4: Version=1 → DistroVersion::Wsl1 ──────────────────────────────────

#[test]
fn parse_wsl1_distro_version() {
    let key = distro_key_path(DISTRO_GUID);
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le("Legacy"))
        .add_value(
            &key,
            "BasePath",
            1,
            &utf16le(r"C:\Users\bob\AppData\Local\Packages\Legacy\LocalState"),
        )
        .add_value(&key, "State", 4, &dword_le(1))
        .add_value(&key, "Version", 4, &dword_le(1)) // WSL1
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(distros.len(), 1);
    assert_eq!(distros[0].version, DistroVersion::Wsl1);
}

// ── Test 5: State=4 → DistroState::Running ───────────────────────────────────

#[test]
fn parse_running_distro_state() {
    let key = distro_key_path(DISTRO_GUID);
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le("Ubuntu"))
        .add_value(&key, "BasePath", 1, &utf16le(r"C:\fake\path"))
        .add_value(&key, "State", 4, &dword_le(4)) // Running
        .add_value(&key, "Version", 4, &dword_le(2))
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(distros[0].state, DistroState::Running);
}

// ── Test 6: missing optional fields are None ─────────────────────────────────

#[test]
fn parse_missing_optional_fields_are_none() {
    let key = distro_key_path(DISTRO_GUID);
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le("Debian"))
        .add_value(&key, "BasePath", 1, &utf16le(r"C:\fake\path"))
        // State, Version, DefaultUid, PackageFamilyName omitted
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(distros.len(), 1);
    let d = &distros[0];
    assert_eq!(d.package_family_name, None);
    assert_eq!(d.default_uid, None);
    assert_eq!(d.state, DistroState::Unknown);
    assert_eq!(d.version, DistroVersion::Unknown);
}

// ── Test 7: two distros returned ─────────────────────────────────────────────

#[test]
fn parse_two_distros_both_returned() {
    let key1 = distro_key_path(DISTRO_GUID);
    let key2 = distro_key_path(DISTRO_GUID2);
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key1)
        .add_value(&key1, "DistributionName", 1, &utf16le("Ubuntu-22.04"))
        .add_value(&key1, "BasePath", 1, &utf16le(r"C:\fake\ubuntu"))
        .add_value(&key1, "State", 4, &dword_le(1))
        .add_value(&key1, "Version", 4, &dword_le(2))
        .add_key(&key2)
        .add_value(&key2, "DistributionName", 1, &utf16le("Debian"))
        .add_value(&key2, "BasePath", 1, &utf16le(r"C:\fake\debian"))
        .add_value(&key2, "State", 4, &dword_le(1))
        .add_value(&key2, "Version", 4, &dword_le(2))
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(distros.len(), 2, "expected 2 distros");
    let names: Vec<&str> = distros
        .iter()
        .map(|d| d.distribution_name.as_str())
        .collect();
    assert!(names.contains(&"Ubuntu-22.04"));
    assert!(names.contains(&"Debian"));
}

// ── Test 8: DefaultDistribution is captured ──────────────────────────────────

#[test]
fn parse_default_distribution_guid() {
    let key = distro_key_path(DISTRO_GUID);
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_value(LXSS_PATH, "DefaultDistribution", 1, &utf16le(DISTRO_GUID))
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le("Ubuntu-22.04"))
        .add_value(&key, "BasePath", 1, &utf16le(r"C:\fake\ubuntu"))
        .add_value(&key, "State", 4, &dword_le(1))
        .add_value(&key, "Version", 4, &dword_le(2))
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(distros.len(), 1);
    assert!(
        distros[0].is_default,
        "distro matching DefaultDistribution should have is_default=true"
    );
}

// ── Test 9: non-GUID subkeys are skipped ─────────────────────────────────────

#[test]
fn parse_non_guid_subkeys_are_skipped() {
    // The Lxss key sometimes has non-GUID subkeys; we only want GUID-named ones
    let key = distro_key_path(DISTRO_GUID);
    let spurious_key = format!("{LXSS_PATH}\\NotAGuid");
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le("Ubuntu"))
        .add_value(&key, "BasePath", 1, &utf16le(r"C:\fake\ubuntu"))
        .add_value(&key, "State", 4, &dword_le(1))
        .add_value(&key, "Version", 4, &dword_le(2))
        .add_key(&spurious_key)
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(
        distros.len(),
        1,
        "only GUID-named subkeys should be included"
    );
}

// ── Test 10: vhdx_path() returns None for WSL1 ───────────────────────────────

#[test]
fn vhdx_path_none_for_wsl1() {
    let key = distro_key_path(DISTRO_GUID);
    let data = TestHiveBuilder::new()
        .add_key(LXSS_PATH)
        .add_key(&key)
        .add_value(&key, "DistributionName", 1, &utf16le("Legacy"))
        .add_value(
            &key,
            "BasePath",
            1,
            &utf16le(r"C:\Users\bob\AppData\Local\lxss"),
        )
        .add_value(&key, "State", 4, &dword_le(1))
        .add_value(&key, "Version", 4, &dword_le(1)) // WSL1
        .build();

    let hive = Hive::from_bytes(data).unwrap();
    let distros = parse(&hive);
    assert_eq!(distros.len(), 1);
    assert!(
        distros[0].vhdx_path().is_none(),
        "WSL1 distros have no ext4.vhdx"
    );
}

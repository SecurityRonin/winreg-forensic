mod common;

use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use winreg_discover::scanner::discover_hives;
use winreg_discover::SourceOrigin;

/// Build a minimal valid REGF hive and write it to a file.
fn write_test_hive(path: &Path) {
    let data = common::hive_builder::TestHiveBuilder::new()
        .add_key("TestKey")
        .build();
    let mut f = fs::File::create(path).unwrap();
    f.write_all(&data).unwrap();
}

#[test]
fn discover_finds_live_system_hive() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("Windows").join("System32").join("config");
    fs::create_dir_all(&config).unwrap();
    write_test_hive(&config.join("SYSTEM"));

    let sources = discover_hives(tmp.path());
    assert!(!sources.is_empty());
    assert!(sources
        .iter()
        .any(|s| matches!(s.origin, SourceOrigin::Live)));
}

#[test]
fn discover_finds_regback() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("Windows").join("System32").join("config");
    let regback = config.join("RegBack");
    fs::create_dir_all(&regback).unwrap();
    write_test_hive(&regback.join("SYSTEM"));

    let sources = discover_hives(tmp.path());
    assert!(sources
        .iter()
        .any(|s| matches!(s.origin, SourceOrigin::RegBack)));
}

#[test]
fn discover_finds_user_hives() {
    let tmp = TempDir::new().unwrap();
    let user_dir = tmp.path().join("Users").join("testuser");
    fs::create_dir_all(&user_dir).unwrap();
    write_test_hive(&user_dir.join("NTUSER.DAT"));

    let sources = discover_hives(tmp.path());
    assert!(!sources.is_empty());
}

#[test]
fn discover_empty_dir_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let sources = discover_hives(tmp.path());
    assert!(sources.is_empty());
}

#[test]
fn discover_skips_non_hive_files() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("Windows").join("System32").join("config");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("SYSTEM"), b"not a registry hive").unwrap();

    let sources = discover_hives(tmp.path());
    assert!(sources.is_empty());
}

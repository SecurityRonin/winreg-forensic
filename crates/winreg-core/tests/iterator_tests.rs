#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_core::hive::Hive;

#[test]
fn bfs_visits_all_keys() {
    let data = TestHiveBuilder::new()
        .add_key("A")
        .add_key("A\\B")
        .add_key("A\\C")
        .add_key("A\\B\\D")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys: Vec<String> = hive
        .iter_bfs()
        .unwrap()
        .map(|k| k.unwrap().name())
        .collect();
    // BFS: root, A, then B and C (in some order), then D
    assert_eq!(keys.len(), 5); // root + A + B + C + D
    assert!(keys[0] != "A"); // root first
}

#[test]
fn dfs_visits_all_keys() {
    let data = TestHiveBuilder::new()
        .add_key("A")
        .add_key("A\\B")
        .add_key("A\\C")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys: Vec<String> = hive
        .iter_dfs()
        .unwrap()
        .map(|k| k.unwrap().name())
        .collect();
    assert_eq!(keys.len(), 4); // root + A + B + C
}

#[test]
fn empty_hive_iterates_root_only() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let keys: Vec<String> = hive
        .iter_bfs()
        .unwrap()
        .map(|k| k.unwrap().name())
        .collect();
    assert_eq!(keys.len(), 1); // just root
}

#[test]
fn from_path_works() {
    use std::io::Write;
    let data = TestHiveBuilder::new().add_key("Test").build();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.as_file().write_all(&data).unwrap();
    // Note: need to flush before reading
    drop(data);
    let hive = Hive::from_path(tmp.path()).unwrap();
    assert_eq!(hive.bin_count(), 1);
}

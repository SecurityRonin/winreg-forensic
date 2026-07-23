//! Fuzz deleted-record carving over a hive opened from arbitrary bytes.
//!
//! Drives the unallocated-cell / slack `nk`/`vk` recovery primitives on a
//! parser-accepted-but-hostile hive: it must return records or an empty vector,
//! never panic, on any input `Hive::from_bytes` admits.
#![no_main]
use libfuzzer_sys::fuzz_target;
use winreg_core::hive::Hive;

fuzz_target!(|data: &[u8]| {
    if let Ok(hive) = Hive::from_bytes(data.to_vec()) {
        let _ = winreg_carve::recover_deleted(&hive);
    }
});

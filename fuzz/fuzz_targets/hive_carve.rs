//! Fuzz the whole-hive carver over an arbitrary signature-anchored window.
//!
//! `HiveCarver::carve` sees only a `&[u8]` window from an unallocated-disk or
//! memory sweep — the most attacker-controllable entry point. It must return a
//! carved item or an empty vector, never panic, on any bytes (crafted `regf`
//! headers, lying `HiveBinsDataSize`, truncated base blocks, checksum collisions).
#![no_main]
use forensic_carve::{CarveContext, Carver, RecoveryMethod};
use libfuzzer_sys::fuzz_target;
use winreg_carve::HiveCarver;

fuzz_target!(|data: &[u8]| {
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::UnallocatedCarve);
    let _ = HiveCarver.carve(data, &ctx);
});

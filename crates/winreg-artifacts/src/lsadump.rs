//! LSA dump artifact decoder (`lsadump`).
//!
//! Enumerates LSA secret names and DCC2 (Domain Cached Credentials v2) cache
//! slot metadata from the SECURITY hive.
//!
//! This module does NOT decrypt secrets. Decryption requires the SYSTEM hive's
//! boot key and live crypto, which is out of scope for offline registry parsing.
//! It enumerates what secrets exist and what DCC2 slots are populated.
//!
//! Key paths (SECURITY hive):
//! - `SECURITY\Policy\Secrets` — subkeys are secret names
//! - `SECURITY\Policy\Secrets\<name>\CurrVal` — REG_BINARY encrypted current value
//! - `SECURITY\Policy\Secrets\<name>\OldVal`  — REG_BINARY encrypted old value
//! - `SECURITY\Cache`       — DCC2 cache
//! - `SECURITY\Cache\NL$1 .. NL$10` — REG_BINARY cached credential slots

use std::io::Cursor;

use winreg_core::hive::Hive;

// ── Output types ──────────────────────────────────────────────────────────────

/// Metadata about a single LSA secret enumerated from `SECURITY\Policy\Secrets`.
///
/// Secrets are NOT decrypted — only names and sizes are returned.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LsaSecretEntry {
    /// Secret name (e.g. `"$MACHINE.ACC"`, `"DefaultPassword"`, `"DPAPI_SYSTEM"`).
    pub name: String,
    /// `true` when the `CurrVal` sub-key exists and its value is non-empty.
    pub has_current: bool,
    /// `true` when the `OldVal` sub-key exists and its value is non-empty.
    pub has_old: bool,
    /// Byte length of `CurrVal` data (0 if absent).
    pub curr_size: usize,
    /// Byte length of `OldVal` data (0 if absent).
    pub old_size: usize,
    /// `true` for well-known forensically significant secret names.
    pub is_interesting: bool,
}

/// Occupancy metadata for a single DCC2 cache slot under `SECURITY\Cache`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Dcc2SlotEntry {
    /// Slot name, e.g. `"NL$1"`, `"NL$2"`.
    pub slot_name: String,
    /// `true` when the binary value is non-empty (> 0 bytes).
    pub is_populated: bool,
    /// Byte length of the slot value.
    pub data_size: usize,
}

// ── Classifier ────────────────────────────────────────────────────────────────

/// Return `true` when the secret name is forensically interesting.
///
/// Interesting names:
/// - `$MACHINE.ACC`   — machine account password
/// - `DefaultPassword` — auto-logon password stored in plaintext
/// - `DPAPI_SYSTEM`   — DPAPI master key protector
/// - `NL$KM`          — DCC2 encryption key
/// - `_SC_` prefix    — service account passwords
/// - `RasDialParams`  — saved VPN/dial-up credentials
pub fn is_interesting_secret(name: &str) -> bool {
    // stub — always returns false
    let _ = name;
    false
}

// ── Public parse functions ────────────────────────────────────────────────────

/// Enumerate LSA secret names and metadata from `SECURITY\Policy\Secrets`.
///
/// Does NOT decrypt — returns names and sizes only.
pub fn parse_secrets(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<LsaSecretEntry> {
    let _ = hive;
    vec![]
}

/// Enumerate DCC2 cache slot occupancy from `SECURITY\Cache`.
pub fn parse_dcc2_slots(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<Dcc2SlotEntry> {
    let _ = hive;
    vec![]
}

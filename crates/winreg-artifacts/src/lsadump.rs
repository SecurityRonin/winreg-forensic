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
//! - `SECURITY\Policy\Secrets\<name>\CurrVal` — `REG_BINARY` encrypted current value
//! - `SECURITY\Policy\Secrets\<name>\OldVal`  — `REG_BINARY` encrypted old value
//! - `SECURITY\Cache`       — DCC2 cache
//! - `SECURITY\Cache\NL$1 .. NL$10` — `REG_BINARY` cached credential slots

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
    /// The secret name key's `LastWriteTime` — approximately when this secret
    /// was last rotated. `None` when the key carries no timestamp.
    pub last_written: Option<jiff::Timestamp>,
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
    /// The slot subkey's `LastWriteTime` — approximately when this cached
    /// credential was last written. `None` when the key carries no timestamp.
    pub last_written: Option<jiff::Timestamp>,
}

// ── Classifier ────────────────────────────────────────────────────────────────

/// Return `true` when the secret name is forensically interesting.
///
/// Interesting names:
/// - `$MACHINE.ACC`    — machine account password
/// - `DefaultPassword` — auto-logon password stored in plaintext
/// - `DPAPI_SYSTEM`    — DPAPI master key protector
/// - `NL$KM`           — DCC2 encryption key
/// - `_SC_` prefix     — service account passwords
/// - `RasDialParams`   — saved VPN/dial-up credentials
pub fn is_interesting_secret(name: &str) -> bool {
    matches!(
        name,
        "$MACHINE.ACC" | "DefaultPassword" | "DPAPI_SYSTEM" | "NL$KM" | "RasDialParams"
    ) || name.starts_with("_SC_")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read the first `REG_BINARY` value under a key and return its byte length.
/// Returns 0 if the key is absent or has no values.
fn read_binary_value_size(hive: &Hive<Cursor<Vec<u8>>>, key_path: &str) -> usize {
    let Ok(Some(key)) = hive.open_key(key_path) else {
        return 0;
    };
    // Try the named "(default)" value first, then fall back to the first value.
    if let Ok(values) = key.values() {
        for val in &values {
            if let Ok(data) = val.raw_data() {
                return data.len();
            }
        }
    }
    0
}

// ── Public parse functions ────────────────────────────────────────────────────

/// Enumerate LSA secret names and metadata from `SECURITY\Policy\Secrets`.
///
/// Does NOT decrypt — returns names and sizes only.
pub fn parse_secrets(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<LsaSecretEntry> {
    let Ok(Some(secrets_key)) = hive.open_key("Policy\\Secrets") else {
        return Vec::new();
    };

    let Ok(subkeys) = secrets_key.subkeys() else {
        return Vec::new();
    };

    let mut entries = Vec::with_capacity(subkeys.len());

    for secret_key in subkeys {
        let name = secret_key.name();

        let currval_path = format!("Policy\\Secrets\\{name}\\CurrVal");
        let oldval_path = format!("Policy\\Secrets\\{name}\\OldVal");

        let curr_size = read_binary_value_size(hive, &currval_path);
        let old_size = read_binary_value_size(hive, &oldval_path);

        let has_current = curr_size > 0;
        let has_old = old_size > 0;
        let is_interesting = is_interesting_secret(&name);

        entries.push(LsaSecretEntry {
            name,
            has_current,
            has_old,
            curr_size,
            old_size,
            is_interesting,
            last_written: secret_key.last_written(),
        });
    }

    entries
}

/// Enumerate DCC2 cache slot occupancy from `SECURITY\Cache`.
pub fn parse_dcc2_slots(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<Dcc2SlotEntry> {
    let Ok(Some(cache_key)) = hive.open_key("Cache") else {
        return Vec::new();
    };

    let Ok(subkeys) = cache_key.subkeys() else {
        return Vec::new();
    };

    let mut slots = Vec::with_capacity(subkeys.len());

    for slot_key in subkeys {
        let slot_name = slot_key.name();

        // Read the first (default) binary value from this slot.
        let data_size = if let Ok(values) = slot_key.values() {
            values
                .into_iter()
                .find_map(|v| v.raw_data().ok())
                .map_or(0, |d| d.len())
        } else {
            0
        };

        slots.push(Dcc2SlotEntry {
            slot_name,
            is_populated: data_size > 0,
            data_size,
            last_written: slot_key.last_written(),
        });
    }

    slots
}

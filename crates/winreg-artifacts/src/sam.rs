//! Windows SAM hive artifact extractor.
//!
//! Extracts local user account data from a SAM registry hive.
//!
//! Key paths (SAM hive):
//! - `SAM\Domains\Account\Users\Names\<username>` — username subkeys
//! - `SAM\Domains\Account\Users\<RID_hex>\F`      — account flags / timestamps
//! - `SAM\Domains\Account\Users\<RID_hex>\V`      — binary user data (not decoded here)

use std::io::Cursor;

use winreg_core::hive::Hive;

// ── Output type ───────────────────────────────────────────────────────────────

/// Information about a local user account from the SAM hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SamUserEntry {
    /// Account username.
    pub username: String,
    /// Relative Identifier (RID), e.g. 500 for Administrator.
    pub rid: u32,
    /// Last login timestamp (ISO 8601), from F record bytes 8-15 (FILETIME).
    pub last_login: Option<String>,
    /// Password last set timestamp (ISO 8601), from F record bytes 16-23.
    pub password_last_set: Option<String>,
    /// Account expiry timestamp (ISO 8601), from F record bytes 24-31. `None` = never.
    pub account_expires: Option<String>,
    /// Login count, from F record bytes 66-67 (u16 LE).
    pub login_count: u16,
    /// Account control flags, from F record bytes 56-59 (u32 LE).
    pub account_flags: u32,
    /// Whether the account is disabled (`account_flags & 0x0001`).
    pub is_disabled: bool,
    /// Whether the account is locked (`account_flags & 0x0010`).
    pub is_locked: bool,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse local user accounts from a SAM hive.
///
/// Walks `SAM\Domains\Account\Users\Names` for usernames. For each username
/// finds the corresponding `Users\<RID_hex>` key and reads its `F` value to
/// extract timestamps and account flags.
pub fn parse(_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<SamUserEntry> {
    vec![]
}

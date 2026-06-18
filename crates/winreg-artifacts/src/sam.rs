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
use winreg_core::key::filetime_to_datetime;

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

// ── F record field offsets ────────────────────────────────────────────────────

const F_LAST_LOGIN_OFF: usize = 8;
const F_PASSWORD_LAST_SET_OFF: usize = 16;
const F_ACCOUNT_EXPIRES_OFF: usize = 24;
const F_ACCOUNT_FLAGS_OFF: usize = 56;
const F_LOGIN_COUNT_OFF: usize = 66;
// (`read_u32`/`read_u16`/`read_filetime` bounds-check each access, so no separate
// minimum-length guard is needed.)

const ACCOUNT_DISABLED: u32 = 0x0001;
const ACCOUNT_LOCKED: u32 = 0x0010;

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse local user accounts from a SAM hive.
///
/// Walks `SAM\Domains\Account\Users\Names` for usernames. For each username
/// finds the corresponding `Users\<RID_hex>` key and reads its `F` value to
/// extract timestamps and account flags.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<SamUserEntry> {
    let mut results = Vec::new();

    let Ok(Some(names_key)) = hive.open_key("SAM\\Domains\\Account\\Users\\Names") else {
        return results;
    };

    let Ok(Some(users_key)) = hive.open_key("SAM\\Domains\\Account\\Users") else {
        return results;
    };

    let Ok(username_keys) = names_key.subkeys() else {
        return results;
    };

    for name_key in username_keys {
        let username = name_key.name();
        if username.is_empty() {
            continue;
        }

        // The RID is the per-account identity, stored as the TYPE field of the
        // `Names\<username>` default value (the canonical SAM layout); the F
        // record lives under `Users\<RID hex>`.
        let rid_opt = rid_and_f(&name_key, &users_key);
        let Some((rid, f_data)) = rid_opt else {
            // No matching RID found — include with defaults
            results.push(SamUserEntry {
                username,
                rid: 0,
                last_login: None,
                password_last_set: None,
                account_expires: None,
                login_count: 0,
                account_flags: 0,
                is_disabled: false,
                is_locked: false,
            });
            continue;
        };

        let entry = parse_f_record(&username, rid, &f_data);
        results.push(entry);
    }

    results
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Find the RID and F record bytes for a username by scanning Users\ subkeys.
///
/// The subkey names under `SAM\Domains\Account\Users` are 8-digit uppercase hex
/// RID strings (e.g. `"000001F4"` for RID 500). We match by name: if the subkey
/// name is a valid hex RID (not "Names"), read its `F` value.
fn rid_and_f(
    name_key: &winreg_core::key::Key<'_>,
    users_key: &winreg_core::key::Key<'_>,
) -> Option<(u32, Vec<u8>)> {
    use winreg_format::flags::ValueType;

    // The account's RID is the TYPE field of the `Names\<username>` default
    // (unnamed) value — the canonical SAM layout (e.g. Administrator = 500,
    // Guest = 501). Real RIDs (>= 500) always decode to `Unknown(rid)`.
    let rid = match name_key.value("").ok().flatten()?.data_type() {
        ValueType::Unknown(rid) => rid,
        _ => return None,
    };

    // The F record lives under `Users\<RID as 8-digit uppercase hex>`.
    let rid_hex = format!("{rid:08X}");
    let f_data = users_key
        .subkey(&rid_hex)
        .ok()
        .flatten()?
        .value("F")
        .ok()
        .flatten()?
        .raw_data()
        .ok()?;
    Some((rid, f_data))
}

/// Build a `SamUserEntry` by decoding the F record binary data.
fn parse_f_record(username: &str, rid: u32, f: &[u8]) -> SamUserEntry {
    let last_login = read_filetime(f, F_LAST_LOGIN_OFF);
    let password_last_set = read_filetime(f, F_PASSWORD_LAST_SET_OFF);
    let account_expires = read_filetime(f, F_ACCOUNT_EXPIRES_OFF);
    let account_flags = read_u32(f, F_ACCOUNT_FLAGS_OFF);
    let login_count = read_u16(f, F_LOGIN_COUNT_OFF);

    SamUserEntry {
        username: username.to_string(),
        rid,
        last_login,
        password_last_set,
        account_expires,
        login_count,
        account_flags,
        is_disabled: (account_flags & ACCOUNT_DISABLED) != 0,
        is_locked: (account_flags & ACCOUNT_LOCKED) != 0,
    }
}

/// Read a FILETIME (u64 LE) at `offset` from `data` and convert to ISO 8601.
/// Returns `None` if the data is too short or the FILETIME is zero.
fn read_filetime(data: &[u8], offset: usize) -> Option<String> {
    if offset + 8 > data.len() {
        return None;
    }
    let ft = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    let dt = filetime_to_datetime(ft)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Read a u32 LE at `offset` from `data`. Returns 0 if out of bounds.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

/// Read a u16 LE at `offset` from `data`. Returns 0 if out of bounds.
fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

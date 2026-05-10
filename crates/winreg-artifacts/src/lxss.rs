//! WSL distro registration parser — HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss

use std::io::Cursor;
use std::path::PathBuf;

use winreg_core::hive::Hive;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DistroVersion {
    Wsl1,
    Wsl2,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DistroState {
    Installed,
    Running,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LxssDistro {
    pub guid: String,
    pub distribution_name: String,
    pub package_family_name: Option<String>,
    pub base_path: String,
    pub state: DistroState,
    pub version: DistroVersion,
    pub default_uid: Option<u32>,
    pub is_default: bool,
}

impl LxssDistro {
    /// Returns the path to `ext4.vhdx` for WSL2 distros; `None` for WSL1.
    ///
    /// WSL2 stores the Linux filesystem at `<BasePath>\ext4.vhdx`.
    /// WSL1 uses a directory tree under `%LOCALAPPDATA%\lxss\` instead.
    pub fn vhdx_path(&self) -> Option<PathBuf> {
        if self.version != DistroVersion::Wsl2 {
            return None;
        }
        let mut path = PathBuf::from(&self.base_path);
        path.push("ext4.vhdx");
        Some(path)
    }
}

// ── Key paths ─────────────────────────────────────────────────────────────────

const LXSS_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns true for GUID-format names like `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn is_guid(name: &str) -> bool {
    let s = name.trim();
    if s.len() != 38 {
        return false;
    }
    let b = s.as_bytes();
    b[0] == b'{'
        && b[37] == b'}'
        && b[9] == b'-'
        && b[14] == b'-'
        && b[19] == b'-'
        && b[24] == b'-'
        && b[1..9].iter().all(|c| c.is_ascii_hexdigit())
        && b[10..14].iter().all(|c| c.is_ascii_hexdigit())
        && b[15..19].iter().all(|c| c.is_ascii_hexdigit())
        && b[20..24].iter().all(|c| c.is_ascii_hexdigit())
        && b[25..37].iter().all(|c| c.is_ascii_hexdigit())
}

fn str_val(key: &winreg_core::key::Key<'_>, name: &str) -> Option<String> {
    key.value(name).ok().flatten().and_then(|v| v.as_string().ok())
}

fn u32_val(key: &winreg_core::key::Key<'_>, name: &str) -> Option<u32> {
    key.value(name).ok().flatten().and_then(|v| v.as_u32().ok())
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse WSL distro registrations from an NTUSER.DAT hive.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<LxssDistro> {
    let lxss_key = match hive.open_key(LXSS_PATH) {
        Ok(Some(k)) => k,
        _ => return Vec::new(),
    };

    let default_guid = str_val(&lxss_key, "DefaultDistribution").unwrap_or_default();

    let subkeys = match lxss_key.subkeys() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut distros = Vec::new();

    for subkey in subkeys {
        let guid = subkey.name();
        if !is_guid(&guid) {
            continue;
        }

        let distribution_name = match str_val(&subkey, "DistributionName") {
            Some(n) => n,
            None => continue,
        };

        let base_path = match str_val(&subkey, "BasePath") {
            Some(p) => p,
            None => continue,
        };

        let package_family_name = str_val(&subkey, "PackageFamilyName");

        let state = match u32_val(&subkey, "State") {
            Some(1) => DistroState::Installed,
            Some(4) => DistroState::Running,
            _ => DistroState::Unknown,
        };

        let version = match u32_val(&subkey, "Version") {
            Some(1) => DistroVersion::Wsl1,
            Some(2) => DistroVersion::Wsl2,
            _ => DistroVersion::Unknown,
        };

        let default_uid = u32_val(&subkey, "DefaultUid");
        let is_default = !default_guid.is_empty() && guid == default_guid;

        distros.push(LxssDistro {
            guid,
            distribution_name,
            package_family_name,
            base_path,
            state,
            version,
            default_uid,
            is_default,
        });
    }

    distros
}

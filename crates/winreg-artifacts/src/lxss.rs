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
    /// Returns the path to ext4.vhdx for WSL2 distros; `None` for WSL1.
    pub fn vhdx_path(&self) -> Option<PathBuf> {
        todo!("implement vhdx_path")
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

const LXSS_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";

/// Parse WSL distro registrations from an NTUSER.DAT hive.
pub fn parse(_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<LxssDistro> {
    todo!("implement lxss::parse")
}

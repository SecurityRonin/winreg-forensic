//! Windows service anomaly detector (`svc_diff`).
//!
//! Reads service configurations from the SYSTEM hive at
//! `SYSTEM\CurrentControlSet\Services` and classifies each service entry
//! for forensic anomalies such as suspicious image paths, missing descriptions,
//! or unusual start types.
//!
//! Maps to MITRE ATT&CK T1543.003 (Create or Modify System Process:
//! Windows Service).

use std::io::Cursor;

use winreg_core::hive::Hive;

// ── Key path ──────────────────────────────────────────────────────────────────

const SERVICES_KEY: &str = "CurrentControlSet\\Services";

// ── Output type ───────────────────────────────────────────────────────────────

/// A single service entry extracted from the SYSTEM registry hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceEntry {
    /// Subkey name (the internal service name, e.g. `"Dnscache"`).
    pub name: String,
    /// Human-readable display name (`DisplayName` value).
    pub display_name: String,
    /// Path to the service binary (`ImagePath` value).
    pub image_path: String,
    /// Numeric start type: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled.
    pub start_type: u32,
    /// Numeric service type: 1=KernelDriver, 2=FsDriver, 16=OwnProcess, 32=ShareProcess.
    pub service_type: u32,
    /// Account the service runs as (`ObjectName` value), e.g. `"LocalSystem"`.
    pub object_name: String,
    /// Service description (`Description` value); empty string when absent.
    pub description: String,
    /// `true` when the service matches one or more anomaly patterns.
    pub is_suspicious: bool,
    /// Human-readable explanation when `is_suspicious` is `true`.
    pub suspicious_reason: Option<String>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a service entry for forensic anomalies.
///
/// Returns `(is_suspicious, reason)`.
///
/// A service is suspicious when **any** of the following is true:
///
/// 1. `image_path` contains `\temp\`, `\appdata\`, `\users\public\`, or
///    `\programdata\` (user-writable directories, not system paths).
/// 2. `image_path` contains `cmd.exe`, `powershell.exe`, `wscript.exe`, or
///    `mshta.exe` (interpreters abused for living-off-the-land persistence).
/// 3. `start_type == 2` (Auto) AND `description` is empty AND `image_path`
///    does not contain `\system32\` or `\syswow64\`.
/// 4. `object_name` is empty (service has no configured account).
pub fn classify_service(
    image_path: &str,
    start_type: u32,
    description: &str,
    object_name: &str,
) -> (bool, Option<String>) {
    let lower = image_path.to_ascii_lowercase();

    // Rule 1: user-writable path
    for suspect_dir in &[r"\temp\", r"\appdata\", r"\users\public\", r"\programdata\"] {
        if lower.contains(suspect_dir) {
            return (
                true,
                Some(format!(
                    "image path is in user-writable directory: {suspect_dir}"
                )),
            );
        }
    }

    // Rule 2: interpreter abuse
    for interpreter in &["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"] {
        if lower.contains(interpreter) {
            return (
                true,
                Some(format!("image path contains interpreter: {interpreter}")),
            );
        }
    }

    // Rule 3: Auto-start with no description and non-system32 path
    if start_type == 2
        && description.is_empty()
        && !lower.contains(r"\system32\")
        && !lower.contains(r"\syswow64\")
    {
        return (
            true,
            Some(
                "auto-start service has no description and image path is not under \\system32\\ or \\syswow64\\"
                    .to_string(),
            ),
        );
    }

    // Rule 4: no configured account
    if object_name.is_empty() {
        return (
            true,
            Some("service has no configured account (ObjectName is empty)".to_string()),
        );
    }

    (false, None)
}

// ── Public parse function ─────────────────────────────────────────────────────

/// Extract all service entries from a SYSTEM hive.
///
/// Walks `SYSTEM\CurrentControlSet\Services`, enumerates every direct subkey,
/// extracts relevant values (with safe defaults for missing values), classifies
/// each entry, and returns the full list (both suspicious and benign).
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ServiceEntry> {
    let services_key = match hive.open_key(SERVICES_KEY) {
        Ok(Some(k)) => k,
        _ => return Vec::new(),
    };

    let subkeys = match services_key.subkeys() {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::with_capacity(subkeys.len());

    for svc_key in subkeys {
        let name = svc_key.name();

        // Read values with safe defaults.
        let image_path = svc_key
            .value("ImagePath")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok())
            .unwrap_or_default();

        let display_name = svc_key
            .value("DisplayName")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok())
            .unwrap_or_default();

        let description = svc_key
            .value("Description")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok())
            .unwrap_or_default();

        let start_type = svc_key
            .value("Start")
            .ok()
            .flatten()
            .and_then(|v| v.as_u32().ok())
            .unwrap_or(3); // default: Manual

        let service_type = svc_key
            .value("Type")
            .ok()
            .flatten()
            .and_then(|v| v.as_u32().ok())
            .unwrap_or(0);

        let object_name = svc_key
            .value("ObjectName")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok())
            .unwrap_or_default();

        let (is_suspicious, suspicious_reason) =
            classify_service(&image_path, start_type, &description, &object_name);

        entries.push(ServiceEntry {
            name,
            display_name,
            image_path,
            start_type,
            service_type,
            object_name,
            description,
            is_suspicious,
            suspicious_reason,
        });
    }

    entries
}

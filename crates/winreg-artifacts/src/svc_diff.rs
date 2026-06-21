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
    /// The DLL a shared-process / svchost-hosted service loads, read from
    /// `Parameters\ServiceDll`. `None` when the service hosts no DLL. Kept raw
    /// (`REG_EXPAND_SZ` env vars like `%SystemRoot%` are NOT pre-expanded),
    /// matching how `image_path` is handled. This is the actual code a
    /// svchost-hosted service runs — and a common persistence vector (T1543.003).
    pub service_dll: Option<String>,
    /// A recovery-action command line (`FailureCommand` value) run when the
    /// service fails — abused for persistence. `None` when absent.
    pub failure_command: Option<String>,
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
    /// The service key's `LastWriteTime` — approximately the service
    /// install/modify time. `None` when the key carries no timestamp.
    pub last_written: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// User-writable directories a system service binary/DLL should never live in.
const USER_WRITABLE_DIRS: &[&str] = &[r"\temp\", r"\appdata\", r"\users\public\", r"\programdata\"];
/// Interpreters/LOLBins abused for living-off-the-land persistence.
const INTERPRETERS: &[&str] = &["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"];

/// Flag a service-loadable path (an `ImagePath` or a `ServiceDll`) that lives in
/// a user-writable directory or names a known interpreter/LOLBin. `label` names
/// which field is being checked so the reason is self-describing. Returns the
/// reason string for the first matching rule, else `None`.
fn classify_path(path_lower: &str, label: &str) -> Option<String> {
    for suspect_dir in USER_WRITABLE_DIRS {
        if path_lower.contains(suspect_dir) {
            return Some(format!(
                "{label} is in user-writable directory: {suspect_dir}"
            ));
        }
    }
    for interpreter in INTERPRETERS {
        if path_lower.contains(interpreter) {
            return Some(format!("{label} contains interpreter: {interpreter}"));
        }
    }
    None
}

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
/// 3. `service_dll` (the DLL a svchost-hosted service loads) matches rule 1 or 2
///    — a malicious `ServiceDll` is at least as suspicious as a malicious
///    `ImagePath`, and is the more common svchost-persistence vector (T1543.003).
/// 4. `start_type == 2` (Auto) AND `description` is empty AND `image_path`
///    does not contain `\system32\` or `\syswow64\`.
/// 5. `object_name` is empty (service has no configured account).
/// 6. `failure_command` is present and non-empty (a recovery-action command —
///    abused for persistence; surfaced as noteworthy, never a verdict).
pub fn classify_service(
    image_path: &str,
    start_type: u32,
    description: &str,
    object_name: &str,
    service_dll: Option<&str>,
    failure_command: Option<&str>,
) -> (bool, Option<String>) {
    let lower = image_path.to_ascii_lowercase();

    // Rules 1 & 2: user-writable path / interpreter abuse in ImagePath.
    if let Some(reason) = classify_path(&lower, "image path") {
        return (true, Some(reason));
    }

    // Rule 3: same checks against the svchost-hosted ServiceDll.
    if let Some(dll) = service_dll {
        if let Some(reason) = classify_path(&dll.to_ascii_lowercase(), "ServiceDll") {
            return (true, Some(reason));
        }
    }

    // Rule 4: Auto-start with no description and non-system32 path
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

    // Rule 5: no configured account
    if object_name.is_empty() {
        return (
            true,
            Some("service has no configured account (ObjectName is empty)".to_string()),
        );
    }

    // Rule 6: a configured FailureCommand recovery action.
    if let Some(fc) = failure_command.filter(|fc| !fc.is_empty()) {
        return (
            true,
            Some(format!(
                "service has a FailureCommand recovery action: {fc}"
            )),
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
    // `CurrentControlSet` is a volatile symlink the running kernel builds; it is
    // absent from offline hives. Resolve `Select\Current` → `ControlSet00N`,
    // falling back to `ControlSet001` then the (live-only) `CurrentControlSet`.
    let active = hive
        .open_key("Select")
        .ok()
        .flatten()
        .and_then(|k| k.value("Current").ok().flatten())
        .and_then(|v| v.as_u32().ok())
        .unwrap_or(1);
    let services_key = [
        format!("ControlSet{active:03}\\Services"),
        "ControlSet001\\Services".to_string(),
        SERVICES_KEY.to_string(),
    ]
    .iter()
    .find_map(|path| hive.open_key(path).ok().flatten());
    let Some(services_key) = services_key else {
        return Vec::new();
    };

    let Ok(subkeys) = services_key.subkeys() else {
        return Vec::new(); // cov:unreachable: a Services key opened from a valid hive has a readable subkey list
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

        // ServiceDll lives one level down, under the `Parameters` subkey — the
        // real code a svchost-hosted (ShareProcess) service loads. Kept raw
        // (REG_EXPAND_SZ env vars not pre-expanded), like ImagePath.
        let service_dll = svc_key
            .subkey("Parameters")
            .ok()
            .flatten()
            .and_then(|p| p.value("ServiceDll").ok().flatten())
            .and_then(|v| v.as_string().ok());

        // FailureCommand is a recovery-action command line directly under the
        // service key.
        let failure_command = svc_key
            .value("FailureCommand")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok());

        let (is_suspicious, suspicious_reason) = classify_service(
            &image_path,
            start_type,
            &description,
            &object_name,
            service_dll.as_deref(),
            failure_command.as_deref(),
        );

        entries.push(ServiceEntry {
            name,
            display_name,
            image_path,
            service_dll,
            failure_command,
            start_type,
            service_type,
            object_name,
            description,
            is_suspicious,
            suspicious_reason,
            last_written: svc_key.last_written(),
        });
    }

    entries
}

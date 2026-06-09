//! Internet Explorer / Edge TypedURLs registry artifact extractor.
//!
//! Extracts URLs typed directly into the IE/Edge address bar from
//! `Software\Microsoft\Internet Explorer\TypedURLs` in NTUSER.DAT hives,
//! along with optional timestamps from the companion `TypedURLsTime` key.

use std::collections::HashMap;
use std::io::Cursor;

use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;

// ── Registry paths ────────────────────────────────────────────────────────────

const TYPED_URLS_PATH: &str = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
const TYPED_URLS_TIME_PATH: &str = "Software\\Microsoft\\Internet Explorer\\TypedURLsTime";

// ── Suspicious domain patterns ────────────────────────────────────────────────

const SUSPICIOUS_DOMAINS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "transfer.sh",
    "mega.nz",
    "anonfiles.com",
    "file.io",
    "temp.sh",
    "gofile.io",
    "ngrok.io",
    "trycloudflare.com",
];

// ── Output type ───────────────────────────────────────────────────────────────

/// A URL entry from the IE/Edge TypedURLs registry key.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TypedUrl {
    /// The URL string typed into the address bar.
    pub url: String,
    /// ISO 8601 timestamp from the TypedURLsTime FILETIME, or `None` if not found.
    pub last_visited: Option<String>,
    /// `true` when the URL matches a known suspicious domain or pattern.
    pub is_suspicious: bool,
    /// Human-readable explanation when `is_suspicious` is `true`.
    pub suspicious_reason: Option<String>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a URL for suspicious patterns.
///
/// Returns `Some(reason)` when suspicious, `None` when benign.
///
/// Patterns detected:
/// - Known suspicious file-sharing / paste / tunnel domains
/// - Raw IPv4 address in the URL authority
pub fn classify_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();

    // Check known suspicious domains
    for &domain in SUSPICIOUS_DOMAINS {
        if lower.contains(domain) {
            return Some(format!("suspicious domain: {domain}"));
        }
    }

    // Check for raw IPv4 address in authority
    if let Some(scheme_end) = lower.find("://") {
        let after_scheme = &lower[scheme_end + 3..];
        let authority = match after_scheme.find('/') {
            Some(pos) => &after_scheme[..pos],
            None => after_scheme,
        };
        // Strip port if present
        let host = match authority.rfind(':') {
            Some(pos) => &authority[..pos],
            None => authority,
        };
        if is_ipv4(host) {
            return Some(format!("raw IP address in URL: {host}"));
        }
    }

    None
}

/// Return `true` if `s` looks like a dotted-decimal IPv4 address.
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── Public parse function ─────────────────────────────────────────────────────

/// Extract all TypedURL entries from an NTUSER.DAT hive.
///
/// Reads `Software\Microsoft\Internet Explorer\TypedURLs` for URL strings
/// and `TypedURLsTime` for corresponding FILETIME timestamps.
///
/// Returns an empty Vec if the TypedURLs key is absent.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<TypedUrl> {
    // Open the TypedURLs key.
    let urls_key = match hive.open_key(TYPED_URLS_PATH) {
        Ok(Some(k)) => k,
        _ => return Vec::new(),
    };

    // Build a timestamp map from TypedURLsTime (value name → ISO 8601 string).
    let time_map: HashMap<String, String> = match hive.open_key(TYPED_URLS_TIME_PATH) {
        Ok(Some(time_key)) => {
            let mut map = HashMap::new();
            if let Ok(vals) = time_key.values() {
                for val in vals {
                    if let Ok(raw) = val.raw_data() {
                        if raw.len() >= 8 {
                            let ft = winreg_core::bytes::le_u64(&raw[..], 0);
                            if let Some(dt) = filetime_to_datetime(ft) {
                                map.insert(val.name(), dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                            }
                        }
                    }
                }
            }
            map
        }
        _ => HashMap::new(),
    };

    // Enumerate TypedURLs values.
    let values = match urls_key.values() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::new();
    for val in values {
        let url = match val.as_string() {
            Ok(s) if !s.is_empty() => s,
            _ => continue,
        };
        let last_visited = time_map.get(&val.name()).cloned();
        let suspicious_reason = classify_url(&url);
        let is_suspicious = suspicious_reason.is_some();
        entries.push(TypedUrl {
            url,
            last_visited,
            is_suspicious,
            suspicious_reason,
        });
    }

    entries
}

// ── Unit tests for classify_url ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_normal_url_is_none() {
        assert!(classify_url("https://www.google.com").is_none());
        assert!(classify_url("https://github.com/user/repo").is_none());
    }

    #[test]
    fn classify_pastebin_suspicious() {
        assert!(classify_url("https://pastebin.com/abc").is_some());
    }

    #[test]
    fn classify_ngrok_suspicious() {
        assert!(classify_url("https://abc.ngrok.io/shell").is_some());
    }

    #[test]
    fn classify_raw_ip_suspicious() {
        assert!(classify_url("http://192.168.1.100/payload").is_some());
        assert!(classify_url("http://10.0.0.1/evil").is_some());
    }

    #[test]
    fn classify_ip_with_port_suspicious() {
        assert!(classify_url("http://192.168.1.1:8080/x").is_some());
    }

    #[test]
    fn classify_normal_domain_with_dots_not_ip() {
        // e.g. "1.2.3.256" — not a valid IPv4
        assert!(classify_url("http://1.2.3.256/page").is_none());
    }
}

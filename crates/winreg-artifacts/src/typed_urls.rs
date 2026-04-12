//! Internet Explorer / Edge TypedURLs registry artifact extractor.
//!
//! Extracts URLs typed directly into the IE/Edge address bar from
//! `Software\Microsoft\Internet Explorer\TypedURLs` in NTUSER.DAT hives,
//! along with optional timestamps from the companion `TypedURLsTime` key.

use std::io::Cursor;

use winreg_core::hive::Hive;

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

/// Extract all TypedURL entries from an NTUSER.DAT hive.
///
/// Returns an empty Vec if the TypedURLs key is absent.
pub fn parse(_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<TypedUrl> {
    todo!("typed_urls::parse not yet implemented")
}

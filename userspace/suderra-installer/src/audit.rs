// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Audit log — her kurulum/silme olayı kalıcı log'a yazılır.
//!
//! Format: JSON Lines (jsonl), satır başına bir event.
//!
//! Audit dosyası: /var/log/suderra/installer.log
//!   - permission: 0644 (root yazar, herkes okur)
//!   - rotation: logrotate ile haftalık (config systemd unit'te)
//!
//! Audit event'leri SIEM (Splunk/Wazuh) tarafından tüketilebilir.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Audit log dosyasının yolu
fn audit_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        // Test sırasında SUDERRA_AUDIT_LOG override edilebilir
        std::env::var("SUDERRA_AUDIT_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/log/suderra/installer.log"))
    })
}

/// Audit log dizini hazır
pub fn init() -> Result<()> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("audit log dizini oluşturulamadı: {}", parent.display()))?;
    }
    Ok(())
}

/// Bir audit event'i — kuru, immutable, makine okunabilir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// UTC timestamp (RFC3339)
    pub timestamp: DateTime<Utc>,
    /// Event türü
    pub event: EventKind,
    /// Paket adı
    pub package: String,
    /// Paket sürümü (varsa)
    pub version: Option<String>,
    /// Sonuç (success/failure)
    pub result: EventResult,
    /// İlave alan (URL, hash, hata mesajı, vb.)
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum EventKind {
    Install,
    Upgrade,
    Rollback,
    Remove,
    VerifySignature,
    Download,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum EventResult {
    Success,
    Failure,
    Aborted,
}

impl Event {
    /// Yeni event yarat — şu an UTC timestamp.
    pub fn new(event: EventKind, package: impl Into<String>, result: EventResult) -> Self {
        Self {
            timestamp: Utc::now(),
            event,
            package: package.into(),
            version: None,
            result,
            metadata: serde_json::Map::new(),
        }
    }

    /// Sürüm bilgisi ekle
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Metadata ekle
    pub fn with_meta(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Audit log'a yaz (append, JSON Lines)
    pub fn record(self) -> Result<()> {
        write_event(audit_path(), &self)
    }
}

fn write_event(path: &Path, event: &Event) -> Result<()> {
    let line = serde_json::to_string(event)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode_for_audit()
        .open(path)
        .with_context(|| format!("audit log açılamadı: {}", path.display()))?;
    writeln!(file, "{line}")?;
    file.flush()?;
    Ok(())
}

/// Unix-only: audit log permission'larını set et (0644)
trait OpenOptionsExt {
    fn mode_for_audit(&mut self) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    #[cfg(unix)]
    fn mode_for_audit(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt as _;
        self.mode(0o644)
    }

    #[cfg(not(unix))]
    fn mode_for_audit(&mut self) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_and_read_event() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("installer.log");

        let event = Event::new(EventKind::Install, "edge", EventResult::Success)
            .with_version("1.6.0")
            .with_meta("hash", "abc123");

        write_event(&log, &event).unwrap();

        let contents = std::fs::read_to_string(&log).unwrap();
        assert!(contents.contains("\"event\":\"install\""));
        assert!(contents.contains("\"package\":\"edge\""));
        assert!(contents.contains("\"version\":\"1.6.0\""));
        assert!(contents.contains("\"hash\":\"abc123\""));
    }

    #[test]
    fn appends_multiple_events() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("installer.log");

        for i in 0..3 {
            let event = Event::new(EventKind::Install, format!("pkg-{i}"), EventResult::Success);
            write_event(&log, &event).unwrap();
        }

        let line_count = std::fs::read_to_string(&log).unwrap().lines().count();
        assert_eq!(line_count, 3);
    }
}

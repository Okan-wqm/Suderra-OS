// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Paket manifest — release artifact metadata.
//!
//! Her release şu yapıda bir `manifest.json` içerir:
//!
//! ```json
//! {
//!   "version": "1.6.0",
//!   "release_date": "2026-05-15T12:00:00Z",
//!   "packages": [
//!     {
//!       "name": "edge",
//!       "arch": "aarch64",
//!       "file": "suderra-edge-v1.6.0-aarch64.raucb",
//!       "sha256": "abc123...",
//!       "size_bytes": 4194304,
//!       "min_os_version": "0.1.0"
//!     }
//!   ],
//!   "changelog_url": "https://github.com/Okan-wqm/Suderra-OS/releases/tag/v1.6.0",
//!   "sbom_url": "https://.../sbom.cyclonedx.json"
//! }
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Bir release'in komple manifesti
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// SemVer versiyon
    pub version: String,
    /// Release tarihi (RFC3339)
    pub release_date: chrono::DateTime<chrono::Utc>,
    /// Bu release'te bulunan paketler
    pub packages: Vec<Package>,
    /// Changelog URL'i (genelde GitHub release notes)
    #[serde(default)]
    pub changelog_url: Option<String>,
    /// SBOM URL'i (CycloneDX)
    #[serde(default)]
    pub sbom_url: Option<String>,
}

/// Manifest'teki bir paket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Paket adı (örn: "edge")
    pub name: String,
    /// Mimari
    pub arch: String,
    /// Artifact dosya adı (URL'in son segmenti)
    pub file: String,
    /// SHA256 hash (hex)
    pub sha256: String,
    /// Boyut byte cinsinden
    pub size_bytes: u64,
    /// Bu paketin kurulabileceği minimum OS sürümü
    #[serde(default)]
    pub min_os_version: Option<String>,
    /// Paket türü
    #[serde(default)]
    pub kind: PackageKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum PackageKind {
    /// RAUC bundle (default — Edge Agent gibi büyük paketler)
    #[default]
    Rauc,
    /// Standalone binary (suderra-installer self-update için)
    Binary,
    /// Tar.gz arşivi (config templates, scripts)
    Tarball,
    /// Bootable OS image artifact.
    Image,
}

impl Manifest {
    /// JSON string'inden parse et
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(Into::into)
    }

    /// Belirli bir paketi mimari + isimle bul
    pub fn find_package(&self, name: &str, arch: &str) -> Option<&Package> {
        self.packages
            .iter()
            .find(|p| p.name == name && p.arch == arch)
    }
}

/// Kurulu paketlerin lokal state'i — /var/lib/suderra/installed.json
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct InstalledState {
    /// Kurulu paketler (key: paket adı)
    pub installed: std::collections::BTreeMap<String, InstalledPackage>,
}

/// Kurulu bir paket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    /// Paket adı
    pub name: String,
    /// Aktif sürüm
    pub version: String,
    /// Önceki sürüm (rollback için)
    #[serde(default)]
    pub previous_version: Option<String>,
    /// Kurulum tarihi (RFC3339)
    pub installed_at: chrono::DateTime<chrono::Utc>,
    /// Bundle SHA256 (audit + integrity check için)
    pub sha256: String,
    /// Cosign verify edildi mi?
    #[serde(default)]
    pub signature_verified: bool,
}

impl InstalledState {
    /// Default path: /var/lib/suderra/installed.json (test'te SUDERRA_STATE_PATH ile override)
    pub fn default_path() -> std::path::PathBuf {
        std::env::var("SUDERRA_STATE_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/suderra/installed.json"))
    }

    /// Disk'ten yükle (yoksa boş state)
    pub fn load() -> Result<Self> {
        let path = Self::default_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Disk'e yaz
    pub fn save(&self) -> Result<()> {
        let path = Self::default_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Bir paketi kurulu olarak işaretle
    pub fn record_install(&mut self, pkg: InstalledPackage) {
        // Önceki versiyon varsa rollback için sakla
        let mut pkg = pkg;
        if let Some(existing) = self.installed.get(&pkg.name) {
            pkg.previous_version = Some(existing.version.clone());
        }
        self.installed.insert(pkg.name.clone(), pkg);
    }

    /// Bir paketi kaldır
    pub fn record_remove(&mut self, name: &str) {
        self.installed.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest() {
        let json = r#"{
            "version": "1.6.0",
            "release_date": "2026-05-15T12:00:00Z",
            "packages": [{
                "name": "edge",
                "arch": "aarch64",
                "file": "suderra-edge-v1.6.0-aarch64.raucb",
                "sha256": "abc123",
                "size_bytes": 4194304
            }]
        }"#;
        let manifest = Manifest::from_json(json).unwrap();
        assert_eq!(manifest.version, "1.6.0");
        assert_eq!(manifest.packages.len(), 1);
        let pkg = manifest.find_package("edge", "aarch64").unwrap();
        assert_eq!(pkg.file, "suderra-edge-v1.6.0-aarch64.raucb");
    }

    #[test]
    fn installed_state_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");
        std::env::set_var("SUDERRA_STATE_PATH", &path);

        let mut state = InstalledState::default();
        state.record_install(InstalledPackage {
            name: "edge".into(),
            version: "1.6.0".into(),
            previous_version: None,
            installed_at: chrono::Utc::now(),
            sha256: "abc".into(),
            signature_verified: true,
        });
        state.save().unwrap();

        let loaded = InstalledState::load().unwrap();
        assert!(loaded.installed.contains_key("edge"));
        assert_eq!(loaded.installed["edge"].version, "1.6.0");

        std::env::remove_var("SUDERRA_STATE_PATH");
    }
}

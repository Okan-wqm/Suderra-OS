// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Suderra OS — Ortak konfigürasyon kütüphanesi
//!
//! Bu lib crate diğer Suderra userspace crate'leri tarafından kullanılır.
//! Config dosyalarını parse eder, validate eder, ortak tipler sağlar.
//!
//! Mimari:
//! - `SuderraConfig` — sistem geneli config (`/etc/suderra/config.yaml`)
//! - [`canonical`] — imza baytları için kanonik JSON (installer + ota ortak)
//! - [`variant`] — üretim varyant tespitinin güven kökü (installer + ota ortak)
//! - Validation: shape (Serde) + invariant'lar (custom check)

pub mod canonical;
pub mod tpm;
pub mod variant;

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Suderra OS sistem geneli konfigürasyon.
///
/// Tipik kaynak: `/etc/suderra/config.yaml` (rootfs-overlay'de veya /data overlay'de).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuderraConfig {
    /// Cihaz unique ID (üretici tarafından üretim sırasında verilen seri no)
    pub device_id: String,

    /// OTA update sunucusu URL (HTTPS + mTLS endpoint)
    pub update_server_url: String,

    /// Cihaz rolü — dev, staging, production
    #[serde(default)]
    pub environment: Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Dev,
    Staging,
    Production,
}

impl Default for Environment {
    fn default() -> Self {
        Self::Production
    }
}

/// Config yükleme/validasyon hataları.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config dosyası okunamadı: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse hatası: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("validasyon hatası: {0}")]
    Validation(String),
}

impl SuderraConfig {
    /// Belirtilen path'den YAML config yükle.
    ///
    /// Tipik kullanım:
    /// ```no_run
    /// use suderra_config::SuderraConfig;
    /// let cfg = SuderraConfig::load_from_file("/etc/suderra/config.yaml")?;
    /// # Ok::<(), suderra_config::ConfigError>(())
    /// ```
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let cfg: Self = serde_yaml::from_str(&content)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Invariant'ları kontrol et.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.device_id.is_empty() {
            return Err(ConfigError::Validation("device_id boş olamaz".into()));
        }
        if !self.update_server_url.starts_with("https://") {
            return Err(ConfigError::Validation(
                "update_server_url HTTPS olmalı (mTLS endpoint)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_https_url() {
        let cfg = SuderraConfig {
            device_id: "test-001".into(),
            update_server_url: "http://insecure.example".into(),
            environment: Environment::Dev,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validates_non_empty_device_id() {
        let cfg = SuderraConfig {
            device_id: String::new(),
            update_server_url: "https://updates.example".into(),
            environment: Environment::Dev,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn happy_path() {
        let cfg = SuderraConfig {
            device_id: "dev-001".into(),
            update_server_url: "https://updates.example".into(),
            environment: Environment::Production,
        };
        assert!(cfg.validate().is_ok());
    }
}

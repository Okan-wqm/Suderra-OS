// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Release kaynak URL'leri — GitHub Releases + Suderra mirror.
//!
//! Suderra OS iki kaynak destekler:
//! 1. GitHub Releases (primary) — Otomatik upload via release.yml CI
//! 2. releases.suderra.com (mirror) — CDN behind S3/MinIO
//!
//! Default: GitHub. Mirror seçilirse fail durumunda GitHub'a fallback.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Mirror tercihi
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum Mirror {
    Github,
    Suderra,
    Auto,
}

impl Mirror {
    /// Bu mirror için base URL döndür
    pub fn base_url(&self) -> &'static str {
        match self {
            Mirror::Github => "https://github.com/Okan-wqm/suderra-os/releases/download",
            Mirror::Suderra => "https://releases.suderra.com",
            Mirror::Auto => "https://github.com/Okan-wqm/suderra-os/releases/download",
        }
    }

    /// Fallback mirror (Auto modunda ilk fail olursa)
    pub fn fallback(&self) -> Option<Mirror> {
        match self {
            Mirror::Auto => Some(Mirror::Suderra),
            Mirror::Github => Some(Mirror::Suderra),
            Mirror::Suderra => Some(Mirror::Github),
        }
    }
}

/// Bir paketin release bilgisi
pub struct PackageRelease {
    /// Paket adı (örn: "edge")
    pub package: String,
    /// Versiyon (örn: "v1.6.0" veya "latest")
    pub version: String,
    /// Mimari (aarch64 / x86_64)
    pub arch: Arch,
}

/// Hedef mimari
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    /// Runtime mimari tespiti (cross-compile destekler — env override)
    pub fn detect() -> Self {
        if let Ok(arch) = std::env::var("SUDERRA_TARGET_ARCH") {
            match arch.as_str() {
                "aarch64" => return Arch::Aarch64,
                "x86_64" => return Arch::X86_64,
                other => {
                    tracing::warn!("Bilinmeyen SUDERRA_TARGET_ARCH={other}, runtime detection")
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        return Arch::Aarch64;
        #[cfg(target_arch = "x86_64")]
        return Arch::X86_64;

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        compile_error!("Suderra OS yalnızca aarch64 ve x86_64 destekler");
    }

    /// String temsili
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PackageRelease {
    /// Mirror için artifact (bundle) URL'i
    pub fn artifact_url(&self, mirror: Mirror) -> String {
        match mirror {
            // GitHub: /Okan-wqm/suderra-os/releases/download/v1.6.0/suderra-edge-agent-aarch64.raucb
            Mirror::Github | Mirror::Auto => format!(
                "{}/{}/suderra-{}-{}-{}.raucb",
                mirror.base_url(),
                self.version,
                self.package,
                self.version,
                self.arch
            ),
            // Suderra: /edge/v1.6.0/suderra-edge-agent-aarch64.raucb
            Mirror::Suderra => format!(
                "{}/{}/{}/suderra-{}-{}-{}.raucb",
                mirror.base_url(),
                self.package,
                self.version,
                self.package,
                self.version,
                self.arch
            ),
        }
    }

    /// Cosign signature URL'i
    pub fn signature_url(&self, mirror: Mirror) -> String {
        format!("{}.sig", self.artifact_url(mirror))
    }

    /// SHA256 checksum URL'i
    #[allow(dead_code)]
    pub fn sha256_url(&self, mirror: Mirror) -> String {
        format!("{}.sha256", self.artifact_url(mirror))
    }

    /// Manifest (metadata) URL'i — paket bilgisi, deps, vb.
    pub fn manifest_url(&self, mirror: Mirror) -> String {
        match mirror {
            Mirror::Github | Mirror::Auto => {
                format!("{}/{}/manifest.json", mirror.base_url(), self.version)
            }
            Mirror::Suderra => format!(
                "{}/{}/{}/manifest.json",
                mirror.base_url(),
                self.package,
                self.version
            ),
        }
    }

    /// Mevcut sürüm listesi URL'i (latest, all versions)
    pub fn versions_url(&self, mirror: Mirror) -> String {
        match mirror {
            Mirror::Github | Mirror::Auto => {
                // GitHub API: /repos/Okan-wqm/suderra-os/releases
                "https://api.github.com/repos/Okan-wqm/suderra-os/releases".to_string()
            }
            Mirror::Suderra => format!("{}/{}/versions.json", mirror.base_url(), self.package),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_artifact_url() {
        let release = PackageRelease {
            package: "edge".into(),
            version: "v1.6.0".into(),
            arch: Arch::Aarch64,
        };
        let url = release.artifact_url(Mirror::Github);
        assert_eq!(
            url,
            "https://github.com/Okan-wqm/suderra-os/releases/download/v1.6.0/suderra-edge-v1.6.0-aarch64.raucb"
        );
    }

    #[test]
    fn suderra_mirror_url() {
        let release = PackageRelease {
            package: "edge".into(),
            version: "v1.6.0".into(),
            arch: Arch::X86_64,
        };
        let url = release.artifact_url(Mirror::Suderra);
        assert_eq!(
            url,
            "https://releases.suderra.com/edge/v1.6.0/suderra-edge-v1.6.0-x86_64.raucb"
        );
    }

    #[test]
    fn fallback_logic() {
        assert_eq!(Mirror::Github.fallback(), Some(Mirror::Suderra));
        assert_eq!(Mirror::Suderra.fallback(), Some(Mirror::Github));
        assert_eq!(Mirror::Auto.fallback(), Some(Mirror::Suderra));
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Cosign keyless signature verification.
//!
//! Suderra OS release artifact'leri Sigstore + GitHub Actions OIDC ile
//! "keyless" şekilde imzalanır — uzun ömürlü gizli anahtarlar yok,
//! her build için ephemeral key + transparency log (Rekor) kaydı.
//!
//! Bu modül `cosign verify-blob` mantığını çağırır:
//!
//!   cosign verify-blob \
//!     --certificate-identity-regexp "https://github.com/Okan-wqm/suderra-os" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     --signature <sig> \
//!     <artifact>
//!
//! İlk implementasyon: subprocess'ten `cosign` binary'sini çağırır.
//! Faz 3'te native sigstore-rs entegrasyonu (in-process, daha hızlı).

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

/// Cosign keyless doğrulama — Sigstore TUF root ile
///
/// Suderra resmi release'lerinin GitHub Actions üzerinden imzalandığını
/// doğrular. Identity policy: certificate-identity-regexp + OIDC issuer.
pub fn verify_keyless(artifact: &Path, signature: &Path) -> Result<VerifyOutcome> {
    let cosign = which_cosign()?;

    info!("cosign keyless doğrulama çalışıyor: {}", artifact.display());
    debug!("cosign binary: {}", cosign.display());

    let output = Command::new(&cosign)
        .args([
            "verify-blob",
            "--certificate-identity-regexp",
            "^https://github\\.com/Okan-wqm/suderra-os/",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--signature",
        ])
        .arg(signature)
        .arg(artifact)
        .output()
        .with_context(|| format!("cosign çalıştırılamadı: {}", cosign.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!("cosign stdout: {stdout}");
    debug!("cosign stderr: {stderr}");

    if output.status.success() {
        info!("cosign signature doğrulandı ✓");
        Ok(VerifyOutcome {
            verified: true,
            details: stderr.into_owned(),
        })
    } else {
        warn!("cosign doğrulama başarısız");
        bail!(
            "cosign signature doğrulanamadı:\n--- stderr ---\n{stderr}\n--- stdout ---\n{stdout}"
        );
    }
}

/// `cosign` binary'sini PATH'te bul. Yoksa kurulum talimatı ile fail.
pub fn which_cosign() -> Result<std::path::PathBuf> {
    let cosign_env = std::env::var("COSIGN_BINARY").ok();
    if let Some(path) = cosign_env {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // PATH'te ara
    if let Ok(path) = which::which("cosign") {
        return Ok(path);
    }

    bail!(
        "cosign binary bulunamadı. Kurulum:\n  \
         curl -sSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign\n  \
         chmod +x /usr/local/bin/cosign\n\n\
         Veya COSIGN_BINARY=/path/to/cosign env değişkeni set et."
    );
}

/// Verify sonucu
#[derive(Debug)]
#[allow(dead_code)]
pub struct VerifyOutcome {
    /// İmza doğrulandı mı
    pub verified: bool,
    /// cosign output detayı (transparency log entry, vb.)
    pub details: String,
}

/// Mini PATH binary lookup — `which` crate'i deps'ten kaçınma
mod which {
    use anyhow::{bail, Result};
    use std::path::PathBuf;

    pub fn which(binary: &str) -> Result<PathBuf> {
        let path_var = std::env::var("PATH").unwrap_or_default();
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join(binary);
            if candidate.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&candidate) {
                        if meta.permissions().mode() & 0o111 != 0 {
                            return Ok(candidate);
                        }
                    }
                }
                #[cfg(not(unix))]
                return Ok(candidate);
            }
        }
        bail!("'{binary}' PATH'te bulunamadı")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_common_binary() {
        // /bin/sh hemen hemen her POSIX sistemde var
        let result = which::which("sh");
        assert!(result.is_ok());
    }

    #[test]
    fn which_fails_for_nonexistent() {
        let result = which::which("definitely-not-a-real-binary-xyz123");
        assert!(result.is_err());
    }
}

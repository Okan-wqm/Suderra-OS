// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! HTTP download + SHA256 verification.
//!
//! reqwest (rustls backend) ile HTTPS, progress bar, retry logic.
//! TLS sertifika doğrulaması zorunlu — SUDERRA_INSECURE=1 ile devre dışı
//! (yalnızca lokal test / air-gapped için).

use anyhow::{anyhow, bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

/// Bir dosyayı URL'den indirip diske yaz, SHA256 hesapla
pub async fn download_file(
    url: &str,
    target: &Path,
    expected_sha256: Option<&str>,
) -> Result<DownloadResult> {
    info!("indiriliyor: {url}");
    debug!("hedef yol: {}", target.display());

    let client = build_client()?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("HTTP GET başarısız: {url}"))?;

    if !response.status().is_success() {
        bail!("HTTP {} — {}", response.status(), url);
    }

    let total_bytes = response.content_length().unwrap_or(0);

    // Progress bar
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-"),
    );

    // Hedef dosyayı aç + parent dir oluştur
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::File::create(target)
        .await
        .with_context(|| format!("dosya oluşturulamadı: {}", target.display()))?;

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;

    // Buffered streaming: response.chunk() loop (reqwest native, no extra deps)
    let mut response = response;
    while let Some(chunk) = response.chunk().await.context("download chunk hatası")? {
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        pb.set_position(downloaded);
    }

    file.flush().await?;
    pb.finish_with_message("indirme tamam");

    let actual_sha256 = hex::encode(hasher.finalize());

    // SHA256 doğrulama (varsa)
    if let Some(expected) = expected_sha256 {
        if !expected.eq_ignore_ascii_case(&actual_sha256) {
            // Bozuk dosyayı sil
            let _ = tokio::fs::remove_file(target).await;
            bail!(
                "SHA256 uyuşmazlığı! beklenen={expected} hesaplanan={actual_sha256}\n\
                 İndirilen dosya silindi: {}",
                target.display()
            );
        }
        info!("SHA256 doğrulandı ✓");
    } else {
        warn!("SHA256 doğrulama atlandı (expected hash sağlanmadı)");
    }

    Ok(DownloadResult {
        path: target.to_path_buf(),
        bytes: downloaded,
        sha256: actual_sha256,
    })
}

/// İndirme sonucu
#[derive(Debug)]
#[allow(dead_code)]
pub struct DownloadResult {
    /// Diske yazılan dosya yolu
    pub path: std::path::PathBuf,
    /// Toplam indirilen byte
    pub bytes: u64,
    /// Hesaplanan SHA256 (hex)
    pub sha256: String,
}

/// reqwest client'ı yapılandır — TLS strict, makul timeout, user-agent
fn build_client() -> Result<reqwest::Client> {
    let insecure = std::env::var("SUDERRA_INSECURE").map(|v| v == "1").unwrap_or(false);
    if insecure {
        warn!("⚠ SUDERRA_INSECURE=1 — TLS doğrulaması devre dışı (yalnızca dev/test)");
    }

    let builder = reqwest::Client::builder()
        .user_agent(concat!("suderra-installer/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(insecure)
        .tcp_keepalive(std::time::Duration::from_secs(60));

    builder.build().map_err(|e| anyhow!("HTTP client başlatılamadı: {e}"))
}

/// Tek string olarak küçük bir dosya indir (örn: .sha256, manifest.json)
pub async fn fetch_text(url: &str) -> Result<String> {
    let client = build_client()?;
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("HTTP {} — {}", response.status(), url);
    }
    Ok(response.text().await?)
}

/// Bir dosyanın SHA256 hash'ini hesapla (lokal kontrol için)
pub async fn hash_file(path: &Path) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn hash_known_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.txt");
        tokio::fs::write(&path, b"hello world\n").await.unwrap();

        let hash = hash_file(&path).await.unwrap();
        // sha256("hello world\n") = a948...
        assert_eq!(
            hash,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
    }
}

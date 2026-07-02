// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! HTTP download + SHA256 verification.
//!
//! reqwest (rustls backend) ile HTTPS ve SHA256 doğrulaması.
//! TLS sertifika doğrulaması zorunlu — SUDERRA_INSECURE=1 ile devre dışı
//! (yalnızca lokal test / air-gapped için).

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

/// İmza/hash doğrulaması OLMADAN indirilen (manifest, .sig, .cert, sürüm listesi
/// gibi) küçük metadata dosyaları için üst sınır. Bunlar doğrulanmadan diske/RAM'e
/// yazıldığından, ele geçirilmiş/MITM bir mirror'ın sınırsız stream ile diski veya
/// belleği tüketmesini engeller.
pub const METADATA_MAX_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB

/// SHA256'sı önceden bilinen bundle indirmeleri için mutlak tavan. Manifest'te
/// beklenen boyut ayrıca kontrol edilir; bu, kötü niyetli bir manifest'e karşı
/// son emniyet sübabıdır.
pub const BUNDLE_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Bir dosyayı URL'den indirip diske yaz, SHA256 hesapla.
///
/// `max_bytes`: indirilen toplam byte bu sınırı aşarsa indirme iptal edilir ve
/// yarım dosya silinir (doğrulama-öncesi kaynak tüketimini engeller).
pub async fn download_file(
    url: &str,
    target: &Path,
    expected_sha256: Option<&str>,
    max_bytes: u64,
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

    // Sunucu Content-Length bildirdiyse, tek byte indirmeden önce reddet.
    if let Some(len) = response.content_length() {
        if len > max_bytes {
            bail!(
                "indirme reddedildi: bildirilen boyut {len} bytes > sınır {max_bytes} bytes ({url})"
            );
        }
    }

    // Hedef dosyayı aç + parent dir oluştur
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::File::create(target)
        .await
        .with_context(|| format!("dosya oluşturulamadı: {}", target.display()))?;

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;

    // Buffered streaming: response.chunk() loop (reqwest native, no extra deps).
    // Content-Length yalan söyleyebilir veya hiç gelmeyebilir; bu yüzden akış
    // sırasında da sınırı zorunlu kılıyoruz.
    let mut response = response;
    while let Some(chunk) = response.chunk().await.context("download chunk hatası")? {
        downloaded += chunk.len() as u64;
        if downloaded > max_bytes {
            drop(file);
            let _ = tokio::fs::remove_file(target).await;
            bail!(
                "indirme iptal: {downloaded} bytes indirildikten sonra sınır {max_bytes} bytes aşıldı ({url})"
            );
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }

    file.flush().await?;
    info!("indirme tamam: {downloaded} bytes");

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
    let insecure = std::env::var("SUDERRA_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if insecure {
        if crate::variant::is_production() {
            bail!("SUDERRA_INSECURE=1 is forbidden on production Suderra OS variants");
        }
        warn!("⚠ SUDERRA_INSECURE=1 — TLS doğrulaması devre dışı (yalnızca dev/test)");
    }

    let builder = reqwest::Client::builder()
        .user_agent(concat!("suderra-installer/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(insecure)
        .tcp_keepalive(std::time::Duration::from_secs(60));

    builder
        .build()
        .map_err(|e| anyhow!("HTTP client başlatılamadı: {e}"))
}

/// Tek string olarak küçük bir dosya indir (örn: .sha256, manifest.json).
/// Gövde `METADATA_MAX_BYTES` ile sınırlıdır — doğrulanmadan belleğe okunduğundan
/// sınırsız bir yanıt belleği tüketemez.
pub async fn fetch_text(url: &str) -> Result<String> {
    let client = build_client()?;
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("HTTP {} — {}", response.status(), url);
    }
    if let Some(len) = response.content_length() {
        if len > METADATA_MAX_BYTES {
            bail!(
                "metadata reddedildi: bildirilen boyut {len} bytes > sınır {METADATA_MAX_BYTES} bytes ({url})"
            );
        }
    }

    let mut response = response;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.context("metadata chunk hatası")? {
        if body.len() as u64 + chunk.len() as u64 > METADATA_MAX_BYTES {
            bail!(
                "metadata iptal: gövde sınır {METADATA_MAX_BYTES} bytes'ı aştı ({url})"
            );
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("metadata gövdesi geçerli UTF-8 değil")
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

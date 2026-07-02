// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `install <package>` — paket kurulum komutu.
//!
//! Akış:
//! 1. Manifest indir + parse (sürüm + dosya bilgisi)
//! 2. Bundle indir (SHA256 doğrulamalı)
//! 3. Cosign signature doğrula
//! 4. RAUC bundle install (Faz 4'te aktif — şu an stub)
//! 5. systemd unit enable + start
//! 6. State dosyasını güncelle
//! 7. Audit log'a yaz

use crate::audit::{Event, EventKind, EventResult};
use crate::cli::InstallArgs;
use crate::download::download_file;
use crate::manifest::{InstalledPackage, InstalledState, Manifest};
use crate::sources::{Arch, PackageRelease};
use crate::verify;
use anyhow::{bail, Context, Result};
use dialoguer::Confirm;
use std::path::PathBuf;
use tracing::{info, warn};

/// `install <package>` çalıştır
pub async fn run(args: InstallArgs) -> Result<()> {
    info!("paket kurulumu: {}", args.package);
    enforce_signature_policy(args.verify_signature)?;

    // 1. Lokal dosyadan mı kuruyor (air-gapped)?
    if let Some(local) = &args.from_file {
        return install_from_local(&args, local).await;
    }

    // 2. Remote'tan indir + kur
    install_from_remote(&args).await
}

async fn install_from_remote(args: &InstallArgs) -> Result<()> {
    let arch = Arch::detect();
    info!("hedef mimari: {arch}");

    // Manifest indir
    let version = args.version.clone().unwrap_or_else(|| "latest".to_string());
    let release = PackageRelease {
        package: args.package.clone(),
        version: version.clone(),
        arch,
    };

    // Manifest authenticity: download manifest.json and its cosign signature
    // to disk and verify before parsing. Without this step, a manipulated
    // manifest could downgrade the install or substitute the bundle SHA256
    // (the bundle's own cosign signature would still verify because the
    // attacker would also be able to fetch a previously-signed older bundle).
    let manifest_url = release.manifest_url(args.mirror);
    let manifest_cache_dir = PathBuf::from("/var/cache/suderra/installer/manifests");
    tokio::fs::create_dir_all(&manifest_cache_dir).await?;
    let manifest_path = manifest_cache_dir.join(format!("{}-{}.json", args.package, version));
    info!("manifest indiriliyor: {manifest_url}");
    download_file(&manifest_url, &manifest_path, None, crate::download::METADATA_MAX_BYTES)
        .await
        .with_context(|| {
            format!(
                "manifest indirilemedi: {manifest_url}\n\
                 - Paket adı doğru mu? '{}'\n\
                 - Sürüm doğru mu? '{}'\n\
                 - GitHub Releases'ta release yayınlandı mı?",
                args.package, version
            )
        })?;

    if args.verify_signature {
        let manifest_sig_url = release.manifest_signature_url(args.mirror);
        let manifest_cert_url = release.manifest_certificate_url(args.mirror);
        let manifest_sig_path =
            manifest_cache_dir.join(format!("{}-{}.json.sig", args.package, version));
        let manifest_cert_path =
            manifest_cache_dir.join(format!("{}-{}.json.cert", args.package, version));
        info!("manifest signature indiriliyor: {manifest_sig_url}");
        download_file(&manifest_sig_url, &manifest_sig_path, None, crate::download::METADATA_MAX_BYTES)
            .await
            .with_context(|| {
                format!(
                    "manifest signature indirilemedi: {manifest_sig_url}\n\
                     Manifest doğrulanmadan paket kurulamaz."
                )
            })?;
        info!("manifest certificate indiriliyor: {manifest_cert_url}");
        download_file(&manifest_cert_url, &manifest_cert_path, None, crate::download::METADATA_MAX_BYTES)
            .await
            .with_context(|| {
                format!(
                    "manifest certificate indirilemedi: {manifest_cert_url}\n\
                     Manifest doğrulanmadan paket kurulamaz."
                )
            })?;
        verify::verify_keyless(&manifest_path, &manifest_sig_path, &manifest_cert_path)
            .with_context(|| {
                // Tampered manifest is not safe to leave on disk
                let _ = std::fs::remove_file(&manifest_path);
                let _ = std::fs::remove_file(&manifest_sig_path);
                let _ = std::fs::remove_file(&manifest_cert_path);
                "manifest cosign doğrulaması başarısız"
            })?;
        Event::new(
            EventKind::VerifySignature,
            &args.package,
            EventResult::Success,
        )
        .with_meta("target", "manifest.json")
        .record()
        .ok();
    } else {
        warn!("⚠ Manifest signature doğrulama devre dışı (--verify-signature=false)");
    }

    let manifest_json = tokio::fs::read_to_string(&manifest_path)
        .await
        .context("manifest okunamadı")?;
    let manifest = Manifest::from_json(&manifest_json).context("manifest JSON parse hatası")?;
    let package_info = manifest
        .find_package(&args.package, arch.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Paket bulunamadı: {}/{}/{}", args.package, arch, version)
        })?;

    // Konfirm prompt
    println!();
    println!("  Paket:     {}", package_info.name);
    println!("  Versiyon:  {}", manifest.version);
    println!("  Mimari:    {}", package_info.arch);
    println!("  Dosya:     {}", package_info.file);
    println!(
        "  Boyut:     {} bytes ({:.1} MiB)",
        package_info.size_bytes,
        package_info.size_bytes as f64 / 1024.0 / 1024.0
    );
    println!(
        "  SHA256:    {}",
        &package_info.sha256[..16.min(package_info.sha256.len())]
    );
    if let Some(min_os) = &package_info.min_os_version {
        println!("  Min OS:    {min_os}");
    }
    println!();

    if !args.yes && !confirm_install()? {
        info!("kurulum iptal edildi (kullanıcı reddetti)");
        Event::new(EventKind::Install, &args.package, EventResult::Aborted)
            .with_version(&manifest.version)
            .with_meta("reason", "user_declined")
            .record()
            .ok();
        return Ok(());
    }

    // Bundle indir
    let target_dir = PathBuf::from("/var/cache/suderra/installer");
    tokio::fs::create_dir_all(&target_dir).await?;
    let target = target_dir.join(&package_info.file);

    let bundle_url = release.artifact_url(args.mirror);
    // Bundle indirmesi için tavan: manifest'in bildirdiği boyut (biraz pay ile),
    // mutlak BUNDLE_MAX_BYTES ile sınırlanır. sha256 zaten sonradan doğrulanır;
    // bu tavan doğrulama-öncesi kaynak tükenmesini önler.
    let bundle_cap = package_info
        .size_bytes
        .saturating_add(1024 * 1024)
        .clamp(1, crate::download::BUNDLE_MAX_BYTES);
    let download_result =
        match download_file(&bundle_url, &target, Some(&package_info.sha256), bundle_cap).await {
            Ok(r) => r,
            Err(e) => {
                // Fallback mirror
                if let Some(fallback) = args.mirror.fallback() {
                    warn!("Ana mirror başarısız ({e}), fallback denenecek: {fallback:?}");
                    let release2 = PackageRelease {
                        package: args.package.clone(),
                        version: manifest.version.clone(),
                        arch,
                    };
                    let fallback_url = release2.artifact_url(fallback);
                    download_file(&fallback_url, &target, Some(&package_info.sha256), bundle_cap).await?
                } else {
                    return Err(e);
                }
            }
        };

    Event::new(EventKind::Download, &args.package, EventResult::Success)
        .with_version(&manifest.version)
        .with_meta("url", bundle_url.clone())
        .with_meta("sha256", download_result.sha256.clone())
        .with_meta("bytes", download_result.bytes)
        .record()
        .ok();

    // Cosign verify (varsa)
    let mut signature_verified = false;
    if args.verify_signature {
        let sig_url = release.signature_url(args.mirror);
        let cert_url = release.certificate_url(args.mirror);
        let sig_path = target_dir.join(format!("{}.sig", &package_info.file));
        let cert_path = target_dir.join(format!("{}.cert", &package_info.file));
        info!("signature indiriliyor: {sig_url}");

        match download_file(&sig_url, &sig_path, None, crate::download::METADATA_MAX_BYTES).await {
            Ok(_) => {
                info!("certificate indiriliyor: {cert_url}");
                download_file(&cert_url, &cert_path, None, crate::download::METADATA_MAX_BYTES)
                    .await
                    .with_context(|| {
                        format!(
                            "certificate indirilemedi: {cert_url}\n\
                         Artifact doğrulanmadan paket kurulamaz."
                        )
                    })?;
                match verify::verify_keyless(&target, &sig_path, &cert_path) {
                    Ok(_outcome) => {
                        signature_verified = true;
                        Event::new(
                            EventKind::VerifySignature,
                            &args.package,
                            EventResult::Success,
                        )
                        .with_version(&manifest.version)
                        .record()
                        .ok();
                    }
                    Err(e) => {
                        Event::new(
                            EventKind::VerifySignature,
                            &args.package,
                            EventResult::Failure,
                        )
                        .with_version(&manifest.version)
                        .with_meta("error", e.to_string())
                        .record()
                        .ok();
                        // Bundle'ı sil — manipüle edilmiş olabilir
                        let _ = tokio::fs::remove_file(&target).await;
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                warn!("signature indirilemedi: {e} — devam edilmiyor");
                bail!("Signature olmadan kurulum reddedildi (--verify-signature aktif)");
            }
        }
    } else {
        warn!("⚠ Signature doğrulama devre dışı (--verify-signature=false)");
    }

    // Bundle install (Faz 4 RAUC integration)
    let outcome = install_bundle(&target, &args.package, args.start_service).await?;
    let method = install_method(outcome);

    // State güncelle
    let mut state = InstalledState::load()
        .context("installed state okunamadı; corrupt state ile kurulum fail-closed durur")?;
    state.record_install(InstalledPackage {
        name: args.package.clone(),
        version: manifest.version.clone(),
        previous_version: None,
        installed_at: chrono::Utc::now(),
        sha256: download_result.sha256,
        signature_verified,
        install_method: method,
    });
    state.save()?;

    // Audit log — kurulum yöntemi açıkça kaydedilir; lab-copy "başarılı kurulum"
    // olarak sunulmaz.
    Event::new(EventKind::Install, &args.package, install_result(outcome))
        .with_version(&manifest.version)
        .with_meta("mirror", format!("{:?}", args.mirror))
        .with_meta("signature_verified", signature_verified)
        .with_meta("install_method", format!("{method:?}"))
        .record()
        .ok();

    report_outcome(outcome, &args.package, &manifest.version, package_info.name == "edge");
    Ok(())
}

/// `InstallOutcome`'u kalıcı `InstallMethod`'a çevir.
fn install_method(outcome: InstallOutcome) -> crate::manifest::InstallMethod {
    match outcome {
        InstallOutcome::Rauc => crate::manifest::InstallMethod::Rauc,
        InstallOutcome::LabCopy => crate::manifest::InstallMethod::LabCopy,
    }
}

/// Lab-copy gerçek bir kurulum olmadığından audit'te `Success` olarak damgalanmaz.
fn install_result(outcome: InstallOutcome) -> EventResult {
    match outcome {
        InstallOutcome::Rauc => EventResult::Success,
        InstallOutcome::LabCopy => EventResult::Aborted,
    }
}

/// Kullanıcıya dürüst çıktı: lab-copy için "kuruldu" demeyiz, servis ipuçlarını basmayız.
fn report_outcome(outcome: InstallOutcome, package: &str, version: &str, is_edge: bool) {
    println!();
    match outcome {
        InstallOutcome::Rauc => {
            println!("✓ {package} v{version} kuruldu");
            println!();
            if is_edge {
                println!("Servis durumu:");
                println!("  systemctl status suderra-edge-agent");
                println!("  journalctl -u suderra-edge-agent -f");
                println!();
            }
        }
        InstallOutcome::LabCopy => {
            println!("⚠ {package} v{version} yalnızca LAB-COPY olarak yerleştirildi.");
            println!("  Bu GERÇEK bir kurulum değildir: RAUC uygulanmadı ve servis");
            println!("  etkinleştirilmedi. Üretimde kullanmayın (RAUC entegrasyonu Faz 4).");
            println!();
        }
    }
}

async fn install_from_local(args: &InstallArgs, local: &std::path::Path) -> Result<()> {
    info!("yerel dosyadan kurulum: {}", local.display());

    if !local.exists() {
        bail!("Dosya bulunamadı: {}", local.display());
    }

    // Signature varsa doğrula
    let mut signature_verified = false;
    if let Some(sig) = &args.signature {
        if !sig.exists() {
            bail!("Signature dosyası bulunamadı: {}", sig.display());
        }
        let cert = args.certificate.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--from-file imzalı kurulum için --certificate gerektirir")
        })?;
        if !cert.exists() {
            bail!("Certificate dosyası bulunamadı: {}", cert.display());
        }
        verify::verify_keyless(local, sig, cert)?;
        signature_verified = true;
    } else if args.verify_signature {
        bail!("--from-file imzalı kurulum için --signature ve --certificate gerektirir");
    } else {
        warn!(
            "Signature doğrulama devre dışı; yalnızca geliştirme/lab kullanımı için kabul edilir"
        );
    }

    // Hash hesapla
    let sha = crate::download::hash_file(local).await?;
    info!("yerel dosya SHA256: {}", &sha[..16]);

    let outcome = install_bundle(local, &args.package, args.start_service).await?;
    let method = install_method(outcome);

    let mut state = InstalledState::load()
        .context("installed state okunamadı; corrupt state ile kurulum fail-closed durur")?;
    state.record_install(InstalledPackage {
        name: args.package.clone(),
        version: "local".into(),
        previous_version: None,
        installed_at: chrono::Utc::now(),
        sha256: sha,
        signature_verified,
        install_method: method,
    });
    state.save()?;

    Event::new(EventKind::Install, &args.package, install_result(outcome))
        .with_meta("source", "local")
        .with_meta("path", local.display().to_string())
        .with_meta("install_method", format!("{method:?}"))
        .record()
        .ok();

    report_outcome(outcome, &args.package, "local", package_kind_is_edge(&args.package));
    Ok(())
}

/// Yerel kurulumda paket adına göre edge olup olmadığını belirle (servis ipuçları için).
fn package_kind_is_edge(package: &str) -> bool {
    package == "edge"
}

/// Bir `install_bundle` çağrısının GERÇEKTE ne yaptığı. Çağıran bu sonuca göre
/// state/audit/insan-mesajı üretir — böylece lab-copy "kuruldu" gibi sunulmaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    /// Gerçek RAUC-backed kurulum (servis etkin). Faz 4'te RAUC motoru
    /// eklendiğinde `install_bundle` bunu döndürecek; şimdilik yalnız match
    /// kollarında kullanılıyor.
    #[allow(dead_code)]
    Rauc,
    /// Yalnız lab: bundle kopyalandı; RAUC yok, servis etkinleştirilmedi.
    LabCopy,
}

/// RAUC bundle install.
///
/// Gerçek RAUC motoru henüz yok. `SUDERRA_ALLOW_LEGACY_COPY_INSTALL=1` (yalnız
/// non-prod) ile bundle bir dizine kopyalanır; bu GERÇEK bir kurulum DEĞİLDİR ve
/// çağırana `LabCopy` döner ki state/audit yanıltıcı biçimde "başarılı kurulum"
/// yazmasın.
async fn install_bundle(
    bundle: &std::path::Path,
    package: &str,
    start_service: bool,
) -> Result<InstallOutcome> {
    info!("bundle kurulumu: {}", bundle.display());

    if std::env::var("SUDERRA_ALLOW_LEGACY_COPY_INSTALL").as_deref() != Ok("1") {
        bail!(
            "RAUC-backed install engine is not implemented yet; refusing to copy {} into /opt/suderra as a successful install",
            bundle.display()
        );
    }
    if is_production_variant() {
        bail!("production images cannot use SUDERRA_ALLOW_LEGACY_COPY_INSTALL");
    }

    warn!("SUDERRA_ALLOW_LEGACY_COPY_INSTALL=1 active; using lab-only copy install path (NOT a real install)");
    let target_dir = PathBuf::from("/opt/suderra").join(package);
    tokio::fs::create_dir_all(&target_dir).await?;
    let target_file = target_dir.join(
        bundle
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("bundle file_name yok"))?,
    );
    tokio::fs::copy(bundle, &target_file).await?;
    info!("bundle kopyalandı: {}", target_file.display());

    if start_service {
        // RAUC/servis motoru yok — servisi BAŞLATMADIĞIMIZI net söyle, aksi halde
        // çağıran "servis çalışıyor" sanır.
        warn!(
            "start_service istendi ama lab-copy modunda systemd unit ETKİNLEŞTİRİLMEDİ (suderra-{package}.service); RAUC entegrasyonu Faz 4"
        );
    }

    Ok(InstallOutcome::LabCopy)
}

fn confirm_install() -> Result<bool> {
    let prompt = Confirm::new()
        .with_prompt("Devam edilsin mi?")
        .default(true)
        .interact();
    Ok(prompt.unwrap_or(false))
}

fn enforce_signature_policy(verify_signature: bool) -> Result<()> {
    if verify_signature {
        return Ok(());
    }
    if is_production_variant() {
        bail!("production images cannot disable signature verification");
    }
    Ok(())
}

fn is_production_variant() -> bool {
    // Tek kaynak: crate::variant (download.rs ile paylaşılan tanım). Önceki iki
    // ayrı/uyuşmayan tanım tek fonksiyonda birleştirildi (M1).
    crate::variant::is_production()
}

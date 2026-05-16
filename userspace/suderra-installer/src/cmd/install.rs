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
    download_file(&manifest_url, &manifest_path, None)
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
        let manifest_sig_path =
            manifest_cache_dir.join(format!("{}-{}.json.sig", args.package, version));
        info!("manifest signature indiriliyor: {manifest_sig_url}");
        download_file(&manifest_sig_url, &manifest_sig_path, None)
            .await
            .with_context(|| {
                format!(
                    "manifest signature indirilemedi: {manifest_sig_url}\n\
                     Manifest doğrulanmadan paket kurulamaz."
                )
            })?;
        verify::verify_keyless(&manifest_path, &manifest_sig_path).with_context(|| {
            // Tampered manifest is not safe to leave on disk
            let _ = std::fs::remove_file(&manifest_path);
            let _ = std::fs::remove_file(&manifest_sig_path);
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
    let download_result =
        match download_file(&bundle_url, &target, Some(&package_info.sha256)).await {
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
                    download_file(&fallback_url, &target, Some(&package_info.sha256)).await?
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
        let sig_path = target_dir.join(format!("{}.sig", &package_info.file));
        info!("signature indiriliyor: {sig_url}");

        match download_file(&sig_url, &sig_path, None).await {
            Ok(_) => {
                match verify::verify_keyless(&target, &sig_path) {
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
    install_bundle(&target, &args.package, args.start_service).await?;

    // State güncelle
    let mut state = InstalledState::load().unwrap_or_default();
    state.record_install(InstalledPackage {
        name: args.package.clone(),
        version: manifest.version.clone(),
        previous_version: None,
        installed_at: chrono::Utc::now(),
        sha256: download_result.sha256,
        signature_verified,
    });
    state.save()?;

    // Audit log
    Event::new(EventKind::Install, &args.package, EventResult::Success)
        .with_version(&manifest.version)
        .with_meta("mirror", format!("{:?}", args.mirror))
        .with_meta("signature_verified", signature_verified)
        .record()
        .ok();

    println!();
    println!("✓ {} v{} kuruldu", args.package, manifest.version);
    println!();
    if package_info.name == "edge" {
        println!("Servis durumu:");
        println!("  systemctl status suderra-edge-agent");
        println!("  journalctl -u suderra-edge-agent -f");
        println!();
    }

    Ok(())
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
        verify::verify_keyless(local, sig)?;
        signature_verified = true;
    } else if args.verify_signature {
        bail!("--from-file imzalı kurulum için --signature gerektirir");
    } else {
        warn!(
            "Signature doğrulama devre dışı; yalnızca geliştirme/lab kullanımı için kabul edilir"
        );
    }

    // Hash hesapla
    let sha = crate::download::hash_file(local).await?;
    info!("yerel dosya SHA256: {}", &sha[..16]);

    install_bundle(local, &args.package, args.start_service).await?;

    let mut state = InstalledState::load().unwrap_or_default();
    state.record_install(InstalledPackage {
        name: args.package.clone(),
        version: "local".into(),
        previous_version: None,
        installed_at: chrono::Utc::now(),
        sha256: sha,
        signature_verified,
    });
    state.save()?;

    Event::new(EventKind::Install, &args.package, EventResult::Success)
        .with_meta("source", "local")
        .with_meta("path", local.display().to_string())
        .record()
        .ok();

    println!("✓ {} (yerel) kuruldu", args.package);
    Ok(())
}

/// RAUC bundle install — Faz 4'te tam, şu an stub
async fn install_bundle(
    bundle: &std::path::Path,
    package: &str,
    start_service: bool,
) -> Result<()> {
    info!("bundle kurulumu (stub): {}", bundle.display());

    // TODO Faz 4 (RAUC integration):
    //   1. rauc install <bundle>
    //   2. rauc status mark-good
    //   3. systemctl enable suderra-edge-agent.service
    //   4. systemctl start suderra-edge-agent.service (start_service ise)

    // Faz 2-D MVP: dosyayı /opt/suderra/<package>/'a kopyala
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
        info!("systemd unit etkinleştiriliyor (stub): suderra-{package}.service");
        // TODO Faz 4: systemctl enable + start
    }

    Ok(())
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
    if std::env::var("SUDERRA_OS_VARIANT")
        .or_else(|_| std::env::var("SUDERRA_VARIANT"))
        .map(|value| value.trim_matches('"').eq_ignore_ascii_case("prod"))
        .unwrap_or(false)
    {
        return true;
    }

    let Ok(os_release) = std::fs::read_to_string("/etc/os-release") else {
        return false;
    };
    os_release.lines().any(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        matches!(key, "VARIANT" | "VARIANT_ID")
            && value.trim().trim_matches('"').eq_ignore_ascii_case("prod")
    })
}

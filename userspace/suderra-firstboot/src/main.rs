// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-firstboot` — Eksen B güven tesis durum makinesi (ADR-0008 §3, ADR-0009).
//!
//! `systemd` Type=oneshot, `Before=suderra-agent.service`, genel kapı
//! `ConditionPathExists=!/var/lib/suderra/.provisioned`. İDEMPOTENT ve FAIL-CLOSED:
//! her adım kendi done-koşulunu kontrol eder; herhangi bir adım hata verirse
//! non-zero çıkar, `.provisioned` YAZILMAZ → cihaz fabrika modunda kalır
//! (systemd Restart politikası). Adımlar (bağımlılık sıralı):
//!
//! 1. `/data` LUKS2 provision  → mevcut `suderra-data-provision` script'ine
//!    shell-out (RT-1, #84; Rust'a PORT EDİLMEZ — contract-testli, idempotent).
//! 2. Cihaz kimliği (RT-3)      → TPM-resident signing key + self-attested
//!    `device.json` (`suderra.device-identity.v1`).
//! 3. Attestation baseline (RT-2)→ `suderra-attestation setup` + `baseline`.
//! 4. Anti-rollback NV çıpası (RT-6)→ TPM-NV counter tanımla + imaj epoch'una
//!    yükselt.
//! 5. mark-provisioned          → `.provisioned` dokunma bayrağı.
//!
//! TPM adımları prod'da zorunlu (TPM yoksa fail-closed, `suderra-data-provision`
//! sözleşmesiyle aynı); non-prod'da TPM yoksa temiz atlanır.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use suderra_config::tpm::{have_tpm, Tpm};
use tracing::{info, warn};

const PROVISIONED_MARKER: &str = "/var/lib/suderra/.provisioned";
const IDENTITY_DIR: &str = "/data/suderra/identity";
const IDENTITY_KEY_HANDLE: u32 = 0x8101_0002;
const IDENTITY_SCHEMA: &str = "suderra.device-identity.v1";
const ROLLBACK_NV_INDEX: u32 = 0x0150_0001;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);

    match run() {
        Ok(()) => {
            info!("ilk boot güven tesisi tamamlandı");
            std::process::ExitCode::SUCCESS
        }
        Err(err) => {
            // FAIL-CLOSED: .provisioned yazılmadı; cihaz fabrika modunda kalır.
            eprintln!("suderra-firstboot FATAL: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    if Path::new(PROVISIONED_MARKER).exists() {
        info!("zaten provision edilmiş; no-op");
        return Ok(());
    }
    let production = suderra_config::variant::os_release_is_prod();
    let tpm_present = have_tpm();
    if production && !tpm_present {
        bail!("prod cihazda TPM yok (/dev/tpm*): güven tesisi fail-closed");
    }

    step_data_provision().context("adım 1: /data provision")?;
    if tpm_present {
        let tpm = Tpm::new(production);
        step_device_identity(&tpm).context("adım 2: cihaz kimliği (RT-3)")?;
        step_attestation_baseline().context("adım 3: attestation baseline (RT-2)")?;
        step_rollback_anchor(&tpm).context("adım 4: TPM-NV rollback çıpası (RT-6)")?;
    } else {
        warn!("TPM yok ve prod değil — kimlik/attestation/NV adımları atlandı (dev)");
    }
    mark_provisioned().context("adım 5: mark-provisioned")?;
    Ok(())
}

/// Adım 1 — /data LUKS2 provision: mevcut script'e shell-out (idempotent).
fn step_data_provision() -> Result<()> {
    let script = "/usr/sbin/suderra-data-provision";
    if !Path::new(script).exists() {
        // Script yoksa (dev overlay), atla — data-unlock zaten dev'de düz ext4.
        info!("suderra-data-provision yok; /data adımı atlandı (dev)");
        return Ok(());
    }
    run_cmd(script, &[])
}

/// Adım 2 — RT-3: TPM-resident signing key + self-attested device.json.
fn step_device_identity(tpm: &Tpm) -> Result<()> {
    let dir = PathBuf::from(IDENTITY_DIR);
    let doc_path = dir.join("device.json");
    if doc_path.exists() {
        info!("cihaz kimliği zaten mevcut; atlandı");
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;

    // Persistent signing key yoksa üret (primary → child signing key → evict).
    let pub_pem = dir.join("device-key.pub.pem");
    if tpm.readpublic_pem(IDENTITY_KEY_HANDLE, &pub_pem).is_err() {
        let primary = dir.join("primary.ctx");
        let key_ctx = dir.join("device-key.ctx");
        let key_pub = dir.join("device-key.pub");
        let key_priv = dir.join("device-key.priv");
        tpm.run(
            "tpm2_createprimary",
            &[
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "ecc",
                "-c",
                pstr(&primary)?,
            ],
        )?;
        tpm.run(
            "tpm2_create",
            &[
                "-C",
                pstr(&primary)?,
                "-g",
                "sha256",
                "-G",
                "ecc:ecdsa",
                "-u",
                pstr(&key_pub)?,
                "-r",
                pstr(&key_priv)?,
            ],
        )?;
        tpm.run(
            "tpm2_load",
            &[
                "-C",
                pstr(&primary)?,
                "-u",
                pstr(&key_pub)?,
                "-r",
                pstr(&key_priv)?,
                "-c",
                pstr(&key_ctx)?,
            ],
        )
        .context("tpm2_load device signing key")?;
        tpm.run(
            "tpm2_evictcontrol",
            &[
                "-C",
                "o",
                "-c",
                pstr(&key_ctx)?,
                &format!("{IDENTITY_KEY_HANDLE:#x}"),
            ],
        )?;
        tpm.readpublic_pem(IDENTITY_KEY_HANDLE, &pub_pem)?;
    }

    let device_id = read_os_release_field("VARIANT")
        .map(|v| format!("suderra-{v}"))
        .unwrap_or_else(|| "suderra-unactivated".to_string());
    let doc = DeviceIdentity {
        schema: IDENTITY_SCHEMA.to_string(),
        device_id,
        tpm_pubkey_pem: std::fs::read_to_string(&pub_pem)?,
        ek_cert_present: Path::new("/sys/kernel/security/tpm0/binary_bios_measurements").exists(),
        version_id: read_os_release_field("VERSION_ID").unwrap_or_default(),
    };
    let tmp = doc_path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
    std::fs::rename(&tmp, &doc_path)?;
    info!(
        "self-attested cihaz kimliği yazıldı: {}",
        doc_path.display()
    );
    Ok(())
}

/// Adım 3 — RT-2: attestation AK setup + PCR baseline.
fn step_attestation_baseline() -> Result<()> {
    let bin = "/usr/bin/suderra-attestation";
    if !Path::new(bin).exists() {
        info!("suderra-attestation yok; baseline adımı atlandı");
        return Ok(());
    }
    run_cmd(bin, &["setup"])?;
    run_cmd(bin, &["baseline"])?;
    Ok(())
}

/// Adım 4 — RT-6: TPM-NV monotonic counter'ı tanımla ve imaj epoch'una yükselt.
fn step_rollback_anchor(tpm: &Tpm) -> Result<()> {
    tpm.nv_define_counter(ROLLBACK_NV_INDEX)
        .context("NV counter tanımlanamadı")?;
    if let Some(epoch) = ota_conf_epoch() {
        let mut nv = tpm.nv_read_counter(ROLLBACK_NV_INDEX)?;
        while nv < epoch {
            tpm.nv_increment(ROLLBACK_NV_INDEX)?;
            nv = tpm.nv_read_counter(ROLLBACK_NV_INDEX)?;
        }
        info!(
            epoch,
            nv, "TPM-NV rollback çıpası imaj epoch'una yükseltildi"
        );
    }
    Ok(())
}

/// Adım 5 — mark-provisioned: dokunma bayrağı (dizin /data bind-mount'ta kalıcı).
fn mark_provisioned() -> Result<()> {
    if let Some(parent) = Path::new(PROVISIONED_MARKER).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(PROVISIONED_MARKER, b"provisioned\n")
        .with_context(|| format!("mark yazılamadı: {PROVISIONED_MARKER}"))?;
    Ok(())
}

// --- yardımcılar -----------------------------------------------------------

#[derive(Serialize)]
struct DeviceIdentity {
    schema: String,
    device_id: String,
    tpm_pubkey_pem: String,
    ek_cert_present: bool,
    version_id: String,
}

fn run_cmd(bin: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(bin)
        .args(args)
        .status()
        .with_context(|| format!("{bin} çalıştırılamadı"))?;
    if !status.success() {
        bail!("{bin} {:?} başarısız: exit {:?}", args, status.code());
    }
    Ok(())
}

fn read_os_release_field(key: &str) -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k == key {
                let v = v.trim().trim_matches('"').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn ota_conf_epoch() -> Option<u64> {
    let content = std::fs::read_to_string("/etc/suderra/ota.conf").ok()?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("rollback_epoch=") {
            return v.trim().parse::<u64>().ok();
        }
    }
    None
}

fn pstr(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| anyhow::anyhow!("path UTF-8 değil: {}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_doc_serializes_with_schema() {
        let doc = DeviceIdentity {
            schema: IDENTITY_SCHEMA.to_string(),
            device_id: "suderra-prod".to_string(),
            tpm_pubkey_pem: "-----BEGIN PUBLIC KEY-----\n".to_string(),
            ek_cert_present: true,
            version_id: "1.2.3".to_string(),
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains(IDENTITY_SCHEMA));
        assert!(json.contains("suderra-prod"));
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-firstboot` — Suderra OS ilk boot provisioning aracı.
//!
//! Lifecycle: `systemd` Type=oneshot, `Before=suderra-edge-agent.service`,
//! `ConditionPathExists=!/var/lib/suderra/.provisioned` ile gate'li.
//!
//! Yapacakları (Faz 2'de tam doldurulur):
//! 1. /data dizinini mount et (yoksa LUKS2 ile mkfs)
//! 2. /etc/machine-id generate et (yoksa)
//! 3. Cloud provisioning: device cert + key fetch (mTLS bootstrap)
//! 4. TPM seal: master key TPM'e seal et
//! 5. /var/lib/suderra/.provisioned dokunma flag'i bırak
//! 6. RAUC mark-good (ilk başarılı boot sonrası)
//!
//! Hata davranışı:
//! - Provisioning başarısız → systemd Restart=on-failure (max 5)
//! - Sonunda başarısız → cihaz "factory" modunda kalır, support gelir

use anyhow::Result;
use tracing::{info, warn};

fn main() -> Result<()> {
    // Logging — systemd-journald JSON output yakalar
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("suderra-firstboot v{} başlatılıyor", env!("CARGO_PKG_VERSION"));

    // systemd'ye "başlatma sürüyor" sinyali (Type=notify)
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);

    // TODO Faz 2:
    // 1. config_path = "/etc/suderra/config.yaml"
    // 2. let cfg = SuderraConfig::load_from_file(config_path)?;
    // 3. ensure_data_partition(&cfg)?;
    // 4. ensure_machine_id()?;
    // 5. cloud_enroll_if_needed(&cfg)?;
    // 6. tpm_seal_master_key(&cfg)?;
    // 7. mark_provisioned()?;

    warn!("suderra-firstboot şu an placeholder — Faz 2'de doldurulacak");
    info!("ilk boot provisioning tamamlandı (no-op)");

    Ok(())
}

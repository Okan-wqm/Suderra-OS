// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-ota` — RAUC OTA orchestrator.
//!
//! Suderra OS update lifecycle'ını yönetir:
//! 1. Update sunucusunu poll (HTTPS + mTLS)
//! 2. Bundle download (resumable, retry)
//! 3. Cosign + RAUC imza doğrula
//! 4. RAUC bundle install (pasif partition'a)
//! 5. Reboot tetikle
//! 6. Boot sonrası health check
//! 7. Başarılı → `rauc mark-good`, başarısız → otomatik rollback
//!
//! Çağırma stratejisi:
//! - systemd timer (her saat veya manuel komut)
//! - `suderra-ota check` → güncelleme var mı, indirme yok
//! - `suderra-ota install` → indir + kur, reboot tetikle
//!
//! Şu an iskelet — Faz 4'te doldurulur.

use anyhow::Result;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("suderra-ota v{} başlatılıyor", env!("CARGO_PKG_VERSION"));

    // TODO Faz 4:
    // 1. let cfg = SuderraConfig::load_from_file("/etc/suderra/config.yaml")?;
    // 2. let update = check_for_update(&cfg).await?;
    // 3. if let Some(bundle) = update { download_and_verify(&bundle).await?; }
    // 4. rauc_install(&bundle_path)?;
    // 5. trigger_reboot();

    warn!("suderra-ota şu an placeholder — Faz 4'te doldurulacak");
    Ok(())
}

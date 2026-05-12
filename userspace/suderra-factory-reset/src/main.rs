// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-factory-reset` — Fabrika ayarlarına dönüş.
//!
//! Tetikleyiciler:
//! 1. **Fiziksel buton** (GPIO line): 10sn basılı tutma
//! 2. **Cloud komut** (mTLS authenticated, 2-person rule)
//! 3. **CLI** (root, sadece DEV variant): `suderra-factory-reset --force`
//!
//! İşlem:
//! 1. /data partition wipe (cryptsetup luksFormat tekrar)
//! 2. /var/lib/suderra/.provisioned sil
//! 3. RAUC slot.A'ya geri dön (en eski stable)
//! 4. Reboot
//!
//! Faz 5'te tam implementasyon.

use anyhow::Result;
use tracing::{info, warn};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!(
        "suderra-factory-reset v{} başlatılıyor",
        env!("CARGO_PKG_VERSION")
    );

    // TODO Faz 5:
    // - GPIO line poll (gpiod crate)
    // - veya cloud command listener
    // - confirm prompt (CLI mode)
    // - wipe + reboot

    warn!("suderra-factory-reset şu an placeholder — Faz 5'te doldurulacak");
    Ok(())
}

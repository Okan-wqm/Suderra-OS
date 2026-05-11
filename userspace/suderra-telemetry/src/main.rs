// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-telemetry` — Cihaz sağlık + uygulama metrikleri cloud push.
//!
//! Metrikler:
//! - System: CPU %, RAM, disk, sıcaklık, uptime, network rx/tx
//! - Edge Agent: Modbus read rate, MQTT publish success, error count
//! - Update: son güncelleme zamanı, kullanılan partition (A/B)
//!
//! Push:
//! - JSON structured, batch (her 60s)
//! - Offline fallback: SQLite ring buffer (max 7 gün)
//! - mTLS HTTPS endpoint
//!
//! Faz 5'te tam implementasyon.

use anyhow::Result;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("suderra-telemetry v{} başlatılıyor", env!("CARGO_PKG_VERSION"));
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);

    // TODO Faz 5:
    // - sysinfo veya procfs okuma loop
    // - Edge Agent prometheus endpoint scrape (varsa)
    // - Batch + push (reqwest + rustls)
    // - Offline buffer (rusqlite ring buffer)

    warn!("suderra-telemetry şu an placeholder — Faz 5'te doldurulacak");
    Ok(())
}

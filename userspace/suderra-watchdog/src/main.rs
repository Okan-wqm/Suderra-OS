//! `suderra-watchdog` — Hardware watchdog + health monitor.
//!
//! İki kademe koruma:
//! 1. **Kernel watchdog** (/dev/watchdog): kernel donduğunda → otomatik reboot
//!    Bu daemon kernel'a heartbeat gönderir; daemon ölürse kernel reboot eder
//! 2. **App watchdog**: Edge Agent + diğer Suderra daemon'ları için health check
//!    systemd unit `Restart=on-failure` zaten var; bu daemon ek koordinasyon
//!
//! Lifecycle:
//! - systemd Type=notify, başlangıçta Ready
//! - Her 5sn: /dev/watchdog'a kick + Edge Agent health check
//! - 3 ardışık fail → systemctl restart
//! - 10 fail → reboot
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

    info!("suderra-watchdog v{} başlatılıyor", env!("CARGO_PKG_VERSION"));
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);

    // TODO Faz 5:
    // - open("/dev/watchdog", O_WRONLY)
    // - ioctl WDIOC_SETTIMEOUT (60s)
    // - loop: write "x" to /dev/watchdog (kick) + check Edge Agent /health
    // - 3 fail → systemctl restart suderra-edge-agent
    // - 10 fail → reboot

    warn!("suderra-watchdog şu an placeholder — Faz 5'te doldurulacak");
    Ok(())
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-watchdog` — Hardware watchdog + health monitor.
//!
//! İki kademe koruma:
//! 1. **Kernel watchdog** (`/dev/watchdog`): sistem donarsa kernel otomatik reboot
//!    eder. Bu daemon periyodik olarak watchdog'u besler (kick). Daemon ölür veya
//!    beslemeyi kesersey donanım watchdog süresi dolar ve kernel tüm sistemi resetler.
//! 2. **App health**: opsiyonel olarak bir systemd unit'in (ör. Edge Agent) sağlığını
//!    izler. Ardışık `restart_threshold` başarısızlıkta unit'i restart eder;
//!    `reboot_threshold` başarısızlıkta watchdog beslemeyi keserek donanım reset'i
//!    tetikler (fail-safe).
//!
//! Lifecycle:
//! - systemd `Type=notify`; hazır olunca `Ready` gönderir ve `WATCHDOG=1` keepalive
//!   forward eder (`WatchdogSec=` ayarlıysa systemd yazılım watchdog'u da beslenir).
//! - Temiz kapanışta (SIGTERM/SIGINT) watchdog'a magic-close (`V`) yazıp cihazı
//!   devre dışı bırakır — planlı restart'ta sistemi resetlememek için.
//!
//! Ayarlar (env, systemd unit üzerinden verilir):
//! - `SUDERRA_WATCHDOG_DEV`            (default `/dev/watchdog`)
//! - `SUDERRA_WATCHDOG_TIMEOUT_SECS`   (default `60`)
//! - `SUDERRA_WATCHDOG_INTERVAL_SECS`  (default `timeout/3`, min `1`)
//! - `SUDERRA_WATCHDOG_HEALTH_UNIT`    (opsiyonel systemd unit adı; boşsa health kapalı)
//! - `SUDERRA_WATCHDOG_RESTART_AFTER`  (default `3` ardışık fail)
//! - `SUDERRA_WATCHDOG_REBOOT_AFTER`   (default `10` ardışık fail)
//! - `SUDERRA_WATCHDOG_REQUIRE_HW`     (`1` ise `/dev/watchdog` yoksa daemon fail eder)

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

// `libc::ioctl` request argümanının tipi platforma göre değişir (glibc: `c_ulong`,
// musl: `c_int`). Sabitleri `u32` tutup çağrıda `as _` ile hedef tipe coerce ediyoruz;
// ioctl numarası 32 bite sığdığı için her iki hedefte de doğru kodlanır.
/// `WDIOC_SETTIMEOUT` = `_IOWR('W', 6, int)` (Linux watchdog API).
const WDIOC_SETTIMEOUT: u32 = 0xC004_5706;
/// `WDIOC_GETTIMEOUT` = `_IOR('W', 7, int)`.
const WDIOC_GETTIMEOUT: u32 = 0x8004_5707;

/// Watchdog cihazına heartbeat gönderir. Kernel dokümantasyonuna göre cihaza
/// yapılan herhangi bir `write()` bir keepalive ping'idir.
fn kick(dev: &mut File) -> Result<()> {
    dev.write_all(b"\0")
        .context("watchdog kick (write) başarısız")?;
    dev.flush().ok();
    Ok(())
}

/// `WDIOC_SETTIMEOUT` ile donanım watchdog süresini ayarlar; kernel'in kabul ettiği
/// (yuvarladığı) gerçek değeri döndürür.
#[allow(unsafe_code)] // donanım watchdog ioctl'i; gerekçe aşağıdaki SAFETY'de
fn set_timeout(dev: &File, secs: i32) -> Result<i32> {
    let mut requested: libc::c_int = secs;
    // SAFETY: `dev` açık ve geçerli bir watchdog karakter aygıtı; `requested`
    // ioctl'in beklediği tek `int` argümanına işaret eder.
    let rc = unsafe { libc::ioctl(dev.as_raw_fd(), WDIOC_SETTIMEOUT as _, &mut requested) };
    if rc != 0 {
        bail!(
            "WDIOC_SETTIMEOUT({secs}) başarısız: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(requested)
}

/// Cihazın raporladığı mevcut timeout'u okur (teşhis için; hata olması ölümcül değil).
#[allow(unsafe_code)] // donanım watchdog ioctl'i; gerekçe aşağıdaki SAFETY'de
fn get_timeout(dev: &File) -> Option<i32> {
    let mut current: libc::c_int = 0;
    // SAFETY: aynı gerekçe `set_timeout` ile; ioctl tek `int` çıktı yazar.
    let rc = unsafe { libc::ioctl(dev.as_raw_fd(), WDIOC_GETTIMEOUT as _, &mut current) };
    (rc == 0).then_some(current)
}

/// Temiz kapanışta watchdog'u devre dışı bırakmayı dener (magic close, `V`).
/// Cihaz `WDIOF_MAGICCLOSE` desteklemiyorsa reset kaçınılmazdır; bu yüzden
/// başarısızlık yalnız loglanır.
fn magic_close(mut dev: File) {
    if dev.write_all(b"V").and_then(|()| dev.flush()).is_ok() {
        info!("watchdog magic-close yazıldı; cihaz temiz kapanışta devre dışı");
    } else {
        warn!("watchdog magic-close yazılamadı; sistem timeout sonunda resetlenebilir");
    }
    drop(dev);
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

/// systemd unit adının güvenli bir token olduğunu doğrular (komut enjeksiyonu
/// önlemek için — env root tarafından verilse de savunma katmanı).
fn valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':' | '\\'))
}

/// `systemctl is-active --quiet <unit>` → sağlıklıysa `true`.
async fn unit_is_active(unit: &str) -> bool {
    match tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(err) => {
            warn!(%unit, %err, "systemctl is-active çalıştırılamadı; unhealthy sayılıyor");
            false
        }
    }
}

async fn systemctl(action: &str, unit: &str) {
    match tokio::process::Command::new("systemctl")
        .args([action, unit])
        .status()
        .await
    {
        Ok(status) if status.success() => info!(%action, %unit, "systemctl başarılı"),
        Ok(status) => warn!(%action, %unit, ?status, "systemctl başarısız çıkış kodu"),
        Err(err) => warn!(%action, %unit, %err, "systemctl çalıştırılamadı"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!(
        "suderra-watchdog v{} başlatılıyor",
        env!("CARGO_PKG_VERSION")
    );

    let dev_path =
        std::env::var("SUDERRA_WATCHDOG_DEV").unwrap_or_else(|_| "/dev/watchdog".to_string());
    let timeout_secs = env_u64("SUDERRA_WATCHDOG_TIMEOUT_SECS")
        .unwrap_or(60)
        .clamp(2, 3600) as i32;
    // Besleme aralığı donanımın GERÇEKTEN uyguladığı timeout bilindikten sonra
    // hesaplanır (cihaz açılınca); burada yalnız kullanıcı tercihini okuyoruz.
    let interval_pref = env_u64("SUDERRA_WATCHDOG_INTERVAL_SECS");
    let require_hw = std::env::var("SUDERRA_WATCHDOG_REQUIRE_HW").ok().as_deref() == Some("1");

    let health_unit = std::env::var("SUDERRA_WATCHDOG_HEALTH_UNIT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(unit) = &health_unit {
        if !valid_unit_name(unit) {
            bail!("SUDERRA_WATCHDOG_HEALTH_UNIT geçersiz unit adı: {unit:?}");
        }
    }
    let restart_after = env_u64("SUDERRA_WATCHDOG_RESTART_AFTER")
        .unwrap_or(3)
        .max(1);
    let reboot_after = env_u64("SUDERRA_WATCHDOG_REBOOT_AFTER")
        .unwrap_or(10)
        .max(restart_after.saturating_add(1));

    // Donanım watchdog cihazını aç. Yoksa: prod'da fail-closed (REQUIRE_HW),
    // dev/QEMU'da yalnız systemd yazılım watchdog'una düşerek çalışmaya devam.
    // Donanımın gerçekten uyguladığı timeout (yuvarlanmış olabilir); besleme
    // aralığını bunun üzerinden kısıtlayacağız.
    let mut applied_timeout_secs: Option<i32> = None;
    let mut hw_dev: Option<File> = match OpenOptions::new().read(false).write(true).open(&dev_path)
    {
        Ok(dev) => {
            match set_timeout(&dev, timeout_secs) {
                Ok(applied) => {
                    applied_timeout_secs = Some(applied);
                    info!(
                        device = %dev_path,
                        requested = timeout_secs,
                        applied,
                        reported = ?get_timeout(&dev),
                        "donanım watchdog açıldı, timeout ayarlandı"
                    )
                }
                Err(err) => {
                    warn!(device = %dev_path, %err, "timeout ayarlanamadı; cihaz varsayılan timeout ile beslenecek")
                }
            }
            Some(dev)
        }
        Err(err) => {
            if require_hw {
                bail!("SUDERRA_WATCHDOG_REQUIRE_HW=1 ama {dev_path} açılamadı: {err}");
            }
            warn!(device = %dev_path, %err,
                "donanım watchdog yok; yalnız systemd yazılım watchdog'u beslenecek (dev/QEMU modu)");
            None
        }
    };

    // Besleme aralığı DAİMA efektif timeout'un yarısının altında olmalı: aksi halde
    // (ör. INTERVAL=30, TIMEOUT=2) sağlıklı bir cihaz beslenmeden önce donanım süresi
    // dolar ve sistem gereksiz yere reset atar. Efektif timeout = donanımın uyguladığı
    // değer; yoksa (dev/QEMU) istenen timeout.
    let effective_timeout = applied_timeout_secs.unwrap_or(timeout_secs).max(1) as u64;
    let max_interval = (effective_timeout / 2).max(1);
    let interval_secs = match interval_pref {
        Some(req) => {
            let clamped = req.clamp(1, max_interval);
            if req > max_interval {
                warn!(
                    requested = req,
                    applied = clamped,
                    effective_timeout,
                    "besleme aralığı efektif timeout'un yarısına kısıtlandı"
                );
            }
            clamped
        }
        None => (effective_timeout / 3).clamp(1, max_interval),
    };

    // İlk kick + systemd Ready. Ready'i cihazı açıp beslemeye HAZIR olduktan sonra
    // gönderiyoruz ki systemd hazır sinyalini gerçekten güvenilir bir noktada alsın.
    if let Some(dev) = hw_dev.as_mut() {
        kick(dev).context("ilk watchdog kick başarısız")?;
    }
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);

    let mut term = signal(SignalKind::terminate()).context("SIGTERM handler kurulamadı")?;
    let mut intr = signal(SignalKind::interrupt()).context("SIGINT handler kurulamadı")?;
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut consecutive_fail: u64 = 0;
    info!(
        interval_secs,
        timeout_secs,
        health = health_unit.as_deref().unwrap_or("kapalı"),
        "watchdog besleme döngüsü başladı"
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // 1) Health değerlendirmesi (opsiyonel). Sağlıksızsa kademeli
                //    müdahale; reboot eşiğinde donanım watchdog'u BESLEMEYİ KESERİZ.
                if let Some(unit) = &health_unit {
                    // Sağlık probu ve systemctl çağrıları zaman-sınırlı çalışır: wedge
                    // olmuş bir systemctl/dbus (D-state, dbus hang) besleme döngüsünü
                    // aç bırakıp SAĞLIKLI cihazı donanım reset'ine sürükleyemesin. Prob
                    // zaman aşımına uğrarsa bu tick'in sağlık hükmü atlanır (sayaca
                    // dokunulmaz) ve watchdog beslenmeye devam eder.
                    let probe_budget = Duration::from_secs(interval_secs.max(1));
                    match tokio::time::timeout(probe_budget, unit_is_active(unit)).await {
                        Err(_) => warn!(%unit, "sağlık probu zaman aşımına uğradı; bu tick atlanıyor"),
                        Ok(true) => {
                            if consecutive_fail > 0 {
                                info!(%unit, "sağlık geri geldi; sayaç sıfırlandı");
                            }
                            consecutive_fail = 0;
                        }
                        Ok(false) => {
                            consecutive_fail += 1;
                            warn!(%unit, consecutive_fail, "izlenen unit sağlıksız");
                            if consecutive_fail == restart_after {
                                warn!(%unit, "restart eşiği aşıldı; systemctl restart");
                                let _ = tokio::time::timeout(probe_budget, systemctl("restart", unit)).await;
                            }
                            if consecutive_fail >= reboot_after {
                                error!(%unit, consecutive_fail,
                                    "reboot eşiği aşıldı; watchdog beslemesi kesiliyor → donanım reset");
                                if hw_dev.is_some() {
                                    // Magic-close YAZMADAN çık: donanım watchdog süresi
                                    // dolunca kernel tüm sistemi resetler (fail-safe).
                                    std::mem::forget(hw_dev.take());
                                    return Ok(());
                                }
                                // Donanım watchdog yoksa (dev) yazılım tarafında reboot iste.
                                let _ = tokio::time::timeout(probe_budget, systemctl("reboot", unit)).await;
                            }
                        }
                    }
                }

                // 2) Kernel/systemd watchdog besle. Sağlıksızlık reboot eşiğine
                //    ulaşmadıysa sistemi ayakta tutmak için beslemeye devam ederiz.
                if let Some(dev) = hw_dev.as_mut() {
                    if let Err(err) = kick(dev) {
                        error!(%err, "watchdog kick başarısız");
                    }
                }
                let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
            }
            _ = term.recv() => { info!("SIGTERM alındı; temiz kapanış"); break; }
            _ = intr.recv() => { info!("SIGINT alındı; temiz kapanış"); break; }
        }
    }

    if let Some(dev) = hw_dev.take() {
        magic_close(dev);
    }
    Ok(())
}

# suderra-watchdog

Hardware watchdog + uygulama health monitor.

## İki Kademe

### 1. Kernel Watchdog

`/dev/watchdog` device. Bu daemon periyodik olarak (`SUDERRA_WATCHDOG_INTERVAL_SECS`,
varsayılan `timeout/3`) `write()` ile kernel'a heartbeat gönderir ve açılışta
`WDIOC_SETTIMEOUT` ile donanım timeout'unu ayarlar (varsayılan 60sn). Daemon ölür,
beslemeyi keser veya sistem donarsa → kernel timeout sonunda tüm sistemi resetler.

Temiz kapanışta (SIGTERM/SIGINT) cihaza magic-close (`V`) yazılır; böylece planlı
restart sistemi resetlemez. `/dev/watchdog` yoksa dev/QEMU'da yalnız systemd yazılım
watchdog'u (`WATCHDOG=1`) beslenir; `SUDERRA_WATCHDOG_REQUIRE_HW=1` ile bu durum
fail-closed yapılabilir.

**Neden:** Kernel panic + bazı driver donmaları systemd-watchdog'u tetiklemez.
Hardware watchdog son savunma hattıdır.

### 2. Uygulama Health Check (opsiyonel)

`SUDERRA_WATCHDOG_HEALTH_UNIT` ayarlıysa izlenen systemd unit'in sağlığı
`systemctl is-active --quiet` ile her tick'te kontrol edilir:

- `SUDERRA_WATCHDOG_RESTART_AFTER` (varsayılan 3) ardışık fail → `systemctl restart <unit>`
- `SUDERRA_WATCHDOG_REBOOT_AFTER` (varsayılan 10) ardışık fail → watchdog **beslemesi
  kesilir**; donanım watchdog süresi dolunca kernel tüm cihazı resetler (fail-safe).
  Donanım watchdog yoksa `systemctl reboot` çağrılır.

Sağlık geri gelirse sayaç sıfırlanır ve besleme normal sürer.

## Ayarlar (env)

| Env | Varsayılan | Açıklama |
|---|---|---|
| `SUDERRA_WATCHDOG_DEV` | `/dev/watchdog` | watchdog karakter aygıtı |
| `SUDERRA_WATCHDOG_TIMEOUT_SECS` | `60` | donanım timeout (2–3600) |
| `SUDERRA_WATCHDOG_INTERVAL_SECS` | `timeout/3` | besleme aralığı (≥1) |
| `SUDERRA_WATCHDOG_HEALTH_UNIT` | (boş) | izlenecek systemd unit; boşsa health kapalı |
| `SUDERRA_WATCHDOG_RESTART_AFTER` | `3` | restart eşiği |
| `SUDERRA_WATCHDOG_REBOOT_AFTER` | `10` | reboot eşiği |
| `SUDERRA_WATCHDOG_REQUIRE_HW` | `0` | `1` ise donanım watchdog zorunlu |

## systemd Unit (örnek)

```ini
[Unit]
Description=Suderra hardware + app watchdog
[Service]
Type=notify
ExecStart=/usr/bin/suderra-watchdog
Environment=SUDERRA_WATCHDOG_TIMEOUT_SECS=60
Environment=SUDERRA_WATCHDOG_HEALTH_UNIT=suderra-agent.service
Restart=always
# systemd yazılım watchdog'u; daemon WATCHDOG=1 forward eder.
WatchdogSec=30s
DeviceAllow=/dev/watchdog rw
CapabilityBoundingSet=CAP_SYS_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
```

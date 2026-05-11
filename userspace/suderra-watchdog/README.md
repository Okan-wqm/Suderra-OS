# suderra-watchdog

Hardware watchdog + uygulama health monitor.

## İki Kademe

### 1. Kernel Watchdog

`/dev/watchdog` device. Bu daemon her ~5sn `write()` ile kernel'a heartbeat
gönderir. Daemon ölürse veya kernel donarsa → kernel ~60sn sonra reboot.

**Neden:** Kernel panic + bazı driver donmaları systemd-watchdog'u
tetiklemiyor. Hardware watchdog son savunma hattı.

### 2. Uygulama Health Check

Edge Agent + diğer Suderra daemon'ları için periyodik kontrol:

- HTTP `/health` endpoint (varsa)
- systemd unit status (`active`?)
- Memory/CPU usage threshold

Politika:

- 3 ardışık fail → `systemctl restart <unit>`
- 10 fail → tüm cihaz reboot
- Telemetry'e alert

## Faz

Faz 5 (operasyonel olgunluk) ile birlikte tam implementasyon.

## systemd Unit (örnek, Faz 5'te eklenir)

```ini
[Unit]
Description=Suderra hardware + app watchdog
[Service]
Type=notify
ExecStart=/usr/bin/suderra-watchdog
Restart=always
WatchdogSec=30s
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
```

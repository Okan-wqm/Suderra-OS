# Cihaz Debug — Suderra OS

> **Status:** Skeleton.

## Felsefe

Production cihazda **SSH yok, shell yok, debugger yok**. Bu kasıtlı bir tasarım kararı (saldırı yüzeyi azaltma).

Debug yolları:

1. **Serial console** (UART) — sadece fiziksel erişim ile
2. **Remote telemetry** (journald → upstream syslog) — uzaktan
3. **Crash dumps** (kernel panic → upstream) — uzaktan
4. **Dev variant** (SSH açık, sadece geliştirme)

## Serial Console

Hardware:

- x86 endüstriyel PC: çoğunda DB9 veya RJ45 serial
- ARM SBC: GPIO UART (USB-TTL adaptör)

Bağlantı:

```bash
sudo screen /dev/ttyUSB0 115200
# veya
sudo minicom -D /dev/ttyUSB0 -b 115200
```

Boot'tan itibaren tüm kernel + systemd log'ları akar. `journalctl -f` ile devam et.

## Cihazda Komutlar (sadece dev variant)

```bash
# Service durum
systemctl status suderra-edge-agent

# Log akışı
journalctl -u suderra-edge-agent -f

# Boot süresi
systemd-analyze
systemd-analyze blame
systemd-analyze critical-chain suderra-edge-agent.service

# Network
ss -tulpn                    # Açık portlar
ip addr                      # Interface'ler
nft list ruleset             # Firewall

# Storage
df -h                        # Disk kullanımı
mount | grep ro              # Read-only mount'lar
findmnt -t ext4              # Encrypted /data

# Process
ps -eo pid,user,comm,wchan
top -bn1

# Edge agent runtime
curl -k https://localhost:8080/health    # Eğer health endpoint açıksa
```

## Remote Telemetry (Faz 5)

journald → rsyslog → upstream (cloud):

- log shipping interval: 1-5 sn
- buffering: 50 MB local (network down olursa)
- format: JSON structured

Cloud tarafında:

- Grafana Loki / ELK / Datadog
- Dashboard: app health, system metrics, error rate

## Crash Dumps (Faz 5)

Kernel panic veya app crash:

1. Kernel: `pstore` ile RAM → reboot sonrası dosya
2. App: systemd `coredump` (yalnız dev), upstream rapor (prod)
3. Otomatik upload: `suderra-crashreport` service

## Yaygın Sorunlar

### Cihaz boot etmiyor (siyah ekran)

1. Serial console aç
2. UEFI POST mesajları görünüyor mu? → BIOS settings, secure boot
3. Bootloader mesajı? → boot order, USB
4. Kernel mesajı? → cmdline, dm-verity hash
5. systemd? → emergency.target

### Edge agent başlamıyor

```bash
journalctl -u suderra-edge-agent --since "1 hour ago"
systemctl status suderra-edge-agent
# Yaygın: TLS cert path, config syntax, port çakışması
```

### Update başarısız

```bash
rauc status
journalctl -u rauc
# Bundle imza, network, disk alanı
```

## Production'da Debug Erişim

Mümkün değil (kasıtlı). Süreç:

1. Cihaz fiziksel olarak alınır (RMA)
2. Lab ortamında dev variant ile boot edilir
3. /data partition decrypt edilir (TPM bypass debug key ile)
4. Forensic analiz

## Yapılacaklar

- [ ] Serial console baudrate dokümantasyonu hardware başına
- [ ] Crash dump pipeline (Faz 5)
- [ ] Remote diagnostic mode (zaman-sınırlı SSH, mTLS, Faz 5+)

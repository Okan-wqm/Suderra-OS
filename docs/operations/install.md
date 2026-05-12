# Suderra OS Kurulum Rehberi

> **Hedef kitle:** Saha mühendisleri, sistem entegratörleri, DevOps ekipleri.
> **Önkoşul yok** — temiz bir laptop + hedef hardware yeterli.

Bu rehber **sıfırdan başlayıp** çalışan bir Suderra OS + Edge Agent kurulumuna ulaştırır. Üç bölüm:

1. [Hızlı Başlangıç (TL;DR)](#1-hızlı-başlangıç-tldr) — 10 dakikada
2. [Raspberry Pi 4 / CM4 detaylı](#2-raspberry-pi-4--cm4) — adım adım
3. [Endüstriyel x86 PC](#3-endüstriyel-x86-pc) — UEFI sistemler
4. [Revolution Pi](#4-revolution-pi) — endüstriyel CM4
5. [Edge Agent kurulumu](#5-edge-agent-kurulumu) — OS sonrası
6. [Sorun Giderme](#6-sorun-giderme)

---

## 1. Hızlı Başlangıç (TL;DR)

**Raspberry Pi 4 için:**

```bash
# 1. Image indir + doğrula (GitHub Releases)
wget https://github.com/Okan-wqm/suderra-os/releases/latest/download/suderra-os-rpi4.img.xz
wget https://github.com/Okan-wqm/suderra-os/releases/latest/download/suderra-os-rpi4.img.xz.sha256
sha256sum -c suderra-os-rpi4.img.xz.sha256

# 2. SD karta yaz (Suderra repo'nun script'i — güvenlik kontrolü dahil)
sudo ./scripts/flash-sd.sh /dev/sdX suderra-os-rpi4.img.xz

# 3. SD'yi Pi'ye tak, güç ver — boot ~30 saniye

# 4. SSH ile bağlan (default: suderra/suderra — DEV variant)
ssh suderra@suderra-rpi4.local
# veya IP ile: ssh suderra@<pi-ip>

# 5. Edge Agent kur
sudo suderra-installer install edge --version 1.6.0

# 6. Çalıştığını doğrula
systemctl status suderra-edge-agent
```

İşte bu kadar. Detaylar için aşağı bak.

---

## 2. Raspberry Pi 4 / CM4

### 2.1. Donanım Gereksinimleri

| Bileşen | Minimum | Önerilen |
|---|---|---|
| **Board** | Pi 4 Model B 2GB | Pi 4 4GB / CM4 4GB+ |
| **Storage** | 8 GB Class 10 SD | 16+ GB A2-rated microSD veya CM4 eMMC |
| **Güç** | 5V/3A USB-C | Endüstriyel 5V/3A regülatörlü |
| **Soğutma** | Pasif heatsink | Kabin + fan (CM4) |
| **Network** | Ethernet 100M | Ethernet 1G + opsiyonel WiFi |
| **Kabin** | — | DIN rail IP54+ (endüstriyel) |

**CM4 için ek:**
- Carrier board (CM4 IO Board veya custom)
- WiFi/Bluetooth disabled için non-W variant tercih
- Endüstriyel uygulamalar için **CM4002032** (Lite + 32GB eMMC, no WiFi)

**Detaylı hardware seçimi:** [docs/hardware/rpi4-cm4.md](../hardware/rpi4-cm4.md)

### 2.2. Image İndirme

**Seçenek A: GitHub Releases (önerilen)**

```bash
# Latest release URL'i
URL_BASE="https://github.com/Okan-wqm/suderra-os/releases/latest/download"

# Image + checksum + signature
wget "${URL_BASE}/suderra-os-rpi4.img.xz"
wget "${URL_BASE}/suderra-os-rpi4.img.xz.sha256"
wget "${URL_BASE}/suderra-os-rpi4.img.xz.sig"      # cosign signature
```

**Seçenek B: Mirror (releases.suderra.com)**

```bash
# Daha hızlı CDN, aynı içerik (cosign ile aynı imza)
URL_BASE="https://releases.suderra.com/os/latest"
wget "${URL_BASE}/suderra-os-rpi4.img.xz"
# ... aynı şekilde
```

**Seçenek C: Lokal build (geliştiriciler için)**

```bash
git clone --recurse-submodules https://github.com/Okan-wqm/suderra-os
cd suderra-os
./scripts/build-in-docker.sh suderra_aarch64_rpi4_defconfig
# Çıktı: output/suderra_aarch64_rpi4_defconfig/images/suderra-rpi4-target.img.xz
# Süre: ~30-60 dk (ilk build), ~5-10 dk (sonraki)
```

### 2.3. Image Doğrulama

**SHA256 kontrolü (zorunlu):**

```bash
sha256sum -c suderra-os-rpi4.img.xz.sha256
# Çıktı: suderra-os-rpi4.img.xz: OK
```

**cosign keyless signature (önerilen, supply chain güvenliği):**

```bash
# cosign kur (one-time)
curl -sSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
  -o /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# Doğrula
cosign verify-blob \
  --certificate-identity-regexp "https://github.com/Okan-wqm/suderra-os" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature suderra-os-rpi4.img.xz.sig \
  suderra-os-rpi4.img.xz
# Çıktı: Verified OK
```

### 2.4. SD Karta Yazma

**Yöntem 1: Suderra flash-sd.sh (önerilen — güvenli)**

```bash
# Önce SD card cihazını bul
lsblk
# Örnek çıktı: sdb     1   29.7G  0 disk
#              └─sdb1  1    1.0G  0 part

# Yaz (güvenlik kontrolü + hash doğrulama + readback verify)
sudo ./scripts/flash-sd.sh /dev/sdb suderra-os-rpi4.img.xz

# Veya signature doğrulamalı:
sudo ./scripts/flash-sd.sh --verify-signature /dev/sdb suderra-os-rpi4.img.xz
```

`flash-sd.sh` şunları otomatik yapar:
- ✅ Root disk koruma (sabit diske yazmaz)
- ✅ Mount unmount
- ✅ SHA256 doğrulama
- ✅ xz açma
- ✅ dd + sync
- ✅ Geri okuma doğrulaması (ilk 64 MiB hash)

**Yöntem 2: Raspberry Pi Imager**

1. https://rpi.com/imager indir + kur
2. "Choose OS" → "Use custom image" → `suderra-os-rpi4.img.xz`
3. "Choose Storage" → SD card seç
4. Write

**Yöntem 3: Manuel dd (gelişmiş kullanıcılar)**

```bash
xz -d suderra-os-rpi4.img.xz
sudo dd if=suderra-os-rpi4.img of=/dev/sdb bs=4M conv=fsync status=progress
sync
```

⚠ `of=/dev/sdb` yerine YANLIŞ cihaz yazarsan sabit diskini siler. `lsblk` ile doğrula.

### 2.5. İlk Boot

1. **SD'yi Pi'ye tak.**
2. **Network kablosu bağla** (DHCP ile IP alır).
3. **Güç ver.**
4. **HDMI veya seri konsoldan boot logu izle:**
   - Seri konsol: GPIO14 (TX) / GPIO15 (RX), 115200 baud
   - USB-Serial adapter ile bağlan: `screen /dev/ttyUSB0 115200`
5. **~30 saniyede login prompt:**
   ```
   Suderra OS — Industrial Edge (Raspberry Pi 4 / CM4)
   suderra-rpi4 login: _
   ```

### 2.6. Network & SSH

**mDNS ile bul:**

```bash
ping suderra-rpi4.local
ssh suderra@suderra-rpi4.local
```

**IP üzerinden:**

```bash
# Router DHCP listesinde MAC adresine göre bul
# veya seri konsolda:
ip addr show eth0
ssh suderra@192.168.1.xxx
```

**Default kimlik bilgileri (DEV variant):**

| User | Password | Notlar |
|---|---|---|
| `root` | `suderra` | SSH login pasif (sadece konsol) |
| `suderra` | `suderra` | sudo NOPASSWD, SSH login aktif |

⚠ **Production'da:** İlk login sonrası `passwd` ile değiştir. PROD variant'larda password login devre dışı, sadece SSH key.

### 2.7. Sonraki Adım

Edge Agent kurulumu → [§5 Edge Agent kurulumu](#5-edge-agent-kurulumu)

---

## 3. Endüstriyel x86 PC

### 3.1. Donanım

Önerilen platformlar:
- **Advantech UNO-2271G** (Atom x6413E, TPM 2.0, dual eth)
- **Siemens SIMATIC IPC227G** (i3/i5, endüstriyel)
- **Kontron KBox A-150-APL** (DIN rail, fanless)
- **Generic x86 mini-PC** (test için yeterli)

Gereksinimler:
- UEFI firmware (Legacy BIOS desteklemez)
- TPM 2.0 (Faz 3 dm-verity için)
- 4+ GB RAM, 16+ GB SSD/eMMC
- 1+ Ethernet port

### 3.2. Image İndirme

```bash
URL_BASE="https://github.com/Okan-wqm/suderra-os/releases/latest/download"
wget "${URL_BASE}/suderra-os-x86_64.img.xz"
wget "${URL_BASE}/suderra-os-x86_64.img.xz.sha256"
wget "${URL_BASE}/suderra-os-x86_64.img.xz.sig"
```

### 3.3. USB Stick'e Yazma

```bash
# USB stick (8+ GB, hızlı USB 3.0 önerilen)
sudo ./scripts/flash-sd.sh --verify-signature /dev/sdc suderra-os-x86_64.img.xz
```

veya Rufus / balenaEtcher (Windows/Mac).

### 3.4. Boot

1. USB stick'i hedef PC'ye tak.
2. BIOS/UEFI'ye gir (F2/F12/DEL — vendor'a göre değişir).
3. Boot order'da USB stick'i öne al.
4. Boot.
5. GRUB menüsü → "Suderra OS" seç (default).
6. ~10 saniyede login prompt.

### 3.5. Kalıcı Kurulum (USB → eMMC/SSD)

İlk boot canlı USB'den. eMMC/SSD'ye kalıcı kurulum:

```bash
# Pi 4'teki SD-to-eMMC migration ile aynı mantık:
suderra-installer install os --target /dev/nvme0n1
# (Faz 2-D'de gelecek)
```

Şu an manuel:

```bash
# USB üzerindeyken, eMMC/SSD'ye dd:
sudo dd if=/dev/sdb of=/dev/nvme0n1 bs=4M status=progress
# Reboot, USB çıkar, eMMC'den boot
```

---

## 4. Revolution Pi

> **Status:** Faz 2-B (yakında). Şu an Pi 4 / CM4 image'i Revolution Pi üzerinde de çalışır ama RevPi-spesifik GPIO/IO modülleri henüz aktif değil.

Bu bölüm Faz 2-B tamamlandığında doldurulacak.

---

## 5. Edge Agent Kurulumu

OS boot ettikten sonra Edge Agent **ayrı** kurulur — Ubuntu mantığında.

### 5.1. Suderra Installer ile (önerilen)

```bash
# Edge Agent en son sürümünü kur
sudo suderra-installer install edge

# Belirli sürüm
sudo suderra-installer install edge --version 1.6.0

# Çıktı:
#   ✓ Downloading suderra-edge-agent-v1.6.0-aarch64.raucb (4.2 MB)
#   ✓ Verifying cosign signature (keyless, GitHub Actions)
#   ✓ Verifying SHA256 checksum
#   ✓ Extracting SBOM (CycloneDX 1.6)
#   ✓ Installing to /opt/suderra/edge/
#   ✓ Audit log: /var/log/suderra/installer.log
#   ✓ systemd unit enabled (suderra-edge-agent.service)
#   ✓ Reboot? [Y/n]: _
```

### 5.2. Curl|sh ile (Ubuntu tarzı)

```bash
curl -fsSL https://get.suderra.com | sudo sh
```

Bu komut:
1. Mimari + OS sürümünü tespit eder
2. `suderra-installer install edge` çağırır
3. Hata raporu verir

### 5.3. Manuel (air-gapped / offline)

```bash
# Başka makinede indir
wget https://releases.suderra.com/edge/latest/suderra-edge-agent-aarch64.raucb
wget https://releases.suderra.com/edge/latest/suderra-edge-agent-aarch64.raucb.sig

# USB ile Pi'ye taşı, sonra:
sudo suderra-installer install edge \
  --from-file suderra-edge-agent-aarch64.raucb \
  --signature suderra-edge-agent-aarch64.raucb.sig
```

### 5.4. Konfigürasyon

```bash
# Edit config
sudo $EDITOR /etc/suderra/edge.toml

# Apply
sudo systemctl restart suderra-edge-agent
```

Konfigürasyon detayları: [docs/operations/runbook.md](runbook.md)

### 5.5. Doğrulama

```bash
# Service durumu
systemctl status suderra-edge-agent

# Log
journalctl -u suderra-edge-agent -f

# Health endpoint (lokal)
curl http://localhost:9090/health

# Metric (Prometheus)
curl http://localhost:9090/metrics
```

### 5.6. Update

Suderra Edge Agent OS'tan **bağımsız** güncellenir:

```bash
# Yeni sürümler arama
suderra-installer list edge --available

# Update
sudo suderra-installer upgrade edge

# Rollback (önceki versiyon)
sudo suderra-installer rollback edge
```

---

## 6. Sorun Giderme

### 6.1. Pi boot etmiyor

**Belirti:** Pi LED'i yanıyor ama HDMI siyah, network yok.

**Sebep + Çözüm:**

| Belirti | Sebep | Çözüm |
|---|---|---|
| Sarı LED hızlı yanıp sönüyor | SD card okunamıyor | Yeniden yaz, başka SD dene |
| Sarı LED 4 kez yanıp duruyor | start4.elf bulunamadı | Image bozuk — yeniden indir |
| Yeşil LED yok | Güç yetersiz | 5V/3A güç adaptörü kullan |
| Boot başlıyor, hang | Kernel panic | Seri konsoldan logu izle |

**Seri konsol bağlantısı (Pi 4):**

| Pi GPIO | USB-Serial | İşlev |
|---|---|---|
| GPIO 14 (Pin 8) | RX | TX (Pi'den USB'ye) |
| GPIO 15 (Pin 10) | TX | RX (USB'den Pi'ye) |
| GND (Pin 6) | GND | Toprak |

```bash
# Linux/Mac:
screen /dev/ttyUSB0 115200
# veya minicom -D /dev/ttyUSB0 -b 115200

# Windows:
# PuTTY → Serial → COMx → 115200
```

### 6.2. Network bağlanmıyor

```bash
# eth0 link durumu
ip link show eth0

# DHCP cevap aldı mı?
journalctl -u systemd-networkd -b

# Manuel test
ip addr add 192.168.1.50/24 dev eth0
ip link set eth0 up
ping 192.168.1.1
```

### 6.3. SSH bağlanmıyor

```bash
# Seri konsoldan
systemctl status sshd
ss -tlnp | grep :22
```

### 6.4. Edge Agent başlamıyor

```bash
journalctl -u suderra-edge-agent -b
ls -la /etc/suderra/
cat /var/log/suderra/installer.log
```

### 6.5. Sıkışıp kaldıysan — factory reset

```bash
# Pi: SD'yi PC'ye tak, sil + yeniden yaz
# x86: USB'den boot et, eMMC'yi yeniden flash et
```

Detaylı: [docs/operations/factory-reset.md](factory-reset.md)

---

## Yardım

- **Issue:** https://github.com/Okan-wqm/suderra-os/issues
- **Discussions:** https://github.com/Okan-wqm/suderra-os/discussions
- **Docs:** https://docs.suderra.example/ (yakında)

## Bir Sonraki

- [Runbook (operasyon)](runbook.md)
- [OTA güncelleme](ota.md)
- [Debug rehberi](debug.md)
- [Hardware seçimi](../hardware/rpi4-cm4.md)
- [Mimari](../architecture/ARCHITECTURE.md)

# Image Flashing — Teknik Detaylar

> **Hızlı başlangıç için:** [install.md](install.md). Bu döküman flash sürecinin
> teknik detaylarını + production scenario'larını anlatır.

## 1. Suderra flash-sd.sh — Önerilen Yöntem

`scripts/flash-sd.sh` enterprise-grade flash wrapper'ı. Sadece `dd` çağırmaz —
güvenlik kontrolleri yapar.

### Özellikler

| Kontrol | Açıklama |
|---|---|
| Root yetki kontrolü | sudo zorunlu |
| Root disk koruma | `/` mount edilen disk'e yazmaz |
| Removable kontrolü | `/sys/block/.../removable` doğrular |
| Mount unmount | Açık partition'ları otomatik kapatır |
| SHA256 doğrulama | `MANIFEST.txt` veya `.sha256` dosyasından |
| cosign signature | `--verify-signature` ile keyless verify |
| xz auto-decompress | `.img.xz` doğrudan çalışır |
| Readback verify | İlk 64 MiB geri okunup hash kontrol |
| Progress indicator | dd `status=progress` + süre raporu |

### Kullanım

```bash
# Temel
sudo ./scripts/flash-sd.sh /dev/sdX <image.img[.xz]>

# Signature doğrulama (production releases için)
sudo ./scripts/flash-sd.sh --verify-signature /dev/sdX <image>

# CI / scripting (onay sormaz)
sudo ./scripts/flash-sd.sh --force /dev/sdX <image>

# Hızlı (readback verify atla — önerilmez)
sudo ./scripts/flash-sd.sh --skip-verify /dev/sdX <image>
```

## 2. Platform-Spesifik Flashing

### 2.1. Raspberry Pi 4 / CM4 — SD Card

```bash
# SD card'ı bul (yeni takılı USB SD reader)
lsblk

# Yaz
sudo ./scripts/flash-sd.sh /dev/sdb \
  output/suderra_aarch64_rpi4_defconfig/images/sdcard.img.xz
```

**Image layout (SD card):**
- Partition 1 (vfat, 256MB, bootable): `/boot` — Pi firmware + kernel + DTB
- Partition 2 (ext4, ~512MB): `/` — Suderra OS root

### 2.2. CM4 eMMC — USB OTG

CM4 modülünün eMMC'sine doğrudan yazma (Pi 4 ile yapılır):

```bash
# Pi 4 (host) üzerinde:
sudo apt install -y rpiboot pkg-config libusb-1.0-0-dev
git clone https://github.com/raspberrypi/usbboot
cd usbboot
make
sudo ./rpiboot
# CM4 USB OTG ile bağlandı, eMMC /dev/sdX olarak görünür

# Suderra OS image'i yaz
sudo /path/to/Suderra-OS/scripts/flash-sd.sh /dev/sdX sdcard.img.xz
```

CM4 IO Board üzerinde:
1. Jumper J2 set et (USB boot mode)
2. USB-C kabloyu host PC'ye bağla
3. CM4'e güç ver
4. `rpiboot` çalıştır

### 2.3. Endüstriyel x86 PC — USB Stick

```bash
# 8+ GB USB stick (USB 3.0 önerilen)
sudo ./scripts/flash-sd.sh /dev/sdc \
  output/suderra_x86_64_defconfig/images/disk.img.xz
```

**Image layout (x86):**
- EFI partition (vfat, 512MB): GRUB EFI + boot config
- Root partition (ext4): Suderra OS root
- Swap (Faz 3'te eklenecek): zram (RAM-based)

**BIOS/UEFI ayarları:**
- Boot mode: UEFI (Legacy değil)
- Secure Boot: Disabled (Faz 3'te enable)
- USB boot: Enabled
- Boot order: USB → SSD/eMMC

### 2.4. PXE/iPXE Network Boot (Faz 4+)

Toplu deployment için. Şu an dokümante edilmedi — Faz 4'te:

```
[DHCP server] → 'next-server' = PXE TFTP server
[Client PXE] → iPXE → HTTP boot → Suderra OS netinstall
```

### 2.5. Factory Programming (Faz 5+)

Üretim hattında otomatik:
- Robot SD insertion
- Image flash + serial number burn
- Doğrulama: boot test + factory cert installation
- Pre-provisioned firstboot config

## 3. Doğrulama

### 3.1. Flash sonrası kontrol listesi

```bash
# 1. SD/USB güvenli çıkar (write cache flush)
sync && sudo eject /dev/sdb

# 2. Hedef cihaza tak, güç ver

# 3. Boot logu izle:
#    - HDMI: ekran kabloyu varsa
#    - Seri konsol: USB-Serial adapter (GPIO14/15)
screen /dev/ttyUSB0 115200

# 4. Login prompt:
#    "Suderra OS — Industrial Edge (Raspberry Pi 4 / CM4)"
#    "suderra-rpi4 login: _"

# 5. Kimlik doğrula (DEV variant):
suderra-rpi4 login: suderra
Password: suderra

# 6. Sistem kontrolü:
$ cat /etc/os-release         # VERSION_ID
$ uname -r                    # 6.12.6
$ systemctl is-system-running # running veya degraded (Edge Agent yoksa normal)
$ journalctl -b 0 -p err      # boot error'ları
$ ip addr                     # network
```

### 3.2. Hash mismatch debugging

```bash
# Image hash hesapla
sha256sum sdcard.img.xz

# Beklenen hash (release'tan):
cat sdcard.img.xz.sha256

# Eşleşmiyorsa: indirme bozuk, yeniden indir
wget -c <url>  # resume download
```

### 3.3. SD card health

Bozuk SD card boot fail'ın #1 sebebi. Test:

```bash
# Linux'ta read/write speed test
sudo dd if=/dev/sdb of=/dev/null bs=4M count=256 status=progress
# A1 SD: >30 MB/s, A2: >40 MB/s. Düşükse SD bozuk veya counterfeit.

# Boot sonrası Pi üzerinde:
sudo dmesg | grep mmc       # SD timeout/CRC error
journalctl -k | grep mmcblk # SD I/O error
```

## 4. Sorun Giderme

### 4.1. "Device not found"

```bash
# USB readers bazen ısrarcı — physically yeniden tak
dmesg | tail -20             # yeni cihaz görünüyor mu?
lsblk -f                     # mevcut tüm bloklar
```

### 4.2. "Device or resource busy" (dd çalışırken)

```bash
# Cihaz hala mount: explicit unmount
sudo umount /dev/sdb1 /dev/sdb2 2>/dev/null || true
sudo udevadm settle
```

### 4.3. dd çok yavaş

```bash
# bs çok küçük olabilir
sudo dd ... bs=4M  # Test: 1M, 4M, 8M, 16M

# USB 2.0 reader kullanıyorsan → USB 3.0 reader'a geç (5-10x hızlı)
```

### 4.4. Flash başarılı ama boot etmiyor

Bkz: [install.md §6 Sorun Giderme](install.md#6-sorun-giderme)

## 5. Production Workflow

### 5.1. Field Update (yerinde manuel flash)

OS'u tamamen yeniden flash etmek nadir — RAUC OTA tercih edilir. Ama
catastrophic recovery için:

```
1. Saha mühendisi USB stick'i yanına alır
2. Cihazı kapat, SD'yi çıkar
3. Laptop'a tak, flash et
4. SD'yi tak, cihazı aç
5. firstboot.service /data partition'ını yeniden oluşturur
6. Eski device certificates kaybolur — re-provisioning gerekir
```

### 5.2. Bulk Initial Provisioning

Aynı image 100+ cihaza yazılır:

```bash
# 10x SD card hub kullanarak paralel
# veya factory programming station
for sd in /dev/sd{b..k}; do
    sudo ./scripts/flash-sd.sh --force "${sd}" sdcard.img.xz &
done
wait
```

## 6. Mevcut Script'ler

| Script | Durum | Hedef |
|---|---|---|
| `scripts/flash-sd.sh` | ✅ Aktif | SD card / USB stick (Pi, x86, RevPi) |
| `scripts/flash-emmc.sh` | ⏳ Faz 2-A.2 | rpiboot + USB OTG (CM4 eMMC) |
| `scripts/flash-pxe.sh` | ❌ Faz 4 | PXE/iPXE network boot |
| `scripts/flash-factory.sh` | ❌ Faz 5 | Factory programming (robot) |

## 7. İlgili Dokümanlar

- [Kurulum rehberi](install.md) — Adım adım kullanıcı senaryosu
- [Hardware seçimi](../hardware/rpi4-cm4.md) — Pi 4 / CM4 BOM
- [Factory reset](factory-reset.md) — Sıfırlama prosedürü
- [OTA güncelleme](ota.md) — RAUC bundle update (Faz 4)

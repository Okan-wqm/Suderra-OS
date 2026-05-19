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
| cosign signature | `--verify-signature` ile `.sig` + `.cert` keyless verify |
| xz auto-decompress | `.img.xz` doğrudan çalışır |
| Readback verify | İlk 64 MiB geri okunup hash kontrol |
| Acceptance mode | `--acceptance` yalnız `/dev/disk/by-id/*` whole-disk hedeflerini kabul eder ve signature/full-readback doğrulamasını zorunlu kılar |
| Progress indicator | dd `status=progress` + süre raporu |

### Kullanım

```bash
# Temel
sudo ./scripts/flash-sd.sh /dev/sdX <image.img[.xz]>

# Signature doğrulama (production releases için; <image>.sig ve <image>.cert gerekir)
sudo ./scripts/flash-sd.sh --verify-signature /dev/sdX <image>

# LAB ONLY: hash dosyası olmayan geçici imajlar
sudo ./scripts/flash-sd.sh --lab-allow-missing-hash /dev/sdX <image>

# Acceptance/lab evidence: stable by-id whole-disk target, signature + full verification
sudo ./scripts/flash-sd.sh --acceptance \
  /dev/disk/by-id/<stable-whole-disk-id> <image.img.xz>

# CI / scripting (onay sormaz)
sudo ./scripts/flash-sd.sh --force /dev/sdX <image>

# Hızlı (readback verify atla — önerilmez)
sudo ./scripts/flash-sd.sh --skip-verify /dev/sdX <image>
```

`--acceptance` is intentionally stricter than operator convenience mode. It
rejects partition targets, non-`/dev/disk/by-id/*` paths, stale decompressed
images beside an `.xz`, `--skip-verify`, and broad `--force`. It also implies
`--verify-signature`, resolves the by-id symlink to the top-level disk before
root/removable checks, and requires full-image readback hashing. The operator
must confirm the stable whole-disk by-id target interactively so lab evidence
records the exact device identity and readback verification path.

## 2. Platform-Spesifik Flashing

### 2.1. Raspberry Pi 4 / CM4 — USB Self-Installer

Factory and field installs use two artifacts:

- `suderra-rpi4-target.img.xz`: the OS image written to SD/eMMC.
- `suderra-pi-cm4-revpi-usb-installer.img.xz`: the USB-booted installer image.

Build order:

```bash
./scripts/gen-dev-keys.sh
export SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY="${HOME}/.suderra-keys/dev/installer-payload.key"
export SUDERRA_INSTALLER_PAYLOAD_PUBKEY="${HOME}/.suderra-keys/dev/installer-payload.ed25519.pub"
export SUDERRA_INSTALLER_PAYLOAD_EXPIRES_AT="2026-12-31T00:00:00Z"
export SUDERRA_INSTALLER_KEY_EPOCH=1

./scripts/build-in-docker.sh suderra_aarch64_rpi4_defconfig
./scripts/build-in-docker.sh suderra_aarch64_revpi4_defconfig
export SUDERRA_RPI4_TARGET_IMAGE_XZ=/workspace/output/suderra_aarch64_rpi4_defconfig/images/suderra-rpi4-target.img.xz
export SUDERRA_REVPI4_TARGET_IMAGE_XZ=/workspace/output/suderra_aarch64_revpi4_defconfig/images/suderra-revpi4-target.img.xz
./scripts/build-in-docker.sh suderra_aarch64_rpi4_usb_installer_defconfig
```

Write the USB installer to a USB stick, boot the Pi/CM4 from it, confirm the
displayed target, then remove the USB stick after poweroff.

Target selection is fail-closed:

- the installer boot disk is excluded
- on-board eMMC is preferred over on-board SD
- removable USB/SATA-style `sd*` disks are refused by default
- multiple equal-priority targets stop the install
- USB targets are refused unless a factory flag explicitly allows them with a
  `/dev/disk/by-id/usb-*` or removable whole-disk path
- a generic Compute Module 4 model string is ambiguous and must fail closed
  unless RevPi-compatible device-tree evidence is present or
  `SUDERRA_INSTALLER_TARGET_BOARD=rpi4-cm4|revpi4` is set with recorded board
  identity evidence

The current USB installer is an alpha/lab provisioning image. Production ARM
requires U-Boot verified boot, signed FIT, immutable cmdline, dm-verity, RAUC
A/B rollback evidence, and production payload keys before promotion.

### 2.2. Raspberry Pi 4 / CM4 — Direct SD Card

```bash
# SD card'ı bul (yeni takılı USB SD reader)
lsblk

# Yaz
sudo ./scripts/flash-sd.sh /dev/sdb \
  output/suderra_aarch64_rpi4_defconfig/images/suderra-rpi4-target.img.xz
```

**Image layout (SD card):**
- Partition 1 (vfat, 256MB, bootable): `/boot` — Pi firmware + kernel + DTB
- Partition 2 (ext4, ~512MB): `/` — Suderra OS root

### 2.3. CM4 eMMC — USB OTG

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
sudo /path/to/Suderra-OS/scripts/flash-sd.sh /dev/sdX suderra-rpi4-target.img.xz
```

CM4 IO Board üzerinde:
1. Jumper J2 set et (USB boot mode)
2. USB-C kabloyu host PC'ye bağla
3. CM4'e güç ver
4. `rpiboot` çalıştır

### 2.4. Revolution Pi Connect 4

RevPi Connect 4 is a separate target:

```bash
./scripts/build-in-docker.sh suderra_aarch64_revpi4_defconfig
sudo ./scripts/flash-sd.sh /dev/sdX \
  output/suderra_aarch64_revpi4_defconfig/images/suderra-revpi4-target.img.xz
```

USB-A self-install is supported when the device boot order allows USB boot.
The official fallback remains micro-USB/rpiboot, where RevPi eMMC appears as
`/dev/sdX` on the host and is flashed with the same target image.

### 2.5. Endüstriyel x86 PC — USB Stick

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

### 2.6. PXE/iPXE Network Boot (Faz 4+)

Toplu deployment için. Şu an dokümante edilmedi — Faz 4'te:

```
[DHCP server] → 'next-server' = PXE TFTP server
[Client PXE] → iPXE → HTTP boot → Suderra OS netinstall
```

### 2.7. Factory Programming (Faz 5+)

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

# 4. Firstboot prints the temporary provision user password on console.
# 5. Tenant provisioning connects as provision@<device-ip>.
# 6. root SSH must fail; provision SSH runs only the forced command.
```

### 3.2. Hash mismatch debugging

```bash
# Image hash hesapla
sha256sum suderra-rpi4-target.img.xz

# Beklenen hash (release'tan):
cat suderra-rpi4-target.img.xz.sha256

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
    sudo ./scripts/flash-sd.sh --force "${sd}" suderra-rpi4-target.img.xz &
done
wait
```

`--force` only skips the interactive prompt. It does not bypass hash checks,
root-disk protection, removable/size guards, or readback verification.

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

# Imaj Flashing

> **Status:** Skeleton — Faz 1 sonunda hardware testleri ile dolar.

## USB Stick Hazırlama (x86_64)

```bash
# DİKKAT: /dev/sdX doğru cihaz mı? `lsblk` ile kontrol et
sudo ./scripts/flash-usb.sh /dev/sdX output/suderra_x86_64_defconfig/images/disk.img
```

`flash-usb.sh` içeriği:
1. Hedef cihaz kontrol (mount edilmiş mi?)
2. `dd if=disk.img of=/dev/sdX bs=4M conv=fsync status=progress`
3. `sync`
4. Doğrulama: ilk 1MB'ı geri oku, hash eşleşmesi

## Endüstriyel Cihaza Yazma (x86_64)

Seçenekler:
1. **USB stick'ten flash** (yukarıdaki) → cihazda BIOS'tan USB boot
2. **Network boot** (PXE/iPXE) — toplu deployment için
3. **eMMC programmer** (factory) — üretim hattında

## ARM SBC Flashing (Pi CM4 / Revolution Pi)

```bash
# RPi Imager veya rpiboot ile
sudo rpiboot
sudo ./scripts/flash-emmc.sh output/suderra_aarch64_defconfig/images/disk.img
```

## Doğrulama

Flash sonrası:
1. Cihazı boot et
2. Seri konsoldan `Suderra OS v0.1.0-alpha` banner görmeli
3. `journalctl -b 0 -u suderra-edge-agent` → READY
4. `cat /etc/os-release` → SUDERRA_VERSION

## Yapılacaklar

- [ ] `scripts/flash-usb.sh` implement (Faz 1)
- [ ] `scripts/flash-emmc.sh` implement (ARM, Faz 1.5)
- [ ] Factory provisioning prosedürü (Faz 5)
- [ ] PXE/iPXE network boot dokümantasyonu

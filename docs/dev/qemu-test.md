# QEMU'da Test

> **Status:** Active. İlk QEMU boot için tam talimatlar (Katman 3).

## Hızlı Test

```bash
# 1. Buildroot submodule güncel mi?
git submodule update --init --recursive

# 2. Build (~30-45 dk ilk seferde)
./scripts/build-in-docker.sh suderra_qemu_x86_64_defconfig

# 3. QEMU'da çalıştır
./scripts/qemu-run.sh

# 4. Otomatik smoke test (CI'da kullanılır)
./tests/qemu/boot-test.sh
```

## Beklenen Davranış

İlk başarılı boot:
```
... (UEFI / GRUB ekranı)
Suderra OS — Industrial Edge

[    0.000000] Linux version 6.12.6 (...) #1 SMP ...
[    0.123456] Command line: console=ttyS0,115200n8 root=/dev/vda1 ro ...
... (kernel boot logları)

Welcome to Suderra OS v0.1.0-alpha!

[ OK ] Reached target Multi-User System.

Suderra OS v0.1.0-alpha suderra ttyS0

suderra login: root
Password: suderra        # DEV variant only
```

## Boot Aşamaları (Beklenen Süre)

| Aşama | Süre | Doğrulama |
|---|---|---|
| QEMU başlatma | <1s | qemu binary çalışır |
| BIOS/UEFI POST | ~2s | Firmware logo veya text |
| GRUB | ~2s | Menüden 0 saniye sonra otomatik boot |
| Kernel + initrd | ~5-10s | "Linux version" + driver init logları |
| systemd init | ~5-15s | "Welcome to Suderra OS" banner |
| systemd target | ~10-30s | "Reached target Multi-User" |
| **Toplam (cold)** | **~30-60s** | login prompt |

## QEMU Komutu (manuel)

```bash
qemu-system-x86_64 \
    -m 512M \
    -smp 2 \
    -drive file=output/suderra_qemu_x86_64_defconfig/images/disk.img,format=raw,if=virtio \
    -nographic \
    -serial mon:stdio \
    -netdev user,id=net0,hostfwd=tcp::5555-:8080 \
    -device virtio-net-pci,netdev=net0 \
    -enable-kvm
```

## QEMU İçinde

```bash
# Boot tamamlandığında:
suderra login: root
Password: suderra      # DEV variant default

# Servis durumu
systemctl status

# Edge agent
journalctl -u suderra-edge-agent -f
```

## TPM Emulation

```bash
# swtpm ile TPM 2.0 emulation
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-state \
    --ctrl type=unixio,path=/tmp/swtpm-sock &

qemu-system-x86_64 \
    -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    ...
```

## UEFI Boot

```bash
qemu-system-x86_64 \
    -bios /usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    ...
```

## QEMU Disk Image Layout

QEMU defconfig `board/suderra/x86_64/genimage-qemu.cfg` ile **tek-rootfs**:

```
disk.img (GPT)
├── EFI partition  (32M)  → /EFI/BOOT/BOOTX64.EFI + grub.cfg + bzImage
└── rootfs partition (256M) → ext4, mount=/
```

Bu production layout'tan farklı (A/B + /data yok). Smoke test 90s'de boot edebilsin
diye sadeleştirildi. RAUC update test'i için Faz 4'te ayrı bir defconfig eklenecek.

## firstboot Davranışı

`/etc/systemd/system/suderra-firstboot.service` ilk boot'ta bir kere çalışır:

1. `/etc/machine-id` üretir (Buildroot empty bırakır)
2. `/data` partition varsa mkfs.ext4 yapar (QEMU layout'ta yok, no-op)
3. `/var/lib/suderra` dizini hazırlar (suderra-edge:suderra-edge sahipliği)
4. `/etc/suderra/config.yaml` skeleton oluşturur
5. `/var/lib/suderra/.firstboot-done` flag'i koyar → bir daha çalışmaz

Faz 2'de inline shell yerine `/usr/bin/suderra-firstboot` Rust binary çağrılır.

## CI Headless Test

`tests/qemu/boot-test.sh` artık **çalışır** durumda:

- 90s timeout
- Banner doğrulama: "Suderra OS"
- Kernel panic yok kontrolü
- systemd başlatma kontrolü
- Login prompt veya target hazır

```bash
# Manuel
./tests/qemu/boot-test.sh

# CI (build.yml)
- name: QEMU smoke test
  run: ./tests/qemu/boot-test.sh suderra_qemu_x86_64_defconfig
```

Çevre değişkenleri:
- `BOOT_TEST_TIMEOUT=90` (default 90s)
- `SUDERRA_DISK_IMG=/path/to/disk.img` (override)

## Kernel Config Detayı

QEMU için kritik CONFIG'ler (`board/suderra/x86_64/linux-x86_64.config`):

| CONFIG | Neden |
|---|---|
| `CONFIG_VIRTIO_NET=y` | QEMU virtio-net |
| `CONFIG_VIRTIO_BLK=y` | QEMU disk |
| `CONFIG_VIRTIO_PCI=y` | virtio bus |
| `CONFIG_SERIAL_8250=y` | ttyS0 console |
| `CONFIG_RTC_DRV_CMOS=y` | RTC (zaman) |
| `CONFIG_HW_RANDOM_VIRTIO=y` | virtio-rng (entropi) |

## Sorun Giderme

- **QEMU çok yavaş:** `-enable-kvm` veya nested virt
- **Network yok:** `-netdev user` ve `hostfwd` ekle
- **Display görünmüyor:** `-nographic -serial mon:stdio`

## Yapılacaklar

- [ ] `scripts/qemu-run.sh` ARM versiyonu (qemu-system-aarch64)
- [ ] swtpm wrapper script
- [ ] Otomatik test framework (expect/pexpect)

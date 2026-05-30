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

Bu production layout'tan farklı (A/B + /data yok). Smoke test 90s'de boot
edebilsin diye sadeleştirildi. Production-runtime davranışı ayrı ve non-public
`suderra_qemu_x86_64_prod_ab_defconfig` lane'iyle kanıtlanır.

## firstboot Davranışı

`/etc/systemd/system/suderra-firstboot.service` ilk boot'ta bir kere çalışır:

1. `/etc/machine-id` üretir (Buildroot empty bırakır)
2. `/data` partition varsa mkfs.ext4 yapar (QEMU layout'ta yok, no-op)
3. `/var/lib/suderra` dizini hazırlar (suderra-edge:suderra-edge sahipliği)
4. `/etc/suderra/config.yaml` skeleton oluşturur
5. `/var/lib/suderra/.firstboot-done` flag'i koyar → bir daha çalışmaz

Faz 2'de inline shell yerine `/usr/bin/suderra-firstboot` Rust binary çağrılır.

## CI Headless Test

`tests/qemu/boot-test.sh` QMP acceptance harness kullanır ve
`suderra.qemu-acceptance.v4` JSON çıktısı üretir:

- 90s timeout
- Banner doğrulama: "Suderra OS"
- Kernel panic yok kontrolü
- systemd başlatma kontrolü
- Login prompt veya target hazır
- Image hash, OVMF firmware hash, QMP event log, serial log ve temiz
  termination kanıtı. Forced-kill veya non-zero QEMU exit passed evidence
  sayılmaz.
- `production-runtime` profili ayrıca Secure Boot, dm-verity table, RAUC
  status, `/data` encryption ve anti-rollback floor semantic facts ister;
  Secure Boot, dm-verity tamper, RAUC good/bad update, health rollback,
  anti-rollback ve `/data` LUKS davranış check'leri geçmeden kabul edilmez.
- Production-runtime senaryo listesi, beklenen outcome, mutation tipi, raw log
  rolleri ve gözlem katmanı `ci/evidence-contract.yml` SSOT'undan üretilir.
  Workflow veya test script'lerinde ayrı senaryo listesi tutulmaz.
- Production-candidate release input yalnızca
  `suderra.qemu-production-runtime-suite.v2` kabul eder. v2 suite her
  senaryoda typed `suderra.runtime-observation.v1`, measured
  `observed_outcome`, QEMU argv, pflash OVMF enrollment digest, swtpm
  before/after digest, raw serial/QMP hash, termination class, semantic guest
  facts, QMP quit ACK/shutdown kanıtı ve mutation artifact before/after hash
  taşır. Validator raw serial/QMP loglarını replay eder ve JSON'daki typed
  observation loglarla ve SSOT senaryo sözleşmesiyle desteklenmiyorsa evidence
  reddedilir.

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
- `BOOT_TEST_LOG_DIR=/path/to/logs` (acceptance JSON ve log kökü)
- `SUDERRA_RELEASE_VERSION=v0.1.0-rc.1` ve `SUDERRA_TARGET=qemu-x86_64`
  (release input için metadata)

CI smoke profili yalnızca boot kanıtı üretir; release-candidate için semantik
guest facts ve per-check evidence gereklidir. Release input preflight için
`qemu.json` şu path'te olmalı ve ayrı validator'dan geçmelidir:

```bash
VERSION=v0.1.0-rc.1
SOURCE_SHA=<exact-main-commit>

SUDERRA_SOURCE_SHA="${SOURCE_SHA}" \
python3 tests/qemu/qmp-acceptance.py \
  --image output/suderra_qemu_x86_64_defconfig/images/disk.img \
  --log-dir "release-lab-input/${VERSION}/qemu-x86_64" \
  --evidence-output "release-lab-input/${VERSION}/qemu-x86_64/qemu.json" \
  --version "${VERSION}" \
  --target qemu-x86_64 \
  --profile release-candidate

python3 scripts/evidence/validate-qemu-input.py \
  --require-pass \
  --check-files \
  --profile release-candidate \
  --expected-source-sha "${SOURCE_SHA}" \
  "release-lab-input/${VERSION}/qemu-x86_64/qemu.json"
```

The default boot smoke does not by itself prove release-grade checks such as
firstboot idempotence or lockdown transition; those must be collected before
tagging.

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

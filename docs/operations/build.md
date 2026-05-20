# Build Talimatları

> **Status:** Skeleton — Faz 1 başında dolar.

## Önkoşullar

- Ubuntu 24.04 LTS (host)
- 20+ GB boş disk
- 8+ GB RAM (Buildroot ccache ile)
- Docker veya tüm Buildroot bağımlılıkları host'a kurulu

## Hızlı Build (Docker, önerilen)

```bash
# Tüm bağımlılıklar pinli container'da
./scripts/build-in-docker.sh suderra_qemu_x86_64_defconfig

# Output: output/suderra_qemu_x86_64_defconfig/images/
ls output/suderra_qemu_x86_64_defconfig/images/disk.img
```

## Host Build (geliştirme)

```bash
# Bağımlılıklar (Ubuntu 24.04)
sudo apt-get install -y build-essential git libncurses-dev rsync \
    bc cpio python3 unzip wget bison flex gettext libssl-dev

# Buildroot artık submodule olarak gelir — clone sırasında:
git submodule update --init --recursive

# Build
make build-qemu                  # veya make build-x86, make build-arm

# İzole Buildroot source tree ile doğrudan Buildroot çağırmak için:
buildroot_source_dir="$(./scripts/buildroot-source.sh prepare --defconfig suderra_qemu_x86_64_defconfig)"
make -C "${buildroot_source_dir}" \
    BR2_EXTERNAL="$(pwd)" \
    O="$(pwd)/output/qemu" \
    suderra_qemu_x86_64_defconfig
make -C "${buildroot_source_dir}" \
    BR2_EXTERNAL="$(pwd)" \
    O="$(pwd)/output/qemu"
```

## Buildroot 2025.05.3 Native Rust Migration

Buildroot `2025.05.3` native Rust `1.86.0` içerdiği için eski
`patches/buildroot/0001-buildroot-rust-1.86.0.patch` kuyruğu kaldırıldı.
`buildroot/` artık sadece pinli upstream submodule olarak temiz kalmalı; build
hazırlığı `output/.buildroot-src/` altında izole source tree oluşturur.

Mimari plan:
[`Buildroot 2025.05.3 Native Rust Migration Enterprise Plan`](../assessments/2026-05-20-buildroot-2025-05-native-rust-migration-plan.md).

Kontrol komutları:

```bash
./scripts/buildroot-source.sh verify-native-rust
./scripts/buildroot-source.sh status
```

## Defconfig'ler

| Defconfig | Hedef | Süre (ilk build) |
|---|---|---|
| `suderra_qemu_x86_64_defconfig` | QEMU geliştirme | ~30 dk |
| `suderra_x86_64_defconfig` | Endüstriyel x86 PC | ~45 dk |
| `suderra_aarch64_defconfig` | ARM SBC | ~50 dk |

İlk build ~30-45 dk, sonraki incremental build'ler ~5-15 dk.

## Output Yapısı

```
output/<defconfig>/
├── images/
│   ├── disk.img              # Bootable image (genimage)
│   ├── rootfs.ext4           # Root filesystem
│   ├── bzImage               # Kernel (x86)
│   ├── Image                 # Kernel (ARM)
│   └── boot.scr              # U-Boot script (ARM)
├── target/                   # Staged rootfs (debug için)
├── legal-info/               # SPDX manifest (SBOM kaynak)
└── build/                    # Build artifacts (geçici)
```

## Disk Image Layout

`board/suderra/common/post-image.sh` defconfig adına göre genimage config seçer:

| Defconfig | genimage config | Partition layout |
|---|---|---|
| `suderra_qemu_x86_64_defconfig` | `x86_64/genimage-qemu.cfg` | EFI (32M) + rootfs (256M) — tek slot, debug için |
| `suderra_x86_64_defconfig` | `x86_64/genimage.cfg` | EFI (64M) + rootfs-a (512M) + rootfs-b (512M) + data (2G) — A/B + persistent |
| `suderra_aarch64_defconfig` | `aarch64/genimage.cfg` | BOOT (32M) + rootfs-a + rootfs-b + data |

QEMU layout production'dan ayrı çünkü:

- A/B partition QEMU smoke test için gereksiz karmaşıklık
- `/data` partition firstboot mkfs gerektirir, smoke test 90s timeout'a sığmaz
- Faz 4'te RAUC bundle test'i için ayrı `suderra_qemu_x86_64_ab_defconfig` eklenebilir

## Buildroot Users Table

`board/suderra/common/users.txt` Buildroot'un user/group tablosu:

- `suderra` (UID 200) — Edge Agent runtime user, login disabled
- `provision` (UID 201) — firstboot tarafından tek kullanımlık parola verilen
  forced-command provisioning user. Genel shell vermez.
- Root password login kapalıdır. `suderra-lockdown` root/provision password
  login'i, getty/debug shell'i, dropbear/SSH unit'lerini ve provisioning
  firewall kuralını kapatır.

Format: `username uid group gid password home shell groups comment`
(Boşluk yerine `_` kullanılmalı, Buildroot satırı space-split eder.)

## Reproducible Build

Iki ayrı geliştirici / makinada **aynı SHA256** elde etmek için:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) ./scripts/build-in-docker.sh suderra_x86_64_defconfig
sha256sum output/suderra_x86_64_defconfig/images/disk.img
```

Container pinned versiyonlar nedeniyle reproducible.

## Sorun Giderme

- **Disk alanı yetmedi:** `make clean` veya `make distclean` (download cache da silinir)
- **ccache cache:** `~/.buildroot-ccache/` paylaşılır
- **Network sorunu:** Buildroot mirror ayarı `BR2_PRIMARY_SITE`
- **Build fail:** `output/<defconfig>/build/<pkg>/.stamp_*` dosyalarına bak

## Yapılacaklar

- [ ] Faz 1'de gerçek build komutları doğrulanmalı
- [ ] ccache distributed (multiple developers) setup
- [ ] CI'da artifact upload + caching

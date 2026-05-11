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

# Buildroot'u doğrudan çağırmak için:
make -C buildroot \
    BR2_EXTERNAL=$(pwd) \
    O=$(pwd)/output/qemu \
    suderra_qemu_x86_64_defconfig
make -C buildroot \
    BR2_EXTERNAL=$(pwd) \
    O=$(pwd)/output/qemu
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

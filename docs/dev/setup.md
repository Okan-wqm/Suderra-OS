# Geliştirici Ortamı Kurulumu

> **Status:** Active. Faz 0 için yeterli.

## Sistem Gereksinimleri

- **OS:** Ubuntu 24.04 LTS (önerilen) veya Debian 12+
- **CPU:** 4+ core önerilir (Buildroot paralel build)
- **RAM:** 8 GB minimum, 16 GB önerilen
- **Disk:** 50+ GB boş (Buildroot output + ccache + Docker)
- **Network:** GitHub + Buildroot mirror erişimi

## Hızlı Kurulum (Docker tabanlı)

```bash
# 1. Repo clone (submodule'lerle birlikte)
git clone --recurse-submodules git@github.com:Okan-wqm/Suderra-OS.git
cd suderra-os

# Eğer submodule'siz klonladıysan:
git submodule update --init --recursive

# 2. Docker kurulu mu?
docker --version || sudo apt-get install -y docker.io
sudo usermod -aG docker $USER
newgrp docker

# 3. Build container hazırla (~5 dk ilk seferde)
docker build -t suderra-builder ci/

# 4. İlk build (QEMU defconfig, ~30 dk)
./scripts/build-in-docker.sh suderra_qemu_x86_64_defconfig

# 5. QEMU'da test
./scripts/qemu-run.sh
```

## Buildroot Submodule

Buildroot 2025.05.x `buildroot/` dizininde git submodule olarak pinli.
Aktif pin `2025.05.3` ve native Rust `1.86.0` içerir.

```bash
# İlk klonlamada otomatik gelmesi için:
git clone --recurse-submodules ...

# Sonradan eklemek/güncellemek için:
git submodule update --init --recursive

# Submodule pin SHA'sını güncellemek için (yeni LTS patch geldiğinde):
cd buildroot
git fetch
git checkout 2025.05.x
cd ..
git add buildroot
git commit -s -m "build: bump Buildroot to <new-sha>"
```

**Neden submodule:** SHA pin = reproducible build (CRA + SLSA gereksinimi).
Upstream main'in kırılmaları bizi etkilemez.

Normal build akışı `buildroot/` içinde patch uygulamaz. `scripts/build.sh` ve CI,
pinli submodule'den `output/.buildroot-src/` altında izole source tree üretir.
Submodule'un temizliğini kontrol etmek için:

```bash
./scripts/buildroot-source.sh verify-native-rust
./scripts/buildroot-source.sh status
```

## Host Kurulum (Docker olmadan)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential git libncurses-dev rsync bc cpio \
    python3 unzip wget bison flex gettext libssl-dev \
    qemu-system-x86 qemu-system-arm \
    shellcheck markdownlint \
    pre-commit
```

## Pre-commit Hooks

```bash
pre-commit install
# Her commit'te shellcheck, markdownlint, gitleaks çalışır
```

## IDE Önerileri

- **VS Code** + extensions:
  - `Buildroot Config` (defconfig syntax)
  - `markdownlint`
  - `ShellCheck`
  - `EditorConfig`
  - `rust-analyzer` (Rust app paketleme için)
- **Vim/Neovim:** mevcut config çoğunlukla yeterli
- **CLion:** Buildroot için ağır ama Rust için iyi

## Git Konfigürasyonu

```bash
# DCO sign-off otomatik
git config commit.gpgsign true     # GPG imza önerilir
git config user.name "Ad Soyad"
git config user.email "you@example.com"

# Suderra OS özel hook'lar
ln -sf $(pwd)/.githooks/* .git/hooks/
```

## Build Bağımlılıkları (Buildroot)

Buildroot artık `buildroot/` dizininde **submodule** olarak gelir
(yukarıdaki "Buildroot Submodule" bölümüne bakın).

İlk paket download'ları (~2-3 GB tar.gz) Buildroot tarafından otomatik
indirilir, `dl/` dizininde cache'lenir.

## QEMU Test Akışı

```bash
make build-qemu
./scripts/qemu-run.sh

# QEMU içinde:
# - Boot logları akar
# - "suderra login:" prompt'u görmeli (dev variant)
# - root / suderra (dev variant default — production'da değiştirilir)
```

## Sorun Giderme

- **Docker permission denied:** `sudo usermod -aG docker $USER`, oturum kapat/aç
- **Disk doluyor:** `make clean` (build artifacts), `make distclean` (download cache)
- **GitHub clone yavaş:** `git config --global protocol.version 2`
- **Buildroot mirror sorunu:** `BR2_PRIMARY_SITE=https://your-mirror`

## Yapılacaklar

- [ ] Faz 1'de gerçek build talimatları doğrulanmalı
- [ ] Devcontainer JSON (VSCode/Codespaces için)
- [ ] Windows WSL2 talimatları (eğer talep gelirse)

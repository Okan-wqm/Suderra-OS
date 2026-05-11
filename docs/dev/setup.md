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
# 1. Repo clone
git clone git@github.com:Okan-wqm/suderra-os.git
cd suderra-os

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

İlk build sırasında otomatik indirilir. Önceden indirmek için:
```bash
git clone https://gitlab.com/buildroot.org/buildroot.git -b 2024.11 buildroot
```

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

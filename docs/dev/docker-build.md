# Reproducible Build (Docker)

> **Status:** Skeleton.

## Amaç

Her geliştirici aynı imajı, aynı SHA256 ile build edebilmeli. Bu hem supply chain güveni için (CRA gereği) hem de CI/dev parity için kritik.

## Container Stratejisi

`ci/Dockerfile`:

- Base: `ubuntu:24.04` (pinli SHA256)
- Pinli Buildroot bağımlılıkları
- Pinli toolchain
- Non-root build user

## Reproducible Build Garantileri

| Faktör | Mekanizma |
|---|---|
| Build host | Pinli Docker image |
| Buildroot version | git submodule pinned (tag: 2025.05.3) |
| Toolchain | Buildroot tarafından bootstrap (deterministik) |
| Source code | git commit SHA |
| Timestamps | `SOURCE_DATE_EPOCH` env var |
| Locale | `LC_ALL=C` |
| Random seed | `--random-seed=$(git rev-parse HEAD)` (paketler) |

## Doğrulama

```bash
# Build 1
./scripts/build-in-docker.sh suderra_x86_64_defconfig
sha256sum output/suderra_x86_64_defconfig/images/disk.img > hash1.txt

# Temizle
rm -rf output/

# Build 2 (farklı zaman)
./scripts/build-in-docker.sh suderra_x86_64_defconfig
sha256sum output/suderra_x86_64_defconfig/images/disk.img > hash2.txt

# Karşılaştır
diff hash1.txt hash2.txt    # Identical olmalı
```

CI'da `scripts/verify-reproducible.sh` her PR'da koşar (bekçi).

## Yapılacaklar

- [ ] `ci/Dockerfile` versiyon pinleme (Faz 0)
- [ ] `SOURCE_DATE_EPOCH` enforcement (Faz 1)
- [ ] CI'da reproducible-build kontrolü (Faz 5)

## Referanslar

- [reproducible-builds.org](https://reproducible-builds.org/)
- [SLSA Level 3 requirements](https://slsa.dev/spec/v1.0/levels)

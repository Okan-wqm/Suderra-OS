# Rust Userspace Workspace — Geliştirici Rehberi

Suderra-OS-spesifik tüm Rust araçları `userspace/` workspace içinde geliştirilir.

> **TL;DR:** `cd userspace/ && cargo cl && cargo t` (host'ta lint + test, dakika
> mertebesinde). Production build için `cargo bm` (musl static, ~5dk).

## Felsefe

**Rust-first userspace + C base layer** ([ROADMAP.md](../../ROADMAP.md)):

| Katman | Dil | Sürdürüce |
|---|---|---|
| Bootloader, kernel, systemd, RAUC | C | Buildroot upstream |
| **Suderra userspace tools** | **Rust (musl static)** | **Bu workspace** |
| Edge Agent (sens-api-gateway) | Rust | Ayrı repo (aquaculture_platform) |

## Workspace Yapısı

```
userspace/
├── Cargo.toml              # workspace root, ortak metadata + deps
├── Cargo.lock              # dependency tree pin (commit'lenir)
├── README.md               # workspace genel bakış
├── rust-toolchain.toml     # Rust 1.85 pinning
├── deny.toml               # cargo-deny config (lisans + advisory)
├── .cargo/config.toml      # musl target, linker, alias'lar
│
├── suderra-config/         # lib crate, ortak config parser
├── suderra-firstboot/      # binary, ilk boot provisioning
├── suderra-ota/            # binary, RAUC OTA orchestrator
├── suderra-telemetry/      # binary, metrics push
├── suderra-watchdog/       # binary, hw watchdog + health
├── suderra-factory-reset/  # binary, factory reset handler
└── suderra-attestation/    # binary, TPM PCR attestation (Faz 8+)
```

## Hızlı Başlangıç

### 1. Toolchain kur

`rust-toolchain.toml` otomatik kurar — sadece `cargo --version` çağırın:

```bash
cd userspace/
cargo --version   # rustup otomatik 1.85.0 indirir
```

### 2. Musl toolchain (production build için)

```bash
# Ubuntu / Debian
sudo apt install musl-tools

# macOS (cross için)
brew install FiloSottile/musl-cross/musl-cross
```

### 3. Lint + Test (host, hızlı)

```bash
cargo fmt --all           # format
cargo cl                  # clippy strict
cargo t                   # test (host glibc, hızlı iterasyon)
```

### 4. Production build (musl static)

```bash
cargo bm                  # x86_64 musl release
cargo bma                 # aarch64 musl release
```

Çıktı:

```
target/x86_64-unknown-linux-musl/release/
├── suderra-firstboot       # ~1-3 MB, static
├── suderra-ota             # ~3-5 MB (reqwest + rustls dahil)
├── suderra-telemetry       # ~3-5 MB
├── suderra-watchdog        # ~1-2 MB
├── suderra-factory-reset   # ~1-2 MB
└── suderra-attestation     # ~2-4 MB
```

## Bağımlılık Politikası

`deny.toml` ile **strict**:

- ✅ İzin: Apache-2.0, MIT, BSD, ISC, MPL-2.0, Unlicense, CC0-1.0
- ❌ Yasak: GPL/AGPL/LGPL (strict copyleft → kaynak kodu açma yükümlülüğü)
- ❌ Yasak: OpenSSL, native-tls (rustls only — musl uyumlu)
- ❌ Yasak: wildcard versions (`*`)
- ⚠️ Uyarı: aynı crate'in birden fazla versiyonu (deduplicate et)

CI'da `cargo audit` + `cargo deny check` her PR'da koşar.

## Cross-Compile Detayları

### Neden musl?

- Static link → tek binary, dependency yok
- ~600KB libc (glibc ~6MB)
- Audit-friendly, sade
- Suderra OS imajının kendisi musl tabanlı

### Linker

`.cargo/config.toml` linker'ı pinler:

- `x86_64-linux-musl-gcc` (apt: `musl-tools`)
- `aarch64-linux-musl-gcc` (musl.cc'den)

### Yaygın Hatalar

**`linker not found: x86_64-linux-musl-gcc`**

```bash
sudo apt install musl-tools
```

**`could not find native static library 'ssl'`**

- Bizim workspace OpenSSL kullanmamalı (deny.toml ile yasak)
- Eğer transitive dep zorluyorsa: o crate'i değiştir veya `rustls` feature'ı seç

**SQLCipher / vendored OpenSSL (Edge Agent için)**

- Bizim workspace'imizi etkilemez (Edge Agent ayrı repo)
- Buildroot tarafında `BR2_PACKAGE_OPENSSL` ile çözülür

## Test Stratejisi

| Test türü | Lokasyon | Çalıştırma | Faz |
|---|---|---|---|
| Unit tests | `<crate>/src/*.rs` `#[cfg(test)]` | `cargo t` | Hemen |
| Integration | `<crate>/tests/*.rs` | `cargo t` | 2+ |
| Property-based | `<crate>/tests/proptest_*.rs` | `cargo t` | 3+ |
| Fuzz | `<crate>/fuzz/` | `cargo fuzz run` | 5+ |
| Benchmark | `<crate>/benches/` | `cargo bench` | 6+ |

## CI / GitHub Actions

`.github/workflows/rust.yml`:

| Job | Süre | Amaç |
|---|---|---|
| `check` (fmt + clippy + test host) | ~3dk | Hızlı geri bildirim |
| `build-musl` (x86_64 + aarch64) | ~15-20dk | Production build |
| `security` (audit + deny) | ~3dk | Supply chain |
| `msrv` (Rust 1.85) | ~5dk | Toolchain pinning doğrula |

PR'da hepsi koşar, başarısız olursa merge bloklu.

## Buildroot Entegrasyonu

Her binary crate Buildroot tarafından paketlenir:

```
package/suderra-firstboot/
├── Config.in              # menüde "Suderra firstboot" görünür
└── suderra-firstboot.mk   # build reçetesi
```

Reçete:

```makefile
SUDERRA_FIRSTBOOT_VERSION = $(SUDERRA_OS_VERSION)
SUDERRA_FIRSTBOOT_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/userspace
SUDERRA_FIRSTBOOT_SITE_METHOD = local
SUDERRA_FIRSTBOOT_SUBDIR = suderra-firstboot
SUDERRA_FIRSTBOOT_DEPENDENCIES = host-rustc

define SUDERRA_FIRSTBOOT_BUILD_CMDS
    cd $(@D) && cargo build --release \
        --target $(BR2_RUSTC_TARGET_NAME)
endef

define SUDERRA_FIRSTBOOT_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 \
        $(@D)/target/$(BR2_RUSTC_TARGET_NAME)/release/suderra-firstboot \
        $(TARGET_DIR)/usr/bin/suderra-firstboot
endef

$(eval $(generic-package))
```

## Yeni Crate Ekleme

1. `userspace/<new-crate>/` dizini oluştur (Cargo.toml + src/main.rs + README.md)
2. `userspace/Cargo.toml` → `members` listesine ekle
3. Buildroot paketi: `package/<new-crate>/Config.in` + `.mk`
4. CHANGELOG'a yaz
5. CI yeşil → merge

## Performans + Boyut

Release profile `Cargo.toml`'da:

```toml
opt-level = "z"     # boyut için
lto = "fat"         # link-time optimization
strip = "symbols"   # debug çıkar
panic = "abort"     # unwind tablosu yok
```

Sonuç: ~50-80% boyut azalması debug build'e göre.

## Faz Planı

| Faz | Crate | Status |
|---|---|---|
| 0 | Workspace iskelet | ✅ |
| 2 | suderra-firstboot impl | TODO |
| 2 | suderra-config tam tipler | TODO |
| 4 | suderra-ota impl | TODO |
| 5 | suderra-telemetry impl | TODO |
| 5 | suderra-watchdog impl | TODO |
| 5 | suderra-factory-reset impl | TODO |
| 8+ | suderra-attestation impl | TODO |

## Dependency Updates (Dependabot)

`userspace/` Cargo.toml'ları **günlük** Dependabot taramasında:

- Minor + patch update'leri **grup PR** olarak gelir (rust-minor-patch)
- Major version bump'lar (tokio, axum, rustls) **manuel review** gerektirir
  (ignore listesinde)
- Max 10 açık Dependabot PR aynı anda
- Etiketler: `dependencies`, `rust`, `security`

Buildroot submodule da `gitsubmodule` ecosystem ile **aylık** kontrol edilir.

## SPDX / REUSE Compliance

Tüm `Cargo.toml` + `*.rs` dosyaları başında:

```rust
// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0
```

## Referanslar

- [ROADMAP.md](../../ROADMAP.md)
- [userspace/README.md](../../userspace/README.md)
- [cargo-deny](https://embarkstudios.github.io/cargo-deny/)
- [Rust musl deployment](https://github.com/rust-cross/rust-musl-cross)
- [Edge Agent (ayrı repo)](https://github.com/Okan-wqm/aquaculture_platform/tree/main/sens-api-gateway)

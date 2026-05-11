# Suderra OS — Rust Userspace Workspace

Bu dizin Suderra OS'in **kendi yazdığımız** tüm Rust userspace araçlarını içerir.
Edge Agent (`sens-api-gateway`) ayrı repoda — bu workspace **Suderra OS sistemi
için** gerekli yardımcı binary'leri içerir.

## Felsefe

**Rust-first userspace, C base layer** ([ROADMAP.md](../ROADMAP.md)):
- Boot/kernel/systemd/RAUC: C upstream (olgun, audit edilmiş)
- Suderra-spesifik tüm tools: 100% Rust (musl static)
- Memory safety = Suderra OS'in güvenlik tezi

## Workspace Içeriği

| Crate | Tür | Faz | Amaç |
|---|---|---|---|
| `suderra-firstboot` | binary | 2 | İlk boot provisioning (machine-id, /data init, TPM seal) |
| `suderra-ota` | binary | 4 | RAUC orchestrator (download, verify, install, rollback) |
| `suderra-telemetry` | binary | 5 | Health metrics + remote ship (CPU, RAM, disk, app metrics) |
| `suderra-watchdog` | binary | 5 | Hardware watchdog + health monitor |
| `suderra-factory-reset` | binary | 5 | GPIO/cloud reset trigger handler |
| `suderra-attestation` | binary | 8+ | TPM PCR remote attestation |
| `suderra-config` | lib | 2 | Ortak config validation (diğer crate'ler tarafından kullanılır) |

## Geliştirme

### Hızlı başlangıç (geliştirme makinesinde, host'ta test)

```bash
cd userspace/

# Compile ve test (host'ta glibc ile, hızlı)
cargo t                    # = cargo test --target x86_64-unknown-linux-gnu

# Lint
cargo cl                   # = cargo clippy --workspace --all-targets -- -D warnings
cargo fmt                  # format

# Security
cargo audit                # CVE database
cargo deny                 # = cargo deny check (lisans + banned + advisory)
```

### Production build (musl static)

```bash
# Önce musl toolchain kurulu olmalı (Ubuntu 24.04):
sudo apt install musl-tools

# x86_64 production binary
cargo bm                   # = cargo build --target x86_64-unknown-linux-musl --release

# aarch64 production binary
# Önce aarch64-musl toolchain: 
#   https://musl.cc/ veya `rustup target add aarch64-unknown-linux-musl`
cargo bma                  # = cargo build --target aarch64-unknown-linux-musl --release
```

Çıktı:
```
target/x86_64-unknown-linux-musl/release/suderra-firstboot   # ~1-3 MB, static
```

### CI / Buildroot tarafından nasıl kullanılır?

Buildroot her crate'i kendi paketi olarak build eder:
- `package/suderra-firstboot/suderra-firstboot.mk` → `cd userspace/suderra-firstboot && cargo build --release`
- Çıktı binary `/usr/bin/suderra-firstboot` olarak rootfs'e kopyalanır
- systemd unit `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service` ile bağlanır

## Toolchain

`rust-toolchain.toml` ile pinned:
- **Rust 1.85.0** (2024 edition, MSRV)
- `cargo`, `rustfmt`, `clippy`, `rust-src`
- Target: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`

Geliştirici makinesinde `rustup` otomatik bu versiyonu indirir. CI ile uyumlu.

## Bağımlılık Politikası

`deny.toml` ile enforced:
- ✅ Sadece OSI permissive lisanslar (Apache-2.0, MIT, BSD, ISC, MPL-2.0)
- ❌ GPL / AGPL / LGPL — strict copyleft bulaşması yasak
- ❌ OpenSSL / native-tls — sadece rustls
- ❌ Wildcard versions (`*`) — reproducible build için
- ❌ Bilinmeyen git registry / unknown source
- ⚠️ Duplicate versions → uyarı (deduplicate et)

CVE database (RustSec) her PR'da kontrol edilir.

## Yeni Crate Ekleme

1. `userspace/Cargo.toml` → `members` listesine ekle
2. Crate iskelet oluştur:
   ```bash
   cargo new suderra-foo --bin   # veya --lib
   ```
3. `Cargo.toml` üst workspace metadata'sını miras alacak şekilde:
   ```toml
   [package]
   name = "suderra-foo"
   version.workspace = true
   edition.workspace = true
   rust-version.workspace = true
   authors.workspace = true
   license.workspace = true
   ```
4. Buildroot paketi ekle: `package/suderra-foo/`
5. README + crate purpose
6. CHANGELOG güncelle

## Test Stratejisi

- **Unit tests**: her crate `src/` içinde, host'ta glibc ile koşar (hızlı)
- **Integration tests**: `tests/` dizini (her crate kendi), gerçek dosya sistemi
- **Property-based**: `proptest` veya `quickcheck` (config parser, OTA bundle validator için)
- **Fuzz**: `cargo-fuzz` (Faz 5+) — Modbus, OPC-UA parser benzeri input handling için

## Cross-compile Sorunları

**"linker not found: x86_64-linux-musl-gcc":**
```bash
sudo apt install musl-tools           # Ubuntu/Debian
brew install musl-cross               # macOS
```

**"SQLCipher / OpenSSL build fail":**
- Edge Agent'ta `vendored-openssl` feature kullan (Buildroot'ta zaten ayarlı)
- Bizim workspace'de OpenSSL kullanılmamalı (deny.toml ile zorunlu)

**aarch64 cross-compile:**
```bash
# musl.cc'den toolchain indir:
wget https://musl.cc/aarch64-linux-musl-cross.tgz
tar -xf aarch64-linux-musl-cross.tgz
export PATH="$PWD/aarch64-linux-musl-cross/bin:$PATH"

rustup target add aarch64-unknown-linux-musl
cargo bma
```

## Referanslar

- [ROADMAP.md](../ROADMAP.md) — Faz planı
- [docs/dev/rust-workspace.md](../docs/dev/rust-workspace.md) — detaylı rehber
- [docs/architecture/](../docs/architecture/) — ADR'lar
- [Rust musl deployment](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [cargo-deny](https://embarkstudios.github.io/cargo-deny/)
- [Edge Agent (ayrı repo)](https://github.com/Okan-wqm/aquaculture_platform/tree/main/sens-api-gateway)

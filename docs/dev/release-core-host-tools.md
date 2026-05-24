# Release Core Host Tools Migration Plan

Tarih: 2026-05-24

Bu doküman release/evidence doğrulayıcılarının Python'dan Rust'a taşınması için
uygulanan ilk enterprise-grade fazı kaydeder. Amaç RC güvenliğini düşürmeden
Rust tabanlı, test edilebilir ve supply-chain kontrollü bir host tooling
yüzeyi açmaktır.

## Karar

Release kapıları ilk RC öncesinde tek adımda Rust'a çevrilmez. Mevcut Python
script'leri release workflow'larında birincil doğrulayıcı olarak kalır.
`host-tools/` altında ayrı bir Rust workspace açılır ve Rust CLI önce shadow
validator olarak geliştirilir.

Bu kararın nedeni:

- Release preflight zaten fail-closed davranışa bağlıdır; doğrulayıcı dilini
  değiştirirken semantik drift kabul edilmez.
- Host tooling Buildroot imajının parçası değildir. Bu yüzden `userspace/`
  workspace içine konmaz ve hedef imaj dependency grafiğini büyütmez.
- Rust cutover yapılmadan önce Python ve Rust çıktıları fixture tabanlı
  parity testlerinden geçmelidir.
- Release job içinde `cargo`, `cross` veya `rustup` çalıştırılmamalıdır.
  Release yalnızca preflight-bound artifact byte'larını terfi ettirir.

## Uygulanan Faz

Bu commit ile açılan yüzey:

- `host-tools/` bağımsız Cargo workspace'i.
- `schema-compat` crate'i:
  - lowercase SHA doğrulama,
  - pozitif run ID normalize etme,
  - güvenli relative path doğrulama,
  - file SHA-256 hesaplama,
  - sorted JSON output helper'ları,
  - release/evidence schema sabitleri.
- `release-core` CLI:
  - `tag-binding parse`,
  - `tag-binding validate-run`,
  - `tag-binding validate-ingress`,
  - `tag-binding validate-cross-binding`,
  - `operator-evidence validate`.
- `host-tools/Cargo.lock` tracked lockfile.
- Dependabot `/host-tools` Cargo ekosistemi.
- Rust CI içinde host-tools fmt/clippy/test ve cargo-deny job'ları.
- Static governance contract testleri:
  - host-tools workspace'in Buildroot/userspace'e bağlanmaması,
  - host lockfile'ın tracked ve unignored olması,
  - release workflow'da `cargo`, `cross build`, `rustup` olmaması,
  - release manifest validation'ın preflight-bound x86_64 installer binary ile
    yapılması.

## Release Workflow Kuralı

Release job'ları Rust build yapmaz. Manifest schema doğrulaması şu kaynaktan
çalışır:

```text
release/suderra-installer-<version>-x86_64
```

Bu binary, Image Build artifact'ından preflight tarafından bağlanmış byte'tır.
Release job bu dosyayı executable yapar ve `validate-manifest` komutunu çalıştırır.
Yeni contract testleri release job içinde aşağıdaki pattern'leri yasaklar:

```text
cargo run
cargo build
cargo install
cross build
rustup
```

Image Build job'unda Rust build devam eder; yasak yalnızca release promotion
aşaması içindir.

## Migration Contract

Rust CLI bu fazda birincil release gate değildir. Bir komutun Python eşdeğeri
yerine geçmesi için şu şartlar gereklidir:

1. Aynı fixture seti üzerinde Python ve Rust aynı exit code'u üretir.
2. Başarılı örneklerde normalized JSON output byte-for-byte eşleşir veya
   farklar yazılı ve testli bir compatibility rule ile açıklanır.
3. Fail fixture'larında Rust en az Python kadar fail-closed davranır.
4. Cutover PR'ı ilgili GitHub workflow'u ve contract testini beraber günceller.
5. Cutover sonrası Python fallback eklenmez; başarısız Rust validator release'i
   durdurur.

## Taşınacak Python Yüzeyi

Öncelik sırası:

| Python script | Rust hedefi | Durum |
|---|---|---|
| `validate-release-tag-binding.py` | `release-core tag-binding ...` | Shadow CLI açıldı |
| `operator-evidence-ingress.py validate` | `release-core operator-evidence validate` | Shadow CLI açıldı |
| Ortak path/SHA/run-id helper'ları | `schema-compat` | Taşındı |
| `release-ingress.py validate` | `release-core release-ingress validate` | Sonraki faz |
| Manifest create/stage işlemleri | `release-core ... create/stage` | Parity test sonrası |

## Komutlar

Host tooling doğrulaması:

```bash
cd host-tools
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
cargo test --locked --workspace --target x86_64-unknown-linux-gnu
```

Static contract suite:

```bash
./scripts/run-tests.sh host-tools
./scripts/run-tests.sh image-contracts
```

Örnek shadow tag binding doğrulaması:

```bash
cd host-tools
cargo run --locked -p release-core -- tag-binding validate-ingress \
  --binding ../release-tag-binding.json \
  --ingress-manifest ../release-ingress/v0.1.0-rc.1/ingress-manifest.json
```

## Sonraki Faz

Sonraki PR'da fixture-driven parity suite eklenmelidir:

- geçerli tag annotation,
- eksik annotation field,
- SHA mismatch,
- expired artifact,
- missing station registry,
- missing audit log,
- path traversal,
- duplicate evidence path,
- wrong schema_version,
- manifest SHA mismatch.

Bu fixture'lar önce Python script'leriyle baseline alır, sonra Rust CLI aynı
fixture'lar üzerinde çalıştırılır. Cutover sadece bu suite yeşil olduktan sonra
yapılır.

# Contributing to Suderra OS

Suderra OS endüstriyel/güvenlik kritik bir işletim sistemidir. Katkı süreci buna göre disiplinlidir.

## İçindekiler
- [Geliştirici Sertifikası (DCO)](#geliştirici-sertifikası-dco)
- [Branch Stratejisi](#branch-stratejisi)
- [Commit Mesaj Formatı](#commit-mesaj-formatı)
- [Pull Request Süreci](#pull-request-süreci)
- [Kod Standartları](#kod-standartları)
- [ADR (Architecture Decision Records)](#adr-architecture-decision-records)
- [Güvenlik Açığı](#güvenlik-açığı)
- [Testler](#testler)

## Geliştirici Sertifikası (DCO)

Tüm commit'ler `Signed-off-by:` satırı ile imzalanmalıdır (Developer Certificate of Origin v1.1, Linux kernel ile aynı):

```
git commit -s -m "feat(kernel): KASLR'ı production'da zorunlu kıl"
```

## Branch Stratejisi

**Trunk-based + release branches:**

| Branch | Amaç |
|---|---|
| `main` | Geliştirme trunk'ı, her zaman build edilebilir olmalı |
| `release/v1.0.x` | LTS release dalları (security patch backport) |
| `feat/<short-name>` | Feature branch (PR ile `main`'e merge) |
| `fix/<short-name>` | Bug fix branch |
| `security/<cve-id>` | Security patch (genelde private, sonra public) |

Direkt `main`'e push **yasak**. PR + en az 1 review + yeşil CI zorunlu.

## Commit Mesaj Formatı

[Conventional Commits](https://www.conventionalcommits.org/) kullanılır:

```
<type>(<scope>): <kısa açıklama>

<gövde — neden, ne, etki>

Signed-off-by: Ad Soyad <email@example.com>
```

**Type'lar:**
- `feat` — yeni özellik
- `fix` — bug fix
- `security` — güvenlik patch'i (CVE referansı gövdede)
- `docs` — dokümantasyon
- `chore` — bağımlılık güncellemesi, refactor
- `ci` — CI/CD değişiklikleri
- `build` — build sistem (Buildroot, Makefile, Dockerfile)
- `test` — test eklemesi/düzeltmesi
- `perf` — performans iyileştirmesi

**Scope örnekleri:** `kernel`, `systemd`, `rauc`, `verity`, `secboot`, `edge-agent`, `x86_64`, `aarch64`, `ci`, `docs`

**Örnekler:**
```
feat(rauc): A/B partition rollback otomatik tetikleme

3 başarısız boot sonrasında bootloader otomatik olarak yedek
slot'a döner. systemd-bootchart watchdog ile entegre.

Refs: ADR-0004
Signed-off-by: Okan Y <okan@example.com>
```

```
security(kernel): CVE-2024-XXXX için 6.12.5 LTS'e yükselt

Linux kernel < 6.12.5'te ksmbd RCE açığı (CVSS 9.8).
Suderra OS ksmbd kullanmıyor ama defense-in-depth.

Refs: GHSA-XXXX-YYYY-ZZZZ
Signed-off-by: Okan Y <okan@example.com>
```

## Pull Request Süreci

1. Issue aç (önemli değişiklik için)
2. `feat/<name>` branch'i oluştur
3. Commit'leri conventional commits formatında yap, hepsi DCO imzalı
4. Test ekle (yeni özellik için), mevcut testleri geçir
5. Dokümantasyonu güncelle (mimari değişiklik için ADR)
6. PR aç — `pull_request_template.md` kullan
7. CI yeşil olmalı (build, lint, security-scan)
8. En az 1 review (security/kernel değişiklikleri için 2)
9. Squash merge (clean history)

## Kod Standartları

### Shell scripts
- `#!/usr/bin/env bash` + `set -euo pipefail`
- `shellcheck` temiz olmalı (CI kontrol eder)
- 4 space indent
- Komut substitution: `$(...)`, backtick yasak

### Markdown
- `markdownlint` temiz
- Satır uzunluğu yumuşak (uzun cümleler ok)
- Tablolar tercih edilir (ASCII art yerine)

### Buildroot paketleri (.mk)
- 4 space tab indent (Buildroot konvansiyonu)
- `<package>_LICENSE`, `<package>_LICENSE_FILES`, `<package>_VERSION` zorunlu
- Hash file (`*.hash`) check zorunlu (supply chain)

### Kernel config
- Sertleştirme: [docs/security/kernel-hardening.md](docs/security/kernel-hardening.md)
- Her aç/kapa kararı yorumlanmış olmalı
- `make savedefconfig` ile minimal tutulur

## ADR (Architecture Decision Records)

Önemli mimari kararlar [docs/architecture/](docs/architecture/) altında ADR olarak yazılır. Yeni ADR için:

```bash
./scripts/new-adr.sh "ARM SBC olarak Raspberry Pi CM4 seçimi"
# → docs/architecture/ADR-0006-arm-sbc-rpi-cm4.md
```

Format (Michael Nygard, kısa):
- **Status:** Proposed / Accepted / Deprecated / Superseded by ADR-XXXX
- **Context:** Hangi soruyu cevaplıyor?
- **Decision:** Ne kararlaştırıldı?
- **Consequences:** Sonuçları nedir? (pozitif + negatif)

## Güvenlik Açığı

**Public issue açmayın.** Detaylar: [SECURITY.md](SECURITY.md).

## Testler

| Tip | Konum | Çalıştırma |
|---|---|---|
| QEMU smoke | `tests/qemu/` | `./scripts/qemu-run.sh && ./tests/qemu/boot-test.sh` |
| Security baseline | `tests/security/` | `./tests/security/lynis-baseline.sh` |
| OTA rollback | `tests/ota/` | `./tests/ota/update-rollback-test.sh` |

CI'da hepsi otomatik koşar. Lokal test için: `make test`.

## Lisans Uyumluluğu

Suderra OS, Linux kernel ve diğer GPL bileşenleri yeniden dağıtır. Kaynak kod sunma yükümlülüğümüz var. Detay: [docs/compliance/licenses.md](docs/compliance/licenses.md).

Yeni paket eklerken:
- SPDX lisans tanımla (`<pkg>_LICENSE = GPL-2.0+`)
- Lisans dosyasını işaretle (`<pkg>_LICENSE_FILES = COPYING`)
- Hash dosyası ekle (supply chain bütünlüğü için)

# OpenSSF Best Practices Badge — Durum

> **Status:** Active tracking. Hedef: Passing → Silver → Gold.

## Badge URL'leri (Faz 0.5'te başvurulacak)

- Passing: <https://www.bestpractices.dev/projects/XXXX/badge>
- Silver: ...
- Gold: ...

README.md güncellenecek.

## Passing Level Kriterleri

| Kategori | Kriter | Suderra OS | Durum |
|---|---|---|---|
| **BASICS** | | | |
| - Description | Public proje açıklaması | README.md | OK |
| - Interaction | Issue tracking | GitHub Issues | OK |
| - License | OSI-onaylı lisans | Apache-2.0 | OK |
| - Documentation | Kullanıcı + tasarım docs | docs/ | OK |
| - Other | Public repo | GitHub | OK |
| **CHANGE CONTROL** | | | |
| - Version Control | Distributed VCS | git | OK |
| - Unique Versions | SemVer | CHANGELOG.md | OK |
| - Release Notes | Her release | CHANGELOG.md + Releases | OK (Faz 1+) |
| **REPORTING** | | | |
| - Bug Reporting | Public + private | SECURITY.md + Issues | OK |
| - Vulnerability Reporting | Private channel | SECURITY.md + CVD | OK |
| - Response Time | < 14 days | CVD policy | OK |
| **QUALITY** | | | |
| - Build System | Otomatize | Buildroot + CI | OK (Faz 1+) |
| - Working Build | Continuous | GitHub Actions | OK |
| - Automated Tests | En az 1 | tests/ scaffolding | OK (Faz 1+) |
| - Test Coverage | Görünür | TBD | Faz 5 |
| - Warning Flags | -Werror veya equivalent | shellcheck strict, markdownlint | OK |
| **SECURITY** | | | |
| - Secure Development Knowledge | Maintainer eğitim | docs/security/ | OK |
| - Use Crypto | Standart kütüphaneler | rustls, nftables | OK |
| - Crypto Algorithms | Modern (no MD5, SHA-1 for sec) | SHA-256+, RSA-3072+ | OK |
| - Vulnerability Response | <14 days | CVD policy | OK |
| **ANALYSIS** | | | |
| - Static Analysis | En az 1 tool | shellcheck, hadolint, Trivy | OK |
| - Dynamic Analysis | En az 1 tool | Faz 3 (Lynis, OpenSCAP) | Faz 3 |

Tahmini: **Passing tier hemen elde edilebilir.**

## Silver Level Ek Kriterleri

| Kategori | Kriter | Durum |
|---|---|---|
| **BASICS** | DCO / CLA | DCO (CONTRIBUTING.md) | OK |
| **BASICS** | Roles documented | GOVERNANCE.md | OK |
| **BASICS** | Code of Conduct | CODE_OF_CONDUCT.md | OK |
| **CHANGE CONTROL** | Backup process | Yedek anahtar lokasyonu | Faz 4 |
| **REPORTING** | Response timeline | CVD policy | OK |
| **QUALITY** | Coding standards documented | docs/dev/coding-standards.md | OK |
| **SECURITY** | Hardening (browser headers vb.) | N/A (no web UI) | N/A |
| **ANALYSIS** | All inputs immutable | Edge Agent input validation | Faz 2 |

Tahmini: **Silver Faz 3 sonu** elde edilebilir.

## Gold Level Ek Kriterleri

| Kategori | Kriter | Hedef |
|---|---|---|
| **BASICS** | 2+ maintainer | Faz 4+ |
| **REPORTING** | Public response timeline | CVD policy var | OK |
| **QUALITY** | Test coverage ≥80% | tests/coverage | Faz 5 |
| **SECURITY** | Cryptographic mechanisms peer-reviewed | TLS/Sigstore | OK |
| **SECURITY** | Hardening (memory-safe lang) | Rust (Edge Agent) | OK |
| **ANALYSIS** | Fuzzing | cargo-fuzz | Faz 5 |

Tahmini: **Gold Faz 6+** elde edilir.

## Otomatik Tracking

`.github/workflows/scorecard.yml` her hafta:

- OpenSSF Scorecard skoru
- Branch protection check
- Pinned dependencies check
- Security policy check
- Vulnerability disclosure check

Skor: <https://api.securityscorecards.dev/projects/github.com/Okan-wqm/Suderra-OS>

## Başvuru Adımları (Faz 0.5)

1. <https://www.bestpractices.dev/en/signup> adresinden hesap aç
2. Proje URL'sini ekle
3. Kriterleri tek tek doldur
4. Badge URL'ini README.md'ye ekle
5. Yıllık review

## Referanslar

- [OpenSSF Best Practices Badge](https://www.bestpractices.dev/en)
- [Passing criteria](https://www.bestpractices.dev/en/criteria/0)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [docs/security/cvd-policy.md](../security/cvd-policy.md)

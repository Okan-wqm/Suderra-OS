# Governance — Suderra OS

> **Status:** Initial. Proje büyüdükçe revize edilir.

## Proje Türü

Suderra OS, başlangıçta **single-maintainer** modeliyle ilerleyen ticari/endüstriyel bir proje. Hedef: olgunlaştıkça **multi-maintainer** ve community-driven hale gelmek.

## Karar Mekanizması

### Mevcut Faz (0-3)

Tek karar verici: proje maintainer'ı (`@okan-wqm`)

- Mimari kararlar: ADR ile kaydedilir
- Kod değişiklikleri: PR + self-review (Faz 4 öncesi)
- Güvenlik kararları: tek karar, gözlemlemek için CHANGELOG'a yazılır

### Sonraki Faz (4+)

Multi-maintainer'a geçince:
- **Lazy consensus**: PR 7 gün boyunca itiraz almazsa kabul edilir
- **Code review**: en az 1 maintainer review (security/kernel için 2)
- **Major decisions**: ADR + en az 2 maintainer onayı
- **Disagreement**: maintainer voting (majority)

## Roller

| Rol | Sorumluluk |
|---|---|
| **Maintainer** | Karar verme, merge yetkisi, release |
| **Reviewer** | PR review, ama merge yetkisi yok |
| **Contributor** | Kod, doküman, issue katkısı |
| **Security Team** | Vulnerability triage, CVD yönetimi |

## Maintainer Olma

Faz 4+:
1. 6+ ay aktif contributor olarak çalış
2. Mevcut maintainer önerir
3. Diğer maintainer'lar lazy consensus ile onaylar
4. `MAINTAINERS.md`'ye eklenir
5. CODEOWNERS güncellenir

## Maintainer'lık Kaybetme

- 6 ay aktivitesizlik (warning, sonra emeritus statüsü)
- Code of Conduct ihlali
- Güvenlik politikası ihlali
- Lazy consensus ile karar

## Karar Dokümanları

- **ADR (Architecture Decision Record):** mimari kararlar
- **CHANGELOG.md:** her release değişiklik
- **CVD policy:** vulnerability disclosure
- **GOVERNANCE.md** (bu dosya): meta-kurallar

## Branch Yönetimi

Detay: [docs/dev/branch-protection.md](docs/dev/branch-protection.md)

- `main` korumalı (force push yasak, signed commits zorunlu)
- `release/v*.x` LTS dalları
- Tüm değişiklikler PR üzerinden

## Sürüm Yönetimi

Detay: [docs/dev/release-cadence.md](docs/dev/release-cadence.md)

- SemVer (Major.Minor.Patch)
- LTS: 2 yıl güvenlik patch, 3 yıl support (CRA gereği 5+ yıl hedefe)

## Code of Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1

İhlal: `conduct@suderra.example`

## License

Bu repo: Apache-2.0
Bileşenler kendi lisanslarında ([docs/compliance/licenses.md](docs/compliance/licenses.md))

## Communication

| Kanal | Amaç |
|---|---|
| GitHub Issues | Bug, feature request |
| GitHub Discussions | Genel soru, design tartışması |
| GitHub Security Advisory | Vulnerability disclosure |
| `security@suderra.example` | Private security |
| `conduct@suderra.example` | Code of Conduct |

## İtiraz Süreci

Kararlardan memnun değilseniz:
1. İlk: PR'da yorum
2. Ardından: maintainer'lara mail
3. Son çare: GitHub Discussions'ta public discussion

## Değişiklik Süreci

Bu doküman değişiklikleri ADR + en az 2 maintainer onayı gerektirir (Faz 4+).

# CRA Annex I — Essential Cybersecurity Requirements Checklist

> **Status:** Skeleton — Faz 6'da denetlenebilir hale gelir.
>
> Bu doküman EU Cyber Resilience Act (Regulation 2024/2847) Annex I'in **madde-madde** Suderra OS karşılığını izler. CE öncesi self-assessment için zorunlu.

## Yasal Tarihler

- CRA yürürlüğe girdi: 11 Aralık 2024
- **Uygulama tarihi: 11 Aralık 2027**
- Vulnerability reporting: 11 Eylül 2026'dan itibaren

## Part I — Cybersecurity Requirements

### Section 1 — Design, development, production

| # | Gereksinim | Suderra OS Karşılama | Kanıt | Durum |
|---|---|---|---|---|
| 1(1) | Risk değerlendirme temelli güvenlik | docs/security/threat-model.md (STRIDE) | Doküman + ADR | Skeleton |
| 1(2) | Risk değerlendirme dokümante | docs/security/threat-model.md | Doküman | Skeleton |
| 1(3) | Yapılan güncellemeler vendor sorumluluğunda | RAUC OTA + 5+ yıl support | docs/compliance/support-period.md | Faz 4 |

### Section 2 — Properties (Annex I.II)

| # | Gereksinim | Suderra OS Karşılama | Kanıt | Durum |
|---|---|---|---|---|
| 2(a) | Uygun seviyede cybersecurity | Defense-in-depth (boot, kernel, app) | ARCHITECTURE.md | Tasarım hazır |
| 2(b) | Bilinen exploitable zafiyet **yok** | CVE tracking, patch SLA | docs/security/cve-process.md | Faz 5 |
| 2(c) | Güvenli default config | DEV/PROD variant ayrımı, PROD secure | Config.in | Tasarım hazır |
| 2(d) | Bütünlük koruması | dm-verity + Secure Boot | ADR-0005 | Faz 3 |
| 2(e) | İşleme sınırlı veri | Sadece telemetry, no PII | docs/security/threat-model.md | Tasarım hazır |
| 2(f) | Yetkisiz erişime karşı koruma | mTLS, no SSH (PROD), seccomp | ARCHITECTURE.md | Faz 3 |
| 2(g) | Veri gizliliği | TLS 1.3 (rustls), LUKS2 at-rest | Edge Agent built-in | Faz 3 |
| 2(h) | Veri bütünlüğü | dm-verity, SQLCipher | ADR-0005 | Faz 3 |
| 2(i) | Veri minimizasyonu | Edge Agent: gerekli sensör verisi | Edge Agent code | Faz 2 |
| 2(j) | Erişilebilirlik (availability) | A/B partition + watchdog | ADR-0004 | Faz 4 |
| 2(k) | Diğer sistemlere etki sınırlı | nftables outbound whitelist | nftables.conf | Faz 3 |
| 2(l) | Saldırı yüzeyini minimize | 50MB imaj, 3-5 daemon | README.md | Faz 1+3 |
| 2(m) | Saldırı etkisini azalt | seccomp, capabilities, namespace | systemd unit | Faz 3 |
| 2(n) | Security-relevant log + monitoring | journald + remote syslog | docs/operations/debug.md | Faz 5 |

### Section 3 — Vulnerability Handling

| # | Gereksinim | Suderra OS Karşılama | Kanıt | Durum |
|---|---|---|---|---|
| 3(1) | Zafiyetlerin tespiti ve dokümantasyonu | SBOM (CycloneDX) | scripts/gen-sbom.sh | Faz 5 |
| 3(2) | SBOM yayınlama (en az top-level) | CycloneDX 1.5 JSON | Release artifact | Faz 5 |
| 3(3) | Zafiyetleri zamanında düzelt | CVE SLA: 7 gün (critical) | docs/security/cve-process.md | Faz 5 |
| 3(4) | Güvenli güncelleme dağıtımı | RAUC + imza | ADR-0004 | Faz 4 |
| 3(5) | Coordinated Vulnerability Disclosure | docs/security/cvd-policy.md | Doküman | P1 |
| 3(6) | Üçüncü taraflarla bilgi paylaşımı | GHSA + CVE talep | SECURITY.md | Faz 5 |
| 3(7) | Public security advisory mekanizması | GitHub Security Advisories | SECURITY.md | Hazır |
| 3(8) | Düzeltme sonrası iletişim | Release notes + müşteri mailing | CHANGELOG.md | Faz 5 |

## Part II — Vulnerability Handling Processes

| # | Gereksinim | Karşılama |
|---|---|---|
| 1 | SBOM çıkar | scripts/gen-sbom.sh (Faz 5) |
| 2 | Zafiyetleri identify ve dokümante et | cve-process.md, VEX |
| 3 | Düzeltmeler için süreç | RAUC OTA + SLA |
| 4 | Test mekanizması | tests/security/ + dış pen-test |
| 5 | Coordinated disclosure policy | cvd-policy.md |
| 6 | Düzeltme/güncellemeler için bilgi paylaşımı | release verify guide |
| 7 | Bildirim sonrası süresel etkili düzeltme | SLA matris (cve-process.md) |
| 8 | Multi-faktör korumalı update mekanizması | RAUC imza + dm-verity + cosign |

## Reporting Obligations (Article 14)

| Süre | Eylem | Hedef |
|---|---|---|
| 24 saat | Erken uyarı bildirimi | ENISA + CSIRT |
| 72 saat | İlk değerlendirme bildirimi | ENISA + CSIRT |
| 14 gün | Düzeltme veya azaltma raporu | ENISA |

> İç süreç: 24/7 security@ monitoring + escalation runbook ([incident-response.md](../security/incident-response.md))

## Technical Documentation (Annex VII)

- [ ] Ürün tanımı + amaç
- [ ] Tasarım, geliştirme, üretim açıklaması
- [ ] Cybersecurity risk assessment
- [ ] SBOM (CycloneDX)
- [ ] CVE handling süreç dokümantasyonu
- [ ] Test sonuçları (Lynis, OpenSCAP, pen-test)
- [ ] CE Declaration of Conformity (eu-doc-template.md)
- [ ] Support period beyanı (support-period.md)

## EU Declaration of Conformity (Article 28)

→ [docs/compliance/eu-doc-template.md](eu-doc-template.md)

## Conformity Assessment

Suderra OS'in beklenen sınıfı: **Class II (default)**

- Class I: Self-assessment yeterli (Annex II/IV)
- **Class II:** Self-assessment OR Third-party (Notified Body)
- Class III (Important): Third-party Notified Body zorunlu (mesela kritik altyapı)

Self-assessment seçimi:
- Daha hızlı (Notified Body yok)
- Vendor sorumluluğu yüksek
- AB ürün denetimleri sırasında dokümantasyon zorunlu

## Yapılacaklar

- [ ] Her madde için detaylı kanıt dosyası (Faz 6)
- [ ] CE marking declaration draft (Faz 6)
- [ ] Notified Body değerlendirmesi (gerekirse, Faz 6)
- [ ] Müşteri eğitim materyali

## Referanslar

- [EU CRA — Regulation 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [Annex I — Essential Requirements](https://streamlex.eu/annexes/cra-en-annex-i/)
- [CRA FAQ — ORCWG](https://cra.orcwg.org/)
- [ENISA CRA guidance](https://www.enisa.europa.eu/)

# CRA (Cyber Resilience Act) Hazırlık Durumu

> **Status:** Skeleton — Faz 6 (sertifikasyon hazırlığı) için.

## Genel

AB Cyber Resilience Act (Regulation 2024/2847) AB pazarına satılan tüm "dijital element içeren ürünler" için zorunlu hale geldi (2027 itibariyle uygulanacak).

Suderra OS hangi sınıfta:

- **Class II** (default sınıf) — endüstriyel cihazlar
- Self-assessment yeterli (Class III ise dış denetim gerekir)

## Temel Yükümlülükler (Annex I)

### 1. Essential Cybersecurity Requirements

| Gereksinim | Karşılama | Durum |
|---|---|---|
| Güvenli default config | DEV/PROD varyantı, PROD secure | OK (Faz 3 sonu) |
| Bilinen exploit edilebilir zafiyet yok | CVE tracking, patch SLA | Faz 5 |
| Identity-based access control | mTLS, RBAC | OK |
| Confidentiality protection | TLS 1.3, LUKS2 | OK (Faz 3) |
| Integrity protection | dm-verity, Secure Boot | OK (ADR-0005) |
| Veri minimizasyonu | Sadece telemetry, no PII | OK |
| Availability + resilience | A/B partition, rollback, watchdog | OK (Faz 4) |
| Saldırı yüzeyi minimize | 50MB imaj, 3-5 daemon | OK (Faz 1+3) |
| Saldırı etkisi azalt | seccomp, capabilities, namespace | OK |
| Security event log + monitoring | journald + remote syslog | Faz 5 |
| Security güncellemeleri | RAUC OTA + 5 yıl commitment | OK (Faz 4) |

### 2. Vulnerability Handling (Annex I, Section 2)

| Yükümlülük | Karşılama |
|---|---|
| Vulnerability disclosure policy | SECURITY.md |
| SBOM provide | CycloneDX, her release |
| Zafiyet düzeltme + güvenli güncelleme | RAUC OTA |
| Düzeltme bilgisi paylaşma | GHSA + müşteri mail listesi |
| Açıkça yayımlanmamış güvenlik testleri | İç pen-test + yıllık dış pen-test |
| Hız: ciddi açıklar için güncelleme yayınla | CVSS 9+ için 7 gün SLA |

### 3. Reporting Obligations

CRA Article 14 gereği:

- **24 saat içinde:** Aktif olarak istismar edilen zafiyetler ENISA'ya raporlanmalı
- **72 saat içinde:** Detaylı rapor
- **14 gün içinde:** Düzeltme raporu

İç süreç:

- Incident response runbook (Faz 6)
- 24/7 <security@suderra.example> monitoring
- Otomatik triage + escalation

## Teknik Dosya (Technical Documentation)

CRA Annex II gereği teknik dosya:

- [ ] Ürün tanımı (Suderra OS + Edge Agent)
- [ ] Tasarım, geliştirme, üretim açıklaması
- [ ] Cybersecurity risk assessment
- [ ] SBOM (CycloneDX)
- [ ] Test sonuçları (pen-test, lynis)
- [ ] CE marking declaration
- [ ] Vulnerability handling policy

## CE Marking

- Self-declaration of Conformity (Class I/II)
- Class III için Notified Body sertifikası gerekir
- Suderra OS Class II beklentisi → self-declaration

## Yapılacaklar

- [ ] Detaylı CE marking declaration (Faz 6)
- [ ] Müşteri bildirim listesi
- [ ] 24-72 saat incident response runbook
- [ ] Yıllık güvenlik test programı
- [ ] 5 yıl support commitment dokümantasyonu

## Referanslar

- [EU CRA — Regulation 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [ENISA CRA implementation guidance](https://www.enisa.europa.eu/)
- [Open Source Foundation CRA roadmap](https://www.linuxfoundation.eu/)

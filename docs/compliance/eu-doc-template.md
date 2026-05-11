# EU Declaration of Conformity — Şablon

> **Status:** Draft template. Her ürün release'i ile finalize edilir.
>
> CRA Article 28 + Annex IV gereği. CE marking için zorunlu.

---

## 1. Üretici (Manufacturer)

- **Ad:** [Şirket adı]
- **Adres:** [Tam adres]
- **Yetkilendirilmiş temsilci (AB içinde):** [Yetkilendirilmiş kurum, varsa]
- **İletişim:** support@suderra.example

## 2. Ürün

- **Marka:** Suderra
- **Model:** Suderra OS
- **Sürüm:** vX.Y.Z
- **Tanımlayıcı:** SHA256 hash (release artifact'inin)
- **Tür:** Endüstriyel edge işletim sistemi
- **Hedef donanım:** Industrial PC (x86_64) / ARM SBC (aarch64)
- **Ek bilgi:** Suderra Edge Agent host'lar (aquaculture)

## 3. Beyan

Bu beyan, üreticinin tek sorumluluğunda düzenlenmiştir.

Yukarıda tanımlanan ürün, aşağıdaki AB yasal mevzuatına uygundur:

- **Regulation (EU) 2024/2847** of the European Parliament and of the Council of 23 October 2024 on horizontal cybersecurity requirements for products with digital elements (Cyber Resilience Act)

## 4. Uygulanan Standartlar

Aşağıdaki harmonize standartlara veya teknik şartnamelere uyum sağlanmıştır:

- **IEC 62443-4-1:2018** — Secure product development lifecycle requirements
- **IEC 62443-4-2:2019** — Technical security requirements for IACS components
- **EN ISO/IEC 27001:2022** — Information security management
- **EN 18031-1:2024** — RED cybersecurity (uygulanabilirse)
- **CycloneDX 1.5** — SBOM format
- **OpenVEX 0.2.0** — Vulnerability disclosure

## 5. Conformity Assessment

- [x] Self-assessment (Class II)
- [ ] Third-party (Notified Body — varsa)

Notified Body (yoksa boş bırak):
- **Ad:**
- **Numara:**
- **Sertifika no:**
- **Geçerlilik:**

## 6. Ek Bilgiler

- Technical documentation: [docs/compliance/cra-annex-i-checklist.md](cra-annex-i-checklist.md)
- SBOM: `output/sbom.cyclonedx.json`
- Support period: [docs/compliance/support-period.md](support-period.md)
- Vulnerability disclosure policy: [docs/security/cvd-policy.md](../security/cvd-policy.md)

## 7. İmza

Bu beyanı [ad, unvan] [yer]'de [tarih] tarihinde imzalamıştır.

```
İmza:    _______________________

Ad:      [Ad Soyad]
Unvan:   [Yetkili kişinin unvanı]
Tarih:   YYYY-MM-DD
Yer:     [Şehir, ülke]
```

---

## Notlar (template doldurulurken)

- Her LTS release için yeni DoC
- DoC ile birlikte technical documentation paketi hazır olmalı
- Müşteriye CD/USB veya HTTPS link ile sun
- 10 yıl saklanmalı (CRA Article 18(3))

## Referanslar

- [CRA Annex IV — EU Declaration of Conformity](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [CRA Article 28](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [CE marking guide — EC](https://single-market-economy.ec.europa.eu/single-market/ce-marking_en)

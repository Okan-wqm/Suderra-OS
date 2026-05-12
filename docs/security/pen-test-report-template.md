# Penetration Test Raporu — Şablon

> Bu şablon Suderra OS için iç veya dış penetration test sonrası kullanılır. IEC 62443-4-1 SVV-3 ve CRA Annex I.I.3.b gereği.

---

## Kapak

- **Test başlığı:** Suderra OS Penetration Test — `<release>`
- **Test tarihi:** YYYY-MM-DD — YYYY-MM-DD
- **Test ekibi:** İç ekip / Dış firma adı
- **Hedef ürün:** Suderra OS `vX.Y.Z`
- **Hedef donanım:** [Advantech UNO-2271G / QEMU / Raspberry Pi CM4]
- **Rapor versiyonu:** v1.0
- **Confidentiality:** CONFIDENTIAL — Suderra OS internal + müşteri NDA

## Executive Summary

(1-2 sayfa, yönetici tarafından okunabilir)

- Test kapsamı + kısıtları
- Skor (Critical/High/Medium/Low bulgu sayıları)
- En kritik bulgular
- Önerilen acil aksiyonlar

## Test Kapsamı

| Kapsam | Dahil mi? |
|---|---|
| Boot zinciri (UEFI, dm-verity) | Y/N |
| Kernel sertleştirme | Y/N |
| systemd unit'lar | Y/N |
| Edge Agent (Rust) | Y/N |
| RAUC OTA | Y/N |
| Network (nftables, exposed services) | Y/N |
| Fiziksel saldırılar (lab) | Y/N |
| Supply chain (build pipeline) | Y/N |

## Metodoloji

- [x] Black-box (sıfırdan, vendor bilgisi yok)
- [ ] Grey-box (kısmen bilgi)
- [ ] White-box (kaynak kod erişimi)

Çerçeve:

- OWASP Embedded Application Security
- OWASP IoT Top 10
- MITRE ATT&CK (Embedded/ICS matrix)
- NIST SP 800-115

## Otomatik Tarama Sonuçları

| Tool | Skor | Hedef | Sonuç |
|---|---|---|---|
| Lynis | XX | ≥85 | PASS/FAIL |
| OpenSCAP (CIS DIL) | XX% | ≥80% | PASS/FAIL |
| Nmap external | X port | 0 | PASS/FAIL |
| Trivy CVE | X critical | 0 | PASS/FAIL |
| Cosign verify | OK | OK | PASS/FAIL |

## Bulgular

Her bulgu için:

### F-XXX: <Başlık>

- **Severity:** Critical / High / Medium / Low / Info
- **CVSS 3.1:** X.X (vector: ...)
- **Kategori:** Kernel / Network / Boot / App / Supply Chain / etc.
- **Etkilenen:** Tüm Suderra OS / sadece DEV variant / specific
- **CWE:** CWE-XXX
- **Beklenen gerçek davranış:** ...
- **Bulgu açıklaması:** ...
- **Reproduksiyon adımları:**
  1. ...
  2. ...
- **Kanıt (screenshot / log):**

  ```
  ...
  ```

- **Etki:** ...
- **Önerilen düzeltme:** ...
- **Geçici workaround:** ...
- **Patch zamanlaması:** Önerilen SLA

## Bulgu Özeti

| ID | Severity | Başlık | Durum |
|---|---|---|---|
| F-001 | Critical | ... | Open |
| F-002 | High | ... | Fixed in vX.Y.Z |
| F-003 | Medium | ... | Accepted risk |
| ... | | | |

## Pozitif Bulgular (kanıtlanmış sertleştirme)

- [x] dm-verity bütünlük: tamper testi başarısız oldu (kernel reddetti) ✓
- [x] Secure Boot zinciri: imzasız bootloader yüklenmedi ✓
- [x] seccomp: yasaklı syscall'lar EPERM döndü ✓
- [x] Kernel lockdown: /dev/mem erişimi engellendi ✓
- [x] Network: dış nmap 0 port gördü ✓
- [x] RAUC: imzasız bundle reddedildi ✓

## Önerilen İyileştirmeler (severity dışı)

- ...
- ...

## Test Sınırlamaları

- Donanım-spesifik testler için OEM dokümantasyonu yetersiz oldu
- TPM 2.0 attestation testi yapılamadı (lab eksik)
- Kullanıcı verilerine erişim yetkimiz olmadı

## Sonuç

Suderra OS `vX.Y.Z` için pen-test:

- [ ] PASS — Üretim için onaylanmaz (kritik/yüksek bulgu yok)
- [ ] PASS WITH CONDITIONS — Belirtilen düzeltmeler sonrası onay
- [ ] FAIL — Kritik/yüksek bulgular düzeltilmeli

## Ekler

- A: Komut + araç çıktıları (raw)
- B: Pcap'ler (varsa)
- C: SBOM ile karşılaştırma
- D: Yeniden test gerekli alanlar

## Test Ekibi İmza

| İsim | Rol | İmza | Tarih |
|---|---|---|---|
| ... | Lead Pentester | | |
| ... | Reviewer | | |

---

## Referanslar

- [OWASP Embedded Application Security](https://owasp.org/www-project-embedded-application-security/)
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [docs/security/pen-test-checklist.md](pen-test-checklist.md)

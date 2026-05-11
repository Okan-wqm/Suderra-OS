# ADR-0006: IEC 62443 hedef seviyesi olarak SL 2 seçimi

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** @okan-wqm
- **Tags:** compliance, security, certification

## Context

IEC 62443-4-2, IACS (Industrial Automation and Control Systems) bileşenleri için 4 farklı **Security Level (SL)** tanımlar. Hedef SL'nin seçimi:

- Saldırgan profili varsayımını belirler
- Sertifikasyon maliyetini etkiler (200-500k TL → 1.5M+ TL)
- Gerekli teknik kontrolleri belirler (multi-factor auth, secure element, SIEM, vb.)
- Pazar segmentasyonunu etkiler

| SL | Saldırgan | Yetenek | Kaynak | Motivasyon | Tipik müşteri |
|---|---|---|---|---|---|
| SL 1 | Kasıtsız | Düşük | Düşük | Hata | İç süreç hatası |
| **SL 2** | **Bilinçli** | **Düşük** | **Düşük** | **Genel** | **Sektör standardı: imalat, su ürünleri, gıda** |
| SL 3 | Bilinçli | Yüksek | Orta | IACS-spesifik | Kritik altyapı (su, enerji, ulaşım) |
| SL 4 | Bilinçli | Yüksek | Yüksek | State actor | Savunma, nükleer, ulusal kritik altyapı |

Hangi seviyeyi hedeflediğimizi şimdi karara bağlamak gerekir çünkü:
- Mimari kararlar (SL3+: secure element, side-channel hardening) tasarım aşamasında verilmeli
- Sertifikasyon hazırlığı (Faz 6) seviye-spesifik kanıt gerektirir
- Pazar pozisyonu erkenden netleşmeli

## Decision

**Suderra OS v1.0 LTS için hedef seviye: IEC 62443-4-2 SL 2 (EDR).**

SL 3'e geçiş yolu **mimari olarak açık tutulur** ama Faz 7 (pilot) sonrası, müşteri profili netleştiğinde yeniden değerlendirilir.

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Karar |
|---|---|---|---|
| **SL 2 (seçilen)** | Uygulama zaten SL2; sektör standardı (aquaculture); self-assessment yeterli; tek geliştirici sürdürebilir; 200-500k TL sertifikasyon | State-actor / hedefli IACS saldırılarına karşı korumasız | **SEÇİLDİ** |
| SL 1 | Çok ucuz, basit | Bilinçli saldırgana karşı tasarlanmamış; pazarda anlamsız (sektör SL2 bekliyor) | Reddedildi: pazar gereksiniminin altında |
| SL 3 | Premium pozisyon; kritik altyapı erişimi açılır; CRA Class III ürünler için zorunlu | Notified Body zorunlu (~1-1.5M TL); secure element + side-channel hardening + SIEM + 2FA gerektirir; uygulama refactor şart; tek geliştirici taşıyamaz; aquaculture için overkill | Reddedildi: maliyet/değer dengesi başlangıçta uymuyor; Faz 7+ yeniden değerlendirilir |
| SL 4 | En yüksek güvenlik | State-actor varsayımı; askeri/nükleer dışı pazar için anlamsız; 2M+ TL; tek geliştirici için imkansız | Reddedildi: hedef pazar dışı |

## Consequences

### Positive
- **Uygulama-OS tutarlılığı:** Edge Agent zaten SL2 için yazılmış; çift seviye karmaşıklığı yok
- **Maliyet sürdürülebilir:** Tek geliştirici / küçük ekip için ulaşılabilir sertifikasyon
- **Self-assessment yeterli:** CRA Class II ile uyumlu, Notified Body zorunlu değil
- **Pazar uygunluğu:** Aquaculture, imalat, gıda sektörü standardı
- **Hızlı time-to-market:** Faz 6 (3-4 hafta) içinde gap analizi tamamlanır
- **SL3 kapısı açık:** Mimari kararlar (dm-verity, Secure Boot, TPM 2.0, mTLS) SL3'e migrasyon yolunu engellemez

### Negative
- **State actor / hedefli IACS saldırılarına karşı sınırlı:** APT, organize crime, sofistike IACS saldırganı için yetersiz
- **Kritik altyapı satışı kapalı:** Elektrik, su, gaz, savunma sektörü SL3+ ister
- **NIS2 directive bazı sektörler kapsamında:** Aquaculture şimdilik kapsam dışı ama mevzuat değişebilir
- **Müşteri pazarlığında dezavantaj:** "SL3" sertifikalı rakip varsa pazar payı kaybı riski
- **Pazarlama yumuşak:** "Sertifikalı" demek ama hangi SL olduğunu netleştirmek gerek

### Neutral / Trade-offs
- SL3 upgrade'e geçiş Faz 8+ olarak ertelendi
- Pilot saha geri bildirimi gerçek tehdit modelini netleştirecek (telemetri verisinden)
- CRA Class kararı SL3 ile bağlantılı: Class III olursa SL3 zorunlu

## Implementation Notes

### SL2 için zaten mimaride VAR olan kontroller

Suderra OS architecture'ı **SL2'yi karşılar ve SL3 birçok kontrolünü zaten içerir**:

| Kontrol | Seviye | Durum |
|---|---|---|
| TLS 1.3 (rustls) | SL2+ | OK |
| mTLS authentication | SL2-3 | OK |
| dm-verity bütünlük | SL2-4 | OK (ADR-0005) |
| UEFI Secure Boot | SL2-4 | OK (ADR-0005) |
| TPM 2.0 | SL2-3 | OK |
| Kernel lockdown + KASLR + SMEP/SMAP | SL2-3 | OK (kernel-fragment.config) |
| seccomp + capabilities + namespaces | SL2-3 | OK |
| nftables default DROP | SL2-3 | OK |
| RAUC + A/B partition + imza | SL2-3 | OK (ADR-0004) |
| SBOM + VEX + CVD policy | SL2-3 | OK |
| journald + remote syslog | SL2-3 | OK (Faz 5) |
| LUKS2 /data encryption | SL2-3 | OK (Faz 3) |

### SL3 için EKSİK olan kontroller (Faz 8+ gerekli)

| Kontrol | Mevcut SL2 plan | SL3 gereği | Faz |
|---|---|---|---|
| Multi-factor authentication | mTLS + key | mTLS + HW token / biometric | Faz 8 |
| Hardware tamper resistance | TPM 2.0 | Secure element (smartcard chip), epoxy, mesh | Faz 8 |
| Side-channel attack hardening | Stock crypto | Constant-time + masking implementations | Faz 8 |
| Real-time SIEM integration | journald → syslog | Live anomaly detection, ML-based | Faz 8 |
| Tamper-evident logging | Remote syslog | Hash-chained log, WORM storage | Faz 8 |
| Network segmentation | Single zone | DMZ + conduits + zones | Faz 8 |
| Insider threat continuous monitoring | RBAC + audit | Behavior analytics + 2-person rule | Faz 8 |
| Rollback HW counter | RAUC version | TPM PCR monotonic counter | Faz 8 |
| Pen-test sıklığı | Yıllık | 6 aylık + sürekli red team | Faz 8 |
| Notified Body certification | Self-assessment | TÜV/ISA Secure 3rd party | Faz 8 |

### Sertifikasyon Yol Haritası

```
Faz 6 (3-4 hafta)        → SL 2 self-assessment, iç pen-test
Faz 7 (4-6 hafta)        → Pilot saha 1-3 cihaz, gerçek dünya feedback
Faz 7 sonu               → Müşteri profili netleşir
                           ↓
                  KARAR: SL2 yeterli mi, SL3 gerekli mi?
                           ↓
            ┌──────────────┴───────────────┐
            ↓                              ↓
    SL 2 yeterli                    SL 3 hedefli
    → Üretim onayı                  → ADR-0006-A (yeni)
    → CRA Class II                  → Faz 8: SL3 gap fix (6-12 ay)
                                    → Notified Body engaged
                                    → CRA Class III (varsa)
```

## Trigger'lar (SL3 değerlendirmesi için)

Aşağıdaki durumlar SL3 kararını ZORUNLU kılabilir:

1. **Pilot müşteri kritik altyapıya geçer** (örn. su işleme tesisi)
2. **NIS2 directive aquaculture'ı kapsama alır** (mevzuat değişikliği)
3. **Müşteri sözleşmesinde SL3 talebi**
4. **Devlet alıcısı görüşmeleri** (yıllık 500k+ TL volume)
5. **Tehdit modeli değişir** (sahada APT-grade saldırı tespit edilirse)
6. **CRA Class III sınıflaması** (Notified Body assessment'ından çıkarsa)

Bu trigger'lardan biri gerçekleşirse: yeni ADR (ADR-0006-A veya superseded) ve Faz 8 planı.

## References

- IEC 62443-3-3:2013 (System security requirements and security levels)
- IEC 62443-4-2:2019 (Component security requirements)
- [ISA Secure SSA Certification](https://isasecure.org/)
- [IEC 62443 SL definitions — jtsec](https://www.jtsec.es/blog-entry/68/iec-62443-part-4-2-technical-security-requirements-for-iacs-components)
- ADR-0005: dm-verity + Secure Boot zinciri (SL2/SL3 ortak temel)
- [docs/compliance/iec-62443-4-2-component-requirements.md](../compliance/iec-62443-4-2-component-requirements.md) — CR-by-CR mapping
- [docs/compliance/cra-readiness.md](../compliance/cra-readiness.md) — CRA Class kararı
- [docs/security/threat-model.md](../security/threat-model.md) — Hedef saldırgan profili

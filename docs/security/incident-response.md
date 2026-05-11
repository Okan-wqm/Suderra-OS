# Incident Response Runbook

> **Status:** Skeleton — Faz 6'da detaylanır.

## Amaç

Bir güvenlik olayı (incident) tespit edildiğinde sahada çalışan Suderra OS cihazlarına yönelik müdahale prosedürü. CRA Article 14 ve IEC 62443-4-1 SI gerekleri.

## Olay Sınıfları

| Severity | Tanım | Örnek |
|---|---|---|
| **P0 — Critical** | Aktif istismar, fleet etkilenir, gizlilik/bütünlük/erişilebilirlik tehlikede | RCE 0-day, OTA signing key sızıntısı |
| **P1 — High** | Yüksek etki, hızlı patch gerekli | CVSS 7+ CVE, müşteri rapor edilmiş davranış değişimi |
| **P2 — Medium** | Düşük-orta etki, plan içinde patch | CVSS 4-6, edge case bug |
| **P3 — Low** | Düşük etki, sonraki release | CVSS <4, kozmetik |

## SLA

| Severity | İlk yanıt | Triage | Patch deploy |
|---|---|---|---|
| P0 | 1 saat | 4 saat | 24-72 saat |
| P1 | 4 saat | 24 saat | 7 gün |
| P2 | 24 saat | 7 gün | 30 gün |
| P3 | 7 gün | 30 gün | Yıllık release |

## P0 Akışı (Critical)

```
0:00  Tespit (alert, müşteri bildirimi, security@)
   ↓
0:30  On-call ekip toplandı (security lead, infra, comms)
   ↓
1:00  İlk durum:
       - Etkilenen cihaz sayısı?
       - Saldırgan içerde mi? (forensic)
       - Yayılma riski?
   ↓
2:00  Containment:
       - Etkilenen fleet'i izole et (firewall + cloud cert revoke)
       - OTA sunucusunu kilitleme moduna al
       - Müşteri ilk bildirim (acil)
   ↓
4:00  Investigation:
       - Root cause analysis
       - Forensic toplama (etkilenen 1-2 cihazdan)
       - Saldırgan profili belirle
   ↓
8:00  Mitigation:
       - Workaround push (config update, OTA disable)
       - Customer guidance email
   ↓
24:00 ENISA bildirimi (CRA Art 14 24 saat erken uyarı)
   ↓
48-72:00 Patch geliştir + test
   ↓
72:00 ENISA detaylı bildirim
   ↓
RC    Release candidate + dış pen-test
   ↓
GA    Production release + OTA dağıtım
   ↓
14 gün ENISA düzeltme raporu
   ↓
30 gün Post-mortem yayınla (public, redacted)
```

## Tools & Channels

| Kanal | Amaç |
|---|---|
| PagerDuty veya OpsGenie | On-call rotation, alert (Faz 5'te kurulum) |
| Slack `#incident` | Eş-zamanlı koordinasyon |
| `security@suderra.example` | Resmi iletişim |
| `incident-comms@suderra.example` | Müşteri bildirim mailing listesi |
| GitHub Security Advisory | Public disclosure |
| ENISA SPOC | https://www.enisa.europa.eu/topics/incident-reporting |

## Roller

| Rol | Sorumluluk | Kim (Faz 6+) |
|---|---|---|
| **Incident Commander** | Genel koordinasyon | On-call security lead |
| **Tech Lead** | Root cause + patch | Maintainer (alan bazlı) |
| **Comms Lead** | Müşteri + ENISA + public | Comms team / lead |
| **Forensics** | Log + memory analysis | Security team |
| **Customer Liason** | Müşteri sorularına yanıt | Support team |

## Forensic Tools

Cihaz üzerinde (canlı):
- `journalctl -b` (boot log)
- `dmesg` (kernel log)
- `ps auxf` (process tree)
- `ss -tulpn` (network)
- `lsof` (open files)
- `last`, `lastlog` (login history, varsa)

Lab analizi:
- Memory dump (eğer mümkün)
- Disk image (dd)
- Volatility framework
- Suricata pcap (network)

## Containment Stratejileri

| Strateji | Kullanım |
|---|---|
| **Cloud cert revoke** | Cihazları cloud broker'dan kes (mTLS) |
| **OTA pause** | Update sunucusu yanıt vermesin |
| **Firewall block** | Cihaz çıkış trafiği belirli IP/port'a kısıt |
| **Factory reset** | Etkilenen cihazlar (son çare) |
| **Physical disconnect** | Saha personeli müdahale (son çare) |

## Post-Mortem

Her P0/P1 sonrası 7 gün içinde:
- Olay zaman çizgisi
- Root cause (5 Whys)
- Detection lag (ne zaman olduysa vs. ne zaman algıladık)
- Response lag
- Etkilenen müşteri/cihaz sayısı
- Veri sızıntısı (varsa)
- Aksiyon maddeleri (önleyici)
- Dış paylaşılabilir versiyon (redacted)

Şablon: TBD Faz 6.

## Tabletop Exercises

Yılda en az 2 kez:
- Senaryoyu seç (OTA compromise, kernel 0-day, vb.)
- Tüm takım simüle et
- SLA'ları ölç
- Gap'leri runbook'a ekle

## Yapılacaklar (Faz 6)

- [ ] PagerDuty / OpsGenie setup
- [ ] Müşteri mailing liste otomasyonu
- [ ] ENISA SPOC iletişim noktası belirle
- [ ] Customer comms şablonları
- [ ] Tabletop exercise planı
- [ ] Bug bounty programı (varsa)

## Referanslar

- [NIST SP 800-61r2 Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [CRA Article 14](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [docs/security/cvd-policy.md](cvd-policy.md)
- [docs/security/cve-process.md](cve-process.md)

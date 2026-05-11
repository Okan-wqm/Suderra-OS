# Suderra OS — Support Period (Vendor Commitment)

> **Status:** Draft.
>
> CRA Article 13(8) "support period" beyanı için. Üretim öncesi (Faz 6) finalize edilir.

## Genel Politika

Suderra OS satılan her sürüm için en az **5 yıl** güvenlik güncellemesi ve **3 yıl** feature/bug-fix güncellemesi commitment'i hedeflenir. CRA gereği ürün hayat döngüsü beklentisi ile eşleşir.

> ⚠️ Üretim öncesi finalize edilecek. Bu doküman taslaktır.

## Sürüm Sınıfları

| Sınıf | Security patch | Feature/bug | Toplam | Açıklama |
|---|---|---|---|---|
| **LTS (Long Term Support)** | 5 yıl | 3 yıl | 5 yıl | Üretim cihazları için |
| **Stable** | 2 yıl | 1 yıl | 2 yıl | Pilot saha |
| **Beta** | 6 ay | 6 ay | 6 ay | Geliştirme döngüsü |
| **Alpha** | — | — | — | Internal only |

## Şu Anki Sürümlerin Support Durumu

> Faz 0 — henüz LTS yok. Faz 6+ üretim ile başlar.

| Sürüm | Status | Security patch'e kadar | Feature patch'e kadar | EOL |
|---|---|---|---|---|
| v0.x | Alpha | — | — | İç geliştirme |
| (Faz 6+) v1.0 LTS | Stable | 2031-XX-XX | 2029-XX-XX | 2031-XX-XX |

## Security-Only Mode

Bir LTS sürümün feature support'u biter ama security support'u devam eder. Bu dönemde:

- CVE patch'leri uygulanır (CVSS 4.0+)
- Backwards-incompatible değişiklik yok
- API stability garantili
- Yeni feature yok

## End-of-Life (EOL)

EOL anlamına gelir:

- Yeni güncelleme yayınlanmaz
- CVE patch'leri yayınlanmaz
- Müşteri yeni LTS'e geçiş zorunlu
- En az 12 ay önceden bildirim
- Müşteriye migration guide verilir

## Migration Path

Major sürüm geçişi (v1 → v2):

1. v2 yayınlanır
2. v1 LTS support azalmış mod'a geçer (sadece security)
3. 12 ay overlap (her iki sürüm de destekli)
4. v1 EOL

## Lifecycle Diyagramı

```
LTS v1.0 yayın
    │
    ├── 0-2 yıl: Full support (feature + security)
    │
    ├── 2-3 yıl: Stability support (sadece bug-fix + security)
    │
    ├── 3-5 yıl: Security-only support
    │
    └── 5 yıl: EOL → migration to vN+
```

## CRA Uyumluluğu

CRA Article 13(8):
> "Manufacturers shall determine the support period in a way that reflects the time during which the product is expected to be in use."

Suderra OS:

- Endüstriyel cihazlar 7-10+ yıl çalışır
- Hedef support period: 5 yıl minimum, 7 yıl tavsiyeli
- Müşteri sözleşmesiyle uzatılabilir (extended support contract)

## Müşteri Communications

- Her release'de support deadline net belirtilir (CHANGELOG)
- Yıllık support özet raporu
- EOL 12 ay öncesinden mailing
- Public dashboard: <https://suderra.example/support-lifecycle>

## Üçüncü Taraf Bağımlılıklar

Bizim support'umuz upstream LTS ile sınırlı:

- Linux kernel: LTS cycle takip (~6 yıl her sürüm)
- Buildroot: 6 aylık release, ama 2 yıllık LTS
- Eğer upstream EOL olursa, biz kendi backport yaparız (best effort)

## Yapılacaklar

- [ ] Üretim öncesi (Faz 6) lifecycle table finalize
- [ ] Müşteri sözleşme şablonu (extended support)
- [ ] Dashboard implement (Faz 7)
- [ ] Yıllık review prosedürü

## Referanslar

- [CRA Article 13](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [Ubuntu LTS lifecycle](https://ubuntu.com/about/release-cycle)
- [RHEL lifecycle](https://access.redhat.com/support/policy/updates/errata)

# Coordinated Vulnerability Disclosure (CVD) Policy

> **Status:** Active.
>
> Bu doküman ISO/IEC 29147:2018 ve CRA Annex I.II.5 gereği Suderra OS'in vulnerability disclosure politikasını tanımlar.

## Felsefe

Açıkları bulanlarla işbirliği yaparak, son kullanıcıya zarar verme süresini minimize ederek, dürüst ve adil bir disclosure süreci uygularız.

## Kapsam

**Bu policy şu ürünleri kapsar:**
- Suderra OS imajları (tüm sürümler)
- Suderra OS build sistemi (Buildroot config, custom paketler)
- RAUC OTA mekanizması
- Boot zinciri (UEFI Secure Boot, dm-verity konfig)
- Bu repo içindeki tüm kod ve dokümantasyon

**Kapsam dışı (lütfen ilgili upstream'e bildirin):**
- Linux kernel CVE'leri → kernel.org
- Buildroot paket CVE'leri → upstream proje
- systemd / nftables / rauc CVE'leri → upstream

## Bildirim Kanalları

**Tercih sırası:**

1. **GitHub Security Advisory** (private)
   - https://github.com/Okan-wqm/suderra-os/security/advisories/new

2. **PGP-encrypted E-mail**
   - `security@suderra.example`
   - PGP key: [docs/security/pgp-key.asc](pgp-key.asc) (TODO Faz 0.5'te eklenecek)

3. **`.well-known/security.txt`** (machine-readable)
   - https://github.com/Okan-wqm/suderra-os/.well-known/security.txt

**Asla:**
- Public GitHub issue açmayın
- Public Slack/Discord'da yayınlamayın
- Twitter/social media'da bahsetmeyin (henüz)

## Beklenen Bilgi

Lütfen bildiriminizde şunları içerin:

1. **Etkilenen bileşen:** kernel CONFIG, paket adı, dosya yolu, RAUC bundle versiyonu, vb.
2. **Etkilenen sürümler:** `vX.Y.Z` ile başlayan tüm sürümler veya specific
3. **Saldırı senaryosu:**
   - Saldırgan profili (remote/local/physical)
   - Gereken yetenek seviyesi
   - PoC (varsa)
4. **Etki:** CIA üzerinde (Confidentiality / Integrity / Availability)
5. **CVSS skoru** (eğer hesaplandıysa)
6. **Önerilen düzeltme** (opsiyonel)
7. **Disclosure zaman çizelgesi** beklentiniz

## Yanıt Süreleri (SLA)

| Aşama | Süre |
|---|---|
| **İlk alındı onayı** | 72 saat |
| **İlk değerlendirme** | 7 gün |
| **Düzeltme planı** | 14 gün |
| **Public disclosure (varsayılan)** | 90 gün |

## Disclosure Süreci

```
1. Bildirim alındı
   ↓
2. Triage (severity, etki, kapsam)
   ↓
3. CVE ID talep et (varsa)
   ↓
4. Düzeltme geliştir + test et
   ↓
5. Embargo: 90 gün (default) veya bildirici ile koordine
   ↓
6. RAUC OTA hazırla (imzalı, SBOM güncelle, VEX güncelle)
   ↓
7. Müşterilere private bildirim (mailing liste)
   ↓
8. Public release (GitHub Security Advisory + CVE)
   ↓
9. Bildiriciye credit + bug bounty (varsa)
```

## Embargo

| Durum | Embargo |
|---|---|
| Kritik (CVSS ≥9, aktif istismar) | 7-14 gün |
| Yüksek (CVSS 7-8.9) | 30-60 gün |
| Orta/Düşük | 90 gün (default) |
| Bildirici uzatma isterse | Görüşülür |
| Üçüncü taraflar (kernel, vs.) | Upstream embargo ile uyumlu |

## Bug Bounty

**Mevcut durumda:** Yok (proje henüz pilot aşamada)

**Faz 6+:** Düşünülüyor. Tahmini skala:
- Critical: 5000-10000 USD
- High: 1000-3000 USD
- Medium: 200-500 USD
- Low: Acknowledgment + swag

## Hall of Fame

Bildirilen ve düzeltilen zafiyetlerin credit'i [GitHub Security Advisories](https://github.com/Okan-wqm/suderra-os/security/advisories) sayfasında ve release notes'larda yer alır.

## "Yapma" Listesi

Lütfen şunları YAPMAYIN:
- Production sistemlerinde test
- Müşteri verilerine erişme (test ortamında bile)
- DoS testleri (canlı sistemde)
- Sosyal mühendislik
- Fiziksel saldırı (lab dışında)

## Yasal

Suderra OS, **iyi niyetli** güvenlik araştırmacılarına karşı yasal aksiyon almayacaktır. "İyi niyetli" şu anlama gelir:
- Bu CVD policy'ye uyum
- Veri minimum (sadece exploit kanıtı için)
- Veriyi üçüncü kişilerle paylaşmama
- Bildirim öncesi disclosure yok

## Müşteri Bildirimi

Düzeltme yayınlanınca:
1. Mailing liste (subscribe: `security-announce@suderra.example`)
2. Release notes
3. CHANGELOG.md
4. SBOM + VEX güncellemesi
5. Dashboard alert (Faz 5)

## Referanslar

- [ISO/IEC 29147:2018 Vulnerability Disclosure](https://www.iso.org/standard/72311.html)
- [ISO/IEC 30111:2019 Vulnerability Handling Processes](https://www.iso.org/standard/69725.html)
- [CISA CVD Guidance](https://www.cisa.gov/coordinated-vulnerability-disclosure-process)
- [RFC 9116 — security.txt](https://www.rfc-editor.org/rfc/rfc9116)
- [Project Zero disclosure policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html)
- [docs/security/cve-process.md](cve-process.md)

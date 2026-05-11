# Security Policy

## Bildirim (Reporting a Vulnerability)

Suderra OS bir endüstriyel edge işletim sistemidir. Bulduğunuz güvenlik açıkları (kernel, paket, OTA, secure boot, RAUC, dm-verity, edge-agent paketleme, kayıp/zayıf imza vb.) için **public GitHub issue açmayın**.

> Detaylı Coordinated Vulnerability Disclosure süreci: [docs/security/cvd-policy.md](docs/security/cvd-policy.md)

Bildirim kanalları (tercih sırası):

1. **GitHub Security Advisory** (private): <https://github.com/Okan-wqm/suderra-os/security/advisories/new>
2. **PGP-encrypted E-posta:** `security@suderra.example`
   - PGP key: [docs/security/pgp-key.asc](docs/security/pgp-key.asc) — TODO Faz 0.5'te eklenecek
3. **`.well-known/security.txt`** (RFC 9116): <https://github.com/Okan-wqm/suderra-os/.well-known/security.txt>

**Beklenen yanıt:** 72 saat içinde alındı onayı, 14 gün içinde değerlendirme.

Lütfen şu bilgileri içerin:

1. Etkilenen bileşen (kernel CONFIG, paket adı, dosya yolu, RAUC bundle versiyonu, vb.)
2. Etkilenen Suderra OS sürüm(ler)i
3. Saldırı senaryosu (PoC, etki sınıfı, gereken erişim seviyesi)
4. Düşündüğünüz düzeltme (varsa)

## Desteklenen Sürümler

| Sürüm | Destek durumu |
|---|---|
| `v0.x` (alpha/beta) | Sadece geliştirme, üretim için **kullanmayın** |
| `v1.x` LTS | Henüz yayınlanmadı |

Üretim sürümleri için en az 2 yıl güvenlik güncelleme commitment'i hedefliyoruz (CRA gereği).

## Açıklama Politikası (Disclosure)

- Coordinated disclosure (90 gün varsayılan, kritik için kısalabilir)
- Düzeltme yayınlandıktan sonra advisory ([GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories))
- CVE talep edilir (CVSS skoru ile)
- Etkilenmiş tüm SBOM'lar güncellenir

## Kapsam

**Bu repo'nun sorumluluğu:**

- Suderra OS build configuration (defconfig, kernel fragment, rootfs overlay)
- Custom paketler (`package/suderra-*`)
- Boot zinciri yapılandırması (secure boot, dm-verity setup)
- RAUC OTA bundle formatı ve imzalama

**Upstream sorumluluğu (yine de raporlayın):**

- Linux kernel CVE'leri → kernel.org
- Buildroot paket CVE'leri → upstream proje
- systemd / nftables / rauc CVE'leri → upstream

## Güvenlik Tasarım Belgeleri

- [docs/security/threat-model.md](docs/security/threat-model.md) — STRIDE threat model
- [docs/security/kernel-hardening.md](docs/security/kernel-hardening.md)
- [docs/security/cve-process.md](docs/security/cve-process.md)
- [docs/security/key-management.md](docs/security/key-management.md)
- [docs/security/pen-test-checklist.md](docs/security/pen-test-checklist.md)

## CRA / IEC 62443 Hazırlığı

Suderra OS, AB Cyber Resilience Act (CRA) ve IEC 62443-4-2 (component-level) gereksinimleri göz önünde bulundurularak tasarlanmaktadır. Detaylar:

- [docs/compliance/cra-readiness.md](docs/compliance/cra-readiness.md)
- [docs/compliance/iec-62443-mapping.md](docs/compliance/iec-62443-mapping.md)

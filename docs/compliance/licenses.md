# Lisans Uyumluluğu

> **Status:** Skeleton — Buildroot otomatik SPDX raporu üretir, bu doküman süreçleri tanımlar.

## Lisans Stratejisi

| Bileşen | Lisans | Yükümlülük |
|---|---|---|
| Suderra OS scaffold (bu repo) | Apache-2.0 | Atıf, lisans dosyası dağıtım |
| Linux kernel | GPL-2.0 only | **Kaynak kodu sunma** |
| Buildroot (build system) | GPL-2.0+ | Kaynak sunma (build tarafı) |
| musl libc | MIT | Atıf |
| BusyBox | GPL-2.0+ | Kaynak sunma |
| systemd | LGPL-2.1+, GPL-2.0+ | Linker exception, dynamic link ok |
| nftables | GPL-2.0 | Kaynak sunma |
| RAUC | LGPL-2.1+ | Dynamic link |
| Suderra Edge Agent | Proprietary veya Apache-2.0 (TBD) | - |

## SPDX SBOM

Buildroot her build sonunda otomatik üretir:

```
output/<defconfig>/legal-info/
├── manifest.csv              # Tüm paketler, versiyon, lisans, URL
├── licenses.txt              # Birleştirilmiş lisans metinleri
└── sources/                  # GPL kaynak kodu (yükümlülük için)
```

`scripts/gen-sbom.sh` bunu CycloneDX'e çevirir.

## GPL Kaynak Sunma Yükümlülüğü

Müşteriye satılan her cihaz ile birlikte:

1. **Yazılı teklif** veya
2. **CD/USB ile kaynak** veya
3. **HTTPS link** ile 3 yıl boyunca erişilebilir kaynak

Önerilen: GitHub'da kalıcı bir tag her release ile:

```
https://github.com/Okan-wqm/Suderra-OS/releases/tag/v1.0.0
└── source-bundle.tar.xz       (GPL kaynaklar + patches)
```

## OpenChain / REUSE

Düşünülmesi gerekenler (Faz 5+):

- [REUSE Specification](https://reuse.software/) — her dosyada SPDX header
  - Suderra'nın kendi kodu için faydalı
  - Buildroot upstream'i kirletmeden
- [OpenChain ISO/IEC 5230](https://openchainproject.org/) — lisans uyum süreç sertifikası

## CI Kontrolleri

- `cargo-deny` — Rust paket lisansları (allowlist)
- `licensecheck` — Buildroot manifest doğrulama
- `reuse lint` — kendi kod SPDX header

## Patent Trolling Koruması

Apache-2.0'ın patent clause'u önemli:

- Suderra kodu Apache-2.0 → patent grant
- GPL bileşenleri kendi koruması (GPL v2 implicit, v3 explicit)

## Yapılacaklar

- [ ] CI'da licensecheck enforcement (Faz 0.5)
- [ ] Müşteri bundle: GPL kaynak teslim prosedürü (Faz 6)
- [ ] REUSE compliance kendi kod için (Faz 5+)
- [ ] Edge Agent lisans kararı (Apache-2.0 mu, proprietary mi?)

## Referanslar

- [SPDX](https://spdx.dev/)
- [Buildroot legal-info](https://buildroot.org/downloads/manual/manual.html#legal-info)
- [Free Software Foundation Europe — Compliance guide](https://fsfe.org/freesoftware/legal/index.html)

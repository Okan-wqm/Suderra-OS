# ADR-0001: Build sistemi olarak Buildroot seçimi

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** @okan-wqm
- **Tags:** build, infrastructure

## Context

Suderra OS için endüstriyel-grade, sertleştirilmiş, OTA-güncellenebilir bir Linux dağıtımı inşa etmemiz gerekiyor. Hedefler:

- Tek geliştirici / küçük ekip ile sürdürülebilir
- Multi-arch (x86_64 endüstriyel PC + aarch64 SBC)
- Reproducible build (supply chain güveni)
- musl libc (statik link, küçük imaj)
- ~50MB final imaj
- 4-6 ay içinde ilk pilot
- IEC 62443 / CRA hazırlığı (SBOM, vulnerability tracking)

Üç ana seçenek var: Buildroot, Yocto Project, ve hazır bir base dağıtım (Alpine, Torizon, balenaOS) üstüne katman.

## Decision

**Buildroot** kullanılacak. Pure scratch, base dağıtım YOK. Aktif üretim
hazırlık pini Buildroot `2025.05.3`; bu pin native Rust `1.86.0` içerdiği için
Suderra-local Rust Buildroot patch kuyruğu kullanılmaz.

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Karar |
|---|---|---|---|
| **Buildroot 2025.05.x** | Basit Kconfig, hızlı öğrenme eğrisi, küçük imaj, BR2_EXTERNAL pattern olgun, musl first-class, RAUC desteği var, native Rust 1.86.0 | Layer mimarisi yok (Yocto kadar modüler değil), paket sayısı Yocto'dan az | **SEÇİLDİ** |
| Yocto Project (Scarthgap LTS) | Endüstri standardı (otomotiv, IoT), layer sistemi güçlü, BSP zenginliği, meta-security/meta-virtualization | Öğrenme eğrisi dik, build süresi 2-3x, tek geliştirici için fazla, recipe yazımı karmaşık | Reddedildi: ekip büyüyünce yeniden değerlendirilebilir |
| Alpine Linux base (apkbuild) | Hızlı başlangıç, musl native, küçük | Hazır dağıtım — kontrol az, OTA disiplini yok, verified boot zinciri belirsiz | Reddedildi: marka değeri ve kontrol kaybı |
| Torizon OS / balenaOS base | OTA + immutable hazır, 1-2 ayda pilot | "Suderra OS by Torizon", vendor lock, marka değeri düşer | Reddedildi: stratejik bağımsızlık tercih |
| Debian/Ubuntu minimal | Yaygın bilgi, kolay debug | 4 GB imaj, 40+ daemon, attack surface çok büyük, supply chain dar değil | Reddedildi: hedeflerle uyumsuz |

## Consequences

### Positive

- Düşük öğrenme eğrisi → tek geliştirici sürdürebilir
- Hızlı iterasyon (build 15-30 dk QEMU defconfig)
- ~30-50 MB imaj realistik
- BR2_EXTERNAL ile clean separation (Buildroot upstream'i kirletmiyoruz)
- musl + statik binary'ler (Rust app ile uyumlu — `rustls`, `sqlcipher vendored`)
- Apache-2.0 + GPL bileşenleri için SPDX raporu otomatik
- Reproducible build görece kolay (Yocto'ya göre)

### Negative

- Yocto layer sistemi yok → eğer ileride çok board desteklenmeli ise BR2_EXTERNAL'da iç organizasyon zorlaşır
- Yocto kadar zengin meta-security/meta-virtualization layer'ları yok
- Buildroot 6 ayda bir release değişikliği yapar; major upgrade ayrı migration
  branch, full matrix build ve release evidence contract doğrulaması ister
- Kernel CONFIG fragment yönetimi manuel (Yocto'da meta-secureboot var)

### Neutral / Trade-offs

- Eğer 5+ farklı board desteklenecek ise Yocto'ya geçiş düşünülebilir (ADR-NNNN ile yeniden değerlendirilir)
- Buildroot'tan Yocto'ya geçiş yapılabilir ama Faz 4+ sonrası ciddi efor

## Implementation Notes

- Buildroot `git submodule` olarak `buildroot/` dizinine eklenecek (Faz 1)
- Tag: `2025.05.3`
- `BR2_EXTERNAL=$(CURDIR)` pattern — bu repo dış katman olarak çalışır
- Normal build `buildroot/` submodule'ünü kirletmez; izole source tree
  `scripts/buildroot-source.sh prepare` ile üretilir
- Buildroot upgrade'i için 6 ayda bir ADR güncellemesi

## References

- [Buildroot manual — Outside BR custom](https://buildroot.org/downloads/manual/manual.html#outside-br-custom)
- [Buildroot vs Yocto comparison — Bootlin](https://bootlin.com/doc/training/buildroot/)
- ADR-0002: systemd minimal seçimi
- ADR-0003: Multi-arch defconfig stratejisi

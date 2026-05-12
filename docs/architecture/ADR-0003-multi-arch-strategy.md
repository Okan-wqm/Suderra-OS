# ADR-0003: Multi-arch defconfig stratejisi (x86_64 + aarch64)

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** @okan-wqm
- **Tags:** build, multi-arch, hardware

## Context

Suderra Edge Agent hem endüstriyel x86_64 PC (Advantech UNO, Siemens IPC, vb.) hem de aarch64 SBC (Revolution Pi, Raspberry Pi CM4) üzerinde çalışacak. Tek mimari hedef sınırlandırma kararı kullanıcı tarafından reddedildi.

Multi-arch desteği üç şekilde verilebilir:

1. Tek `unified` defconfig + conditional Kconfig
2. Her mimari için ayrı defconfig, ortak rootfs-overlay
3. Tamamen ayrı build sistemleri (iki repo)

## Decision

**Ayrı defconfig + ortak rootfs-overlay + mimari-özel board klasörleri.**

Yapı:

```
configs/
├── suderra_qemu_x86_64_defconfig    # Geliştirme/CI
├── suderra_x86_64_defconfig         # Endüstriyel x86
└── suderra_aarch64_defconfig        # ARM SBC

board/suderra/
├── common/                          # Ortak: rootfs overlay, post scripts, kernel fragment
└── <arch>/                          # Mimari-özel: bootloader, genimage, kernel config
```

Faz sıralaması:

1. Faz 1: **x86_64 (QEMU)** önce — geliştirme döngüsü hızlı
2. Faz 1.5: **x86_64 endüstriyel** gerçek donanım
3. Faz 2 sonu: **aarch64** ekle

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Karar |
|---|---|---|---|
| **Ayrı defconfig + ortak overlay** | Net ayrım, debug kolay, CI matrix uyumlu | Bazı duplikasyon (kernel fragment her arch için) | **SEÇİLDİ** |
| Tek `unified` defconfig | Tek dosya bakım | Buildroot tek defconfig çoklu mimari desteklemez | Reddedildi (teknik olarak imkansız) |
| İki ayrı repo | Tam izolasyon | Kod duplikasyonu, supply chain ikiye katlanır | Reddedildi |

## Consequences

### Positive

- CI matrix: tek workflow tüm mimarileri build eder
- Geliştirme döngüsü: QEMU x86_64 (~15 dk build) ile hızlı iterasyon
- Donanım eklerken sadece yeni `board/suderra/<arch>/` klasörü + defconfig
- Ortak rootfs-overlay → uygulama davranışı tutarlı

### Negative

- Kernel config iki yerde tutulur (`board/suderra/x86_64/linux-x86_64.config`, `aarch64/linux-aarch64.config`)
- → çözüm: ortak `kernel-fragment.config` (sertleştirme) + arch-specific add-on
- aarch64 secure boot zinciri x86_64'ten farklı (U-Boot FIT image vs UEFI shim)
- → ADR-0005'te detay

### Neutral / Trade-offs

- Faz 1 sadece x86_64 — ARM ertelendi, ama yapı baştan hazır
- ARM hedef cihazı henüz seçilmedi (Faz 0 açık soru)

## Implementation Notes

- `BR2_EXTERNAL` her iki defconfig'i de tanır
- CI matrix: `[suderra_qemu_x86_64, suderra_x86_64, suderra_aarch64]`
- Cross-toolchain Buildroot tarafından otomatik (toolchain-buildroot, gcc-musl)
- Geliştirici makinesinde QEMU emulation ile aarch64 lokal test (qemu-system-aarch64)
- Final imaj boyutu: x86_64 ~60MB, aarch64 ~50MB (hedef)

## References

- [Buildroot manual — Customization](https://buildroot.org/downloads/manual/manual.html#customize)
- ADR-0001: Buildroot seçimi
- ADR-0005: Secure boot zinciri (x86 UEFI vs ARM U-Boot)
- Açık soru: Hedef ARM modeli (Pi CM4 vs Revolution Pi) — Faz 0 sonunda netleşecek

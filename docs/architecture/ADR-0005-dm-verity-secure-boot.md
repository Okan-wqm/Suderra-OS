# ADR-0005: dm-verity + UEFI Secure Boot zinciri

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** @okan-wqm
- **Tags:** security, boot, verity, secureboot

## Context

Suderra OS, sahada fiziksel veya yazılım saldırılarına karşı korunmalı. CRA ve IEC 62443-4-2 gereği:
- Boot zinciri kriptografik doğrulanmalı (FR3.4 — software integrity)
- Rootfs çalışma anında değiştirilmemeli (FR3.4)
- Saldırgan root olsa bile diskteki kodu kalıcı değiştirememeli (anti-persistence)

İki ana mekanizma:
1. **dm-verity** — Linux kernel'in blok-seviyesi Merkle tree hash doğrulaması
2. **UEFI Secure Boot** — firmware-seviyesi imza doğrulama zinciri

Bunlar birbirini tamamlar ve birlikte kullanılır.

## Decision

**Tam doğrulama zinciri:**

```
UEFI Firmware (TPM 2.0 PCR ölçer)
    ↓ imza doğrular
shim.efi (Microsoft veya kendi MOK imzalı)
    ↓ imza doğrular
systemd-boot veya GRUB2 (Suderra imzalı)
    ↓ imza doğrular
Linux kernel + initramfs (Suderra imzalı, FIT image veya bütünsel)
    ↓ verity root hash kernel cmdline'da
dm-verity (her blok Merkle tree ile doğrulanır)
    ↓ rootfs read-only, doğrulanmış
systemd PID 1
    ↓ unit imzaları (opsiyonel, gelecek)
suderra-edge-agent (Cargo build, statik link)
```

Anahtarlar:
- **Platform Key (PK)** — UEFI firmware, OEM'de saklı
- **Key Exchange Key (KEK)** — Suderra root signing key
- **Database (db)** — Suderra image signing key
- **MOK** — Machine Owner Key (geliştirme için)
- **Verity root hash** — kernel cmdline'a embed edilir, kernel imzasında korunur

Filesystem:
- **erofs** + dm-verity (read-only optimize, küçük, hızlı)
- ext4 alternatifi (eğer erofs sorun çıkarırsa fallback)

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Karar |
|---|---|---|---|
| **dm-verity + UEFI Secure Boot (seçilen)** | Endüstri standardı, ChromeOS modeli, kernel built-in | Anahtar yönetimi karmaşık | **SEÇİLDİ** |
| IMA/EVM (file-level signing) | Per-file imza, dynamic check | Performans overhead, debug zor, mature değil | Reddedildi |
| AppArmor/SELinux only | Mandatory access control | Bütünlük garantisi vermez, sadece policy | Reddedildi (yine ekleyebiliriz) |
| Yalnız dm-verity (secboot yok) | Basit | Bootloader değiştirilebilir → zincir kopar | Reddedildi (zayıf) |
| TPM-only measured boot | Attestation güzel | Kendi başına bütünlük zorla- maz, sadece raporlar | Reddedildi (tek başına yetersiz) |

## Consequences

### Positive
- **Anti-persistence garantisi:** Saldırgan root olsa bile rootfs'i kalıcı değiştiremez (reboot = saldırgan gitti)
- **Evil maid attack koruması:** Fiziksel erişim ile bile kodu değiştirmek için Suderra signing key gerekir
- **Compliance:** IEC 62443-4-2 FR3.4 (software integrity) doğrudan karşılanır
- **Boot süresi etkisi minimal:** dm-verity lazy verification (ilk okumada)
- **Forensic:** TPM PCR'lar boot ölçümlerini saklar — manipülasyon tespit edilebilir

### Negative
- **Anahtar yönetimi katmanlı ve kritik:**
  - Kayıp: Tüm cihaz fleet'i güncellenemez (signing key kaybolursa)
  - Sızıntı: Tüm fleet manipüle edilebilir → fleet rotation gerekir
- **Filesystem read-only:** /etc çalışma anında değiştirilemez
  - → /etc'in writable kısmı: `/var/lib/suderra/config-overrides` (firstboot ile populate)
- **Update karmaşıklığı:** RAUC bundle hem rootfs hem verity hash içerir
- **OEM bağımlılığı:** PK/KEK ile UEFI provisioning donanım üreticisi ile koordinasyon
  - Alternatif: kullanıcı Secure Boot'u kendisi enroll eder (MOK)

### Neutral / Trade-offs
- Geliştirme varyantında dm-verity disabled (debug için)
- PROD varyantında dm-verity ZORUNLU (Config.in'de `BR2_PACKAGE_SUDERRA_VARIANT_PROD`)
- erofs vs ext4: erofs daha küçük (~30% saving) ama eğer Buildroot/kernel'de sorun olursa ext4 fallback

## Implementation Notes

### Kernel CONFIG (`kernel-fragment.config`)
```
CONFIG_DM_VERITY=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY_FEC=y       # Forward error correction (opsiyonel)
CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_SIGNATURE=y
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
CONFIG_TRUSTED_KEYS=y
CONFIG_TPM=y
CONFIG_TPM_TIS=y
CONFIG_TPM_CRB=y
CONFIG_SECONDARY_TRUSTED_KEYRING=y
CONFIG_SECURITY=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
CONFIG_MODULES=n              # Monolithic kernel
CONFIG_KEXEC=n                # Saldırı yüzeyi azaltma
```

### Verity setup
- `scripts/gen-verity-hash.sh` rootfs.img → root hash + verity tree
- Root hash kernel cmdline'a embed: `root=/dev/sda2 dm-verity.hash=...`
- Bütün cmdline kernel image'a baked (signed) → değiştirilemez

### Secure Boot enroll (üretim)
- OEM ile koordine: PK enrollment factory'de
- Eğer OEM PK enroll edemiyorsa: müşteri kurulum sırasında MOK enroll

### Geliştirme vs Üretim
| Variant | dm-verity | Secure Boot | SSH |
|---|---|---|---|
| DEV | Disabled | Disabled (test) | Açık (anahtarla) |
| PROD | Enforced | Enforced | YOK |

## References

- [dm-verity kernel docs](https://www.kernel.org/doc/Documentation/device-mapper/verity.txt)
- [Buildroot dm-verity setup — Mind.be blog](https://mind.be/blog/2024/12/30/setting-up-a-fully-secure-boot-chain-on-buildroot/)
- [systemd-boot Secure Boot guide](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
- [ChromeOS verified boot design](https://www.chromium.org/chromium-os/chromiumos-design-docs/verified-boot/)
- ADR-0004: RAUC bundle format=verity ile entegrasyon
- IEC 62443-4-2 FR3.4 (Software integrity)
- CRA Annex I, Section 1(3)(d) (integrity)

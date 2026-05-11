# ADR-0004: RAUC + A/B partition tabanlı OTA

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** @okan-wqm
- **Tags:** ota, rauc, boot, security

## Context

Suderra OS sahada güvenli ve geri dönülebilir update mekanizması gerektirir. CRA gereği:
- Vendor en az 5 yıl security update commitment vermeli
- Update'ler imzalı olmalı, doğrulanmalı
- Bozuk update otomatik geri dönmeli (rollback)
- Update sırasında cihaz bricking olmamalı (anti-brick guarantee)

Üç ana OTA framework:
1. **RAUC** — Pengutronix, A/B veya custom, Buildroot first-class
2. **Mender** — Northern.tech, A/B + delta + cloud platform
3. **swupdate** — Stefano Babic, çok formatlı, A/B opsiyonel

## Decision

**RAUC** + **A/B root partition** + **bundle imzalama (X.509 + RSA-4096)** kullanılacak.

Partition layout:
```
/dev/<disk>
├── p1: EFI/Boot (~256MB, FAT32, shared)
├── p2: rootfs.A (~512MB-1GB, erofs, dm-verity)
├── p3: rootfs.B (~512MB-1GB, erofs, dm-verity)
├── p4: /data    (kalan alan, ext4, encrypted, RW kalıcı)
└── (opsiyonel) p5: rescue/factory
```

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Karar |
|---|---|---|---|
| **RAUC + A/B** | Buildroot entegrasyonu mature, signed bundle, küçük footprint (~1MB), Pengutronix arkasında | Cloud platform yok (kendi sunucu) | **SEÇİLDİ** |
| Mender | Hazır cloud platform, delta updates, fleet management | Bağımlılık ağır, Go runtime, vendor risk | Reddedildi: bağımsızlık + minimallik |
| swupdate | Çok format desteği (FIT, cpio, vb.), esnek | Daha az dokümantasyon, daha az Buildroot entegrasyonu | Reddedildi: RAUC daha mature |
| Custom OTA | Tam kontrol | Tekerleği yeniden icat, denenmemiş kod = güvenlik riski | Reddedildi: NIH anti-pattern |

## Consequences

### Positive
- A/B garantili anti-brick: bozuk update otomatik fallback
- Imza doğrulama RAUC içinde built-in (`x509-cert`, RSA-4096)
- Buildroot defconfig'de tek satır: `BR2_PACKAGE_RAUC=y`
- Bundle format açık (squashfs + manifest) — debug kolay
- Health-check + bootloader fallback zinciri:
  1. Update yazıldı, bayrak: `boot_other`
  2. Yeni rootfs boot → health-check (3 retry)
  3. Başarılı → `boot_good`, A/B swap kalıcı
  4. Başarısız → bootloader otomatik eski rootfs'e döner

### Negative
- /data partition KENDİ KENDİNE backup'lanmaz (kullanıcı verisi)
  - → Edge Agent'in `offline.db` ve `retain.db`'si update sırasında korunur (RAUC `/data`'ya dokunmaz)
- Disk boyutu 2x rootfs gerekiyor (A/B)
- Delta update yok → her update tam imaj (~50MB)
  - Sahada bant genişliği problemi olursa Faz 5+ delta eklenebilir
- /boot shared — bootloader update riski (nadir ama mümkün)

### Neutral / Trade-offs
- Cloud platform yok → basit HTTPS sunucu yeterli (Faz 4)
- Mender gibi fleet management özelliği yok → Faz 5 telemetry ile dolaylı çözüm

## Implementation Notes

- Buildroot: `BR2_PACKAGE_RAUC=y` + `BR2_TARGET_GENERIC_GETTY=n`
- Bundle imzalama: `scripts/sign-bundle.sh` → `rauc bundle create --cert=... --key=...`
- Bootloader: GRUB2 (x86) ve U-Boot (ARM) RAUC ile uyumlu
- `system.conf` örnek (board/suderra/common/rootfs-overlay/etc/rauc/system.conf):
  ```ini
  [system]
  compatible=suderra-os-x86_64
  bootloader=grub
  bundle-formats=verity
  
  [keyring]
  path=/etc/rauc/keyring.pem
  
  [slot.rootfs.0]
  device=/dev/disk/by-partlabel/rootfs-a
  type=raw
  bootname=A
  
  [slot.rootfs.1]
  device=/dev/disk/by-partlabel/rootfs-b
  type=raw
  bootname=B
  ```
- Health-check: `suderra-firstboot.service` boot sonrası 5 dk içinde "mark good"
- Test: `tests/ota/update-rollback-test.sh` — 10× update + 1 bozuk → rollback

## References

- [RAUC documentation](https://rauc.readthedocs.io/)
- [RAUC + Buildroot integration](https://rauc.readthedocs.io/en/latest/integration.html#buildroot)
- ADR-0005: dm-verity + secure boot (RAUC bundle-formats=verity ile bağlantı)
- IEC 62443-4-1 SR 7.6 (least functionality after update)
- CRA Annex I — Vulnerability handling, security updates

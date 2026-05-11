# OTA (Over-the-Air) Update

> **Status:** Skeleton — Faz 4 (OTA sistemi) içinde detaylanır.

## Genel Bakış

Suderra OS, RAUC tabanlı A/B partition OTA kullanır. Detay: [ADR-0004](../architecture/ADR-0004-rauc-ab-partition.md).

```
Geliştirici makinesi              Update sunucu                Cihaz
─────────────────────             ─────────────                 ─────
1. make build-x86      
2. rauc bundle create  
   (imzalı bundle)     
3. scripts/sign-bundle.sh
4. upload to server      ───────→  /bundles/<version>.raucb
                                                     ↑
                                                     │ HTTPS GET
                                                     │
                                   ←─── rauc install /bundles/v0.2.0.raucb
                                   ←─── reboot (yeni slot)
                                   ←─── health check (5 dk)
                                   ←─── mark good veya rollback
```

## Bundle Oluşturma

```bash
# Build sonrası, post-image.sh otomatik üretir:
ls output/suderra_x86_64_defconfig/images/suderra-os-v0.2.0.raucb

# Manuel imzalama (CI'da otomatik):
./scripts/sign-bundle.sh \
    output/suderra_x86_64_defconfig/images/suderra-os-v0.2.0.raucb \
    ~/.suderra-keys/prod/rauc-signing.key
```

## Bundle Manifest

```
[update]
compatible=suderra-os-x86_64
version=v0.2.0
description=Security patches CVE-2026-XXXX

[bundle]
format=verity

[image.rootfs]
filename=rootfs.img
size=...
sha256=...

[hooks]
filename=hook
```

## Cihazda Update

> Üretim varyantında cihaza shell yok — update tetikleme:
>
> 1. Cihaz periodic olarak update sunucusunu kontrol eder
> 2. Cloud command (`update-now`) ile remote tetikleme
> 3. Manuel: serial console (sadece dev mode)

```bash
# Cihazda (dev mode):
rauc install https://updates.suderra.example/bundles/v0.2.0.raucb
systemctl reboot
```

## Health Check ve Rollback

`suderra-firstboot.service` ilk boot'tan sonra 5 dk timer ile:

1. Edge agent active mi? (`systemctl is-active`)
2. Network connection ok? (cloud broker'a ulaşılabiliyor mu?)
3. Health check başarılı mı? (HTTP /ready endpoint)
4. **Hepsi OK** → `rauc status mark-good`
5. **Fail** → reboot → bootloader otomatik eski slot'a döner

Failure threshold: 3 deneme → kalıcı rollback.

## Update Sunucusu

İlk versiyonda basit HTTPS file server:

- Nginx + Let's Encrypt
- Cihaz başına unique mTLS client cert ile authentication
- Bundle storage: S3-compatible (Minio veya AWS S3)

Faz 5+: bundle metadata API, fleet management, canary rollouts.

## Yapılacaklar

- [ ] `scripts/sign-bundle.sh` implementasyonu (Faz 4)
- [ ] Update sunucusu setup runbook (Faz 4)
- [ ] Canary release stratejisi (Faz 5)
- [ ] Delta updates (Faz 6+, opsiyonel)

## Test

`tests/ota/update-rollback-test.sh`:

- 10× başarılı update + 1 bozuk update = otomatik rollback
- Imza tampering reddedilir
- Downgrade reddedilir

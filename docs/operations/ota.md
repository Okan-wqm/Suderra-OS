# OTA (Over-the-Air) Update

> **Status:** Production contract is implemented, but production readiness
> remains closed until runtime QEMU and x86 hardware evidence are collected.

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

# Production signing uses PKCS#11 plus exact HSM evidence:
SUDERRA_SIGNING_MODE=prod \
SUDERRA_RAUC_PKCS11_URI='pkcs11:token=Suderra;object=rauc-prod;type=private' \
SUDERRA_RAUC_SIGNING_CERT=/secure/rauc-prod.crt \
SUDERRA_RAUC_KEYRING=/secure/rauc-keyring.pem \
SUDERRA_HSM_SIGNING_EVIDENCE=/secure/hsm-session.json \
./scripts/create-rauc-bundle.sh x86 output/.../images v0.2.0 suderra-os-v0.2.0.raucb

python3 scripts/create-os-update-manifest.py create \
  --bundle suderra-os-v0.2.0.raucb \
  --version v0.2.0 \
  --target x86_64 \
  --min-current-version v0.1.0 \
  --rollback-floor v0.2.0 \
  --key-epoch 1 \
  --key-id os-update-prod-1 \
  --expires-at 2026-12-31T00:00:00Z \
  --signing-key /secure/os-update-manifest.key \
  --public-key /secure/os-update-manifest.ed25519.pub \
  --output suderra-os-v0.2.0.manifest.json
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
# Cihazda (dev mode veya controlled operator session):
suderra-ota install suderra-os-v0.2.0.manifest.json suderra-os-v0.2.0.raucb
```

## Health Check ve Rollback

`suderra-rauc-mark-good.service` slot boot ettikten sonra:

1. Edge agent active mi? (`systemctl is-active`)
2. Network connection ok? (cloud broker'a ulaşılabiliyor mu?)
3. Health check başarılı mı? (HTTP /ready endpoint)
4. **Hepsi OK** → `rauc status mark-good` ve `suderra-ota mark-good`
5. **Fail** → `suderra-ota rollback --reason health-gate` ve reboot
   isteği; bootloader eski slot'a döner.

Failure threshold: 3 deneme → kalıcı rollback.

## Update Sunucusu

İlk versiyonda basit HTTPS file server:

- Nginx + Let's Encrypt
- Cihaz başına unique mTLS client cert ile authentication
- Bundle storage: S3-compatible (Minio veya AWS S3)

Faz 5+: bundle metadata API, fleet management, canary rollouts.

## Yapılacaklar

- [ ] Update sunucusu setup runbook
- [ ] Canary release stratejisi
- [ ] Delta updates (opsiyonel)

## Test

`tests/ota/update-rollback-test.sh`:

- 10× başarılı update + 1 bozuk update = otomatik rollback
- Imza tampering reddedilir
- Downgrade reddedilir

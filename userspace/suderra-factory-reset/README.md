# suderra-factory-reset

Fabrika ayarlarına dönüş handler.

## Tetikleyiciler

| Yöntem | Yetki | Doğrulama |
|---|---|---|
| Fiziksel buton (GPIO) | Cihaz başı operatör | 10sn basılı tutma + LED feedback |
| Cloud komut | Mfg admin | mTLS + Ed25519 signature + 2-person rule |
| CLI (root) | Geliştirici | Sadece DEV variant, PROD'da disabled |

## İşlem

1. `/data` partition wipe (cryptsetup luksFormat)
2. `/var/lib/suderra/.provisioned` flag sil → firstboot tekrar çalışır
3. RAUC slot.A'ya manuel switch (en eski stable image)
4. Reboot

## Güvenlik

- PROD variant'ta CLI yolu **fiziksel buton + GPIO confirm** ister
- Cloud yolu **two-person rule** (ed25519 imza, iki farklı admin'den)
- Audit log: telemetry'e immutable kayıt (reset olayı + sebep)

## Faz

Faz 5 (operasyonel olgunluk).

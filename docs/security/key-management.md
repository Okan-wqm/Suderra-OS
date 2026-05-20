# Anahtar Yönetimi — Suderra OS

> **Status:** Skeleton. Üretim anahtar saklama altyapısı Faz 4 öncesi netleşmeli.

## Anahtar Envanteri

| Anahtar | Algoritma | Kullanım | Saklama (DEV) | Saklama (PROD) |
|---|---|---|---|---|
| **PK** (Platform Key) | RSA-2048+ | UEFI root | Yok (test) | OEM enrollment veya MOK |
| **KEK** (UEFI) | RSA-2048+ | UEFI KEK | Repo (gitignored) | HSM (Yubikey/YubiHSM) |
| **db key** (image signing) | RSA-3072 / Ed25519 | Bootloader/kernel imzala | Repo (gitignored) | HSM |
| **Kernel signing key** | RSA-3072 | Kernel modul imzala (modüller kapalı ama yine de) | Repo (gitignored) | HSM |
| **RAUC bundle key** | RSA-4096 / Ed25519 | OTA bundle imzala | Repo (gitignored) | **HSM zorunlu** |
| **dm-verity hash signing** | RSA-3072 | Verity root hash imzala | Repo (gitignored) | HSM |
| **MQTT client cert (CA)** | RSA-3072 / ECDSA P-256 | Cloud broker mTLS | Test CA | Cihaz başına unique |
| **TPM SRK** | TPM endorsement | /data encryption | TPM | TPM (cihaz başına) |

## Lifecycle

| Aşama | Eylem |
|---|---|
| **Generation** | Cold ceremony (offline machine, 2-person rule), HSM-backed |
| **Storage** | YubiHSM 2 (Faz 4+), kapalı kasada yedeği |
| **Usage** | CI sadece **kısa-ömürlü** child key kullanır (15 dk imzalama session) |
| **Rotation** | Image signing: 2-3 yıl. RAUC: 2-3 yıl. UEFI KEK: 10 yıl |
| **Compromise response** | Yeni anahtar yayınla → fleet OTA ile yeni keyring → eski anahtar revoke |
| **Destruction** | Eski anahtar HSM'den silinir, audit log |

## Geliştirme Anahtarları

`board/keys/README.md`:

- Dev anahtarları **tek-kullanım**, kısa ömürlü
- Asla üretim cihazlarına enroll edilmez
- `.gitignore` ile repo'ya GİREMEZ
- Konum: geliştirici makinesinde `~/.suderra-keys/dev/`

## Üretim Anahtar Altyapısı (Faz 4 öncesi karar)

Seçenekler:

| Seçenek | Maliyet | Güvenlik | Karmaşıklık |
|---|---|---|---|
| **YubiHSM 2** | ~650 USD | Yüksek | Düşük |
| AWS KMS | Aylık | Yüksek | Orta |
| On-prem HSM (Thales) | 10k+ USD | Çok yüksek | Yüksek |
| Yubikey (FIDO/PIV) | ~70 USD | Orta | Düşük |

İlk versiyon için **YubiHSM 2 + 2 adet Yubikey (yedek)** önerilir.

## Rollback Protection

- Image signing key her sürümde **tek artımlı sayaç** (monotonic)
- Bootloader düşürme saldırılarını reddeder (downgrade attack)
- TPM PCR rolling counters (Faz 5+)

## Audit

- Anahtar erişimi: kim, ne zaman, hangi imza için
- HSM audit log → cold storage
- Anahtar kullanımı sadece imzalama (export edilmez)

## Yapılacaklar

- [ ] Üretim HSM/PKCS#11 provider implementation. Production scripts now
      reject file-backed private keys instead of silently signing with PEM
      files.
- [ ] Cold ceremony prosedürü (yazılı runbook)
- [ ] CI'da kısa-ömürlü key delegation
- [ ] Anahtar yedekleme + kurtarma planı
- [ ] Compromise drill testi

## Referanslar

- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [YubiHSM 2 setup](https://developers.yubico.com/YubiHSM2/)
- ADR-0005: dm-verity + Secure Boot

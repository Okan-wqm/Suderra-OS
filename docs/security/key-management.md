# Anahtar Yönetimi — Suderra OS

> **Status:** Active production-candidate contract. Hardware ceremony,
> delegation, recovery, and compromise-drill runbooks remain required before
> any `production_ready=true` change.

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

## Edge sözleşmesi anahtar envanteri (ADR-048 DEC-3.9)

Suderra OS ile edge agent arasındaki imzalı ifadelerin anahtarları (ADR-048 DEC-3; kümesi
`contracts/suderra-edge/v1/statements.json` `purposes`). Amaç başına ayrı anahtar ve ayrı epoch vardır;
iki amaç bir anahtarı paylaşamaz. Üretim anahtarlarının tek kayıt yeri aşağıdaki tablodur: üretim imajı
yalnız burada kayıtlı keyid'leri pinler, kök kurucu `PRODUCTION_KEYIDS` sabitini bu tablodan alır ve
kayıt edilmemiş her keyid (dev/CI anahtarları ve sözleşmenin TEST-ONLY anahtarları dahil) build'i
başarısız eder. Dev/CI anahtarları (`scripts/gen-dev-keys.sh`, `scripts/ci/prepare-ci-keyring.sh`) bu
tabloya **hiçbir zaman** girmez: yalnız dev imajları ve QEMU hedefleri onları pinler.

`Keyid`: ham 32 bayt Ed25519 public key'in SHA-256'sı (küçük harf hex). `bekliyor: operatör`: anahtar
henüz seremonide üretilmemiştir (üretim anahtar seremonisi operatör eylemidir, ADR-048 Soru 9); bu durumda
`Köken` hedeflenen kökeni söyler. `Köken` değerleri: `ceremony-hsm-offline` (özel anahtar HSM'den
çıkmaz, imza offline), `ceremony-service-secret` (seremonide üretilir, P2'deki KMS'e kadar servis
secret'ında; EDGE-HIGH-119), `kms` (P2). `Çapa`: cihazın anahtarı nereden aldığı (`os-image`: verity
rootfs `/etc/suderra/keys/<amaç>/<epoch>.pub`; `trust-anchors`: fleet-root imzalı bundle; `kernel-keyring`).

| Amaç | Epoch | Keyid | Köken | Saklama | Çapa |
|---|---|---|---|---|---|
| edge-release | 1 | bekliyor: operatör | ceremony-hsm-offline | Offline HSM, iki emanetçi; üretim release statement'ı offline imzalanır | os-image |
| edge-provisioning | 1 | bekliyor: operatör | ceremony-service-secret | Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119) | os-image |
| fleet-root | 1 | bekliyor: operatör | ceremony-hsm-offline | Offline HSM, iki emanetçi; yalnız trust-anchors ve key-epoch-advance imzalar | os-image |
| device-lifecycle | 1 | bekliyor: operatör | ceremony-service-secret | Seremonide üretilir, ayrı signer secret'ı (KMS'e kadar, EDGE-HIGH-119) | os-image |
| config-integrity | 1 | bekliyor: operatör | ceremony-service-secret | Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119) | trust-anchors |
| rbac-manifest | 1 | bekliyor: operatör | ceremony-service-secret | Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119) | trust-anchors |
| command | 1 | bekliyor: operatör | ceremony-service-secret | Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119) | trust-anchors |
| edge-image | 1 | bekliyor: operatör | kms | KMS (P2); X.509, kernel keyring'ine gömülü sertifika | kernel-keyring |

`mqtt-ca` bu tabloda yoktur: P1'de bir seremoni anahtarı değil, broker'ın kamu CA kök kümesidir (üretim
bundle'ı, yalnız sunucu kimlik doğrulaması, DEC-10.6); P2'de özel cihaz PKI'sinin offline kökü
buraya ve seremoniye girer. `edge-image` P2 anahtarıdır (DEC-1.6): satırı vardır, keyid'i P1'de yazılmaz.

**Kayıt kuralı.** Seremoni her anahtarın public key'ini (SubjectPublicKeyInfo PEM) dışa aktarır; satır
elle yazılmaz, hesaplanır, çünkü keyid yanlış yazılırsa üretim imajı yanlış anahtarı pinler:

```bash
python3 -I package/suderra-keys/edge_key_inventory.py row --purpose edge-release --epoch 1 \
    --public-key edge-release-1.pub --origin ceremony-hsm-offline     # tablo satırını yazar
python3 -I package/suderra-keys/edge_key_inventory.py check           # tablonun kuralları
python3 -I package/suderra-keys/edge_key_inventory.py rust            # PRODUCTION_KEYIDS sabiti
```

Satır `bekliyor: operatör` satırının yerine geçer, `rust` çıktısı
`userspace/suderra-installer/src/trust_anchors.rs` `PRODUCTION_KEYIDS` sabitinin yerine yazılır, aynı
commit'te. `tests/image-contracts/edge-key-inventory-contract-test.sh` tablonun kurallarını (her amaç
için satır, tekil keyid, amaca uygun köken, sözleşmeye uygun çapa, TEST-ONLY anahtar yok) ve sabitin tabloya
eşitliğini denetler; `package/suderra-keys/suderra-edge-pins.py` üretim imajında yalnız bu tabloda
kayıtlı keyid'leri pinler. Seremoninin adımları, emanet ve kontrol listesi:
[key-ceremony.md](key-ceremony.md) §Edge contract keys. Rotasyon, iptal ve ihlal: aynı bölümün §Rotation
and compromise ve aquaculture_platform `docs/runbooks/edge-key-compromise.md` (ADR-048 DEC-15, anahtar
başına bir bölüm; `key-epoch-advance` ile iptal P2'dir).

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
- Production signing scripts require `suderra.hsm-signing-session.v2`
  evidence before using a PKCS#11 URI. The evidence binds provider, token
  serial/module identity, non-extractable key attributes, certificate digest,
  ceremony/operator, expiry, signed challenge transcript, audit log digests,
  artifact roles, exact artifact digests, nested `key.id == key_id`, and the
  exact requested PKCS#11 URI. Release validation replays the HSM validator
  against the preserved certificate and rejects SoftHSM/software-token/file-key
  production evidence.
- OS update manifests use `suderra.os-update-manifest.v1` Ed25519 keys. The
  device public key is installed as
  `/etc/suderra/os-update-manifest.ed25519.pub`; dev key generation writes this
  public key as lowercase raw-key hex because `suderra-ota` verifies raw
  Ed25519 bytes.
- The `/data` recovery keys (ADR-048 DEC-14.3) are escrowed to one offline RSA
  key: its public half is installed as `/etc/suderra/recovery-escrow.pub.pem`
  (an RSA public key of at least 3072 bits, checked by
  `scripts/ci/validate-trust-roots.sh`), its private half lives only in the
  offline HSM and decrypts nothing automatically. Dev key generation writes a
  file key for recovery drills. The production key is generated at the key
  ceremony (an operator action, ADR-048 question 9); until then a production
  image cannot be built, which is the intent. See
  [data-recovery.md](data-recovery.md).

## Yapılacaklar

- [x] Üretim RAUC signing scripts reject file-backed private keys and require
      PKCS#11 URI plus validated HSM session evidence.
- [x] Cold ceremony prosedürü (yazılı runbook) — [key-ceremony.md](key-ceremony.md) §Ceremony (iki-kişi kontrolü)
- [x] CI'da kısa-ömürlü key delegation — [key-ceremony.md](key-ceremony.md) §Delegation (time-boxed PKCS#11 credential)
- [x] Anahtar yedekleme + kurtarma planı — [key-ceremony.md](key-ceremony.md) §Backup And Recovery (replay-doğrulamalı drill)
- [x] Compromise drill testi — [key-ceremony.md](key-ceremony.md) §Compromise Drill (7 adımlı, replay-doğrulamalı)
- [ ] Edge sözleşmesi üretim anahtar seremonisi (ADR-048 DEC-3.9): fleet-root ve edge-release offline HSM'de,
      online anahtarlar servis secret'larında; envanter tablosu ve `PRODUCTION_KEYIDS` kayıtla dolar
      — **bekliyor: operatör** ([key-ceremony.md](key-ceremony.md) §Edge contract keys)
- [x] Approved production HSM provider/model allowlist — `ci/evidence-contract.yml` `signing.replay_requirements.approved_provider_allowlist`, `validate-hsm-signing-evidence.py --require-production` ile zorlanıyor

## Referanslar

- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [YubiHSM 2 setup](https://developers.yubico.com/YubiHSM2/)
- ADR-0005: dm-verity + Secure Boot

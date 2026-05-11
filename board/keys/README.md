# Anahtar Yönetimi

> **UYARI:** Bu klasör anahtar **dosyalarını** içermez (gitignore). Sadece politika ve dokümantasyon içerir.

Detaylı politika: [../../docs/security/key-management.md](../../docs/security/key-management.md)

## Klasör Yapısı (PROD setup'tan sonra)

```
board/keys/
├── README.md              # Bu dosya (repo'da)
├── .gitignore             # *.key, *.pem hariç tut
└── (gitignored)
    ├── dev/               # Geliştirme anahtarları (lokal)
    │   ├── uefi-db.key
    │   ├── kernel-signing.key
    │   ├── rauc-signing.key
    │   └── verity-signing.key
    └── prod/              # ÜRETIM anahtarları — HSM'de, lokal dosya YOK
        └── README.md      # "Bu klasör boş — anahtarlar HSM'de"
```

## Geliştirme Anahtarları Oluşturma

Hızlı setup için (sadece DEV variant):

```bash
mkdir -p ~/.suderra-keys/dev
cd ~/.suderra-keys/dev

# UEFI db key
openssl req -newkey rsa:3072 -nodes -keyout uefi-db.key \
    -x509 -sha256 -days 365 -out uefi-db.crt \
    -subj "/CN=Suderra Dev UEFI/"

# Kernel signing
openssl req -newkey rsa:3072 -nodes -keyout kernel-signing.key \
    -x509 -sha256 -days 365 -out kernel-signing.crt \
    -subj "/CN=Suderra Dev Kernel/"

# RAUC bundle signing
openssl req -newkey rsa:4096 -nodes -keyout rauc-signing.key \
    -x509 -sha256 -days 365 -out rauc-signing.crt \
    -subj "/CN=Suderra Dev RAUC/"

# dm-verity hash signing
openssl req -newkey rsa:3072 -nodes -keyout verity-signing.key \
    -x509 -sha256 -days 365 -out verity-signing.crt \
    -subj "/CN=Suderra Dev Verity/"

chmod 0600 *.key
```

## Build Sırasında Anahtar Bulma

Build script'leri `SUDERRA_KEYS_DIR` env var arar:

```bash
export SUDERRA_KEYS_DIR=~/.suderra-keys/dev
./scripts/build-in-docker.sh suderra_x86_64_defconfig
```

## Üretim Anahtarları

**ASLA repo'ya commit etme. ASLA dev laptop'unda saklama.**

Üretim için:

- YubiHSM 2 (önerilen, ~650 USD)
- AWS KMS (cloud)
- Thales/Utimaco HSM (yüksek bütçe)

Detay: [../../docs/security/key-management.md](../../docs/security/key-management.md)

## Anahtar Kaybı / Sızıntı

Kayıp:

- Tüm fleet recovery zor → yedek anahtar (cold storage) zorunlu
- Yedek de kayıp ise → ürün hayat döngüsü sonu (yeni firmware imkansız)

Sızıntı:

1. Compromise tespiti (audit log)
2. Yeni anahtar yayınla
3. OTA ile fleet'e yeni keyring
4. Eski anahtar revoke (UEFI dbx)
5. Müşteri bildirimi
6. Drill: en az yılda 1 kez

## Yapılacaklar

- [ ] `scripts/gen-dev-keys.sh` — yukarıdaki adımları otomatize et
- [ ] HSM seçimi (Faz 4 öncesi)
- [ ] Cold ceremony runbook
- [ ] Backup + recovery prosedürü

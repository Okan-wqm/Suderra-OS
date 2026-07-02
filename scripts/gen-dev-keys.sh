#!/usr/bin/env bash
#
# Suderra OS — Geliştirme anahtarları üret
#
# ASLA üretim için kullanma. Sadece DEV variant + lokal test.
# Üretim anahtarları: HSM (YubiHSM 2 vb.)
#
# Kullanım:
#   ./scripts/gen-dev-keys.sh                       # ~/.suderra-keys/dev/
#   ./scripts/gen-dev-keys.sh /custom/path

set -euo pipefail
IFS=$'\n\t'

KEYS_DIR="${1:-${HOME}/.suderra-keys/dev}"

if [ -d "${KEYS_DIR}" ] && [ -n "$(ls -A "${KEYS_DIR}" 2>/dev/null)" ]; then
    echo "WARNING: ${KEYS_DIR} zaten dolu."
    read -r -p "Üzerine yazılsın mı? [y/N] " REPLY
    if [ "${REPLY}" != "y" ]; then
        echo "İptal"
        exit 0
    fi
fi

# Anahtarlar doğduğu andan itibaren yalnız sahibine açık olsun — sondaki
# chmod'a kadar grup/dünya-okunur pencere bırakma.
umask 077
mkdir -p "${KEYS_DIR}"
chmod 0700 "${KEYS_DIR}"
cd "${KEYS_DIR}"

echo "==> Geliştirme anahtarları üretiliyor: ${KEYS_DIR}"

# UEFI Secure Boot hiyerarşisi: PK -> KEK -> db.
#   - PK  (Platform Key): platform sahibi; KEK'i yetkilendirir.
#   - KEK (Key Exchange Key): db/dbx güncellemelerini yetkilendirir.
#   - db  (Signature DB): boot binary'lerini (UKI/GRUB) doğrulayan güven kökü.
# db, UKI'yi imzalayan sertifikayla AYNI olmalı (SUDERRA_SECUREBOOT_SIGNING_CERT
# dev'de bu uefi-db.crt'yi gösterir); aksi halde imzalı-boot firmware'de reddedilir.
echo "==> UEFI PK — Platform Key (RSA-3072, 1 yıl)"
openssl req -newkey rsa:3072 -nodes -keyout uefi-pk.key \
    -x509 -sha256 -days 365 -out uefi-pk.crt \
    -subj "/CN=Suderra Dev UEFI PK/" 2>/dev/null

echo "==> UEFI KEK — Key Exchange Key (RSA-3072, 1 yıl)"
openssl req -newkey rsa:3072 -nodes -keyout uefi-kek.key \
    -x509 -sha256 -days 365 -out uefi-kek.crt \
    -subj "/CN=Suderra Dev UEFI KEK/" 2>/dev/null

echo "==> UEFI db key (RSA-3072, 1 yıl)"
openssl req -newkey rsa:3072 -nodes -keyout uefi-db.key \
    -x509 -sha256 -days 365 -out uefi-db.crt \
    -subj "/CN=Suderra Dev UEFI db/" 2>/dev/null

# Kernel signing
echo "==> Kernel signing key (RSA-3072)"
openssl req -newkey rsa:3072 -nodes -keyout kernel-signing.key \
    -x509 -sha256 -days 365 -out kernel-signing.crt \
    -subj "/CN=Suderra Dev Kernel/" 2>/dev/null

# RAUC bundle signing
echo "==> RAUC bundle signing key (RSA-4096)"
openssl req -newkey rsa:4096 -nodes -keyout rauc-signing.key \
    -x509 -sha256 -days 365 -out rauc-signing.crt \
    -subj "/CN=Suderra Dev RAUC/" 2>/dev/null

# dm-verity hash signing
echo "==> dm-verity hash signing key (RSA-3072)"
openssl req -newkey rsa:3072 -nodes -keyout verity-signing.key \
    -x509 -sha256 -days 365 -out verity-signing.crt \
    -subj "/CN=Suderra Dev Verity/" 2>/dev/null

# ARM U-Boot signed-FIT signing (ADR-0007). mkimage imzalar; U-Boot içine gömülü
# public key ile boot'ta doğrulanır. RSA-2048 (U-Boot FIT_SIGNATURE yaygın seçim).
echo "==> ARM signed-FIT signing key (RSA-2048)"
openssl req -newkey rsa:2048 -nodes -keyout fit-signing.key \
    -x509 -sha256 -days 365 -out fit-signing.crt \
    -subj "/CN=Suderra Dev FIT/" 2>/dev/null

# USB installer payload manifest signing
echo "==> USB installer payload signing key (Ed25519)"
openssl genpkey -algorithm ED25519 -out installer-payload.key 2>/dev/null
openssl pkey -in installer-payload.key -pubout \
    -out installer-payload.ed25519.pub 2>/dev/null

# OS update manifest signing. suderra-ota expects the public key as raw
# Ed25519 bytes or lowercase hex; write the hex form for stable deployment.
echo "==> OS update manifest signing key (Ed25519)"
openssl genpkey -algorithm ED25519 -out os-update-manifest.key 2>/dev/null
openssl pkey -in os-update-manifest.key -pubout -outform DER 2>/dev/null |
    tail -c 32 |
    od -An -tx1 -v |
    tr -d ' \n' > os-update-manifest.ed25519.pub

# Edge artifact/provisioning manifest signing
echo "==> Edge artifact signing key (Ed25519)"
openssl genpkey -algorithm ED25519 -out edge-artifact.key 2>/dev/null
openssl pkey -in edge-artifact.key -pubout \
    -out edge-artifact.ed25519.pub 2>/dev/null

# Permissions
chmod 0600 ./*.key
chmod 0644 ./*.crt ./*.pub

echo ""
echo "==> Tamamlandı:"
ls -l "${KEYS_DIR}"
echo ""
echo "Kullanım:"
echo "  export SUDERRA_TRUST_ROOTS_DIR='${KEYS_DIR}'"
echo "  export SUDERRA_KEYS_DIR='${KEYS_DIR}'"
echo "  export SUDERRA_SECUREBOOT_SIGNING_KEY='${KEYS_DIR}/uefi-db.key'"
echo "  export SUDERRA_SECUREBOOT_SIGNING_CERT='${KEYS_DIR}/uefi-db.crt'"
echo "  export SUDERRA_SB_PK_CERT='${KEYS_DIR}/uefi-pk.crt'"
echo "  export SUDERRA_SB_KEK_CERT='${KEYS_DIR}/uefi-kek.crt'"
echo "  export SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY='${KEYS_DIR}/installer-payload.key'"
echo "  export SUDERRA_INSTALLER_PAYLOAD_PUBKEY='${KEYS_DIR}/installer-payload.ed25519.pub'"
echo "  ./scripts/build-in-docker.sh suderra_qemu_x86_64_defconfig"
echo ""
echo "UYARI: Bu anahtarlar SADECE geliştirme için. ÜRETİM için HSM kullan."

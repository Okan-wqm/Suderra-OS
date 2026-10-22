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
#
# Edge anahtarları (ADR-048 DEC-3.9): amaç başına birer Ed25519 anahtarı
# (edge-release, edge-provisioning, fleet-root, device-lifecycle,
# config-integrity, rbac-manifest, command; epoch 1), dev fleet-root'u, dev
# MQTT test broker CA'sı ve dev fleet-root'uyla imzalı trust-anchor bundle'ı
# <dir>/edge/ altına yazılır (scripts/ci/edge-dev-keys.py). Bunlar sözleşmenin
# TEST-ONLY anahtarları değildir; yalnız dev imajları ve QEMU hedefleri pinler.
# Bundle'ın tenant_scope'u SUDERRA_EDGE_TENANT_IDS (virgülle ayrılmış UUID'ler)
# ile verilir; verilmezse mevcut bundle'ınki korunur, yoksa rastgele biri.

set -euo pipefail
IFS=$'\n\t'

KEYS_DIR="${1:-${HOME}/.suderra-keys/dev}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

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
# Absolute from here on: the usage lines printed at the end name it, and a
# relative path stops resolving once the script has cd'd into it.
KEYS_DIR="$(cd -- "${KEYS_DIR}" && pwd)"
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

# Recovery-key escrow (ADR-048 DEC-14.3): every device encrypts the recovery key
# of its /data to this public key; the private half is the offline HSM key in
# production and a file here, for recovery drills.
echo "==> /data recovery escrow key (RSA-4096)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out recovery-escrow.key 2>/dev/null
openssl pkey -in recovery-escrow.key -pubout -out recovery-escrow.pub.pem 2>/dev/null

# Trust-root profile (validate-trust-roots.sh, package/suderra-keys).
printf 'dev\n' > suderra-keys.profile

# Edge keys, dev fleet-root and the signed dev trust-anchor bundle.
echo "==> Edge per-purpose keys, dev fleet-root, trust-anchor bundle (Ed25519)"
edge_args=(generate --keys-dir "${KEYS_DIR}" --profile dev --days 365)
IFS=',' read -r -a edge_tenants <<<"${SUDERRA_EDGE_TENANT_IDS:-}"
for tenant in "${edge_tenants[@]}"; do
    [ -n "${tenant}" ] && edge_args+=(--tenant-id "${tenant}")
done
python3 -I "${SCRIPT_DIR}/ci/edge-dev-keys.py" "${edge_args[@]}"

# Permissions
chmod 0600 ./*.key
chmod 0644 ./*.crt ./*.pub recovery-escrow.pub.pem suderra-keys.profile

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

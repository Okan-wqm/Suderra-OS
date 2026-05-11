#!/usr/bin/env bash
#
# Suderra OS — Buildroot post-image hook
# Image dosyaları üretildikten sonra çalışır.
#
# Görevler (Faz aşamasına göre):
#   1. genimage çağrısı (disk.img üret)              [Faz 1]
#   2. dm-verity root hash hesapla                   [Faz 3]
#   3. Kernel cmdline'a hash embed et                [Faz 3]
#   4. Image imzala                                  [Faz 3]
#   5. RAUC bundle oluştur                           [Faz 4]
#   6. Bundle imzala                                 [Faz 4]
#   7. SBOM üret                                     [Faz 5]
#
# Buildroot tarafından çağrılır:
#   BR2_ROOTFS_POST_IMAGE_SCRIPT="$(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra/common/post-image.sh"

set -euo pipefail
IFS=$'\n\t'

BINARIES_DIR="${1:?BINARIES_DIR not set}"
BR2_EXTERNAL_SUDERRA_PATH="${BR2_EXTERNAL_SUDERRA_PATH:?BR2_EXTERNAL_SUDERRA_PATH not set}"

echo "==> Suderra OS post-image hook"

# Mimari tespit (BR2_ARCH env'inden gelir)
ARCH="${BR2_ARCH:-unknown}"
echo "==> Arch: ${ARCH}"

# 1. genimage çağrısı — disk.img oluştur (Faz 1)
GENIMAGE_CFG=""
case "${ARCH}" in
    x86_64)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/x86_64/genimage.cfg"
        ;;
    aarch64)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64/genimage.cfg"
        ;;
    *)
        echo "ERROR: Unsupported arch: ${ARCH}"
        exit 1
        ;;
esac

if [ -f "${GENIMAGE_CFG}" ]; then
    echo "==> genimage çağrılıyor: ${GENIMAGE_CFG}"
    # Faz 1'de aktive edilecek
    # genimage --config "${GENIMAGE_CFG}" \
    #     --rootpath "${BINARIES_DIR}/.." \
    #     --inputpath "${BINARIES_DIR}" \
    #     --outputpath "${BINARIES_DIR}"
    echo "==> [TODO Faz 1] genimage çağrısı aktive et"
else
    echo "WARNING: genimage.cfg yok: ${GENIMAGE_CFG} (Faz 1'de oluşturulacak)"
fi

# 2-4. Faz 3 — dm-verity + imzalama
# TODO Faz 3:
#   veritysetup format rootfs.img verity.img > verity.txt
#   ROOT_HASH=$(awk '/Root hash:/ {print $3}' verity.txt)
#   # Kernel cmdline'a embed
#   # objcopy --update-section .cmdline="root=... dm-verity-hash=${ROOT_HASH}" kernel.efi

# 5-6. Faz 4 — RAUC bundle
# TODO Faz 4:
#   rauc bundle create --cert=${SUDERRA_KEYS_DIR}/rauc-signing.crt \
#                      --key=${SUDERRA_KEYS_DIR}/rauc-signing.key \
#                      bundle-source/ "${BINARIES_DIR}/suderra-os-${SUDERRA_VERSION}.raucb"

# 7. Faz 5 — SBOM
# TODO Faz 5:
#   "${BR2_EXTERNAL_SUDERRA_PATH}/scripts/gen-sbom.sh" \
#       "${BINARIES_DIR}/../legal-info/manifest.csv" \
#       "${BINARIES_DIR}/sbom.cyclonedx.json"

echo "==> post-image tamamlandı"

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
# BR2_ROOTFS_POST_SCRIPT_ARGS'tan gelen defconfig adı (suderra_qemu_x86_64,
# suderra_x86_64, suderra_aarch64). Layout seçimi için kullanılır.
DEFCONFIG_NAME="${2:-suderra_x86_64}"
BR2_EXTERNAL_SUDERRA_PATH="${BR2_EXTERNAL_SUDERRA_PATH:?BR2_EXTERNAL_SUDERRA_PATH not set}"

echo "==> Suderra OS post-image hook"
echo "    Defconfig: ${DEFCONFIG_NAME}"
echo "    Binaries:  ${BINARIES_DIR}"

# Mimari tespit (BR2_ARCH env'inden gelir, fallback defconfig adından)
ARCH="${BR2_ARCH:-}"
if [ -z "${ARCH}" ]; then
    case "${DEFCONFIG_NAME}" in
        *aarch64*) ARCH="aarch64" ;;
        *x86_64*)  ARCH="x86_64"  ;;
    esac
fi
echo "    Arch: ${ARCH}"

# 1. genimage config seçimi — QEMU için tek-rootfs, prod için A/B+/data
GENIMAGE_CFG=""
case "${DEFCONFIG_NAME}" in
    suderra_qemu_x86_64*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/x86_64/genimage-qemu.cfg"
        ;;
    suderra_x86_64*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/x86_64/genimage.cfg"
        ;;
    suderra_aarch64*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64/genimage.cfg"
        ;;
    *)
        echo "ERROR: Unsupported defconfig: ${DEFCONFIG_NAME}"
        exit 1
        ;;
esac

if [ ! -f "${GENIMAGE_CFG}" ]; then
    echo "ERROR: genimage.cfg yok: ${GENIMAGE_CFG}"
    exit 1
fi

# genimage host tool'u Buildroot'ta otomatik kurulur (BR2_PACKAGE_HOST_GENIMAGE)
GENIMAGE_TMP="${BUILD_DIR:-${BINARIES_DIR}/..}/genimage.tmp"
rm -rf "${GENIMAGE_TMP}"

echo "==> genimage çağrılıyor: $(basename "${GENIMAGE_CFG}")"
genimage \
    --config "${GENIMAGE_CFG}" \
    --rootpath "${TARGET_DIR:-${BINARIES_DIR}/../target}" \
    --inputpath "${BINARIES_DIR}" \
    --outputpath "${BINARIES_DIR}" \
    --tmppath "${GENIMAGE_TMP}"

echo "==> disk.img üretildi: ${BINARIES_DIR}/disk.img"
ls -la "${BINARIES_DIR}/disk.img" 2>/dev/null || true

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

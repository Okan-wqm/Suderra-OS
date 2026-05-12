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
# BR2_ROOTFS_POST_SCRIPT_ARGS'tan gelen defconfig adı:
#   - suderra_qemu_x86_64        -> QEMU disk image (test)
#   - suderra_x86_64             -> Endüstriyel x86 PC (UEFI + GRUB)
#   - suderra_aarch64            -> Generic aarch64 (template)
#   - suderra_aarch64_rpi4       -> Raspberry Pi 4 / CM4 (SD card)
#   - suderra_aarch64_revpi      -> Revolution Pi (Faz 2-B)
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

# 1. genimage config seçimi — defconfig'e göre dispatch
GENIMAGE_CFG=""
IMAGE_OUTPUT_NAME=""

prepare_rpi4_installer_payload() {
    default_target="${BR2_EXTERNAL_SUDERRA_PATH}/output/suderra_aarch64_rpi4_defconfig/images/suderra-rpi4-target.img.xz"
    target_image="${SUDERRA_TARGET_IMAGE_XZ:-${default_target}}"
    sign_key="${SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY:-}"

    [ -f "${target_image}" ] || {
        echo "ERROR: target payload image missing: ${target_image}"
        echo "Build suderra_aarch64_rpi4_defconfig first or set SUDERRA_TARGET_IMAGE_XZ."
        exit 1
    }
    [ -n "${sign_key}" ] && [ -f "${sign_key}" ] || {
        echo "ERROR: SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY must point to the manifest signing key."
        exit 1
    }

    echo "==> USB installer payload hazırlanıyor"
    cp -f "${target_image}" "${BINARIES_DIR}/suderra-rpi4-target.img.xz"

    compressed_sha="$(sha256sum "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    compressed_size="$(wc -c "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    uncompressed_sha="$(xz -dc "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | sha256sum | awk '{print $1}')"
    uncompressed_size="$(xz -dc "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | wc -c | awk '{print $1}')"

    cat > "${BINARIES_DIR}/manifest.json" <<EOF
{
  "version": "${SUDERRA_VERSION:-v0.1.0-alpha}",
  "board": "rpi4-cm4",
  "image": "suderra-rpi4-target.img.xz",
  "sha256": "${compressed_sha}",
  "size_bytes": ${compressed_size},
  "uncompressed_sha256": "${uncompressed_sha}",
  "uncompressed_size_bytes": ${uncompressed_size},
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    openssl dgst -sha256 -sign "${sign_key}" \
        -out "${BINARIES_DIR}/manifest.sig" \
        "${BINARIES_DIR}/manifest.json"
}

case "${DEFCONFIG_NAME}" in
    suderra_qemu_x86_64*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/x86_64/genimage-qemu.cfg"
        IMAGE_OUTPUT_NAME="disk.img"
        ;;
    suderra_x86_64*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/x86_64/genimage.cfg"
        IMAGE_OUTPUT_NAME="disk.img"
        ;;
    suderra_aarch64_rpi4*)
        if [ "${DEFCONFIG_NAME}" = "suderra_aarch64_rpi4_usb_installer" ]; then
            prepare_rpi4_installer_payload
            GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64-rpi4-usb-installer/genimage.cfg"
            IMAGE_OUTPUT_NAME="suderra-rpi4-usb-installer.img"
        else
            GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64-rpi4/genimage.cfg"
            IMAGE_OUTPUT_NAME="suderra-rpi4-target.img"
        fi
        ;;
    suderra_aarch64_revpi*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64-revpi4/genimage.cfg"
        IMAGE_OUTPUT_NAME="suderra-revpi4-target.img"
        ;;
    suderra_aarch64*)
        GENIMAGE_CFG="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64/genimage.cfg"
        IMAGE_OUTPUT_NAME="disk.img"
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

IMAGE_PATH="${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}"
echo "==> ${IMAGE_OUTPUT_NAME} üretildi: ${IMAGE_PATH}"
ls -la "${IMAGE_PATH}" 2>/dev/null || true

# Release artifact: xz sıkıştırma + SHA256 manifest (CI'da release.yml kullanır)
if [ -f "${IMAGE_PATH}" ] && [ "${SUDERRA_SKIP_COMPRESS:-0}" != "1" ]; then
    echo "==> ${IMAGE_OUTPUT_NAME}.xz üretiliyor"
    xz -k -T0 -9 -f "${IMAGE_PATH}"

    {
        echo "# Suderra OS — release manifest"
        echo "# Build: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Defconfig: ${DEFCONFIG_NAME}"
        echo "# Arch: ${ARCH}"
        echo ""
        echo "# SHA256 checksums:"
        ( cd "${BINARIES_DIR}" && sha256sum "${IMAGE_OUTPUT_NAME}" "${IMAGE_OUTPUT_NAME}.xz" )
    } > "${BINARIES_DIR}/MANIFEST.txt"
    cat "${BINARIES_DIR}/MANIFEST.txt"
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

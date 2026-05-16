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

CONFIG_VARIANT=""
if [ -n "${BR2_CONFIG:-}" ] && [ -f "${BR2_CONFIG}" ]; then
    if grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_DEV=y' "${BR2_CONFIG}"; then
        CONFIG_VARIANT="dev"
    elif grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${BR2_CONFIG}"; then
        CONFIG_VARIANT="prod"
    fi
fi
ENV_VARIANT="${SUDERRA_VARIANT:-}"
case "${ENV_VARIANT}" in
    ""|dev|prod) ;;
    *)
        echo "ERROR: SUDERRA_VARIANT must be dev or prod, got '${ENV_VARIANT}'"
        exit 1
        ;;
esac
if [ -n "${CONFIG_VARIANT}" ] && [ -n "${ENV_VARIANT}" ] && [ "${CONFIG_VARIANT}" != "${ENV_VARIANT}" ]; then
    echo "ERROR: BR2 Suderra variant (${CONFIG_VARIANT}) conflicts with SUDERRA_VARIANT=${ENV_VARIANT}"
    echo "Production/dev variant selection must come from one authoritative build contract."
    exit 1
fi
if [ -n "${CONFIG_VARIANT}" ]; then
    SUDERRA_OS_VARIANT="${CONFIG_VARIANT}"
elif [ -n "${ENV_VARIANT}" ]; then
    SUDERRA_OS_VARIANT="${ENV_VARIANT}"
else
    case "${DEFCONFIG_NAME}" in
        suderra_x86_64*)
            echo "ERROR: production-capable ${DEFCONFIG_NAME} requires BR2_CONFIG or SUDERRA_VARIANT"
            exit 1
            ;;
        *)
            SUDERRA_OS_VARIANT="dev"
            ;;
    esac
fi
echo "    Variant: ${SUDERRA_OS_VARIANT}"

# 1. genimage config seçimi — defconfig'e göre dispatch
GENIMAGE_CFG=""
IMAGE_OUTPUT_NAME=""

prepare_rpi4_installer_payload() {
    # CI/release pipelines export these explicitly via MATRIX_PAYLOAD_IMAGE_EXPORTS.
    # Local dev builds must point them at concrete artifacts; fall back paths
    # would silently resolve against host paths inside the container.
    rpi4_image="${SUDERRA_RPI4_TARGET_IMAGE_XZ:?SUDERRA_RPI4_TARGET_IMAGE_XZ must point to the RPi4 target image (.img.xz)}"
    revpi4_image="${SUDERRA_REVPI4_TARGET_IMAGE_XZ:?SUDERRA_REVPI4_TARGET_IMAGE_XZ must point to the RevPi4 target image (.img.xz)}"
    sign_key="${SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY:-}"
    public_key="${SUDERRA_INSTALLER_PAYLOAD_PUBKEY:-}"

    [ -f "${rpi4_image}" ] || {
        echo "ERROR: RPi4/CM4 target payload image missing: ${rpi4_image}"
        echo "Build suderra_aarch64_rpi4_defconfig first or set SUDERRA_RPI4_TARGET_IMAGE_XZ."
        exit 1
    }
    [ -f "${revpi4_image}" ] || {
        echo "ERROR: RevPi4 target payload image missing: ${revpi4_image}"
        echo "Build suderra_aarch64_revpi4_defconfig first or set SUDERRA_REVPI4_TARGET_IMAGE_XZ."
        exit 1
    }
    [ -n "${sign_key}" ] && [ -f "${sign_key}" ] || {
        echo "ERROR: SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY must point to an Ed25519 PEM signing key."
        exit 1
    }
    [ -n "${public_key}" ] && [ -f "${public_key}" ] || {
        echo "ERROR: SUDERRA_INSTALLER_PAYLOAD_PUBKEY must point to the pinned Ed25519 public key."
        exit 1
    }

    echo "==> USB installer payload hazırlanıyor"
    cp -f "${rpi4_image}" "${BINARIES_DIR}/suderra-rpi4-target.img.xz"
    cp -f "${revpi4_image}" "${BINARIES_DIR}/suderra-revpi4-target.img.xz"

    rpi4_compressed_sha="$(sha256sum "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    rpi4_compressed_size="$(wc -c "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    rpi4_uncompressed_sha="$(xz -dc "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | sha256sum | awk '{print $1}')"
    rpi4_uncompressed_size="$(xz -dc "${BINARIES_DIR}/suderra-rpi4-target.img.xz" | wc -c | awk '{print $1}')"

    revpi4_compressed_sha="$(sha256sum "${BINARIES_DIR}/suderra-revpi4-target.img.xz" | awk '{print $1}')"
    revpi4_compressed_size="$(wc -c "${BINARIES_DIR}/suderra-revpi4-target.img.xz" | awk '{print $1}')"
    revpi4_uncompressed_sha="$(xz -dc "${BINARIES_DIR}/suderra-revpi4-target.img.xz" | sha256sum | awk '{print $1}')"
    revpi4_uncompressed_size="$(xz -dc "${BINARIES_DIR}/suderra-revpi4-target.img.xz" | wc -c | awk '{print $1}')"

    cat > "${BINARIES_DIR}/manifest.json" <<EOF
{
  "schema_version": 1,
  "kind": "suderra.usb-payload-index.v1",
  "board_family": "pi-cm4-revpi",
  "compatible_models": ["rpi4-cm4", "revpi4"],
  "payloads": [
    {
      "name": "rpi4-cm4",
      "board_family": "rpi4-cm4",
      "compatible_models": ["rpi4-cm4"],
      "arch": "aarch64",
      "image_path": "suderra-rpi4-target.img.xz",
      "compressed_sha256": "${rpi4_compressed_sha}",
      "compressed_size_bytes": ${rpi4_compressed_size},
      "uncompressed_sha256": "${rpi4_uncompressed_sha}",
      "uncompressed_size_bytes": ${rpi4_uncompressed_size},
      "min_storage_bytes": 8589934592,
      "rollback_floor": "${SUDERRA_ROLLBACK_FLOOR:-v0.1.0-alpha}"
    },
    {
      "name": "revpi4",
      "board_family": "revpi4",
      "compatible_models": ["revpi4"],
      "arch": "aarch64",
      "image_path": "suderra-revpi4-target.img.xz",
      "compressed_sha256": "${revpi4_compressed_sha}",
      "compressed_size_bytes": ${revpi4_compressed_size},
      "uncompressed_sha256": "${revpi4_uncompressed_sha}",
      "uncompressed_size_bytes": ${revpi4_uncompressed_size},
      "min_storage_bytes": 8589934592,
      "rollback_floor": "${SUDERRA_ROLLBACK_FLOOR:-v0.1.0-alpha}"
    }
  ],
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "expires_at": "${SUDERRA_INSTALLER_PAYLOAD_EXPIRES_AT:?SUDERRA_INSTALLER_PAYLOAD_EXPIRES_AT must be an ISO-8601 UTC timestamp}",
  "key_epoch": ${SUDERRA_INSTALLER_KEY_EPOCH:?SUDERRA_INSTALLER_KEY_EPOCH must be set (positive integer)}
}
EOF

    python3 - "${BINARIES_DIR}/manifest.json" > "${BINARIES_DIR}/manifest.canonical" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    payload = json.load(fh)
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
PY

    openssl pkeyutl -sign -rawin -inkey "${sign_key}" \
        -in "${BINARIES_DIR}/manifest.canonical" \
        -out "${BINARIES_DIR}/manifest.sig"
    openssl pkeyutl -verify -rawin -pubin -inkey "${public_key}" \
        -sigfile "${BINARIES_DIR}/manifest.sig" \
        -in "${BINARIES_DIR}/manifest.canonical"
    rm -f "${BINARIES_DIR}/manifest.canonical"
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
            IMAGE_OUTPUT_NAME="suderra-pi-cm4-revpi-usb-installer.img"
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

enforce_production_contract() {
    missing=""
    production_target="0"

    case "${DEFCONFIG_NAME}" in
        suderra_x86_64*|suderra_aarch64_rpi4*|suderra_aarch64_revpi*)
            production_target="1"
            ;;
    esac
    if [ "${production_target}" != "1" ]; then
        echo "==> Production contract gate skipped: ${DEFCONFIG_NAME} is not a production target"
        return 0
    fi

    for artifact in \
        "${BINARIES_DIR}/rootfs.verity" \
        "${BINARIES_DIR}/rootfs.verity.roothash" \
        "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}.sig" \
        "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}.cert"
    do
        if [ ! -s "${artifact}" ]; then
            missing="${missing} ${artifact}"
        fi
    done

    case "${DEFCONFIG_NAME}" in
        suderra_x86_64*)
            for artifact in \
                "${BINARIES_DIR}/suderra.efi" \
                "${BINARIES_DIR}/suderra.efi.sig"
            do
                if [ ! -s "${artifact}" ]; then
                    missing="${missing} ${artifact}"
                fi
            done
            ;;
        suderra_aarch64_rpi4*|suderra_aarch64_revpi*)
            if [ "${DEFCONFIG_NAME}" != "suderra_aarch64_rpi4_usb_installer" ]; then
                for artifact in \
                    "${BINARIES_DIR}/suderra.fit" \
                    "${BINARIES_DIR}/suderra.fit.sig"
                do
                    if [ ! -s "${artifact}" ]; then
                        missing="${missing} ${artifact}"
                    fi
                done
            fi
            ;;
    esac

    if [ -n "${missing}" ]; then
        echo "ERROR: production build is missing required signed/verity artifacts:"
        # shellcheck disable=SC2086
        for artifact in ${missing}; do
            echo "  - ${artifact}"
        done
        echo "Production images must fail closed until dm-verity, signed boot artifacts, and release signing are wired."
        exit 1
    fi

    if ! grep -Eq '^[0-9a-f]{64}$' "${BINARIES_DIR}/rootfs.verity.roothash"; then
        echo "ERROR: rootfs.verity.roothash must contain a lowercase sha256 root hash"
        exit 1
    fi
    if [ "$(wc -c < "${BINARIES_DIR}/rootfs.verity")" -lt 4096 ]; then
        echo "ERROR: rootfs.verity is too small to be a real verity hash tree"
        exit 1
    fi
    if [ "$(wc -c < "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}.sig")" -lt 64 ]; then
        echo "ERROR: ${IMAGE_OUTPUT_NAME}.sig is too small to be a production signature"
        exit 1
    fi
    if ! openssl x509 -in "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}.cert" -noout >/dev/null 2>&1; then
        echo "ERROR: ${IMAGE_OUTPUT_NAME}.cert must be a parseable X.509 certificate"
        exit 1
    fi

    # Cryptographic gates — boyut/parse syntax kontrolü yetmez. Imza ve
    # verity hash tree gerçek kriptografik testle doğrulanmalı.
    cert_pubkey="${GENIMAGE_TMP:-${BINARIES_DIR}}/${IMAGE_OUTPUT_NAME}.pubkey"
    if ! openssl x509 -in "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}.cert" \
            -pubkey -noout > "${cert_pubkey}" 2>/dev/null; then
        echo "ERROR: ${IMAGE_OUTPUT_NAME}.cert does not contain a usable public key"
        exit 1
    fi
    if ! openssl dgst -sha256 -verify "${cert_pubkey}" \
            -signature "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}.sig" \
            "${BINARIES_DIR}/${IMAGE_OUTPUT_NAME}" >/dev/null 2>&1; then
        echo "ERROR: ${IMAGE_OUTPUT_NAME}.sig does not validate against ${IMAGE_OUTPUT_NAME}.cert"
        rm -f "${cert_pubkey}"
        exit 1
    fi
    rm -f "${cert_pubkey}"

    # Verity hash tree must actually correspond to the rootfs it claims to
    # protect. Without this check the file could be any 4KiB+ blob.
    if command -v veritysetup >/dev/null 2>&1; then
        declared_roothash="$(cat "${BINARIES_DIR}/rootfs.verity.roothash")"
        if ! veritysetup verify \
                "${BINARIES_DIR}/rootfs.img" \
                "${BINARIES_DIR}/rootfs.verity" \
                "${declared_roothash}" >/dev/null 2>&1; then
            echo "ERROR: rootfs.verity hash tree does not match declared roothash"
            exit 1
        fi
    else
        echo "ERROR: veritysetup not available in build environment — production gate cannot pass"
        exit 1
    fi

    if grep -q '^BR2_TARGET_ENABLE_ROOT_LOGIN=y' "${BR2_CONFIG}" 2>/dev/null; then
        echo "ERROR: production defconfig must not enable BR2_TARGET_ENABLE_ROOT_LOGIN"
        exit 1
    fi
}

if [ "${SUDERRA_OS_VARIANT}" = "prod" ]; then
    enforce_production_contract
fi

# dm-verity, signed boot artifacts, RAUC bundles, and SBOM release evidence are
# production gates, not best-effort post-image decorations. Until those
# artifacts are generated by their dedicated build/release stages, production
# variants fail closed in enforce_production_contract above.

echo "==> post-image tamamlandı"

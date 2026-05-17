#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
INSTALLER="${PROJECT_ROOT}/package/suderra-os-installer/suderra-os-install"
VERIFY_BIN="${SUDERRA_INSTALLER_VERIFY_BIN:-${PROJECT_ROOT}/userspace/target/x86_64-unknown-linux-gnu/debug/suderra-installer}"
CARGO_BIN="${CARGO_BIN:-cargo}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

ensure_verify_bin() {
    (cd "${PROJECT_ROOT}/userspace" && \
        "${CARGO_BIN}" build -p suderra-installer --target x86_64-unknown-linux-gnu)
}

make_disk() {
    local name="$1"
    local sectors="$2"
    local removable="$3"
    local media_type="${4:-}"
    mkdir -p "${TMPDIR}/sys/block/${name}"
    printf '%s\n' "${sectors}" > "${TMPDIR}/sys/block/${name}/size"
    printf '%s\n' "${removable}" > "${TMPDIR}/sys/block/${name}/removable"
    if [ -n "${media_type}" ]; then
        mkdir -p "${TMPDIR}/sys/block/${name}/device"
        printf '%s\n' "${media_type}" > "${TMPDIR}/sys/block/${name}/device/type"
    fi
}

reset_sys() {
    rm -rf "${TMPDIR:?}/sys" "${TMPDIR:?}/payload" "${TMPDIR:?}/keys" "${TMPDIR:?}/dev"
    mkdir -p "${TMPDIR}/sys/block" "${TMPDIR}/payload" "${TMPDIR}/keys"
    mkdir -p "${TMPDIR}/dev/disk/by-id"
}

run_select() {
    SUDERRA_INSTALLER_SYS_BLOCK="${TMPDIR}/sys/block" \
    SUDERRA_INSTALLER_SOURCE_DISK="${1}" \
    SUDERRA_INSTALLER_MIN_BYTES=1 \
    SUDERRA_INSTALLER_DEV_DIR="${TMPDIR}/dev" \
    "${INSTALLER}" --select-target
}

expect_eq() {
    local expected="$1"
    local actual="$2"
    if [ "${expected}" != "${actual}" ]; then
        echo "expected '${expected}', got '${actual}'" >&2
        exit 1
    fi
}

expect_fail() {
    if "$@" >/tmp/suderra-installer-test.out 2>&1; then
        cat /tmp/suderra-installer-test.out >&2
        echo "command unexpectedly succeeded: $*" >&2
        exit 1
    fi
}

test_self_usb_excluded() {
    reset_sys
    make_disk sda 16777216 1
    expect_fail run_select sda
}

test_emmc_preferred_over_sd() {
    reset_sys
    make_disk mmcblk0 16777216 0 MMC
    make_disk mmcblk1 16777216 1 SD
    expect_eq "${TMPDIR}/dev/mmcblk0" "$(run_select sda)"
}

test_sd_fallback() {
    reset_sys
    make_disk mmcblk1 16777216 1 SD
    expect_eq "${TMPDIR}/dev/mmcblk1" "$(run_select sda)"
}

test_multiple_equal_targets_fail() {
    reset_sys
    make_disk mmcblk0 16777216 0 MMC
    make_disk mmcblk1 16777216 0 MMC
    expect_fail run_select sda
}

test_usb_target_requires_factory_flag() {
    reset_sys
    make_disk sdb 16777216 1
    expect_fail run_select sda

    touch "${TMPDIR}/dev/sdb"
    ln -s ../../sdb "${TMPDIR}/dev/disk/by-id/usb-suderra-target"
    actual="$(
        SUDERRA_INSTALLER_SYS_BLOCK="${TMPDIR}/sys/block" \
        SUDERRA_INSTALLER_SOURCE_DISK=sda \
        SUDERRA_INSTALLER_MIN_BYTES=1 \
        SUDERRA_INSTALLER_DEV_DIR="${TMPDIR}/dev" \
        SUDERRA_INSTALLER_ALLOW_USB_TARGET=1 \
        SUDERRA_INSTALLER_USB_TARGET_BY_ID="${TMPDIR}/dev/disk/by-id/usb-suderra-target" \
        "${INSTALLER}" --select-target
    )"
    expect_eq "${TMPDIR}/dev/disk/by-id/usb-suderra-target" "${actual}"
}

test_usb_target_non_usb_by_id_requires_removable() {
    reset_sys
    make_disk sdb 16777216 0
    touch "${TMPDIR}/dev/sdb"
    ln -s ../../sdb "${TMPDIR}/dev/disk/by-id/ata-fixed-target"
    expect_fail env \
        SUDERRA_INSTALLER_SYS_BLOCK="${TMPDIR}/sys/block" \
        SUDERRA_INSTALLER_SOURCE_DISK=sda \
        SUDERRA_INSTALLER_MIN_BYTES=1 \
        SUDERRA_INSTALLER_DEV_DIR="${TMPDIR}/dev" \
        SUDERRA_INSTALLER_ALLOW_USB_TARGET=1 \
        SUDERRA_INSTALLER_USB_TARGET_BY_ID="${TMPDIR}/dev/disk/by-id/ata-fixed-target" \
        "${INSTALLER}" --select-target
}

test_board_detection_allowlist() {
    prepare_payload
    printf 'Raspberry Pi 4 Model B Rev 1.5\000' > "${TMPDIR}/model"
    SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
    SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
    SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
    SUDERRA_INSTALLER_PROC_MODEL="${TMPDIR}/model" \
    SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
    SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
    SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
    "${INSTALLER}" --verify-payload >/tmp/suderra-board-detect.out
    grep -q "Payload verified" /tmp/suderra-board-detect.out
}

test_unsupported_pi_model_rejected() {
    prepare_payload
    printf 'Raspberry Pi 5 Model B Rev 1.0\000' > "${TMPDIR}/model"
    expect_fail env \
        SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
        SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
        SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
        SUDERRA_INSTALLER_PROC_MODEL="${TMPDIR}/model" \
        SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
        SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
        SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
        "${INSTALLER}" --verify-payload
}

test_revpi_model_detected() {
    prepare_payload
    printf 'RevPi Connect 4 Rev 1.0\000' > "${TMPDIR}/model"
    SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
    SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
    SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
    SUDERRA_INSTALLER_PROC_MODEL="${TMPDIR}/model" \
    SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
    SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
    SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
    "${INSTALLER}" --verify-payload >/tmp/suderra-revpi-detect.out
    grep -q "Verifying signed installer payload for revpi4" /tmp/suderra-revpi-detect.out
}

test_revpi_compatible_detected_with_generic_cm4_model() {
    prepare_payload
    printf 'Raspberry Pi Compute Module 4 Rev 1.1\000' > "${TMPDIR}/model"
    printf 'raspberrypi,4-compute-module\000kunbus,revpi-connect-4\000' > "${TMPDIR}/compatible"
    SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
    SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
    SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
    SUDERRA_INSTALLER_PROC_MODEL="${TMPDIR}/model" \
    SUDERRA_INSTALLER_PROC_COMPATIBLE="${TMPDIR}/compatible" \
    SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
    SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
    SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
    "${INSTALLER}" --verify-payload >/tmp/suderra-revpi-compatible.out
    grep -q "Verifying signed installer payload for revpi4" /tmp/suderra-revpi-compatible.out
}

test_generic_cm4_requires_explicit_board() {
    prepare_payload
    printf 'Raspberry Pi Compute Module 4 Rev 1.1\000' > "${TMPDIR}/model"
    expect_fail env \
        SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
        SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
        SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
        SUDERRA_INSTALLER_PROC_MODEL="${TMPDIR}/model" \
        SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
        SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
        SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
        "${INSTALLER}" --verify-payload
}

test_generic_cm4_explicit_override_allowed() {
    prepare_payload
    printf 'Raspberry Pi Compute Module 4 Rev 1.1\000' > "${TMPDIR}/model"
    SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
    SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
    SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
    SUDERRA_INSTALLER_PROC_MODEL="${TMPDIR}/model" \
    SUDERRA_INSTALLER_TARGET_BOARD=rpi4-cm4 \
    SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
    SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
    SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
    "${INSTALLER}" --verify-payload >/tmp/suderra-cm4-override.out
    grep -q "Verifying signed installer payload for rpi4-cm4" /tmp/suderra-cm4-override.out
}

write_manifest() {
    local sha="$1"
    local size="$2"
    local uncompressed_sha="$3"
    local uncompressed_size="$4"
    local expires_at="${MANIFEST_EXPIRES_AT:-2099-01-01T00:00:00Z}"
    local key_epoch="${MANIFEST_KEY_EPOCH:-1}"
    local rollback_floor="${MANIFEST_ROLLBACK_FLOOR:-v0.1.0-alpha}"
    cat > "${TMPDIR}/payload/manifest.json" <<EOF
{
  "schema_version": 1,
  "kind": "suderra.usb-payload-index.v1",
  "board_family": "pi-cm4-revpi",
  "compatible_models": ["rpi4-cm4", "revpi4"],
    "payloads": [
    {
      "name": "rpi4",
      "board_family": "rpi4-cm4",
      "compatible_models": ["rpi4-cm4"],
      "arch": "aarch64",
      "image_path": "suderra-rpi4-target.img.xz",
      "compressed_sha256": "${sha}",
      "compressed_size_bytes": ${size},
      "uncompressed_sha256": "${uncompressed_sha}",
      "uncompressed_size_bytes": ${uncompressed_size},
      "min_storage_bytes": 1024,
      "rollback_floor": "${rollback_floor}"
    },
    {
      "name": "revpi4",
      "board_family": "revpi4",
      "compatible_models": ["revpi4"],
      "arch": "aarch64",
      "image_path": "suderra-rpi4-target.img.xz",
      "compressed_sha256": "${sha}",
      "compressed_size_bytes": ${size},
      "uncompressed_sha256": "${uncompressed_sha}",
      "uncompressed_size_bytes": ${uncompressed_size},
      "min_storage_bytes": 1024,
      "rollback_floor": "${rollback_floor}"
    }
  ],
  "created_at": "2026-05-12T00:00:00Z",
  "expires_at": "${expires_at}",
  "key_epoch": ${key_epoch}
}
EOF
}

sign_manifest() {
    SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
    "${VERIFY_BIN}" usb-payload sign \
        --manifest "${TMPDIR}/payload/manifest.json" \
        --private-key "${TMPDIR}/keys/payload.key" \
        --signature "${TMPDIR}/payload/manifest.sig"
}

prepare_payload() {
    ensure_verify_bin
    reset_sys
    openssl genpkey -algorithm ED25519 \
        -out "${TMPDIR}/keys/payload.key" >/dev/null 2>&1
    openssl pkey -in "${TMPDIR}/keys/payload.key" \
        -pubout -out "${TMPDIR}/keys/payload.pub.pem" >/dev/null 2>&1
    printf 'target image bytes' > "${TMPDIR}/payload/suderra-rpi4-target.img"
    xz -z -k -f "${TMPDIR}/payload/suderra-rpi4-target.img"
    sha="$(sha256sum "${TMPDIR}/payload/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    size="$(wc -c "${TMPDIR}/payload/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    uncompressed_sha="$(sha256sum "${TMPDIR}/payload/suderra-rpi4-target.img" | awk '{print $1}')"
    uncompressed_size="$(wc -c "${TMPDIR}/payload/suderra-rpi4-target.img" | awk '{print $1}')"
    write_manifest "${sha}" "${size}" "${uncompressed_sha}" "${uncompressed_size}"
    sign_manifest
}

verify_payload() {
    local target_board="${1:-rpi4-cm4}"
    local min_key_epoch="${2:-1}"
    local min_rollback_floor="${3:-v0.1.0-alpha}"
    SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
    SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
    SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
    SUDERRA_INSTALLER_TARGET_BOARD="${target_board}" \
    SUDERRA_INSTALLER_TARGET_ARCH=aarch64 \
    SUDERRA_INSTALLER_MIN_KEY_EPOCH="${min_key_epoch}" \
    SUDERRA_INSTALLER_MIN_ROLLBACK_FLOOR="${min_rollback_floor}" \
    SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
    SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
    "${INSTALLER}" --verify-payload >/dev/null
}

test_manifest_signature_required() {
    prepare_payload
    rm -f "${TMPDIR}/payload/manifest.sig"
    expect_fail verify_payload rpi4-cm4
}

test_manifest_sha_required() {
    prepare_payload
    printf 'tampered' > "${TMPDIR}/payload/suderra-rpi4-target.img.xz"
    expect_fail verify_payload rpi4-cm4
}

test_manifest_expiry_required() {
    MANIFEST_EXPIRES_AT="2000-01-01T00:00:00Z" prepare_payload
    expect_fail verify_payload rpi4-cm4
}

test_manifest_wrong_board_rejected() {
    prepare_payload
    expect_fail verify_payload unknown-board
}

test_manifest_rollback_floor_required() {
    prepare_payload
    expect_fail verify_payload rpi4-cm4 1 v0.2.0
}

test_manifest_key_epoch_floor_required() {
    MANIFEST_KEY_EPOCH=1 prepare_payload
    expect_fail verify_payload rpi4-cm4 2 v0.1.0-alpha
}

test_manifest_wrong_arch_rejected() {
    prepare_payload
    expect_fail env \
        SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
        SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
        SUDERRA_INSTALLER_VERIFY_BIN="${VERIFY_BIN}" \
        SUDERRA_INSTALLER_TARGET_BOARD=rpi4-cm4 \
        SUDERRA_INSTALLER_TARGET_ARCH=x86_64 \
        SUDERRA_INSTALLER_REPORT_DIR="${TMPDIR}/report" \
        SUDERRA_AUDIT_LOG="${TMPDIR}/audit.log" \
        "${INSTALLER}" --verify-payload
}

test_manifest_verifies() {
    prepare_payload
    verify_payload rpi4-cm4
}

for test_name in \
    test_self_usb_excluded \
    test_emmc_preferred_over_sd \
    test_sd_fallback \
    test_multiple_equal_targets_fail \
    test_usb_target_requires_factory_flag \
    test_usb_target_non_usb_by_id_requires_removable \
    test_board_detection_allowlist \
    test_unsupported_pi_model_rejected \
    test_revpi_model_detected \
    test_revpi_compatible_detected_with_generic_cm4_model \
    test_generic_cm4_requires_explicit_board \
    test_generic_cm4_explicit_override_allowed \
    test_manifest_signature_required \
    test_manifest_sha_required \
    test_manifest_expiry_required \
    test_manifest_wrong_board_rejected \
    test_manifest_rollback_floor_required \
    test_manifest_key_epoch_floor_required \
    test_manifest_wrong_arch_rejected \
    test_manifest_verifies
do
    echo "  - ${test_name}"
    "${test_name}"
done

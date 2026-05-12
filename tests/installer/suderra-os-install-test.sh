#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
INSTALLER="${PROJECT_ROOT}/package/suderra-os-installer/suderra-os-install"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

make_disk() {
    local name="$1"
    local sectors="$2"
    local removable="$3"
    mkdir -p "${TMPDIR}/sys/block/${name}"
    printf '%s\n' "${sectors}" > "${TMPDIR}/sys/block/${name}/size"
    printf '%s\n' "${removable}" > "${TMPDIR}/sys/block/${name}/removable"
}

reset_sys() {
    rm -rf "${TMPDIR}/sys" "${TMPDIR}/payload" "${TMPDIR}/keys"
    mkdir -p "${TMPDIR}/sys/block" "${TMPDIR}/payload" "${TMPDIR}/keys"
}

run_select() {
    SUDERRA_INSTALLER_SYS_BLOCK="${TMPDIR}/sys/block" \
    SUDERRA_INSTALLER_SOURCE_DISK="${1}" \
    SUDERRA_INSTALLER_MIN_BYTES=1 \
    SUDERRA_INSTALLER_DEV_DIR=/dev \
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
    make_disk mmcblk0 16777216 0
    make_disk mmcblk1 16777216 1
    expect_eq /dev/mmcblk0 "$(run_select sda)"
}

test_sd_fallback() {
    reset_sys
    make_disk mmcblk1 16777216 1
    expect_eq /dev/mmcblk1 "$(run_select sda)"
}

test_multiple_equal_targets_fail() {
    reset_sys
    make_disk mmcblk0 16777216 0
    make_disk mmcblk1 16777216 0
    expect_fail run_select sda
}

test_usb_target_requires_factory_flag() {
    reset_sys
    make_disk sdb 16777216 1
    expect_fail run_select sda

    actual="$(
        SUDERRA_INSTALLER_SYS_BLOCK="${TMPDIR}/sys/block" \
        SUDERRA_INSTALLER_SOURCE_DISK=sda \
        SUDERRA_INSTALLER_MIN_BYTES=1 \
        SUDERRA_INSTALLER_DEV_DIR=/dev \
        SUDERRA_INSTALLER_ALLOW_USB_TARGET=1 \
        "${INSTALLER}" --select-target
    )"
    expect_eq /dev/sdb "${actual}"
}

write_manifest() {
    local sha="$1"
    local size="$2"
    cat > "${TMPDIR}/payload/manifest.json" <<EOF
{
  "version": "test",
  "board": "rpi4-cm4",
  "image": "suderra-rpi4-target.img.xz",
  "sha256": "${sha}",
  "size_bytes": ${size},
  "uncompressed_sha256": "${sha}",
  "uncompressed_size_bytes": ${size},
  "created_at": "2026-05-12T00:00:00Z"
}
EOF
}

sign_manifest() {
    openssl dgst -sha256 -sign "${TMPDIR}/keys/payload.key" \
        -out "${TMPDIR}/payload/manifest.sig" \
        "${TMPDIR}/payload/manifest.json"
}

prepare_payload() {
    reset_sys
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "${TMPDIR}/keys/payload.key" >/dev/null 2>&1
    openssl rsa -in "${TMPDIR}/keys/payload.key" \
        -pubout -out "${TMPDIR}/keys/payload.pub.pem" >/dev/null 2>&1
    printf 'target image bytes' > "${TMPDIR}/payload/suderra-rpi4-target.img.xz"
    sha="$(sha256sum "${TMPDIR}/payload/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    size="$(wc -c "${TMPDIR}/payload/suderra-rpi4-target.img.xz" | awk '{print $1}')"
    write_manifest "${sha}" "${size}"
    sign_manifest
}

verify_payload() {
    SUDERRA_INSTALLER_PAYLOAD_DIR="${TMPDIR}/payload" \
    SUDERRA_INSTALLER_PUBKEY="${TMPDIR}/keys/payload.pub.pem" \
    "${INSTALLER}" --verify-payload >/dev/null
}

test_manifest_signature_required() {
    prepare_payload
    rm -f "${TMPDIR}/payload/manifest.sig"
    expect_fail verify_payload
}

test_manifest_sha_required() {
    prepare_payload
    printf 'tampered' > "${TMPDIR}/payload/suderra-rpi4-target.img.xz"
    expect_fail verify_payload
}

test_manifest_verifies() {
    prepare_payload
    verify_payload
}

for test_name in \
    test_self_usb_excluded \
    test_emmc_preferred_over_sd \
    test_sd_fallback \
    test_multiple_equal_targets_fail \
    test_usb_target_requires_factory_flag \
    test_manifest_signature_required \
    test_manifest_sha_required \
    test_manifest_verifies
do
    echo "  - ${test_name}"
    "${test_name}"
done

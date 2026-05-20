#!/usr/bin/env bash
#
# Suderra OS production artifact generator.
#
# This script creates the artifacts that post-image later verifies. Production
# builds must not satisfy gates with hand-written placeholder files.

set -euo pipefail
IFS=$'\n\t'

usage() {
    cat <<'EOF'
Usage:
  production-artifacts.sh x86-pre-genimage <BINARIES_DIR> <TARGET_DIR>
  production-artifacts.sh sign-image <BINARIES_DIR> <IMAGE_NAME>

Required for x86-pre-genimage:
  SUDERRA_UKI_STUB                         EFI stub used to build signed UKI
  SUDERRA_SECUREBOOT_SIGNING_KEY           Secure Boot signing private key
  SUDERRA_SECUREBOOT_SIGNING_CERT          Secure Boot signing certificate
  SUDERRA_GRUB_EFI_INPUT                   Optional unsigned GRUB EFI input
  SUDERRA_GRUB_EDITENV                     Optional grub-editenv path

Required for sign-image:
  SUDERRA_IMAGE_SIGNING_KEY or SUDERRA_SECUREBOOT_SIGNING_KEY
  SUDERRA_IMAGE_SIGNING_CERT or SUDERRA_SECUREBOOT_SIGNING_CERT
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_file() {
    [ -s "$1" ] || die "required file missing or empty: $1"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

resolve_grub_editenv() {
    local candidate="${SUDERRA_GRUB_EDITENV:-}"

    if [ -n "${candidate}" ]; then
        [ -x "${candidate}" ] || die "SUDERRA_GRUB_EDITENV is not executable: ${candidate}"
        printf '%s\n' "${candidate}"
        return 0
    fi
    if [ -n "${HOST_DIR:-}" ] && [ -x "${HOST_DIR}/bin/grub-editenv" ]; then
        printf '%s\n' "${HOST_DIR}/bin/grub-editenv"
        return 0
    fi
    if command -v grub-editenv >/dev/null 2>&1; then
        command -v grub-editenv
        return 0
    fi
    die "grub-editenv is required to initialize the RAUC/GRUB boot environment"
}

reproducible_timestamp() {
    if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
        date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ
    else
        date -u +%Y-%m-%dT%H:%M:%SZ
    fi
}

generate_verity() {
    local binaries_dir="$1"
    local rootfs="${binaries_dir}/rootfs.ext4"
    local hash="${binaries_dir}/rootfs.verity"
    local roothash="${binaries_dir}/rootfs.verity.roothash"
    local meta="${binaries_dir}/rootfs.verity.env"
    local log="${binaries_dir}/rootfs.verity.format.log"

    need_cmd veritysetup
    need_file "${rootfs}"

    rm -f "${hash}" "${roothash}" "${meta}" "${log}"
    : > "${hash}"
    veritysetup format "${rootfs}" "${hash}" > "${log}"

    awk -F: '/Root hash/ {gsub(/^[ \t]+/, "", $2); print $2}' "${log}" > "${roothash}"
    root_hash="$(cat "${roothash}")"
    [ -n "${root_hash}" ] || die "veritysetup did not emit a root hash"

    data_blocks="$(awk -F: '/Data blocks/ {gsub(/^[ \t]+/, "", $2); print $2}' "${log}")"
    salt="$(awk -F: '/Salt/ {gsub(/^[ \t]+/, "", $2); print $2}' "${log}")"
    [ -n "${data_blocks}" ] || die "veritysetup did not emit data block count"
    [ -n "${salt}" ] || die "veritysetup did not emit salt"

    {
        printf 'ROOT_HASH=%s\n' "${root_hash}"
        printf 'DATA_BLOCKS=%s\n' "${data_blocks}"
        printf 'DATA_BLOCK_SIZE=4096\n'
        printf 'HASH_BLOCK_SIZE=4096\n'
        printf 'HASH_START_BLOCK=0\n'
        printf 'HASH_ALGORITHM=sha256\n'
        printf 'SALT=%s\n' "${salt}"
        printf 'GENERATED_AT=%s\n' "$(reproducible_timestamp)"
    } > "${meta}"

    veritysetup verify "${rootfs}" "${hash}" "${root_hash}" >/dev/null
}

write_x86_verity_cmdline() {
    local binaries_dir="$1"
    local slot="$2"
    local slot_lower
    local root_partlabel
    local verity_partlabel
    local cmdline="${binaries_dir}/suderra-${slot}.cmdline"
    local data_sectors
    local dm_table

    slot_lower="$(printf '%s' "${slot}" | tr 'A-Z' 'a-z')"
    root_partlabel="rootfs-${slot_lower}"
    verity_partlabel="rootfs-${slot_lower}-verity"

    # shellcheck disable=SC1091
    . "${binaries_dir}/rootfs.verity.env"

    data_sectors=$((DATA_BLOCKS * DATA_BLOCK_SIZE / 512))
    dm_table="suderra-root,,,ro,0 ${data_sectors} verity 1 /dev/disk/by-partlabel/${root_partlabel} /dev/disk/by-partlabel/${verity_partlabel} ${DATA_BLOCK_SIZE} ${HASH_BLOCK_SIZE} ${DATA_BLOCKS} ${HASH_START_BLOCK} ${HASH_ALGORITHM} ${ROOT_HASH} ${SALT}"
    printf '%s\n' \
        "console=ttyS0,115200n8 console=tty0 root=/dev/dm-0 ro rootwait rauc.slot=${slot} dm-mod.create=\"${dm_table}\" lockdown=confidentiality slab_nomerge slub_debug=- page_alloc.shuffle=1 randomize_kstack_offset=on init_on_alloc=1 init_on_free=1 vsyscall=none debugfs=off oops=panic panic=10 module.sig_enforce=1 quiet" \
        > "${cmdline}"
}

build_signed_slot_uki() {
    local binaries_dir="$1"
    local target_dir="$2"
    local slot="A"
    local stub="${SUDERRA_UKI_STUB:-}"
    local sb_key="${SUDERRA_SECUREBOOT_SIGNING_KEY:-}"
    local sb_cert="${SUDERRA_SECUREBOOT_SIGNING_CERT:-}"
    local unsigned="${binaries_dir}/suderra-${slot}.efi.unsigned"
    local signed="${binaries_dir}/suderra-${slot}.efi"
    local sig="${binaries_dir}/suderra-${slot}.efi.sig"
    local cert_out="${binaries_dir}/suderra-${slot}.efi.cert"
    local esp_slot="${binaries_dir}/efi-part/EFI/SUDERRA/suderra-${slot}.efi"
    local osrel

    [ -n "${stub}" ] || die "SUDERRA_UKI_STUB must point to linuxx64.efi.stub or equivalent"
    [ -n "${sb_key}" ] || die "SUDERRA_SECUREBOOT_SIGNING_KEY must be set"
    [ -n "${sb_cert}" ] || die "SUDERRA_SECUREBOOT_SIGNING_CERT must be set"
    need_file "${stub}"
    need_file "${sb_key}"
    need_file "${sb_cert}"
    need_file "${binaries_dir}/bzImage"
    need_cmd objcopy
    need_cmd sbsign
    need_cmd sbverify
    need_cmd openssl

    osrel="${target_dir}/etc/os-release"
    need_file "${osrel}"
    write_x86_verity_cmdline "${binaries_dir}" "${slot}"

    objcopy \
        --add-section .osrel="${osrel}" --change-section-vma .osrel=0x20000 \
        --add-section .cmdline="${binaries_dir}/suderra-${slot}.cmdline" --change-section-vma .cmdline=0x30000 \
        --add-section .linux="${binaries_dir}/bzImage" --change-section-vma .linux=0x2000000 \
        "${stub}" \
        "${unsigned}"

    sbsign \
        --key "${sb_key}" \
        --cert "${sb_cert}" \
        --output "${signed}" \
        "${unsigned}" >/dev/null
    sbverify --cert "${sb_cert}" "${signed}" >/dev/null

    openssl dgst -sha256 -sign "${sb_key}" -out "${sig}" "${signed}"
    install -m 0644 "${sb_cert}" "${cert_out}"

    install -D -m 0644 "${signed}" "${esp_slot}"
}

build_signed_grub() {
    local binaries_dir="$1"
    local sb_key="${SUDERRA_SECUREBOOT_SIGNING_KEY:-}"
    local sb_cert="${SUDERRA_SECUREBOOT_SIGNING_CERT:-}"
    local input="${SUDERRA_GRUB_EFI_INPUT:-${binaries_dir}/efi-part/EFI/BOOT/bootx64.efi}"
    local unsigned="${binaries_dir}/grubx64.efi.unsigned"
    local signed="${binaries_dir}/grubx64.efi"
    local sig="${binaries_dir}/grubx64.efi.sig"
    local cert_out="${binaries_dir}/grubx64.efi.cert"
    local esp_loader="${binaries_dir}/efi-part/EFI/BOOT/BOOTX64.EFI"

    [ -n "${sb_key}" ] || die "SUDERRA_SECUREBOOT_SIGNING_KEY must be set"
    [ -n "${sb_cert}" ] || die "SUDERRA_SECUREBOOT_SIGNING_CERT must be set"
    need_file "${input}"
    need_file "${sb_key}"
    need_file "${sb_cert}"
    need_cmd sbsign
    need_cmd sbverify
    need_cmd openssl

    if [ "${input}" = "${esp_loader}" ]; then
        die "SUDERRA_GRUB_EFI_INPUT must be an unsigned input, not the signed BOOTX64.EFI output"
    fi

    install -D -m 0644 "${input}" "${unsigned}"
    sbsign \
        --key "${sb_key}" \
        --cert "${sb_cert}" \
        --output "${signed}" \
        "${unsigned}" >/dev/null
    sbverify --cert "${sb_cert}" "${signed}" >/dev/null

    openssl dgst -sha256 -sign "${sb_key}" -out "${sig}" "${signed}"
    install -m 0644 "${sb_cert}" "${cert_out}"
    install -D -m 0644 "${signed}" "${esp_loader}"

    if [ "${input}" = "${binaries_dir}/efi-part/EFI/BOOT/bootx64.efi" ]; then
        rm -f "${input}"
    fi
}

initialize_grubenv() {
    local binaries_dir="$1"
    local grub_editenv
    local grubenv="${binaries_dir}/efi-part/EFI/BOOT/grubenv"

    grub_editenv="$(resolve_grub_editenv)"
    install -d -m 0755 "$(dirname -- "${grubenv}")"
    rm -f "${grubenv}"
    "${grub_editenv}" "${grubenv}" create
    "${grub_editenv}" "${grubenv}" set \
        "ORDER=A B" \
        A_OK=1 \
        A_TRY=0 \
        B_OK=0 \
        B_TRY=0
    need_file "${grubenv}"
}

sign_image() {
    local binaries_dir="$1"
    local image_name="$2"
    local image="${binaries_dir}/${image_name}"
    local key="${SUDERRA_IMAGE_SIGNING_KEY:-${SUDERRA_SECUREBOOT_SIGNING_KEY:-}}"
    local cert="${SUDERRA_IMAGE_SIGNING_CERT:-${SUDERRA_SECUREBOOT_SIGNING_CERT:-}}"

    [ -n "${key}" ] || die "SUDERRA_IMAGE_SIGNING_KEY or SUDERRA_SECUREBOOT_SIGNING_KEY must be set"
    [ -n "${cert}" ] || die "SUDERRA_IMAGE_SIGNING_CERT or SUDERRA_SECUREBOOT_SIGNING_CERT must be set"
    need_file "${image}"
    need_file "${key}"
    need_file "${cert}"
    need_cmd openssl

    openssl dgst -sha256 -sign "${key}" -out "${image}.sig" "${image}"
    install -m 0644 "${cert}" "${image}.cert"
}

command="${1:-}"
case "${command}" in
    x86-pre-genimage)
        [ "$#" -eq 3 ] || {
            usage >&2
            exit 2
        }
        generate_verity "$2"
        initialize_grubenv "$2"
        build_signed_grub "$2"
        build_signed_slot_uki "$2" "$3"
        ;;
    sign-image)
        [ "$#" -eq 3 ] || {
            usage >&2
            exit 2
        }
        sign_image "$2" "$3"
        ;;
    --help|-h|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

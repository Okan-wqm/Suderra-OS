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
  production-artifacts.sh arm-board-dtb <BINARIES_DIR> <BOARD_DIR>
  production-artifacts.sh arm-pre-genimage <BINARIES_DIR> <TARGET_DIR> [<BOARD_DIR>]
  production-artifacts.sh arm-fit-gate <FIT> <BINARIES_DIR> <BOARD_DIR>
  production-artifacts.sh sign-image <BINARIES_DIR> <IMAGE_NAME>

arm-board-dtb merges the board's device-tree overlays into its stock tree
(fdtoverlay) and fails unless the result enables every node the board's
dt-required.txt names. BOARD_DIR holds board-boot.conf; a board without one has
no merged tree. arm-pre-genimage with a BOARD_DIR that has a board-boot.conf
builds that board's FIT from its template and merged tree and gates the tree it
extracts from every built FIT; without one (or without the argument) it emits one
signed configuration per stock board tree in BINARIES_DIR. arm-fit-gate runs that
FIT gate alone on a FIT already built (BINARIES_DIR holds the board's merged tree
the FIT must carry byte for byte).

Required for arm-pre-genimage (ADR-0007 signed FIT, gates G1/G2):
  SUDERRA_FIT_KEYS_DIR or SUDERRA_KEYS_DIR   dir with fit-signing.{key,crt}
  SUDERRA_FIT_SIGNING_KEY                     prod HSM PKCS#11 URI (file key
                                              rejected in production mode)
  BINARIES_DIR must contain Image, a board *.dtb, u-boot.dtb, rootfs.ext4
  target rootfs must contain busybox, blkid, dmsetup, mount, sleep, switch_root

Required for x86-pre-genimage:
  SUDERRA_UKI_STUB                         EFI stub used to build signed UKI
  SUDERRA_SECUREBOOT_SIGNING_KEY           Secure Boot signing private key
  SUDERRA_SECUREBOOT_SIGNING_CERT          Secure Boot signing certificate
  SUDERRA_GRUB_EFI_INPUT                   Optional unsigned GRUB EFI input
  SUDERRA_GRUB_EDITENV                     Optional grub-editenv path
  target rootfs must contain busybox, blkid, dmsetup, mount and switch_root

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

production_mode() {
    [ "${SUDERRA_SIGNING_MODE:-}" = "prod" ] || [ "${SUDERRA_RELEASE_TIER:-}" = "production" ]
}

reject_prod_file_key() {
    local role="$1"
    local value="$2"
    if ! production_mode; then
        return 0
    fi
    case "${value}" in
        pkcs11:*)
            ;;
        "")
            die "${role} PKCS#11 URI must be set for production signing"
            ;;
        *)
            die "production ${role} signing rejects file-backed private keys: ${value}"
            ;;
    esac
}

is_pkcs11_uri() {
    case "$1" in
        pkcs11:*) return 0 ;;
        *) return 1 ;;
    esac
}

need_signing_key() {
    local role="$1"
    local key="$2"

    reject_prod_file_key "${role}" "${key}"
    if is_pkcs11_uri "${key}"; then
        case "${key}" in
            pkcs11:*object=*|pkcs11:*id=*) ;;
            *) die "${role} PKCS#11 URI must identify a key with object= or id=" ;;
        esac
        return 0
    fi
    need_file "${key}"
}

pkcs11_engine() {
    local engine="${SUDERRA_PKCS11_ENGINE:-${SUDERRA_OPENSSL_PKCS11_ENGINE:-}}"
    [ -n "${engine}" ] || die "SUDERRA_PKCS11_ENGINE must be set for PKCS#11 production signing"
    printf '%s\n' "${engine}"
}

hsm_evidence_file() {
    local evidence="${SUDERRA_HSM_SIGNING_EVIDENCE:-}"
    [ -n "${evidence}" ] || die "SUDERRA_HSM_SIGNING_EVIDENCE must be set for production signing"
    need_file "${evidence}"
    printf '%s\n' "${evidence}"
}

validate_hsm_role() {
    local role="$1"
    local key="$2"
    local cert="$3"
    local artifact="${4:-}"
    local args=(
        python3
        "$(dirname -- "$0")/evidence/validate-hsm-signing-evidence.py"
        validate
        "$(hsm_evidence_file)"
        --pkcs11-uri "${key}"
        --certificate "${cert}"
        --artifact-role "${role}"
        --require-production
    )
    if [ -n "${artifact}" ] && [ -s "${artifact}" ]; then
        args+=(--artifact-sha256 "$(sha256sum "${artifact}" | awk '{print $1}')")
    fi
    "${args[@]}" >/dev/null
}

sbsign_artifact() {
    local role="$1"
    local key="$2"
    local cert="$3"
    local input="$4"
    local output="$5"

    if is_pkcs11_uri "${key}"; then
        validate_hsm_role "${role}" "${key}" "${cert}" "${input}"
        sbsign \
            --engine "$(pkcs11_engine)" \
            --key "${key}" \
            --cert "${cert}" \
            --output "${output}" \
            "${input}" >/dev/null
    else
        sbsign \
            --key "${key}" \
            --cert "${cert}" \
            --output "${output}" \
            "${input}" >/dev/null
    fi
}

openssl_sign_artifact() {
    local role="$1"
    local key="$2"
    local cert="$3"
    local input="$4"
    local output="$5"

    if is_pkcs11_uri "${key}"; then
        validate_hsm_role "${role}" "${key}" "${cert}" "${input}"
        openssl dgst -sha256 \
            -engine "$(pkcs11_engine)" \
            -keyform engine \
            -sign "${key}" \
            -out "${output}" \
            "${input}"
    else
        openssl dgst -sha256 -sign "${key}" -out "${output}" "${input}"
    fi
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

# Arch-agnostic dm-verity bootargs emitter. Writes suderra-<slot>.cmdline as:
#   <console_and_root> rauc.slot=.. suderra.slot=.. <suderra.verity.* tokens> <hardening_tail>
# The verity token block is identical across architectures (partlabel-based,
# parsed by the shared verity initramfs); the console/root prefix and the
# hardening tail are arch-specific (x86 enforces module.sig_enforce=1; ARM, with
# modules enabled pending signed-FIT, must not). ARM (PR-A3) supplies its own
# prefix/tail and reuses this emitter so the verity contract never diverges.
emit_verity_bootargs() {
    local binaries_dir="$1"
    local slot="$2"
    local console_and_root="$3"
    local hardening_tail="$4"
    local slot_lower
    local root_partlabel
    local verity_partlabel
    local cmdline="${binaries_dir}/suderra-${slot}.cmdline"
    local data_sectors

    slot_lower="$(printf '%s' "${slot}" | tr 'A-Z' 'a-z')"
    root_partlabel="rootfs-${slot_lower}"
    verity_partlabel="rootfs-${slot_lower}-verity"

    # shellcheck disable=SC1091
    . "${binaries_dir}/rootfs.verity.env"

    data_sectors=$((DATA_BLOCKS * DATA_BLOCK_SIZE / 512))
    printf '%s\n' \
        "${console_and_root} rauc.slot=${slot} suderra.slot=${slot} suderra.verity.root_partlabel=${root_partlabel} suderra.verity.hash_partlabel=${verity_partlabel} suderra.verity.data_sectors=${data_sectors} suderra.verity.data_blocks=${DATA_BLOCKS} suderra.verity.data_block_size=${DATA_BLOCK_SIZE} suderra.verity.hash_block_size=${HASH_BLOCK_SIZE} suderra.verity.hash_start_block=${HASH_START_BLOCK} suderra.verity.hash_algorithm=${HASH_ALGORITHM} suderra.verity.root_hash=${ROOT_HASH} suderra.verity.salt=${SALT} ${hardening_tail}" \
        > "${cmdline}"
}

write_x86_verity_cmdline() {
    emit_verity_bootargs "$1" "$2" \
        "console=ttyS0,115200n8 console=tty0 root=/dev/mapper/suderra-root ro rootwait" \
        "lockdown=confidentiality slab_nomerge slub_debug=- page_alloc.shuffle=1 randomize_kstack_offset=on init_on_alloc=1 init_on_free=1 vsyscall=none debugfs=off oops=panic panic=10 module.sig_enforce=1 quiet"
}

copy_target_binary() {
    local target_dir="$1"
    local initramfs_root="$2"
    local path="$3"

    need_file "${target_dir}${path}"
    install -D -m 0755 "${target_dir}${path}" "${initramfs_root}${path}"
}

copy_first_target_binary() {
    local target_dir="$1"
    local initramfs_root="$2"
    shift 2
    local candidate

    for candidate in "$@"; do
        if [ -s "${target_dir}${candidate}" ]; then
            copy_target_binary "${target_dir}" "${initramfs_root}" "${candidate}"
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    die "required initramfs binary missing from target rootfs: $*"
}

copy_target_runtime_libs() {
    local target_dir="$1"
    local initramfs_root="$2"
    local libdir

    for libdir in /lib /lib64 /usr/lib; do
        if [ -d "${target_dir}${libdir}" ]; then
            mkdir -p "${initramfs_root}${libdir}"
            cp -a "${target_dir}${libdir}/." "${initramfs_root}${libdir}/"
        fi
    done
}

# Arch-agnostic verity initramfs builder. The generated /init reads the
# dm-verity parameters from the kernel cmdline (suderra.verity.*) and resolves
# partitions by PARTLABEL, so it is identical for x86 and arm64 (both ship an
# ext4 rootfs behind dm-verity). build_x86_verity_initramfs is a thin wrapper
# kept for the existing x86 callers/contracts; ARM (PR-A3) calls this directly.
build_verity_initramfs() {
    local binaries_dir="$1"
    local target_dir="$2"
    local slot="$3"
    local output="$4"
    local work
    local root
    local blkid_path
    local dmsetup_path
    local switch_root_path

    need_cmd cpio
    need_cmd gzip
    need_file "${binaries_dir}/rootfs.verity.env"
    need_file "${target_dir}/bin/busybox"

    work="$(mktemp -d)"
    root="${work}/initramfs"
    mkdir -p "${root}/bin" "${root}/sbin" "${root}/usr/bin" "${root}/usr/sbin" \
        "${root}/dev" "${root}/proc" "${root}/sys" "${root}/newroot" "${root}/run"

    copy_target_binary "${target_dir}" "${root}" "/bin/busybox"
    blkid_path="$(copy_first_target_binary "${target_dir}" "${root}" /sbin/blkid /usr/sbin/blkid /bin/blkid /usr/bin/blkid)"
    dmsetup_path="$(copy_first_target_binary "${target_dir}" "${root}" /sbin/dmsetup /usr/sbin/dmsetup)"
    switch_root_path="$(copy_first_target_binary "${target_dir}" "${root}" /sbin/switch_root /usr/sbin/switch_root /bin/switch_root /usr/bin/switch_root)"
    copy_first_target_binary "${target_dir}" "${root}" /bin/mount /usr/bin/mount >/dev/null
    copy_first_target_binary "${target_dir}" "${root}" /bin/sleep /usr/bin/sleep >/dev/null
    copy_target_runtime_libs "${target_dir}" "${root}"

    for applet in sh cat mkdir mount umount sleep head reboot poweroff; do
        ln -sfn busybox "${root}/bin/${applet}"
    done

    cat > "${root}/init" <<EOF
#!/bin/sh
set -eu

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

die() {
    # Fail-secure: verified boot basarisiz oldugunda ASLA shell'e dusme —
    # kurcalanmis rootfs kimlik dogrulamasiz root kabugu elde ederdi.
    # Konsol logu icin bekle, sonra zorla reboot: GRUB boot-count diger
    # A/B slotuna dusurur. Reboot da basarisizsa kapat; o da olmazsa dur.
    echo "Suderra initramfs failure: \$*" >&2
    sleep 10
    reboot -f 2>/dev/null || true
    poweroff -f 2>/dev/null || true
    while :; do sleep 3600; done
}

mount -t proc proc /proc || die "cannot mount proc"
mount -t sysfs sysfs /sys || die "cannot mount sysfs"
mount -t devtmpfs devtmpfs /dev || mount -t tmpfs tmpfs /dev || die "cannot mount dev"
mkdir -p /dev/mapper /newroot /run

arg() {
    key="\$1"
    for token in \$(cat /proc/cmdline); do
        case "\${token}" in
            "\${key}="*) printf '%s\n' "\${token#*=}"; return 0 ;;
        esac
    done
    return 1
}

root_label="\$(arg suderra.verity.root_partlabel || true)"
hash_label="\$(arg suderra.verity.hash_partlabel || true)"
data_sectors="\$(arg suderra.verity.data_sectors || true)"
data_blocks="\$(arg suderra.verity.data_blocks || true)"
data_block_size="\$(arg suderra.verity.data_block_size || true)"
hash_block_size="\$(arg suderra.verity.hash_block_size || true)"
hash_start_block="\$(arg suderra.verity.hash_start_block || true)"
hash_algorithm="\$(arg suderra.verity.hash_algorithm || true)"
root_hash="\$(arg suderra.verity.root_hash || true)"
salt="\$(arg suderra.verity.salt || true)"

[ -n "\${root_label}" ] || die "missing root partition label"
[ -n "\${hash_label}" ] || die "missing verity partition label"
[ -n "\${data_sectors}" ] || die "missing data sectors"
[ -n "\${data_blocks}" ] || die "missing data blocks"
[ -n "\${root_hash}" ] || die "missing dm-verity root hash"

find_partlabel() {
    label="\$1"
    i=0
    while [ "\${i}" -lt 100 ]; do
        device="\$(${blkid_path} -t "PARTLABEL=\${label}" -o device 2>/dev/null | head -n 1 || true)"
        if [ -n "\${device}" ] && [ -b "\${device}" ]; then
            printf '%s\n' "\${device}"
            return 0
        fi
        i=\$((i + 1))
        sleep 0.1
    done
    return 1
}

rootdev="\$(find_partlabel "\${root_label}")" || die "cannot resolve verified root partition identity \${root_label}"
hashdev="\$(find_partlabel "\${hash_label}")" || die "cannot resolve verified verity partition identity \${hash_label}"

table="0 \${data_sectors} verity 1 \${rootdev} \${hashdev} \${data_block_size} \${hash_block_size} \${data_blocks} \${hash_start_block} \${hash_algorithm} \${root_hash} \${salt}"
echo "\${table}" | ${dmsetup_path} create suderra-root --readonly || die "dm-verity mapping create failed"
mount -o ro -t ext4 /dev/mapper/suderra-root /newroot || die "cannot mount verified root"

umount /proc || true
umount /sys || true
exec ${switch_root_path} /newroot /sbin/init
EOF
    chmod 0755 "${root}/init"

    (
        cd "${root}"
        find . -print0 | cpio --null -o --format=newc | gzip -n > "${output}"
    )
    need_file "${output}"
    rm -rf "${work}"
    echo "==> ${slot} slot verity initramfs: ${output}"
}

build_x86_verity_initramfs() {
    # x86 wrapper; arch-agnostic body is build_verity_initramfs.
    build_verity_initramfs "$@"
}

build_signed_slot_uki() {
    local binaries_dir="$1"
    local target_dir="$2"
    local slot="$3"
    local stub="${SUDERRA_UKI_STUB:-}"
    local sb_key="${SUDERRA_SECUREBOOT_SIGNING_KEY:-}"
    local sb_cert="${SUDERRA_SECUREBOOT_SIGNING_CERT:-}"
    local unsigned="${binaries_dir}/suderra-${slot}.efi.unsigned"
    local signed="${binaries_dir}/suderra-${slot}.efi"
    local sig="${binaries_dir}/suderra-${slot}.efi.sig"
    local cert_out="${binaries_dir}/suderra-${slot}.efi.cert"
    local initrd="${binaries_dir}/suderra-${slot}.initrd"
    local esp_slot="${binaries_dir}/efi-part/EFI/SUDERRA/suderra-${slot}.efi"
    local osrel

    [ -n "${stub}" ] || die "SUDERRA_UKI_STUB must point to linuxx64.efi.stub or equivalent"
    [ -n "${sb_key}" ] || die "SUDERRA_SECUREBOOT_SIGNING_KEY must be set"
    [ -n "${sb_cert}" ] || die "SUDERRA_SECUREBOOT_SIGNING_CERT must be set"
    need_signing_key "Secure Boot" "${sb_key}"
    need_file "${stub}"
    need_file "${sb_cert}"
    need_file "${binaries_dir}/bzImage"
    need_cmd objcopy
    need_cmd sbsign
    need_cmd sbverify
    need_cmd openssl

    osrel="${target_dir}/etc/os-release"
    need_file "${osrel}"
    write_x86_verity_cmdline "${binaries_dir}" "${slot}"
    build_x86_verity_initramfs "${binaries_dir}" "${target_dir}" "${slot}" "${initrd}"

    objcopy \
        --add-section .osrel="${osrel}" --change-section-vma .osrel=0x20000 \
        --add-section .cmdline="${binaries_dir}/suderra-${slot}.cmdline" --change-section-vma .cmdline=0x30000 \
        --add-section .initrd="${initrd}" --change-section-vma .initrd=0x3000000 \
        --add-section .linux="${binaries_dir}/bzImage" --change-section-vma .linux=0x2000000 \
        "${stub}" \
        "${unsigned}"

    sbsign_artifact "secureboot-uki" "${sb_key}" "${sb_cert}" "${unsigned}" "${signed}"
    sbverify --cert "${sb_cert}" "${signed}" >/dev/null

    openssl_sign_artifact "secureboot-uki-sidecar" "${sb_key}" "${sb_cert}" "${signed}" "${sig}"
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
    need_signing_key "GRUB Secure Boot" "${sb_key}"
    need_file "${input}"
    need_file "${sb_cert}"
    need_cmd sbsign
    need_cmd sbverify
    need_cmd openssl

    if [ "${input}" = "${esp_loader}" ]; then
        die "SUDERRA_GRUB_EFI_INPUT must be an unsigned input, not the signed BOOTX64.EFI output"
    fi

    install -D -m 0644 "${input}" "${unsigned}"
    sbsign_artifact "secureboot-grub" "${sb_key}" "${sb_cert}" "${unsigned}" "${signed}"
    sbverify --cert "${sb_cert}" "${signed}" >/dev/null

    openssl_sign_artifact "secureboot-grub-sidecar" "${sb_key}" "${sb_cert}" "${signed}" "${sig}"
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
    need_signing_key "image" "${key}"
    need_file "${image}"
    need_file "${cert}"
    need_cmd openssl

    openssl_sign_artifact "image-sidecar" "${key}" "${cert}" "${image}" "${image}.sig"
    install -m 0644 "${cert}" "${image}.cert"
}

# ---------------------------------------------------------------------------
# ARM signed-FIT producer (ADR-0007, gates G1/G2)
# ---------------------------------------------------------------------------
write_arm_verity_cmdline() {
    # ARM bootargs reuse the shared verity emitter (A1). Arch-specific: serial
    # console (ttyAMA0 unless the board names its own, $3) and tty1, and NO
    # module.sig_enforce on the command line (a board that forces module
    # signatures does it in its kernel config, linux-revpi-suderra-prod.config).
    emit_verity_bootargs "$1" "$2" \
        "console=${3:-ttyAMA0,115200} console=tty1 root=/dev/mapper/suderra-root ro rootwait" \
        "lockdown=confidentiality slab_nomerge slub_debug=- page_alloc.shuffle=1 randomize_kstack_offset=on init_on_alloc=1 init_on_free=1 oops=panic panic=10 quiet"
}

resolve_fit_signing_material() {
    # Emits "<key>\t<cert>". Dev: file key under the keys dir. Prod: the private
    # key MUST be an HSM PKCS#11 URI (file keys rejected via need_signing_key),
    # mirroring the x86 signing path.
    local dir="${SUDERRA_FIT_KEYS_DIR:-${SUDERRA_KEYS_DIR:-}}"
    local key="${SUDERRA_FIT_SIGNING_KEY:-}"
    local cert="${SUDERRA_FIT_SIGNING_CERT:-}"
    if [ -z "${key}" ] && [ -n "${dir}" ]; then key="${dir}/fit-signing.key"; fi
    if [ -z "${cert}" ] && [ -n "${dir}" ]; then cert="${dir}/fit-signing.crt"; fi
    [ -n "${key}" ] || die "SUDERRA_FIT_SIGNING_KEY or SUDERRA_FIT_KEYS_DIR must be set"
    [ -n "${cert}" ] || die "SUDERRA_FIT_SIGNING_CERT or SUDERRA_FIT_KEYS_DIR must be set"
    need_signing_key "FIT" "${key}"
    need_file "${cert}"
    printf '%s\t%s\n' "${key}" "${cert}"
}

mkimage_sign_fit() {
    # Sign the FIT and insert the verification pubkey into the U-Boot control
    # DTB (-K). Prod uses the HSM PKCS#11 key via the openssl engine; dev uses
    # the file key in keydir.
    local its="$1" fit="$2" uboot_dtb="$3" key="$4" cert="$5" keydir="$6"
    if is_pkcs11_uri "${key}"; then
        validate_hsm_role "signed-fit" "${key}" "${cert}" "${fit}"
        mkimage -f "${its}" -k "${keydir}" -N "$(pkcs11_engine)" -K "${uboot_dtb}" -r "${fit}" >/dev/null
    else
        mkimage -f "${its}" -k "${keydir}" -K "${uboot_dtb}" -r "${fit}" >/dev/null
    fi
    need_file "${fit}"
}

sign_fit_sidecars() {
    # Detached sidecars mirror the x86 UKI contract (enforce_production_contract
    # requires suderra-<slot>.fit + .sig + .cert).
    local fit="$1" key="$2" cert="$3"
    openssl_sign_artifact "signed-fit-sidecar" "${key}" "${cert}" "${fit}" "${fit}.sig"
    install -m 0644 "${cert}" "${fit}.cert"
}

build_signed_slot_fit() {
    local binaries_dir="$1"
    local target_dir="$2"
    local slot="$3"
    local uboot_dtb="${binaries_dir}/u-boot.dtb"
    local kernel="${binaries_dir}/Image"
    local initrd="${binaries_dir}/suderra-${slot}.initrd"
    local its="${binaries_dir}/suderra-${slot}.its"
    local fit="${binaries_dir}/suderra-${slot}.fit"
    local keydir cmdline key cert material

    need_cmd mkimage
    need_cmd dtc
    need_cmd openssl
    need_file "${kernel}"
    need_file "${uboot_dtb}"
    # mkimage -k needs a directory containing <key-name-hint>.{key,crt}.
    material="$(resolve_fit_signing_material)"
    key="${material%$'\t'*}"
    cert="${material#*$'\t'}"
    keydir="${SUDERRA_FIT_KEYS_DIR:-${SUDERRA_KEYS_DIR:-}}"
    [ -n "${keydir}" ] || die "SUDERRA_FIT_KEYS_DIR (or SUDERRA_KEYS_DIR) required for mkimage -k"

    write_arm_verity_cmdline "${binaries_dir}" "${slot}"
    build_verity_initramfs "${binaries_dir}" "${target_dir}" "${slot}" "${initrd}"
    cmdline="$(cat "${binaries_dir}/suderra-${slot}.cmdline")"

    # HIGH1: emit ONE signed config per board DTB (not the alphabetically-first
    # only), so CM4 / CM4-IO / RevPi boot with the correct device tree. boot.scr
    # selects the config by the board U-Boot reports; the default is the first
    # (Pi 4 Model B for rpi4). Each config is individually signed (required=conf).
    local dtbfile boardname fdt_nodes="" conf_nodes="" default_conf="" idx=0
    local dtbs
    dtbs="$(find "${binaries_dir}" -maxdepth 1 -name '*.dtb' ! -name 'u-boot.dtb' | sort)"
    [ -n "${dtbs}" ] || die "no board DTB found in ${binaries_dir}"
    local board_compat
    while IFS= read -r dtbfile; do
        [ -n "${dtbfile}" ] || continue
        idx=$((idx + 1))
        boardname="$(basename "${dtbfile}" .dtb)"
        # Extract the board root compatible so U-Boot auto-selects the matching
        # config against the running board (fit_conf_get_node), instead of a
        # fragile board-name string match in boot.scr. Falls back to no
        # compatible (default config) if extraction fails.
        # NOTE: sed self-terminates on the first match (q) — do NOT pipe into
        # `head`, which closes the pipe early and SIGPIPEs sed; under the
        # script's `set -euo pipefail` that aborts the build mid-loop when a
        # real board DTB has many `compatible` properties (buffer-size race).
        board_compat="$(dtc -I dtb -O dts "${dtbfile}" 2>/dev/null \
            | sed -n '/^[[:space:]]*compatible = /{s/^[[:space:]]*compatible = \(.*\);[[:space:]]*$/\1/p;q;}' || true)"
        fdt_nodes="${fdt_nodes}
        fdt-${idx} {
            data = /incbin/(\"${dtbfile}\");
            type = \"flat_dt\"; arch = \"arm64\"; compression = \"none\";
            hash-1 { algo = \"sha256\"; };
        };"
        conf_nodes="${conf_nodes}
        conf-${boardname} {
            description = \"${boardname} (slot ${slot})\";${board_compat:+
            compatible = ${board_compat};}
            kernel = \"kernel\"; fdt = \"fdt-${idx}\"; ramdisk = \"ramdisk-1\";
            bootargs = \"${cmdline}\";
            signature-1 {
                algo = \"sha256,rsa2048\";
                key-name-hint = \"fit-signing\";
                sign-images = \"kernel\", \"fdt\", \"ramdisk\";
                required = \"conf\";
            };
        };"
        [ -n "${default_conf}" ] || default_conf="conf-${boardname}"
    done <<EOF
${dtbs}
EOF

    cat > "${its}" <<ITS
/dts-v1/;
/ {
    description = "Suderra signed FIT (slot ${slot})";
    #address-cells = <1>;
    images {
        kernel {
            data = /incbin/("${kernel}");
            type = "kernel"; arch = "arm64"; os = "linux"; compression = "none";
            load = <0x00080000>; entry = <0x00080000>;
            hash-1 { algo = "sha256"; };
        };
        ramdisk-1 {
            data = /incbin/("${initrd}");
            type = "ramdisk"; arch = "arm64"; os = "linux"; compression = "gzip";
            hash-1 { algo = "sha256"; };
        };${fdt_nodes}
    };
    configurations {
        default = "${default_conf}";${conf_nodes}
    };
};
ITS

    mkimage_sign_fit "${its}" "${fit}" "${uboot_dtb}" "${key}" "${cert}" "${keydir}"
    sign_fit_sidecars "${fit}" "${key}" "${cert}"
    echo "==> ${slot} slot signed FIT: ${fit}"
}

# ---------------------------------------------------------------------------
# Board device tree and board FIT (ADR-048 DEC-8.7; EI-024, EI-029, EI-032)
#
# In production U-Boot hands the kernel the device tree of the signed FIT, never
# the one the Pi firmware builds from config.txt, so a board whose nodes come
# from an overlay (the Revolution Pi Connect 4's PiBridge, RS485, SPI TPM, RTC
# and LEDs) needs the overlay merged into the tree that goes into the FIT. A
# board directory with a board-boot.conf describes such a board; the build then
# fails unless the merged tree, and the tree extracted from every built FIT,
# enable the nodes the board's dt-required.txt names.
# ---------------------------------------------------------------------------
BOARD_BOOT_KEYS=(
    BOARD_BASE_DTB BOARD_DT_OVERLAYS BOARD_FINAL_DTB BOARD_COMPATIBLE
    BOARD_FIT_ITS BOARD_DT_REQUIRED BOARD_CONSOLE
)

board_has_boot_conf() {
    [ -f "$1/board-boot.conf" ]
}

read_board_boot() {
    local board_dir="$1"
    local conf="${board_dir}/board-boot.conf"
    local line key value k known

    need_file "${conf}"
    for k in "${BOARD_BOOT_KEYS[@]}"; do
        printf -v "${k}" '%s' ""
    done
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            '' | '#'*) continue ;;
            [A-Z]*=*) ;;
            *) die "${conf}: not a KEY=VALUE line: ${line}" ;;
        esac
        key="${line%%=*}"
        value="${line#*=}"
        case "${value}" in
            \"*\")
                value="${value#\"}"
                value="${value%\"}"
                ;;
        esac
        known=0
        for k in "${BOARD_BOOT_KEYS[@]}"; do
            if [ "${k}" = "${key}" ]; then known=1; fi
        done
        [ "${known}" = 1 ] || die "${conf}: unknown key ${key}"
        case "${value}" in
            *[!A-Za-z0-9._,:@+/\ -]*)
                die "${conf}: ${key} has a character outside [A-Za-z0-9._,:@+/ -]"
                ;;
        esac
        printf -v "${key}" '%s' "${value}"
    done < "${conf}"
    for k in "${BOARD_BOOT_KEYS[@]}"; do
        [ -n "${!k}" ] || die "${conf}: ${k} is required"
    done
}

# gate_dtb_nodes <dtb> <spec> <what>: every line of the spec ("<node> <property>
# <value>", see board/suderra/aarch64-revpi-connect4/dt-required.txt) must hold
# in the device tree. A label is looked up in the tree's own __symbols__, so the
# check needs a tree built with dtc -@ and follows the node wherever the base
# tree puts it.
gate_dtb_nodes() {
    local dtb="$1" spec="$2" what="$3"
    local line node prop want extra base rest path props value words w ok checked=0

    need_cmd fdtget
    need_file "${dtb}"
    need_file "${spec}"
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            '' | '#'*) continue ;;
        esac
        node="" prop="" want="" extra=""
        IFS=' ' read -r node prop want extra <<< "${line}"
        if [ -z "${node}" ] || [ -z "${prop}" ] || [ -z "${want}" ] || [ -n "${extra}" ]; then
            die "${spec}: expected '<node> <property> <value>': ${line}"
        fi
        case "${node}" in
            label:*)
                base="${node#label:}"
                rest=""
                case "${base}" in
                    */*)
                        rest="/${base#*/}"
                        base="${base%%/*}"
                        ;;
                esac
                path="$(fdtget -t s "${dtb}" /__symbols__ "${base}" 2>/dev/null)" ||
                    die "${what}: label ${base} (${node}) is not in the tree's __symbols__: the tree was built without dtc -@, or the node is gone"
                path="${path}${rest}"
                ;;
            path:/*)
                path="${node#path:}"
                ;;
            *)
                die "${spec}: node must be label:<name>[/child] or path:/<absolute>: ${node}"
                ;;
        esac
        if [ "${want}" = "-" ]; then
            props="$(fdtget -p "${dtb}" "${path}" 2>/dev/null)" ||
                die "${what}: ${node} (${path}) is not a node of the tree"
            grep -Fxq -- "${prop}" <<< "${props}" ||
                die "${what}: ${node} (${path}) has no property ${prop}"
        else
            value="$(fdtget -t s "${dtb}" "${path}" "${prop}" 2>/dev/null)" ||
                die "${what}: ${node} (${path}) has no property ${prop}"
            ok=0
            IFS=' ' read -r -a words <<< "${value}"
            for w in "${words[@]}"; do
                if [ "${w}" = "${want}" ]; then ok=1; fi
            done
            [ "${ok}" = 1 ] ||
                die "${what}: ${node} (${path}) ${prop} is '${value}', must be '${want}'"
        fi
        checked=$((checked + 1))
    done < "${spec}"
    [ "${checked}" -gt 0 ] || die "${spec}: no node requirement in it"
    echo "==> ${what}: ${checked} required nodes present"
}

# build_board_dtb <binaries_dir> <board_dir>: the board's final device tree, the
# stock tree with the board's overlays merged by fdtoverlay.
build_board_dtb() {
    local binaries_dir="$1" board_dir="$2"
    local base final overlay compat o
    local overlay_names=() overlay_files=()

    need_cmd fdtoverlay
    need_cmd fdtget
    read_board_boot "${board_dir}"
    base="${binaries_dir}/${BOARD_BASE_DTB}"
    final="${binaries_dir}/${BOARD_FINAL_DTB}"
    need_file "${base}"
    IFS=' ' read -r -a overlay_names <<< "${BOARD_DT_OVERLAYS}"
    [ "${#overlay_names[@]}" -gt 0 ] || die "${board_dir}/board-boot.conf: BOARD_DT_OVERLAYS names no overlay"
    for o in "${overlay_names[@]}"; do
        overlay="${binaries_dir}/${o}"
        need_file "${overlay}"
        overlay_files+=("${overlay}")
    done

    # An overlay finds its targets through the stock tree's __symbols__, which
    # the kernel emits only when dtc runs with -@: without it fdtoverlay stops
    # with an unexplained FDT_ERR_NOTFOUND.
    fdtget -l "${base}" / | grep -Fxq __symbols__ ||
        die "${base} has no __symbols__ node: the kernel must build its device trees with dtc -@ (BR2_LINUX_KERNEL_DTB_OVERLAY_SUPPORT=y)"
    rm -f "${final}"
    fdtoverlay -i "${base}" -o "${final}" "${overlay_files[@]}" ||
        die "fdtoverlay could not merge ${BOARD_DT_OVERLAYS} into ${BOARD_BASE_DTB}"
    need_file "${final}"

    compat="$(fdtget -t s "${final}" / compatible)" ||
        die "${final} has no root compatible"
    [ "${compat%% *}" = "${BOARD_COMPATIBLE}" ] ||
        die "${final} root compatible is '${compat}', its first entry must be ${BOARD_COMPATIBLE}"
    gate_dtb_nodes "${final}" "${board_dir}/${BOARD_DT_REQUIRED}" "board device tree ${BOARD_FINAL_DTB}"
    echo "==> board device tree: ${final}"
}

# U-Boot copies the FIT's kernel from where the boot script loaded the FIT
# (fitaddr) to the kernel's load address; a kernel larger than the gap between
# the two would overwrite the rest of the FIT while it is copied. The KUNBUS
# kernel is a large distribution kernel, so the gap is checked on the real Image.
check_fit_kernel_headroom() {
    local kernel="$1" script="$2"
    local fitaddr size room load=$((0x00080000))

    need_file "${script}"
    fitaddr="$(sed -n 's/^setenv fitaddr \(0x[0-9a-fA-F]*\)$/\1/p' "${script}")"
    [ -n "${fitaddr}" ] || die "${script}: no 'setenv fitaddr 0x...' line"
    room=$((fitaddr - load))
    size="$(wc -c < "${kernel}")"
    [ "${size}" -lt "${room}" ] ||
        die "kernel Image is ${size} bytes but only ${room} fit between fitaddr ${fitaddr} (${script}) and the kernel load address: raise fitaddr, or compress the kernel inside the FIT"
}

render_board_its() {
    local template="$1" out="$2" slot="$3" kernel="$4" initrd="$5" fdt="$6" bootargs="$7"
    local v

    need_file "${template}"
    need_cmd awk
    for v in "${slot}" "${kernel}" "${initrd}" "${fdt}" "${bootargs}"; do
        case "${v}" in
            *'&'* | *\\* | *'"'*) die "a value cannot go into the FIT template: ${v}" ;;
        esac
    done
    SLOT="${slot}" KERNEL="${kernel}" INITRD="${initrd}" FDT="${fdt}" BOOTARGS="${bootargs}" \
        awk '{
            gsub(/@SLOT@/, ENVIRON["SLOT"])
            gsub(/@KERNEL@/, ENVIRON["KERNEL"])
            gsub(/@INITRD@/, ENVIRON["INITRD"])
            gsub(/@FDT@/, ENVIRON["FDT"])
            gsub(/@BOOTARGS@/, ENVIRON["BOOTARGS"])
            print
        }' "${template}" > "${out}"
    if grep -Eq '@[A-Z]+@' "${out}"; then
        die "${template}: a placeholder is left in the rendered FIT source"
    fi
}

# gate_fit_dtb <fit> <binaries_dir> <board_dir>: what the board's FIT hands the
# kernel. The FIT has exactly one configuration, its compatible is the board's,
# the tree inside is byte-identical to the merged tree, and it enables every
# required node: the check runs on the tree extracted from the signed FIT, not
# on the file it was built from.
gate_fit_dtb() {
    local fit="$1" binaries_dir="$2" board_dir="$3"
    local default conf_count fdt_name compat n idx=0 found=-1 extracted

    need_cmd dumpimage
    need_cmd fdtget
    read_board_boot "${board_dir}"
    conf_count="$(fdtget -l "${fit}" /configurations | wc -l)"
    [ "${conf_count}" -eq 1 ] ||
        die "${fit} has ${conf_count} configurations, the ${BOARD_COMPATIBLE} board FIT has exactly one"
    default="$(fdtget -t s "${fit}" /configurations default)" ||
        die "${fit} has no default configuration"
    compat="$(fdtget -t s "${fit}" "/configurations/${default}" compatible)" ||
        die "${fit} configuration ${default} has no compatible"
    [ "${compat%% *}" = "${BOARD_COMPATIBLE}" ] ||
        die "${fit} configuration ${default} compatible is '${compat}', its first entry must be ${BOARD_COMPATIBLE}"
    fdt_name="$(fdtget -t s "${fit}" "/configurations/${default}" fdt)" ||
        die "${fit} configuration ${default} names no fdt"
    while IFS= read -r n; do
        if [ "${n}" = "${fdt_name}" ]; then found="${idx}"; fi
        idx=$((idx + 1))
    done <<< "$(fdtget -l "${fit}" /images)"
    [ "${found}" -ge 0 ] || die "${fit} has no image ${fdt_name}"

    extracted="${fit}.fdt.dtb"
    rm -f "${extracted}"
    dumpimage -T flat_dt -p "${found}" -o "${extracted}" "${fit}" >/dev/null ||
        die "dumpimage could not extract ${fdt_name} from ${fit}"
    need_file "${extracted}"
    cmp -s "${extracted}" "${binaries_dir}/${BOARD_FINAL_DTB}" ||
        die "the device tree inside ${fit} is not ${binaries_dir}/${BOARD_FINAL_DTB}"
    gate_dtb_nodes "${extracted}" "${board_dir}/${BOARD_DT_REQUIRED}" "device tree of ${fit##*/}"
    rm -f "${extracted}"
}

build_board_slot_fit() {
    local binaries_dir="$1" target_dir="$2" slot="$3" board_dir="$4"
    local uboot_dtb="${binaries_dir}/u-boot.dtb"
    local kernel="${binaries_dir}/Image"
    local initrd="${binaries_dir}/suderra-${slot}.initrd"
    local its="${binaries_dir}/suderra-${slot}.its"
    local fit="${binaries_dir}/suderra-${slot}.fit"
    local boot_script
    local keydir cmdline key cert material

    boot_script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/board/suderra/aarch64-rpi4/boot.scr.cmd"
    read_board_boot "${board_dir}"
    need_cmd mkimage
    need_cmd dtc
    need_cmd openssl
    need_file "${kernel}"
    need_file "${uboot_dtb}"
    need_file "${binaries_dir}/${BOARD_FINAL_DTB}"
    check_fit_kernel_headroom "${kernel}" "${boot_script}"
    material="$(resolve_fit_signing_material)"
    key="${material%$'\t'*}"
    cert="${material#*$'\t'}"
    keydir="${SUDERRA_FIT_KEYS_DIR:-${SUDERRA_KEYS_DIR:-}}"
    [ -n "${keydir}" ] || die "SUDERRA_FIT_KEYS_DIR (or SUDERRA_KEYS_DIR) required for mkimage -k"

    write_arm_verity_cmdline "${binaries_dir}" "${slot}" "${BOARD_CONSOLE}"
    build_verity_initramfs "${binaries_dir}" "${target_dir}" "${slot}" "${initrd}"
    cmdline="$(cat "${binaries_dir}/suderra-${slot}.cmdline")"

    render_board_its "${board_dir}/${BOARD_FIT_ITS}" "${its}" "${slot}" "${kernel}" "${initrd}" \
        "${binaries_dir}/${BOARD_FINAL_DTB}" "${cmdline}"
    grep -Fq "compatible = \"${BOARD_COMPATIBLE}\"" "${its}" ||
        die "${board_dir}/${BOARD_FIT_ITS}: the configuration's compatible is not ${BOARD_COMPATIBLE}"

    mkimage_sign_fit "${its}" "${fit}" "${uboot_dtb}" "${key}" "${cert}" "${keydir}"
    gate_fit_dtb "${fit}" "${binaries_dir}" "${board_dir}"
    sign_fit_sidecars "${fit}" "${key}" "${cert}"
    echo "==> ${slot} slot signed FIT (${BOARD_FINAL_DTB}): ${fit}"
}

command="${1:-}"
case "${command}" in
    arm-pre-genimage)
        [ "$#" -eq 3 ] || [ "$#" -eq 4 ] || {
            usage >&2
            exit 2
        }
        generate_verity "$2"
        if [ "$#" -eq 4 ] && board_has_boot_conf "$4"; then
            build_board_dtb "$2" "$4"
            build_board_slot_fit "$2" "$3" A "$4"
            build_board_slot_fit "$2" "$3" B "$4"
        else
            build_signed_slot_fit "$2" "$3" A
            build_signed_slot_fit "$2" "$3" B
        fi
        ;;
    arm-board-dtb)
        [ "$#" -eq 3 ] || {
            usage >&2
            exit 2
        }
        board_has_boot_conf "$3" || die "$3 has no board-boot.conf"
        build_board_dtb "$2" "$3"
        ;;
    arm-fit-gate)
        [ "$#" -eq 4 ] || {
            usage >&2
            exit 2
        }
        board_has_boot_conf "$4" || die "$4 has no board-boot.conf"
        need_file "$2"
        gate_fit_dtb "$2" "$3" "$4"
        ;;
    x86-pre-genimage)
        [ "$#" -eq 3 ] || {
            usage >&2
            exit 2
        }
        generate_verity "$2"
        initialize_grubenv "$2"
        build_signed_grub "$2"
        build_signed_slot_uki "$2" "$3" A
        build_signed_slot_uki "$2" "$3" B
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

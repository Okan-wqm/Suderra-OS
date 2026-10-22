#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# RAUC slot-post-install hook (ARM, ADR-0007). x86 rauc-x86-slot-hook.sh'in
# ARM eşleniği: imzalı UKI yerine imzalı FIT'i boot FAT bölümüne kopyalar.
# U-Boot's compiled-in bootcmd picks the new slot from BOOT_ORDER and boots
# suderra-<bootname>.fit with the signature enforced.
set -eu

# RAUC yalnız rootfs slot sınıfı için FIT kopyalar.
[ "${RAUC_SLOT_CLASS:-}" = "rootfs" ] || exit 0

bootname="${RAUC_SLOT_BOOTNAME:-}"
case "${bootname}" in
    A|B) ;;
    *)
        echo "suderra-rauc-arm-slot-hook: beklenmeyen bootname '${bootname}'" >&2
        exit 1
        ;;
esac

mount="${RAUC_BUNDLE_MOUNT_POINT:-${RAUC_MOUNT_PREFIX:-}}"
[ -n "${mount}" ] || { echo "suderra-rauc-arm-slot-hook: bundle mount yok" >&2; exit 1; }

src="${mount}/suderra-${bootname}.fit"
[ -s "${src}" ] || { echo "suderra-rauc-arm-slot-hook: FIT yok: ${src}" >&2; exit 1; }

dst="/boot/suderra-${bootname}.fit"
tmp="${dst}.tmp"

# /boot is mounted read-only (boot.mount.arm). It is writable for this one copy,
# and read-only again however the copy ends: a FAT left writable after an
# install is what ADR-048 DEC-18.4 removes. A slot that is not yet BOOT_ORDER's
# first has its FIT replaced while the running slot's FIT is not touched.
mount -o remount,rw /boot || { echo "suderra-rauc-arm-slot-hook: /boot cannot be made writable" >&2; exit 1; }
trap 'rm -f "${tmp}"; sync; mount -o remount,ro /boot || echo "suderra-rauc-arm-slot-hook: /boot stayed writable" >&2' EXIT

cp "${src}" "${tmp}"
sync "${tmp}" 2>/dev/null || true
mv -f "${tmp}" "${dst}"
sync 2>/dev/null || true
echo "suderra-rauc-arm-slot-hook: slot ${bootname} FIT güncellendi -> ${dst}"

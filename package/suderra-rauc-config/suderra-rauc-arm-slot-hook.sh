#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# RAUC slot-post-install hook (ARM, ADR-0007). x86 rauc-x86-slot-hook.sh'in
# ARM eşleniği: imzalı UKI yerine imzalı FIT'i boot FAT bölümüne kopyalar.
# U-Boot boot.scr yeni slotu BOOT_ORDER üzerinden seçip suderra-<bootname>.fit'i
# imza-zorunlu boot eder.
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
cp "${src}" "${tmp}"
sync "${tmp}" 2>/dev/null || true
mv -f "${tmp}" "${dst}"
sync 2>/dev/null || true
echo "suderra-rauc-arm-slot-hook: slot ${bootname} FIT güncellendi -> ${dst}"

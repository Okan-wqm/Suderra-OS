#!/bin/sh
set -eu

case "${1:-}" in
    slot-post-install)
        ;;
    *)
        exit 1
        ;;
esac

if [ "${RAUC_SLOT_CLASS:-}" != "rootfs" ]; then
    exit 0
fi

bootname="${RAUC_SLOT_BOOTNAME:-}"
case "${bootname}" in
    A|B) ;;
    *)
        echo "ERROR: unsupported RAUC slot bootname: ${bootname}" >&2
        exit 1
        ;;
esac

bundle_mount="${RAUC_BUNDLE_MOUNT_POINT:-}"
[ -n "${bundle_mount}" ] || {
    echo "ERROR: RAUC_BUNDLE_MOUNT_POINT is not set" >&2
    exit 1
}

src="${bundle_mount}/suderra-${bootname}.efi"
dst="/boot/EFI/SUDERRA/suderra-${bootname}.efi"
tmp="${dst}.tmp"

[ -s "${src}" ] || {
    echo "ERROR: signed slot UKI missing from RAUC bundle: ${src}" >&2
    exit 1
}
[ -d /boot/EFI/SUDERRA ] || mkdir -p /boot/EFI/SUDERRA

cp -f "${src}" "${tmp}"
chmod 0644 "${tmp}"
sync -f "${tmp}" 2>/dev/null || true
mv -f "${tmp}" "${dst}"
sync -f "${dst}" 2>/dev/null || true

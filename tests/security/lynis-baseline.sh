#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
KERNEL_FRAGMENT="${ROOT}/board/suderra/common/kernel-fragment.config"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
POST_IMAGE="${ROOT}/board/suderra/common/post-image.sh"
DATA_UNLOCK="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock"

for token in \
    'CONFIG_SECURITY_LOCKDOWN_LSM=y' \
    'CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y' \
    'CONFIG_DM_VERITY=y' \
    'CONFIG_INTEGRITY_SIGNATURE=y' \
    'CONFIG_AUDIT=y' \
    'CONFIG_SECCOMP_FILTER=y' \
    '# CONFIG_KEXEC is not set' \
    '# CONFIG_HIBERNATION is not set'
do
    grep -q "${token}" "${KERNEL_FRAGMENT}" || {
        echo "ERROR: kernel hardening baseline missing ${token}" >&2
        exit 1
    }
done

for token in \
    'dropbear.service' \
    'debug-shell.service' \
    'rescue.service' \
    'emergency.service' \
    'systemd-logind.service' \
    'Production variant her zaman kilitli imaj'
do
    grep -q "${token}" "${POST_BUILD}" || {
        echo "ERROR: production lockdown baseline missing ${token}" >&2
        exit 1
    }
done

for token in \
    'production defconfig must not include Dropbear' \
    'production defconfig must not enable BR2_TARGET_GENERIC_GETTY' \
    'production defconfig must not enable BR2_TARGET_ENABLE_ROOT_LOGIN' \
    'sbverify --cert' \
    'veritysetup verify'
do
    grep -q "${token}" "${POST_IMAGE}" || {
        echo "ERROR: production image security gate missing ${token}" >&2
        exit 1
    }
done

grep -q 'cryptsetup isLuks' "${DATA_UNLOCK}" &&
    grep -q 'production data partition must be LUKS2' "${DATA_UNLOCK}" || {
    echo "ERROR: /data encryption baseline is not enforced" >&2
    exit 1
}

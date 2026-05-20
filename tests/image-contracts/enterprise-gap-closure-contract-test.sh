#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
POST_IMAGE="${ROOT}/board/suderra/common/post-image.sh"
X86_DEFCONFIG="${ROOT}/configs/suderra_x86_64_defconfig"
X86_GENIMAGE="${ROOT}/board/suderra/x86_64/genimage.cfg"
KERNEL_FRAGMENT="${ROOT}/board/suderra/common/kernel-fragment.config"
FIRSTBOOT_UNIT="${ROOT}/package/suderra-firstboot/suderra-firstboot.service"
OVERLAY_FIRSTBOOT_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service"
DATA_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-data.service"
NFTABLES_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/nftables.service"
INSTALLER="${ROOT}/userspace/suderra-installer/src/cmd/install.rs"
EDGE_INSTALL="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install"
MANIFEST="${ROOT}/userspace/suderra-installer/src/manifest.rs"
PRODUCTION_ARTIFACTS="${ROOT}/scripts/production-artifacts.sh"
RAUC_CONFIG="${ROOT}/package/suderra-rauc-config/system.conf"
PLAN_DOC="${ROOT}/docs/assessments/2026-05-20-enterprise-grade-gap-closure-plan.md"

grep -q 'ExecStart=/usr/bin/suderra-firstboot' "${FIRSTBOOT_UNIT}" || {
    echo "ERROR: packaged firstboot unit must execute the installed /usr/bin binary" >&2
    exit 1
}
if grep -Eq '^Before=.*sysinit\.target' "${DATA_UNIT}" "${OVERLAY_FIRSTBOOT_UNIT}"; then
    echo "ERROR: data/firstboot units must not force themselves before sysinit.target" >&2
    exit 1
fi
grep -q '^After=.*suderra-data.service' "${NFTABLES_UNIT}" || {
    echo "ERROR: nftables must load after suderra-data so lockdown state is visible" >&2
    exit 1
}

grep -q 'SUDERRA_OS_VARIANT.*prod' "${POST_BUILD}" || {
    echo "ERROR: post-build must branch on the production variant" >&2
    exit 1
}
grep -q 'Production variant her zaman kilitli imaj' "${POST_BUILD}" || {
    echo "ERROR: production post-build lockdown must be explicit" >&2
    exit 1
}
grep -q 'dropbear.service' "${POST_BUILD}" || {
    echo "ERROR: post-build contract must still know which remote shell unit to mask" >&2
    exit 1
}

grep -q 'production defconfig must not include Dropbear' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must reject Dropbear" >&2
    exit 1
}
grep -q 'production defconfig must not enable BR2_TARGET_GENERIC_GETTY' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must reject getty" >&2
    exit 1
}
grep -q 'production defconfig must enable RAUC A/B update support' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must require RAUC before production can pass" >&2
    exit 1
}
grep -q 'production defconfig must install Suderra RAUC slot configuration' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must require Suderra RAUC slot config" >&2
    exit 1
}
grep -q 'x86 production boot/verity artifact' "${POST_IMAGE}" || {
    echo "ERROR: post-image must generate x86 production boot/verity artifacts before genimage" >&2
    exit 1
}
grep -q 'sbverify --cert' "${POST_IMAGE}" || {
    echo "ERROR: post-image must verify Secure Boot signature on the signed UKI" >&2
    exit 1
}
grep -q 'suderra.efi.sig does not validate' "${POST_IMAGE}" || {
    echo "ERROR: post-image must verify the signed UKI sidecar signature" >&2
    exit 1
}

if grep -Eq '^BR2_PACKAGE_DROPBEAR=y|^BR2_TARGET_GENERIC_GETTY=y|^BR2_TARGET_ENABLE_ROOT_LOGIN=y' "${X86_DEFCONFIG}"; then
    echo "ERROR: x86 production defconfig must not boot with SSH/getty/root-login debug surfaces" >&2
    exit 1
fi
for token in \
    'BR2_PACKAGE_RAUC=y' \
    'BR2_PACKAGE_RAUC_DBUS=y' \
    'BR2_PACKAGE_RAUC_GPT=y' \
    'BR2_PACKAGE_RAUC_JSON=y' \
    'BR2_PACKAGE_SUDERRA_RAUC_CONFIG=y' \
    'BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES='
do
    grep -q "${token}" "${X86_DEFCONFIG}" || {
        echo "ERROR: x86 production defconfig missing token: ${token}" >&2
        exit 1
    }
done

grep -q 'CONFIG_DM_INIT=y' "${KERNEL_FRAGMENT}" || {
    echo "ERROR: kernel hardening fragment must enable dm-mod.create boot-time verity mapping" >&2
    exit 1
}
grep -q 'partition rootfs-a-verity' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 genimage must include a rootfs-a verity partition" >&2
    exit 1
}
grep -q 'partition rootfs-b-verity' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 genimage must reserve a rootfs-b verity partition" >&2
    exit 1
}
grep -q 'label = "SUDERRA-DATA"' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 genimage must create a labelled /data filesystem" >&2
    exit 1
}
if awk '/partition rootfs-b[[:space:]]*{/,/}/ {print}' "${X86_GENIMAGE}" | grep -q 'image = "rootfs.ext4"'; then
    echo "ERROR: x86 rootfs-b must start blank for RAUC ownership" >&2
    exit 1
fi

for token in \
    'bootloader=grub' \
    'bundle-formats=verity' \
    'statusfile=/data/rauc/status.ini' \
    'device=/dev/disk/by-partlabel/rootfs-a' \
    'device=/dev/disk/by-partlabel/rootfs-b'
do
    grep -q "${token}" "${RAUC_CONFIG}" || {
        echo "ERROR: RAUC system.conf missing token: ${token}" >&2
        exit 1
    }
done

for token in \
    'veritysetup format' \
    'veritysetup verify' \
    'dm-mod.create=' \
    'objcopy' \
    'sbsign' \
    'sbverify' \
    'SUDERRA_UKI_STUB' \
    'SUDERRA_SECUREBOOT_SIGNING_KEY'
do
    grep -q "${token}" "${PRODUCTION_ARTIFACTS}" || {
        echo "ERROR: production artifact generator missing token: ${token}" >&2
        exit 1
    }
done

grep -q 'RAUC-backed install engine is not implemented yet' "${INSTALLER}" || {
    echo "ERROR: installer must fail closed instead of reporting a copy as a successful install" >&2
    exit 1
}
grep -q 'SUDERRA_ALLOW_LEGACY_COPY_INSTALL' "${INSTALLER}" || {
    echo "ERROR: any legacy copy install path must be explicit and lab-only" >&2
    exit 1
}
grep -q 'corrupt state ile kurulum fail-closed' "${INSTALLER}" || {
    echo "ERROR: installer must fail closed on corrupt installed state" >&2
    exit 1
}
grep -q 'std::fs::rename' "${MANIFEST}" || {
    echo "ERROR: installed state writes must use atomic rename" >&2
    exit 1
}
grep -q 'WORK_DIR=/run/suderra-installer/edge' "${EDGE_INSTALL}" || {
    echo "ERROR: edge install workdir must be root-owned runtime state, not agent-writable /var/lib/suderra" >&2
    exit 1
}
grep -q -- "--proto '=https'" "${EDGE_INSTALL}" || {
    echo "ERROR: edge install downloads must restrict curl to HTTPS" >&2
    exit 1
}
grep -q 'digest-bound config payload' "${EDGE_INSTALL}" || {
    echo "ERROR: signed Edge manifest must require a config payload" >&2
    exit 1
}
grep -q 'refusing monotonic downgrade' "${EDGE_INSTALL}" || {
    echo "ERROR: edge install must reject downgrades without a signed rollback path" >&2
    exit 1
}
grep -q 'rolling back current link' "${EDGE_INSTALL}" || {
    echo "ERROR: edge activation must rollback current link on failed health/lockdown" >&2
    exit 1
}

test -s "${PLAN_DOC}" || {
    echo "ERROR: enterprise gap closure plan documentation must exist" >&2
    exit 1
}
for token in \
    "production_ready=false" \
    "x86_64-first" \
    "factory/provisioning" \
    "signed UKI" \
    "dm-verity" \
    "RAUC" \
    "signed release ingress" \
    "hardware/lab evidence"
do
    grep -q "${token}" "${PLAN_DOC}" || {
        echo "ERROR: enterprise plan doc missing token: ${token}" >&2
        exit 1
    }
done

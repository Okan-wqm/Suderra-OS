#!/usr/bin/env bash
#
# ARM RAUC U-Boot backend sözleşmesi (PR-A5, ADR-0007/ADR-0004).
#
# RAUC'un ARM'da U-Boot backend'iyle (grub değil) yapılandığını, imzalı FIT
# slot hook'unu, fw_printenv boot-state branch'ini, arch-split paketlemeyi ve
# create-rauc-bundle arm subcommand'ını korur. Fonksiyonel RAUC koşusu prod
# build/donanımda (rauc host tool gerekir).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
P="${ROOT}/package/suderra-rauc-config"

# system.conf.arm: U-Boot backend, per-board compatible placeholder (filled
# by post-build from the OTA target contract, rauc-compatible-contract-test.sh),
# by-partuuid slots, hook.
arm_conf="${P}/system.conf.arm"
[ -f "${arm_conf}" ] || { echo "ERROR: system.conf.arm yok" >&2; exit 1; }
grep -q '^bootloader=uboot' "${arm_conf}" || { echo "ERROR: ARM bootloader=uboot değil" >&2; exit 1; }
grep -qx 'compatible=@SUDERRA_RAUC_COMPATIBLE@' "${arm_conf}" || { echo "ERROR: ARM compatible kart başına placeholder değil (DEC-8.3)" >&2; exit 1; }
grep -q 'suderra-rauc-arm-slot-hook.sh' "${arm_conf}" || { echo "ERROR: ARM system.conf slot hook bağlamıyor" >&2; exit 1; }
# Slots are named by the PARTUUID the build writes (a placeholder post-build.sh
# renders from board/suderra/common/gpt-partuuids.conf), never by a label a
# removable disk can carry (ADR-048 DEC-18.1; gpt-partuuid-contract-test.sh).
grep -qx 'device=/dev/disk/by-partuuid/@SUDERRA_PARTUUID_ROOTFS_A@' "${arm_conf}" || { echo "ERROR: ARM slotlar by-partuuid değil" >&2; exit 1; }
if grep -q 'by-partlabel\|by-label' "${arm_conf}"; then echo "ERROR: ARM slot a label ile adlandırılmış" >&2; exit 1; fi
if grep -q 'grubenv' "${arm_conf}"; then echo "ERROR: ARM system.conf grubenv içermemeli" >&2; exit 1; fi

# x86 system.conf değişmeden GRUB kalmalı.
grep -q '^bootloader=grub' "${P}/system.conf" || { echo "ERROR: x86 system.conf grub kalmalı" >&2; exit 1; }

# boot.mount.arm: Pi FAT boot partition (by PARTUUID), read-only: only RAUC's
# slot hook writes it, and it remounts for that copy (DEC-18.4).
grep -qx 'What=/dev/disk/by-partuuid/@SUDERRA_PARTUUID_BOOT@' "${P}/boot.mount.arm" || { echo "ERROR: ARM boot.mount by-partuuid değil" >&2; exit 1; }
grep -qE '^Options=ro,' "${P}/boot.mount.arm" || { echo "ERROR: ARM /boot must be mounted read-only (DEC-18.4)" >&2; exit 1; }

# fw_env.config: the raw redundant environment (uboot-env-contract-test.sh holds
# its offsets to U-Boot's and to genimage's).
[ "$(grep -cE '^/dev/mmcblk0[[:space:]]+0x' "${P}/fw_env.config")" -eq 2 ] || {
    echo "ERROR: fw_env.config must name the two raw copies on /dev/mmcblk0" >&2; exit 1; }
if grep -q 'uboot.env' <(grep -v '^#' "${P}/fw_env.config"); then
    echo "ERROR: fw_env.config names a uboot.env file" >&2; exit 1; fi

# Every boot spends one try (U-Boot's compiled-in bootcmd) and RAUC's mark-good
# arms the slot again with boot-attempts, which must be the tries U-Boot gives
# when it arms both slots itself (suderra_attempts); a freshly installed slot
# holds boot-attempts-primary, which may not exceed that.
armed="$(sed -n 's/^suderra_attempts=//p' "${ROOT}/board/suderra/uboot/suderra.env")"
attempts="$(sed -n 's/^boot-attempts=//p' "${arm_conf}")"
primary="$(sed -n 's/^boot-attempts-primary=//p' "${arm_conf}")"
[ -n "${armed}" ] && [ "${attempts}" = "${armed}" ] || {
    echo "ERROR: system.conf.arm boot-attempts (${attempts}) must equal U-Boot's suderra_attempts (${armed})" >&2; exit 1; }
[ -n "${primary}" ] && [ "${primary}" -ge 1 ] && [ "${primary}" -le "${attempts}" ] || {
    echo "ERROR: system.conf.arm boot-attempts-primary (${primary}) must be at least 1 and at most boot-attempts (${attempts})" >&2; exit 1; }

# arm slot hook: imzalı FIT'i boot'a kopyalar.
hook="${P}/suderra-rauc-arm-slot-hook.sh"
for t in 'RAUC_SLOT_BOOTNAME' 'suderra-${bootname}.fit' '/boot/suderra-${bootname}.fit' 'mount -o remount,rw /boot' 'mount -o remount,ro /boot'; do
    grep -qF -e "${t}" "${hook}" || { echo "ERROR: arm hook eksik: ${t}" >&2; exit 1; }
done

# boot-state: U-Boot fw_printenv branch (BOOT_ORDER/BOOT_x_LEFT) + bootloader alanı.
bs="${P}/suderra-rauc-boot-state"
for t in 'fw_printenv' 'BOOT_ORDER' 'BOOT_A_LEFT' 'BOOT_B_LEFT' 'bootloader'; do
    grep -qF -e "${t}" "${bs}" || { echo "ERROR: boot-state eksik U-Boot desteği: ${t}" >&2; exit 1; }
done
grep -q 'suderra.rauc-boot-state.v1' "${bs}" || { echo "ERROR: boot-state schema_version korunmalı" >&2; exit 1; }
grep -q 'active_slot' "${bs}" || { echo "ERROR: boot-state active_slot korunmalı (health-gate okur)" >&2; exit 1; }

# .mk arch-split: BR2_aarch64 ise ARM dosyaları.
mk="${P}/suderra-rauc-config.mk"
grep -q 'ifeq ($(BR2_aarch64),y)' "${mk}" || { echo "ERROR: .mk arch-split yok" >&2; exit 1; }
grep -q 'system.conf.arm' "${mk}" || { echo "ERROR: .mk ARM system.conf kurmuyor" >&2; exit 1; }
grep -q 'suderra-rauc-arm-slot-hook.sh' "${mk}" || { echo "ERROR: .mk ARM hook kurmuyor" >&2; exit 1; }
grep -q 'fw_env.config' "${mk}" || { echo "ERROR: .mk fw_env.config kurmuyor" >&2; exit 1; }

# create-rauc-bundle arm subcommand.
crb="${ROOT}/scripts/create-rauc-bundle.sh"
bash -n "${crb}"
grep -q 'create_arm_bundle' "${crb}" || { echo "ERROR: create-rauc-bundle arm subcommand yok" >&2; exit 1; }
grep -q 'compatible=\${compatible}' "${crb}" || { echo "ERROR: arm bundle compatible OTA target'tan gelmiyor" >&2; exit 1; }
if grep -q 'compatible=suderra-os-aarch64' "${crb}"; then echo "ERROR: arm bundle paylaşılan aarch64 compatible taşıyor (EI-045)" >&2; exit 1; fi
grep -q 'suderra-A.fit' "${crb}" || { echo "ERROR: arm bundle FIT staging yapmıyor" >&2; exit 1; }

# PROD defconfig'ler RAUC + config paketini seçmeli (dev = minimal, x86 desenine
# uygun: RAUC/OTA yalnız prod'da; dev host-rauc kurmaz).
for dc in suderra_aarch64_rpi4_prod_ab_defconfig suderra_aarch64_revpi4_prod_ab_defconfig; do
    grep -q '^BR2_PACKAGE_RAUC=y' "${ROOT}/configs/${dc}" || { echo "ERROR: ${dc} RAUC seçmiyor" >&2; exit 1; }
    grep -q '^BR2_PACKAGE_SUDERRA_RAUC_CONFIG=y' "${ROOT}/configs/${dc}" || { echo "ERROR: ${dc} SUDERRA_RAUC_CONFIG seçmiyor" >&2; exit 1; }
done
# DEV defconfig'ler RAUC İÇERMEMELİ (host-rauc build warning'lerinden kaçın).
for dc in suderra_aarch64_rpi4_defconfig suderra_aarch64_revpi4_defconfig; do
    if grep -qE '^BR2_PACKAGE_RAUC=y|^BR2_PACKAGE_SUDERRA_RAUC_CONFIG=y' "${ROOT}/configs/${dc}"; then
        echo "ERROR: dev ${dc} RAUC içermemeli (yalnız prod_ab)" >&2; exit 1; fi
done

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

# system.conf.arm: U-Boot backend, aarch64 device class, by-partlabel slots, hook.
arm_conf="${P}/system.conf.arm"
[ -f "${arm_conf}" ] || { echo "ERROR: system.conf.arm yok" >&2; exit 1; }
grep -q '^bootloader=uboot' "${arm_conf}" || { echo "ERROR: ARM bootloader=uboot değil" >&2; exit 1; }
grep -q '^compatible=suderra-os-aarch64' "${arm_conf}" || { echo "ERROR: ARM compatible aarch64 değil" >&2; exit 1; }
grep -q 'suderra-rauc-arm-slot-hook.sh' "${arm_conf}" || { echo "ERROR: ARM system.conf slot hook bağlamıyor" >&2; exit 1; }
grep -q 'by-partlabel/rootfs-a$' "${arm_conf}" || { echo "ERROR: ARM slotlar by-partlabel değil" >&2; exit 1; }
if grep -q 'grubenv' "${arm_conf}"; then echo "ERROR: ARM system.conf grubenv içermemeli" >&2; exit 1; fi

# x86 system.conf değişmeden GRUB kalmalı.
grep -q '^bootloader=grub' "${P}/system.conf" || { echo "ERROR: x86 system.conf grub kalmalı" >&2; exit 1; }

# boot.mount.arm: Pi FAT boot partition (by-partlabel/boot).
grep -q 'by-partlabel/boot' "${P}/boot.mount.arm" || { echo "ERROR: ARM boot.mount by-partlabel/boot değil" >&2; exit 1; }

# fw_env.config: U-Boot env.
grep -q '/boot/uboot.env' "${P}/fw_env.config" || { echo "ERROR: fw_env.config U-Boot env göstermiyor" >&2; exit 1; }

# arm slot hook: imzalı FIT'i boot'a kopyalar.
hook="${P}/suderra-rauc-arm-slot-hook.sh"
for t in 'RAUC_SLOT_BOOTNAME' 'suderra-${bootname}.fit' '/boot/suderra-${bootname}.fit'; do
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
grep -q 'compatible=suderra-os-aarch64' "${crb}" || { echo "ERROR: arm bundle aarch64 compatible değil" >&2; exit 1; }
grep -q 'suderra-A.fit' "${crb}" || { echo "ERROR: arm bundle FIT staging yapmıyor" >&2; exit 1; }

# defconfig'ler RAUC + config paketini seçmeli.
for dc in suderra_aarch64_rpi4_defconfig suderra_aarch64_revpi4_defconfig; do
    grep -q '^BR2_PACKAGE_RAUC=y' "${ROOT}/configs/${dc}" || { echo "ERROR: ${dc} RAUC seçmiyor" >&2; exit 1; }
    grep -q '^BR2_PACKAGE_SUDERRA_RAUC_CONFIG=y' "${ROOT}/configs/${dc}" || { echo "ERROR: ${dc} SUDERRA_RAUC_CONFIG seçmiyor" >&2; exit 1; }
done

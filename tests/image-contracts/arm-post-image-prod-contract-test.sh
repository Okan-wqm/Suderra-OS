#!/usr/bin/env bash
#
# ARM prod post-image wiring sözleşmesi (PR-A6, ADR-0007 G1/G2).
#
# post-image.sh'in ARM prod variant'ında A3 üreticisini + A4 düzenini
# birleştirdiğini korur: arm-pre-genimage çağrısı, config-uboot yerleştirme, prod
# genimage seçimi, enforce gate'in A/B FIT'i ve keyed firmware device tree'lerini
# zorunlu tutması (arm-boot-gate), ve hiçbir imzasız boot script'in olmaması.
# DEV yolu değişmeden kalır (fail-closed sadece prod'da).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PI="${ROOT}/board/suderra/common/post-image.sh"

bash -n "${PI}"

# Prod variant ARM üreticisini çağırmalı + config-uboot koymalı + boot zincirini
# artifact'ler üzerinde kapıdan geçirmeli (arm-boot-gate).
for token in \
    'arm-pre-genimage' \
    'arm-boot-gate' \
    'firmware-dtb/bcm2711-rpi-cm4.dtb' \
    'config-uboot.txt' \
    'rpi-firmware/config.txt'
do
    grep -qF -e "${token}" "${PI}" || {
        echo "ERROR: post-image ARM prod wiring eksik: ${token}" >&2; exit 1; }
done

# No unsigned boot script and no loose control device tree (EI-013, EI-036): the
# slot choice is compiled into U-Boot, the key is in the firmware's device trees.
if grep -qE 'mkimage .*-T script|boot\.scr|"\$\{BINARIES_DIR\}/u-boot\.dtb"' "${PI}"; then
    grep -nE 'mkimage .*-T script|boot\.scr|u-boot\.dtb' "${PI}" >&2
    echo "ERROR: post-image still builds or requires a boot script or a loose u-boot.dtb" >&2; exit 1; fi
[ ! -e "${ROOT}/board/suderra/aarch64-rpi4/boot.scr.cmd" ] || {
    echo "ERROR: boot.scr.cmd is back: an unsigned legacy script on a writable FAT (EI-036)" >&2; exit 1; }

# Prod genimage seçimi variant-aware olmalı (dev MBR, prod GPT).
grep -q 'aarch64-rpi4/genimage-prod.cfg' "${PI}" || {
    echo "ERROR: rpi4 prod genimage-prod.cfg seçilmiyor" >&2; exit 1; }
grep -qF 'ARM_BOARD_DIR="${BR2_EXTERNAL_SUDERRA_PATH}/board/suderra/aarch64-revpi-connect4"' "${PI}" || {
    echo "ERROR: revpi4 board dizini (aarch64-revpi-connect4) tanımlı değil" >&2; exit 1; }
grep -qF 'GENIMAGE_CFG="${ARM_BOARD_DIR}/genimage-prod.cfg"' "${PI}" || {
    echo "ERROR: revpi4 prod genimage-prod.cfg seçilmiyor" >&2; exit 1; }

# enforce_production_contract A/B FIT'i zorunlu tutmalı; tekil suderra.fit DEĞİL.
for token in 'suderra-A.fit' 'suderra-A.fit.sig' 'suderra-A.fit.cert' \
             'suderra-B.fit' 'suderra-B.fit.sig' 'suderra-B.fit.cert'; do
    grep -qF -e "${token}" "${PI}" || {
        echo "ERROR: enforce gate eksik ARM artefaktı: ${token}" >&2; exit 1; }
done
# Eski tekil FIT sözleşmesi kalmamalı (A/B'ye evrildi).
if grep -qE '"\$\{BINARIES_DIR\}/suderra\.fit"' "${PI}"; then
    echo "ERROR: enforce gate hâlâ tekil suderra.fit istiyor (A/B'ye evrilmeli)" >&2; exit 1; fi

# ARM prod wiring yalnız SUDERRA_OS_VARIANT=prod bloğunda olmalı (dev'i kırmaz).
awk '/if \[ "\$\{SUDERRA_OS_VARIANT\}" = "prod" \]; then/{p=1} p&&/arm-pre-genimage/{found=1} /^fi$/{if(p)p=0} END{exit(found?0:1)}' "${PI}" || {
    echo "ERROR: arm-pre-genimage prod bloğu içinde olmalı" >&2; exit 1; }

#!/usr/bin/env bash
#
# ARM prod GPT A/B genimage sözleşmesi (PR-A4, ADR-0007 gate G2).
#
# rpi4/revpi4 PROD disk düzeninin GPT A/B + verity + data olduğunu ve boot
# zincirinin U-Boot + imzalı FIT'e çevrildiğini korur. Mümkünse genimage'ı
# gerçekten koşturup 6-partition GPT ürettiğini doğrular (dev MBR düzeni
# aarch64-*/genimage.cfg'de değişmeden kalır — A4 additive, dev'i kırmaz).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

for board in aarch64-rpi4 aarch64-revpi-connect4; do
    prod="${ROOT}/board/suderra/${board}/genimage-prod.cfg"
    [ -f "${prod}" ] || { echo "ERROR: ${board} prod genimage yok" >&2; exit 1; }
    grep -q 'partition-table-type = "gpt"' "${prod}" || { echo "ERROR: ${board} prod GPT değil" >&2; exit 1; }
    for part in 'partition boot' 'partition rootfs-a' 'partition rootfs-a-verity' \
                'partition rootfs-b' 'partition rootfs-b-verity' 'partition data'; do
        grep -qF "${part} {" "${prod}" || { echo "ERROR: ${board} eksik partition: ${part}" >&2; exit 1; }
    done
    # Boot FAT signed-FIT + U-Boot taşımalı, ham Image/cmdline TAŞIMAMALI; nothing
    # unsigned that U-Boot could run (no boot.scr, no loose u-boot.dtb: the slot
    # choice is compiled in and the key is in the firmware's device trees).
    for f in 'u-boot.bin' 'suderra-A.fit' 'suderra-B.fit'; do
        grep -qF "\"${f}\"" "${prod}" || { echo "ERROR: ${board} boot eksik: ${f}" >&2; exit 1; }
    done
    for f in 'boot.scr' 'u-boot.dtb'; do
        if grep -qF "\"${f}\"" "${prod}"; then
            echo "ERROR: ${board} boot partition carries ${f} (EI-013, EI-036)" >&2; exit 1; fi
    done
    # The device trees are the keyed copies (firmware-dtb/), mapped by name; a
    # plain "<name>.dtb" entry would put the unkeyed stock tree on the FAT, and
    # U-Boot would then run with no key in its control FDT.
    if grep -qE '^[[:space:]]*"[^"]*\.dtb",?$' "${prod}"; then
        echo "ERROR: ${board} boot places an unkeyed device tree: map it from firmware-dtb/" >&2; exit 1; fi
    grep -qE '^    file bcm2711-[a-z0-9-]+\.dtb \{$' "${prod}" || {
        echo "ERROR: ${board} boot has no firmware device tree" >&2; exit 1; }
    while IFS= read -r dtb; do
        grep -qF "image = \"firmware-dtb/${dtb}\"" "${prod}" || {
            echo "ERROR: ${board} ${dtb} is not mapped from firmware-dtb/" >&2; exit 1; }
    done < <(sed -n 's/^    file \(bcm2711-[a-z0-9-]*\.dtb\) {$/\1/p' "${prod}")
    if grep -qF '"Image"' "${prod}"; then
        echo "ERROR: ${board} prod boot'ta ham Image olmamalı (kernel imzalı FIT'te)" >&2; exit 1; fi
    # ESP tipi boot partition.
    grep -q 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B' "${prod}" || {
        echo "ERROR: ${board} boot ESP-tipi olmalı" >&2; exit 1; }
done

# config.txt HÂLÂ dev (kernel=Image); prod config-uboot.txt kernel=u-boot.bin.
grep -q '^kernel=Image' "${ROOT}/board/suderra/aarch64-rpi4/config.txt" || {
    echo "ERROR: dev config.txt kernel=Image kalmalı (A4 dev'i kırmaz)" >&2; exit 1; }
grep -q '^kernel=u-boot.bin' "${ROOT}/board/suderra/aarch64-rpi4/config-uboot.txt" || {
    echo "ERROR: prod config-uboot.txt kernel=u-boot.bin olmalı" >&2; exit 1; }

# The slot choice is U-Boot's compiled-in bootcmd (board/suderra/uboot/suderra.env):
# RAUC's counters, the FIT of the slot, bootm. No boot script exists.
env="${ROOT}/board/suderra/uboot/suderra.env"
for token in 'BOOT_ORDER' 'BOOT_A_LEFT' 'BOOT_B_LEFT' 'suderra-${suderra_slot}.fit' 'bootm ${fitaddr}'; do
    grep -qF -e "${token}" "${env}" || { echo "ERROR: suderra.env eksik: ${token}" >&2; exit 1; }
done

# Dev genimage HÂLÂ MBR (A4 dev'i değiştirmez).
grep -q 'partition-table-type = "mbr"' "${ROOT}/board/suderra/aarch64-rpi4/genimage.cfg" || {
    echo "ERROR: dev rpi4 genimage MBR kalmalı" >&2; exit 1; }

# Mümkünse genimage'ı gerçekten koştur → 6-partition GPT, boot partition 1 MiB'de
# (U-Boot'un raw ortamı onun önünde), FAT'te yalnız imzalı içerik + keyed DTB'ler.
if command -v genimage >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1 \
   && command -v mkfs.vfat >/dev/null 2>&1 && command -v sfdisk >/dev/null 2>&1; then
    W="$(mktemp -d)"; trap 'rm -rf "${W}"' EXIT
    run_genimage() { # <board> <image name> <dtb>... : the stock trees that firmware-dtb/ holds
        local board="$1" image="$2" listing names start fat f
        shift 2
        rm -rf "${W}/input" "${W}/images" "${W}/root" "${W}/gtmp"
        mkdir -p "${W}/input/rpi-firmware/overlays" "${W}/input/firmware-dtb" "${W}/images" "${W}/root" "${W}/gtmp"
        sed -E 's/size = 512M/size = 1M/; s/size = 64M/size = 1M/; s/size = 2G/size = 2M/; s/size = 256M/size = 20M/' \
            "${ROOT}/board/suderra/${board}/genimage-prod.cfg" > "${W}/prod.cfg"
        for f in u-boot.bin suderra-A.fit suderra-B.fit rootfs.verity; do
            printf 'xx' > "${W}/input/${f}"
        done
        for f in "$@"; do printf 'xx' > "${W}/input/firmware-dtb/${f}"; done
        dd if=/dev/zero of="${W}/input/rootfs.ext4" bs=1k count=64 status=none
        for f in config.txt fixup4.dat start4.elf; do printf 'xx' > "${W}/input/rpi-firmware/${f}"; done
        printf 'xx' > "${W}/input/rpi-firmware/overlays/dummy.dtbo"
        genimage --config "${W}/prod.cfg" --inputpath "${W}/input" --outputpath "${W}/images" \
            --rootpath "${W}/root" --tmppath "${W}/gtmp" >/dev/null 2>&1 || {
            echo "ERROR: ${board} genimage prod GPT imajı üretemedi" >&2; exit 1; }
        listing="$(sfdisk -J "${W}/images/${image}")"
        names="$(python3 -c "import json,sys; d=json.load(sys.stdin)['partitiontable']; print(d['label'], ' '.join(p.get('name','') for p in d['partitions']))" <<<"${listing}")"
        [ "${names}" = "gpt boot rootfs-a rootfs-a-verity rootfs-b rootfs-b-verity data" ] || {
            echo "ERROR: ${board} beklenmeyen GPT partition düzeni: ${names}" >&2; exit 1; }
        start="$(python3 -c "import json,sys; print(json.load(sys.stdin)['partitiontable']['partitions'][0]['start'])" <<<"${listing}")"
        [ "${start}" -eq 2048 ] || {
            echo "ERROR: ${board} boot partition starts at sector ${start}, not 2048 (1 MiB): U-Boot's raw environment is in front of it" >&2; exit 1; }
        # The FAT holds the signed FIT, U-Boot, the firmware and the keyed trees,
        # and no boot script or control device tree of U-Boot's own.
        fat="${W}/boot.fat"
        dd if="${W}/images/${image}" of="${fat}" bs=512 skip=2048 count=40960 status=none
        listing="$(mdir -b -i "${fat}" :: 2>/dev/null | tr 'A-Z' 'a-z')"
        for f in u-boot.bin suderra-a.fit suderra-b.fit "$@"; do
            grep -qxF "::/${f}" <<<"${listing}" || {
                echo "ERROR: ${board} boot FAT lacks ${f}: $(tr '\n' ' ' <<<"${listing}")" >&2; exit 1; }
        done
        for f in boot.scr u-boot.dtb; do
            ! grep -qxF "::/${f}" <<<"${listing}" || {
                echo "ERROR: ${board} boot FAT carries ${f}" >&2; exit 1; }
        done
    }
    run_genimage aarch64-rpi4 suderra-rpi4-target.img bcm2711-rpi-4-b.dtb bcm2711-rpi-cm4.dtb bcm2711-rpi-cm4-io.dtb
    run_genimage aarch64-revpi-connect4 suderra-revpi4-target.img bcm2711-rpi-cm4.dtb
else
    echo "NOTE: genimage/mtools yok; yapısal kontrol yapıldı, gerçek build Image Build kapsıyor"
fi

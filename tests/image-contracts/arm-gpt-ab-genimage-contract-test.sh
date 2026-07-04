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

for board in aarch64-rpi4 aarch64-revpi4; do
    prod="${ROOT}/board/suderra/${board}/genimage-prod.cfg"
    [ -f "${prod}" ] || { echo "ERROR: ${board} prod genimage yok" >&2; exit 1; }
    grep -q 'partition-table-type = "gpt"' "${prod}" || { echo "ERROR: ${board} prod GPT değil" >&2; exit 1; }
    for part in 'partition boot' 'partition rootfs-a' 'partition rootfs-a-verity' \
                'partition rootfs-b' 'partition rootfs-b-verity' 'partition data'; do
        grep -qF "${part} {" "${prod}" || { echo "ERROR: ${board} eksik partition: ${part}" >&2; exit 1; }
    done
    # Boot FAT signed-FIT + U-Boot taşımalı, ham Image/cmdline TAŞIMAMALI.
    for f in 'u-boot.bin' 'boot.scr' 'suderra-A.fit' 'suderra-B.fit'; do
        grep -qF "\"${f}\"" "${prod}" || { echo "ERROR: ${board} boot eksik: ${f}" >&2; exit 1; }
    done
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

# Boot script RAUC slot mantığı + imzalı FIT bootm taşımalı.
scr="${ROOT}/board/suderra/aarch64-rpi4/boot.scr.cmd"
for token in 'BOOT_ORDER' 'BOOT_A_LEFT' 'BOOT_B_LEFT' 'suderra-${bootslot}.fit' 'bootm'; do
    grep -qF -e "${token}" "${scr}" || { echo "ERROR: boot.scr.cmd eksik: ${token}" >&2; exit 1; }
done

# Dev genimage HÂLÂ MBR (A4 dev'i değiştirmez).
grep -q 'partition-table-type = "mbr"' "${ROOT}/board/suderra/aarch64-rpi4/genimage.cfg" || {
    echo "ERROR: dev rpi4 genimage MBR kalmalı" >&2; exit 1; }

# Mümkünse genimage'ı gerçekten koştur → 6-partition GPT doğrula.
if command -v genimage >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1 \
   && command -v mkfs.vfat >/dev/null 2>&1 && command -v sfdisk >/dev/null 2>&1; then
    W="$(mktemp -d)"; trap 'rm -rf "${W}"' EXIT
    mkdir -p "${W}/input/rpi-firmware/overlays" "${W}/images" "${W}/root" "${W}/gtmp"
    sed -E 's/size = 512M/size = 1M/; s/size = 64M/size = 1M/; s/size = 2G/size = 2M/; s/size = 256M/size = 20M/' \
        "${ROOT}/board/suderra/aarch64-rpi4/genimage-prod.cfg" > "${W}/prod.cfg"
    for f in u-boot.bin u-boot.dtb boot.scr suderra-A.fit suderra-B.fit \
             bcm2711-rpi-4-b.dtb bcm2711-rpi-cm4.dtb bcm2711-rpi-cm4-io.dtb rootfs.verity; do
        printf 'xx' > "${W}/input/${f}"
    done
    dd if=/dev/zero of="${W}/input/rootfs.ext4" bs=1k count=64 status=none
    for f in config.txt fixup4.dat start4.elf; do printf 'xx' > "${W}/input/rpi-firmware/${f}"; done
    printf 'xx' > "${W}/input/rpi-firmware/overlays/dummy.dtbo"
    genimage --config "${W}/prod.cfg" --inputpath "${W}/input" --outputpath "${W}/images" \
        --rootpath "${W}/root" --tmppath "${W}/gtmp" >/dev/null 2>&1 || {
        echo "ERROR: genimage prod GPT imajı üretemedi" >&2; exit 1; }
    names="$(sfdisk -J "${W}/images/suderra-rpi4-target.img" | python3 -c \
        "import json,sys; d=json.load(sys.stdin)['partitiontable']; print(d['label'], ' '.join(p.get('name','') for p in d['partitions']))")"
    [ "${names}" = "gpt boot rootfs-a rootfs-a-verity rootfs-b rootfs-b-verity data" ] || {
        echo "ERROR: beklenmeyen GPT partition düzeni: ${names}" >&2; exit 1; }
else
    echo "NOTE: genimage/mtools yok; yapısal kontrol yapıldı, gerçek build Image Build kapsıyor"
fi

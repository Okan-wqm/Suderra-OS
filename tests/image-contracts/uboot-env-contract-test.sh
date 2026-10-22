#!/usr/bin/env bash
#
# The U-Boot environment of the ARM production images is two raw copies in the gap
# in front of the first partition (ADR-048 DEC-18.5; EI-034). Four files say where
# they are, and a disagreement between them is not a build error: U-Boot reads
# one place, fw_setenv (RAUC's U-Boot backend) writes another, and the boot
# counters never reach the boot. This test holds them equal:
#
#   board/suderra/aarch64-rpi4/uboot-fragment.config   what U-Boot reads and writes
#   package/suderra-rauc-config/fw_env.config          what fw_setenv reads and writes
#   board/suderra/aarch64-*/genimage-prod.cfg          where the first partition starts
#
# Both copies must lie after the GPT entries (gpt-location + 16 KiB) and before the
# boot partition, must not overlap, and must be the device U-Boot reads (mmc 0).
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# check <root>: the whole contract on a tree.
check() {
    local root="$1"
    local frag="${root}/board/suderra/aarch64-rpi4/uboot-fragment.config"
    local fwenv="${root}/package/suderra-rauc-config/fw_env.config"
    local off1 off2 size dev board cfg start gpt entries_end lines dev1 dev2 o1 o2 s1 s2

    off1="$(sed -n 's/^CONFIG_ENV_OFFSET=\(0x[0-9a-fA-F]*\)$/\1/p' "${frag}")"
    off2="$(sed -n 's/^CONFIG_ENV_OFFSET_REDUND=\(0x[0-9a-fA-F]*\)$/\1/p' "${frag}")"
    size="$(sed -n 's/^CONFIG_ENV_SIZE=\(0x[0-9a-fA-F]*\)$/\1/p' "${frag}")"
    dev="$(sed -n 's/^CONFIG_SYS_MMC_ENV_DEV=\([0-9]*\)$/\1/p' "${frag}")"
    [ -n "${off1}" ] && [ -n "${off2}" ] && [ -n "${size}" ] ||
        { echo "ERROR: ${frag} must set CONFIG_ENV_OFFSET, CONFIG_ENV_OFFSET_REDUND and CONFIG_ENV_SIZE" >&2; return 1; }
    [ "${dev}" = 0 ] ||
        { echo "ERROR: CONFIG_SYS_MMC_ENV_DEV must be 0 (the SD/eMMC controller; fw_env.config names /dev/mmcblk0)" >&2; return 1; }
    grep -q '^CONFIG_ENV_IS_IN_MMC=y$' "${frag}" ||
        { echo "ERROR: the environment must be CONFIG_ENV_IS_IN_MMC (raw), not a file" >&2; return 1; }
    if [ $((off1)) -ge $((off2)) ]; then
        echo "ERROR: the second copy (${off2}) must come after the first (${off1})" >&2
        return 1
    fi
    if [ $((off1 + size)) -gt $((off2)) ]; then
        echo "ERROR: the two environment copies overlap: ${off1}+${size} > ${off2}" >&2
        return 1
    fi

    # fw_env.config: exactly two entries, the same device, offsets and size.
    mapfile -t lines < <(grep -Ev '^[[:space:]]*(#|$)' "${fwenv}")
    [ "${#lines[@]}" -eq 2 ] ||
        { echo "ERROR: ${fwenv} must have exactly two entries (a redundant environment), has ${#lines[@]}" >&2; return 1; }
    IFS=" " read -r dev1 o1 s1 _ <<< "$(tr -s ' \t' ' ' <<< "${lines[0]}")"
    IFS=" " read -r dev2 o2 s2 _ <<< "$(tr -s ' \t' ' ' <<< "${lines[1]}")"
    [ "${dev1}" = /dev/mmcblk0 ] && [ "${dev2}" = /dev/mmcblk0 ] ||
        { echo "ERROR: ${fwenv} must name /dev/mmcblk0 twice, names ${dev1} and ${dev2}" >&2; return 1; }
    [ $((o1)) -eq $((off1)) ] ||
        { echo "ERROR: fw_env.config's first offset ${o1} is not U-Boot's CONFIG_ENV_OFFSET ${off1}" >&2; return 1; }
    [ $((o2)) -eq $((off2)) ] ||
        { echo "ERROR: fw_env.config's second offset ${o2} is not U-Boot's CONFIG_ENV_OFFSET_REDUND ${off2}" >&2; return 1; }
    [ $((s1)) -eq $((size)) ] && [ $((s2)) -eq $((size)) ] ||
        { echo "ERROR: fw_env.config's size ${s1}/${s2} is not U-Boot's CONFIG_ENV_SIZE ${size}" >&2; return 1; }

    # genimage: the boot partition starts after both copies, the GPT entries
    # end before the first.
    for board in aarch64-rpi4 aarch64-revpi-connect4; do
        cfg="${root}/board/suderra/${board}/genimage-prod.cfg"
        start="$(awk '/^  partition boot \{/ {inboot = 1} inboot && /^    offset = / {print $3; exit}' "${cfg}")"
        [ -n "${start}" ] ||
            { echo "ERROR: ${cfg}: the boot partition has no offset; it would start inside the environment" >&2; return 1; }
        case "${start}" in
            *M) start=$((${start%M} * 1024 * 1024)) ;;
            *K) start=$((${start%K} * 1024)) ;;
            *) echo "ERROR: ${cfg}: offset ${start} must end in K or M" >&2; return 1 ;;
        esac
        [ "${start}" -ge $((off2 + size)) ] ||
            { echo "ERROR: ${cfg}: the boot partition starts at ${start}, inside the environment (ends at $((off2 + size)))" >&2; return 1; }
        gpt="$(sed -n 's/^ *gpt-location = \([0-9]*\)K$/\1/p' "${cfg}")"
        [ -n "${gpt}" ] ||
            { echo "ERROR: ${cfg}: no gpt-location in K" >&2; return 1; }
        # 128 entries of 128 bytes follow the GPT location.
        entries_end=$((gpt * 1024 + 128 * 128))
        [ "${entries_end}" -le $((off1)) ] ||
            { echo "ERROR: ${cfg}: the GPT entries end at ${entries_end}, inside the environment (starts at ${off1})" >&2; return 1; }
    done
    return 0
}

echo "the repository"
check "${ROOT}" || exit 1

# An FAT file is not a redundant environment: no unit, hook or script of the
# image may name uboot.env.
if grep -rIl 'uboot\.env' "${ROOT}/package/suderra-rauc-config" "${ROOT}/package/suderra-os-installer" \
    "${ROOT}/board/suderra/common" "${ROOT}/board/suderra/uboot" "${ROOT}/board/suderra/aarch64-rpi4" \
    "${ROOT}/board/suderra/aarch64-revpi-connect4" 2>/dev/null | grep -q .; then
    fail "something still names a uboot.env file: the environment is raw on the disk"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
fresh() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree"
    (cd "${ROOT}" && cp -a --parents board/suderra/aarch64-rpi4/uboot-fragment.config \
        board/suderra/aarch64-rpi4/genimage-prod.cfg board/suderra/aarch64-revpi-connect4/genimage-prod.cfg \
        package/suderra-rauc-config/fw_env.config "${WORK}/tree")
}
expect_fail() {
    local label="$1"
    if (check "${WORK}/tree") >/dev/null 2>&1; then
        fail "the contract accepted: ${label}"
    fi
    echo "  rejects: ${label}"
}

echo "mutations"
fresh
sed -i 's#^/dev/mmcblk0\( *\)0x60000#/dev/mmcblk0\10x60400#' "${WORK}/tree/package/suderra-rauc-config/fw_env.config"
expect_fail "fw_setenv writes where U-Boot does not read"

fresh
sed -i 's#^/dev/mmcblk0\( *\)0x80000#/dev/mmcblk0\10x88000#' "${WORK}/tree/package/suderra-rauc-config/fw_env.config"
expect_fail "fw_setenv's second copy is somewhere else"

fresh
sed -i '/^\/dev\/mmcblk0 *0x80000/d' "${WORK}/tree/package/suderra-rauc-config/fw_env.config"
expect_fail "fw_env.config with one copy only (not redundant)"

fresh
sed -i 's/^CONFIG_ENV_SIZE=0x4000$/CONFIG_ENV_SIZE=0x8000/' "${WORK}/tree/board/suderra/aarch64-rpi4/uboot-fragment.config"
expect_fail "U-Boot's environment larger than fw_setenv's"

fresh
sed -i 's/^CONFIG_ENV_OFFSET_REDUND=0x80000$/CONFIG_ENV_OFFSET_REDUND=0x62000/' "${WORK}/tree/board/suderra/aarch64-rpi4/uboot-fragment.config"
sed -i 's#0x80000#0x62000#' "${WORK}/tree/package/suderra-rauc-config/fw_env.config"
expect_fail "the two copies overlap"

fresh
sed -i '/^    offset = 1M$/d' "${WORK}/tree/board/suderra/aarch64-rpi4/genimage-prod.cfg"
expect_fail "the boot partition has no offset (it would start inside the environment)"

fresh
sed -i 's/^    offset = 1M$/    offset = 512K/' "${WORK}/tree/board/suderra/aarch64-revpi-connect4/genimage-prod.cfg"
expect_fail "the RevPi boot partition starts inside the second copy"

fresh
sed -i 's/gpt-location = 32K/gpt-location = 380K/' "${WORK}/tree/board/suderra/aarch64-rpi4/genimage-prod.cfg"
expect_fail "the GPT entries run into the environment"

fresh
sed -i 's/^CONFIG_ENV_IS_IN_MMC=y$/CONFIG_ENV_IS_IN_FAT=y/' "${WORK}/tree/board/suderra/aarch64-rpi4/uboot-fragment.config"
expect_fail "the environment back in a FAT file"

echo "U-Boot environment contract test OK"

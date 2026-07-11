#!/usr/bin/env bash
#
# ARM U-Boot signed-FIT build sözleşmesi (PR-A2, statik).
#
# U-Boot'un gerçek derlenmesi Image Build job'ında (Buildroot). Burada, ARM
# defconfig'lerinin U-Boot'u FIT_SIGNATURE ile derleyecek şekilde yapılandığını
# ve config.txt'nin HENÜZ U-Boot'a çevrilmediğini (PR-A4) kod düzeyinde koruruz.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FRAGMENT="${ROOT}/board/suderra/aarch64-rpi4/uboot-fragment.config"
GEN_KEYS="${ROOT}/scripts/gen-dev-keys.sh"
CONFIG_TXT="${ROOT}/board/suderra/aarch64-rpi4/config.txt"

[ -f "${FRAGMENT}" ] || { echo "ERROR: U-Boot fragment eksik" >&2; exit 1; }

# CONFIG_FIT_BEST_MATCH: 'bootm ${fitaddr}' (#conf'suz) çok-kartlı FIT'te doğru
# config'i çalışan-kartın compatible'ıyla YALNIZ bu açıkken seçer; olmadan default
# (alfabetik ilk) boot edilir ve multi-board üretici boot'ta etkisiz kalır (HIGH1).
for token in 'CONFIG_FIT=y' 'CONFIG_FIT_SIGNATURE=y' 'CONFIG_RSA=y' 'CONFIG_OF_CONTROL=y' 'CONFIG_FIT_BEST_MATCH=y'; do
    grep -qF -e "${token}" "${FRAGMENT}" || {
        echo "ERROR: U-Boot fragment eksik: ${token}" >&2; exit 1; }
done

for defconfig in suderra_aarch64_rpi4_defconfig suderra_aarch64_revpi4_defconfig; do
    dc="${ROOT}/configs/${defconfig}"
    for token in \
        'BR2_TARGET_UBOOT=y' \
        'BR2_TARGET_UBOOT_BOARD_DEFCONFIG="rpi_arm64"' \
        'BR2_TARGET_UBOOT_CONFIG_FRAGMENT_FILES=' \
        'BR2_TARGET_UBOOT_NEEDS_OPENSSL=y' \
        'BR2_PACKAGE_HOST_UBOOT_TOOLS_FIT_SIGNATURE_SUPPORT=y'
    do
        grep -qF -e "${token}" "${dc}" || {
            echo "ERROR: ${defconfig} eksik U-Boot token: ${token}" >&2; exit 1; }
    done
done

# Gate: config.txt HENÜZ u-boot.bin'e çevrilmemeli (boot switch PR-A4).
if grep -qE '^kernel=u-boot' "${CONFIG_TXT}" 2>/dev/null; then
    echo "ERROR: config.txt U-Boot chainload'a PR-A2'de çevrilemez (PR-A4 işi)" >&2
    exit 1
fi

# fit-signing anahtarı gen-dev-keys tarafından üretilmeli.
grep -qF -e 'fit-signing.key' "${GEN_KEYS}" || {
    echo "ERROR: gen-dev-keys.sh fit-signing anahtarı üretmeli" >&2; exit 1; }

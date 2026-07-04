#!/usr/bin/env bash
#
# ARM prod post-image wiring sözleşmesi (PR-A6, ADR-0007 G1/G2).
#
# post-image.sh'in ARM prod variant'ında A3 üreticisini + A4 düzenini
# birleştirdiğini korur: arm-pre-genimage çağrısı, boot.scr derleme,
# config-uboot yerleştirme, prod genimage seçimi ve enforce gate'in A/B FIT'i
# zorunlu tutması. DEV yolu değişmeden kalır (fail-closed sadece prod'da).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PI="${ROOT}/board/suderra/common/post-image.sh"

bash -n "${PI}"

# Prod variant ARM üreticisini çağırmalı + boot.scr derlemeli + config-uboot koymalı.
for token in \
    'arm-pre-genimage' \
    'mkimage -A arm64 -T script' \
    'boot.scr.cmd' \
    'config-uboot.txt' \
    'rpi-firmware/config.txt'
do
    grep -qF -e "${token}" "${PI}" || {
        echo "ERROR: post-image ARM prod wiring eksik: ${token}" >&2; exit 1; }
done

# Prod genimage seçimi variant-aware olmalı (dev MBR, prod GPT).
grep -q 'aarch64-rpi4/genimage-prod.cfg' "${PI}" || {
    echo "ERROR: rpi4 prod genimage-prod.cfg seçilmiyor" >&2; exit 1; }
grep -q 'aarch64-revpi4/genimage-prod.cfg' "${PI}" || {
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

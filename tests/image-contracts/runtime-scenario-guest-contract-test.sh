#!/usr/bin/env bash
#
# Production-runtime GUEST senaryo sürücüsü sözleşmesi (statik).
#
# Sürücünün gerçek koşusu tam production-runtime suite'inde (QEMU boot). Burada
# yapısını ve — kritik — mutasyon-kabul eden bu affordance'ın SAHA imajına
# sızmayacağını kod düzeyinde garanti ederiz.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIVER="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-runtime-scenario"
UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-runtime-scenario.service"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"

[ -f "${DRIVER}" ] || { echo "ERROR: guest senaryo sürücüsü eksik" >&2; exit 1; }
[ -f "${UNIT}" ] || { echo "ERROR: guest senaryo servisi eksik" >&2; exit 1; }

# 1) fw_cfg'den senaryo okur + deterministik outcome markeri basar.
grep -q 'opt/suderra/runtime-scenario' "${DRIVER}" || {
    echo "ERROR: sürücü fw_cfg runtime-scenario okumalı" >&2; exit 1; }
grep -q 'SUDERRA_PRODUCTION_RUNTIME_OUTCOME=%s' "${DRIVER}" || {
    echo "ERROR: sürücü deterministik outcome markeri basmalı" >&2; exit 1; }

# 2) Guest'e ulaşan senaryoların hepsini ele almalı.
for scenario in signed-boot data-luks-swtpm rauc-good-update rauc-bad-signature-rejection \
    rauc-health-rollback anti-rollback-downgrade-rejection; do
    grep -qF -e "${scenario})" "${DRIVER}" || {
        echo "ERROR: sürücü senaryoyu ele almıyor: ${scenario}" >&2; exit 1; }
done

# 3) Payload sürücüsünü sabit seri no ile okumalı (harness ile eşleşir).
grep -q 'virtio-suderra-scenario-payload' "${DRIVER}" || {
    echo "ERROR: sürücü sabit-seri payload sürücüsünü okumalı" >&2; exit 1; }

# 4) PROFİL-GATING: yalnız prod-ab enable; diğer TÜM imajlardan silinir.
grep -q 'suderra_qemu_x86_64_prod_ab\*)' "${POST_BUILD}" || {
    echo "ERROR: post-build sürücüyü prod-ab için gate etmeli" >&2; exit 1; }
grep -q 'rm -f "\${TARGET_DIR}/usr/sbin/suderra-runtime-scenario"' "${POST_BUILD}" || {
    echo "ERROR: post-build sürücüyü prod-ab dışı imajlardan SİLMELİ (saha yüzeyi)" >&2; exit 1; }

# 5) Servis ancak fw_cfg senaryosu varsa çalışmalı (saha donanımında koşmaz).
grep -q 'ConditionPathExists=/sys/firmware/qemu_fw_cfg/by_name/opt/suderra/runtime-scenario/raw' "${UNIT}" || {
    echo "ERROR: servis fw_cfg senaryosu yoksa çalışmamalı" >&2; exit 1; }

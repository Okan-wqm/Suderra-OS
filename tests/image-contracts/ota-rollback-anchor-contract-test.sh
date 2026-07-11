#!/usr/bin/env bash
# ota-rollback-anchor-contract-test — RT-6 TPM-NV anti-rollback çıpası sözleşmesi.
#
# 1. post-build.sh YALNIZ prod varyantta imzalı /etc/suderra/ota.conf üretir
#    (tpm-nv kaynağı + NV index + runtime floor yolu + epoch/floor).
# 2. suderra-ota floor sync servisi mark-good'dan ÖNCE, TPM erişimiyle çalışır.
# 3. suderra-ota kaynağı: floor kaynağı imzalı config'ten okunur, floor yolu
#    prod'da env ile kaydırılamaz (fail-open engeli).
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
FLOOR_SVC="${ROOT}/package/suderra-ota/suderra-ota-floor.service"
OTA_MK="${ROOT}/package/suderra-ota/suderra-ota.mk"
OTA_SRC="${ROOT}/userspace/suderra-ota/src/main.rs"
fail() { echo "ERROR: $*" >&2; exit 1; }

# 1. post-build: prod ota.conf üretimi, prod-gate'li.
grep -q 'etc/suderra/ota.conf' "${POST_BUILD}" \
    || fail "post-build must generate /etc/suderra/ota.conf"
grep -q 'rollback_floor_source=tpm-nv' "${POST_BUILD}" \
    || fail "prod ota.conf must declare tpm-nv rollback source"
grep -q 'rollback_epoch=' "${POST_BUILD}" \
    || fail "prod ota.conf must carry a rollback_epoch"
# Prod-gate: ota.conf yalnız prod varyantta yazılmalı (dev Tier-1 kalır).
awk '/etc\/suderra\/ota.conf.*prod anti-rollback|ota.conf \(prod/{found=1} END{exit !found}' "${POST_BUILD}" \
    || grep -q 'SUDERRA_OS_VARIANT.*=.*.prod.*' "${POST_BUILD}" \
    || fail "ota.conf generation must be gated to the prod variant"

# 2. floor.service: oneshot, mark-good'dan önce, TPM erişimli, config koşullu.
[ -f "${FLOOR_SVC}" ] || fail "missing suderra-ota-floor.service"
grep -q 'Before=suderra-ota-mark-good.service' "${FLOOR_SVC}" \
    || fail "floor sync must run before mark-good"
grep -q 'ConditionPathExists=/etc/suderra/ota.conf' "${FLOOR_SVC}" \
    || fail "floor sync must be conditional on ota.conf presence"
grep -q 'ExecStart=/usr/bin/suderra-ota floor sync' "${FLOOR_SVC}" \
    || fail "floor sync ExecStart mismatch"
grep -q '/dev/tpmrm0' "${FLOOR_SVC}" || fail "floor sync needs TPM device access"
grep -q 'suderra-ota-floor.service' "${OTA_MK}" \
    || fail "suderra-ota.mk must install + enable the floor service"

# 3. Kaynak: floor kaynağı config kökünden; prod'da env yol kaydırma dev_override'lu.
grep -q 'fn rollback_floor_source' "${OTA_SRC}" \
    || fail "ota must resolve rollback floor source from signed config"
grep -q 'ota_conf_value("rollback_floor_path")' "${OTA_SRC}" \
    || fail "trusted floor path must come from signed ota.conf (config-first)"
grep -q 'fn floor_sync' "${OTA_SRC}" || fail "ota must implement floor sync (RT-6)"
grep -q 'downgrade' "${OTA_SRC}" \
    || fail "floor sync must fail closed on epoch-vs-NV downgrade"

echo "PASS: RT-6 TPM-NV anti-rollback anchor contract"

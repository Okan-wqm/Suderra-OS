#!/usr/bin/env bash
#
# QEMU boot smoke test (Faz 1 placeholder)
#
# Test: Imaj QEMU'da boot edip "Suderra OS" banner gösteriyor mu?
# Timeout: 60s

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

DEFCONFIG="${1:-suderra_qemu_x86_64_defconfig}"
DISK_IMG="${PROJECT_ROOT}/output/${DEFCONFIG}/images/disk.img"

if [ ! -f "${DISK_IMG}" ]; then
    echo "SKIP: ${DISK_IMG} yok (Faz 1'de oluşturulacak)"
    exit 0
fi

echo "==> QEMU boot test: ${DEFCONFIG}"

# expect ile boot logunu izle
LOG=$(mktemp)
trap 'rm -f "${LOG}"' EXIT

timeout 60 qemu-system-x86_64 \
    -m 256M \
    -drive "file=${DISK_IMG},format=raw,if=virtio" \
    -nographic \
    -serial "file:${LOG}" \
    -bios /usr/share/OVMF/OVMF_CODE.fd \
    -no-reboot 2>/dev/null || true

if grep -q "Suderra OS" "${LOG}"; then
    echo "PASS: Suderra OS banner görüldü"
    exit 0
else
    echo "FAIL: Suderra OS banner yok"
    echo "--- Log son 20 satır ---"
    tail -20 "${LOG}"
    exit 1
fi

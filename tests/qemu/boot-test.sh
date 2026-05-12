#!/usr/bin/env bash
#
# Suderra OS — QEMU boot smoke test (Katman 3)
#
# Test: İmaj QEMU'da boot edip "Suderra OS" banner gösteriyor mu?
# Timeout: 90s (Buildroot init + systemd minimal target ~30-60s)
#
# Çalıştırma:
#   ./tests/qemu/boot-test.sh                                # default qemu defconfig
#   ./tests/qemu/boot-test.sh suderra_qemu_x86_64_defconfig
#   ./tests/qemu/boot-test.sh --image /path/to/disk.img
#
# CI'da regression detection için kullanılır.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

# CLI args
DEFCONFIG="${1:-suderra_qemu_x86_64_defconfig}"
TIMEOUT="${BOOT_TEST_TIMEOUT:-90}"
DISK_IMG=""

# Image path tespit (Buildroot output veya CLI override)
if [[ "${1:-}" == "--image" ]]; then
    DISK_IMG="${2:?--image needs path}"
elif [ -n "${SUDERRA_DISK_IMG:-}" ]; then
    DISK_IMG="${SUDERRA_DISK_IMG}"
else
    # Buildroot output layout
    for candidate in \
        "${PROJECT_ROOT}/output/${DEFCONFIG}/images/disk.img" \
        "${PROJECT_ROOT}/buildroot/output/images/disk.img" \
        "${PROJECT_ROOT}/output/images/disk.img"
    do
        if [ -f "${candidate}" ]; then
            DISK_IMG="${candidate}"
            break
        fi
    done
fi

if [ -z "${DISK_IMG}" ] || [ ! -f "${DISK_IMG}" ]; then
    echo "SKIP: imaj bulunamadı"
    echo "  Aranılan: ${PROJECT_ROOT}/output/${DEFCONFIG}/images/disk.img"
    echo "  Önce: ./scripts/build-in-docker.sh ${DEFCONFIG}"
    exit 0
fi

# QEMU varlığı kontrol
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "SKIP: qemu-system-x86_64 yok (apt install qemu-system-x86)"
    exit 0
fi

echo "==> QEMU boot test"
echo "    Defconfig: ${DEFCONFIG}"
echo "    Image:     ${DISK_IMG}"
echo "    Timeout:   ${TIMEOUT}s"
echo

# Log dosyası
LOG=$(mktemp -t suderra-boot-test-XXXXXX.log)
trap 'rm -f "${LOG}"' EXIT

# QEMU args — quoted because commas are QEMU key=value syntax (SC2054).
QEMU_ARGS=(
    -machine "q35"
    -m "256M"
    -smp "2"
    -cpu "max,+pdpe1gb"
    -drive "file=${DISK_IMG},format=raw,if=virtio"
    -netdev "user,id=net0"
    -device "virtio-net-pci,netdev=net0"
    -nographic
    -serial "file:${LOG}"
    -no-reboot
)

# UEFI firmware varsa secure-boot ready test (yoksa BIOS mode)
if [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    QEMU_ARGS+=(-bios /usr/share/OVMF/OVMF_CODE.fd)
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    QEMU_ARGS+=(-bios /usr/share/qemu/OVMF.fd)
fi

# Boot ve banner bekle
echo "==> QEMU başlatılıyor..."
timeout "${TIMEOUT}" qemu-system-x86_64 "${QEMU_ARGS[@]}" 2>/dev/null || true

# Sonuç değerlendirme
echo "==> Boot loglarını analiz ediliyor..."

PASS=0
FAIL=0

# 1. Banner var mı?
if grep -q "Suderra OS" "${LOG}"; then
    echo "  ✓ Suderra OS banner görüldü"
    ((PASS++))
else
    echo "  ✗ Suderra OS banner görülmedi"
    ((FAIL++))
fi

# 2. Kernel panic yok mu?
if grep -q "Kernel panic" "${LOG}"; then
    echo "  ✗ Kernel panic tespit edildi"
    ((FAIL++))
else
    echo "  ✓ Kernel panic yok"
    ((PASS++))
fi

# 3. systemd başlatma sonu
if grep -qE "(Welcome to|Reached target|systemd\[1\])" "${LOG}"; then
    echo "  ✓ systemd başlatma görüldü"
    ((PASS++))
else
    echo "  ⚠ systemd başlatma kanıtı yok (init başka olabilir)"
fi

# 4. Provisioning image: local login prompt is expected until Edge install
# runs suderra-lockdown. Runtime appliance validation is a separate test.
if grep -qE "(suderra login| login:|Reached target|reached target|multi-user.target)" "${LOG}"; then
    echo "  ✓ Provisioning login/target hazır"
    ((PASS++))
else
    echo "  ⚠ Provisioning login/target görülmedi (timeout olabilir)"
fi

echo
echo "==> Sonuç: ${PASS} PASS, ${FAIL} FAIL"

if [ "${FAIL}" -eq 0 ] && [ "${PASS}" -ge 2 ]; then
    echo "==> BOOT TEST PASSED"
    exit 0
else
    echo "==> BOOT TEST FAILED"
    echo "--- Log son 50 satır ---"
    tail -50 "${LOG}"
    exit 1
fi

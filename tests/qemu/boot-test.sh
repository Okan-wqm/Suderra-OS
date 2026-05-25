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
    echo "ERROR: imaj bulunamadı"
    echo "  Aranılan: ${PROJECT_ROOT}/output/${DEFCONFIG}/images/disk.img"
    echo "  Önce: ./scripts/build-in-docker.sh ${DEFCONFIG}"
    exit 1
fi

# QEMU varlığı kontrol
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "ERROR: qemu-system-x86_64 yok (apt install qemu-system-x86)"
    exit 1
fi

find_ovmf_code() {
    local candidate
    local base
    local -a candidates

    if [ -n "${OVMF_CODE:-}" ]; then
        if [ -f "${OVMF_CODE}" ]; then
            printf '%s\n' "${OVMF_CODE}"
            return 0
        fi
        echo "ERROR: OVMF_CODE bulundu değil: ${OVMF_CODE}" >&2
        return 1
    fi

    candidates=(
        /usr/share/OVMF/OVMF_CODE_4M.fd
        /usr/share/OVMF/OVMF_CODE.fd
        /usr/share/OVMF/OVMF_CODE_4M.secboot.fd
        /usr/share/OVMF/OVMF_CODE.secboot.fd
        /usr/share/qemu/edk2-x86_64-code.fd
        /usr/share/qemu/OVMF.fd
        /usr/share/ovmf/OVMF.fd
        /usr/share/edk2/ovmf/OVMF_CODE.fd
        /usr/share/edk2/ovmf/OVMF_CODE.secboot.fd
        /usr/share/edk2/x64/OVMF_CODE.fd
        /usr/share/edk2/x64/OVMF_CODE.4m.fd
        /usr/share/edk2-ovmf/x64/OVMF_CODE.fd
        /usr/share/edk2-ovmf/x64/OVMF_CODE_4M.fd
    )

    for candidate in "${candidates[@]}"; do
        if [ -f "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    while IFS= read -r candidate; do
        [ -f "${candidate}" ] || continue
        base="$(basename "${candidate}")"
        case "${base}" in
            *VARS*|*vars*|*ia32*|*IA32*|*arm*|*ARM*|*aarch64*|*AARCH64*|*riscv*|*RISCV*)
                continue
                ;;
        esac
        printf '%s\n' "${candidate}"
        return 0
    done < <(
        {
            find /usr/share/OVMF /usr/share/ovmf /usr/share/qemu /usr/share/edk2 /usr/share/edk2-ovmf \
                -maxdepth 4 \
                -type f \
                \( -iname 'OVMF_CODE*.fd' -o -iname 'OVMF.fd' -o -iname 'edk2-x86_64-code*.fd' \) \
                2>/dev/null || true
        } | sort
    )

    echo "ERROR: OVMF firmware bulunamadı. OVMF_CODE=/path/to/OVMF_CODE.fd ayarlayın." >&2
    return 1
}

OVMF_CODE_PATH="$(find_ovmf_code)" || exit "$?"

echo "==> QEMU boot test"
echo "    Defconfig: ${DEFCONFIG}"
echo "    Image:     ${DISK_IMG}"
echo "    Timeout:   ${TIMEOUT}s"
echo "    OVMF:      ${OVMF_CODE_PATH}"
echo

# Log dosyaları: success/failure ayrımı olmadan korunur.
LOG_DIR="${BOOT_TEST_LOG_DIR:-${PROJECT_ROOT}/output/qemu-boot-logs}"
mkdir -p "${LOG_DIR}"
echo "==> QMP acceptance harness başlatılıyor..."
python3 "${PROJECT_ROOT}/tests/qemu/qmp-acceptance.py" \
    --image "${DISK_IMG}" \
    --ovmf "${OVMF_CODE_PATH}" \
    --timeout "${TIMEOUT}" \
    --log-dir "${LOG_DIR}"

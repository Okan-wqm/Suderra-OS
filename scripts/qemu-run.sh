#!/usr/bin/env bash
#
# Suderra OS — QEMU runner
#
# Kullanım:
#   ./scripts/qemu-run.sh                                # Son build edilen QEMU x86_64
#   ./scripts/qemu-run.sh suderra_qemu_x86_64_defconfig
#   ./scripts/qemu-run.sh --arch aarch64

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

DEFCONFIG="${1:-suderra_qemu_x86_64_defconfig}"
OUTPUT_DIR="${PROJECT_ROOT}/output/${DEFCONFIG}"

if [ ! -d "${OUTPUT_DIR}" ]; then
    echo "ERROR: ${OUTPUT_DIR} yok. Önce build edin:"
    echo "  ./scripts/build-in-docker.sh ${DEFCONFIG}"
    exit 1
fi

# Mimari tespit (defconfig adından)
if [[ "${DEFCONFIG}" == *aarch64* ]]; then
    ARCH="aarch64"
elif [[ "${DEFCONFIG}" == *x86_64* ]]; then
    ARCH="x86_64"
else
    echo "ERROR: Defconfig adından mimari çıkarılamadı: ${DEFCONFIG}"
    exit 1
fi

DISK_IMG="${OUTPUT_DIR}/images/disk.img"
if [ ! -f "${DISK_IMG}" ]; then
    echo "ERROR: ${DISK_IMG} yok (Faz 1'de oluşturulacak)"
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

case "${ARCH}" in
    x86_64)
        OVMF_CODE_PATH="$(find_ovmf_code)"
        echo "==> QEMU x86_64 başlatılıyor"
        echo "==> OVMF: ${OVMF_CODE_PATH}"
        echo "==> CTRL-A X ile çıkış"
        exec qemu-system-x86_64 \
            -machine q35 \
            -m 512M \
            -smp 2 \
            -drive "file=${DISK_IMG},format=raw,if=virtio" \
            -nographic \
            -serial mon:stdio \
            -fw_cfg name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes \
            -netdev user,id=net0,hostfwd=tcp::5555-:8080 \
            -device virtio-net-pci,netdev=net0 \
            -bios "${OVMF_CODE_PATH}" \
            ${QEMU_KVM:+-enable-kvm}
        ;;
    aarch64)
        echo "==> QEMU aarch64 başlatılıyor"
        echo "==> CTRL-A X ile çıkış"
        exec qemu-system-aarch64 \
            -M virt \
            -cpu cortex-a72 \
            -m 512M \
            -smp 2 \
            -drive "file=${DISK_IMG},format=raw,if=virtio" \
            -nographic \
            -serial mon:stdio \
            -netdev user,id=net0,hostfwd=tcp::5555-:8080 \
            -device virtio-net-pci,netdev=net0
        ;;
esac

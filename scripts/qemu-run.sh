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

case "${ARCH}" in
    x86_64)
        echo "==> QEMU x86_64 başlatılıyor"
        echo "==> CTRL-A X ile çıkış"
        exec qemu-system-x86_64 \
            -m 512M \
            -smp 2 \
            -drive "file=${DISK_IMG},format=raw,if=virtio" \
            -nographic \
            -serial mon:stdio \
            -netdev user,id=net0,hostfwd=tcp::5555-:8080 \
            -device virtio-net-pci,netdev=net0 \
            -bios /usr/share/OVMF/OVMF_CODE.fd \
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

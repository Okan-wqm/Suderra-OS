#!/usr/bin/env bash
#
# Suderra OS — Host build wrapper
# Buildroot zaten clone edilmiş olmalı (./buildroot/).
#
# Kullanım:
#   ./scripts/build.sh <defconfig>
#   ./scripts/build.sh suderra_qemu_x86_64_defconfig

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

DEFCONFIG="${1:?Kullanım: $0 <defconfig>}"
BUILDROOT_DIR="${BUILDROOT_DIR:-${PROJECT_ROOT}/buildroot}"
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_ROOT}/output/${DEFCONFIG}}"

# Buildroot var mı?
if [ ! -d "${BUILDROOT_DIR}" ]; then
    echo "ERROR: Buildroot bulunamadı: ${BUILDROOT_DIR}"
    echo ""
    echo "İlk seferde clone et:"
    echo "  git clone https://gitlab.com/buildroot.org/buildroot.git -b 2024.11 ${BUILDROOT_DIR}"
    exit 1
fi

# Defconfig var mı?
if [ ! -f "${PROJECT_ROOT}/configs/${DEFCONFIG}" ]; then
    echo "ERROR: Defconfig yok: configs/${DEFCONFIG}"
    echo ""
    echo "Mevcut defconfig'ler:"
    ls -1 "${PROJECT_ROOT}/configs/"
    exit 1
fi

# Build
echo "==> Suderra OS build: ${DEFCONFIG}"
echo "==> BR2_EXTERNAL: ${PROJECT_ROOT}"
echo "==> BUILDROOT_DIR: ${BUILDROOT_DIR}"
echo "==> OUTPUT_DIR: ${OUTPUT_DIR}"

cd "${BUILDROOT_DIR}"

make BR2_EXTERNAL="${PROJECT_ROOT}" O="${OUTPUT_DIR}" "${DEFCONFIG}"
make O="${OUTPUT_DIR}"

echo ""
echo "==> Build tamamlandı"
echo "==> Output: ${OUTPUT_DIR}/images/"
ls -lh "${OUTPUT_DIR}/images/" 2>/dev/null || echo "(images dizini henüz yok — placeholder defconfig)"

#!/usr/bin/env bash
#
# Suderra OS — Host build wrapper
# Buildroot submodule must be checked out cleanly. The actual build uses a
# managed source tree prepared from that pinned upstream checkout.
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
BUILDROOT_SOURCE_DIR="${BUILDROOT_SOURCE_DIR:-}"
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_ROOT}/output/${DEFCONFIG}}"
export BR2_DL_DIR="${BR2_DL_DIR:-${PROJECT_ROOT}/dl}"
export BR2_CCACHE_DIR="${BR2_CCACHE_DIR:-${PROJECT_ROOT}/.ccache}"

# Buildroot var mı?
if [ ! -d "${BUILDROOT_DIR}" ]; then
    echo "ERROR: Buildroot bulunamadı: ${BUILDROOT_DIR}"
    echo ""
    echo "İlk seferde clone et:"
    echo "  git submodule update --init --recursive"
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
echo "==> BR2_DL_DIR: ${BR2_DL_DIR}"
echo "==> BR2_CCACHE_DIR: ${BR2_CCACHE_DIR}"

mkdir -p "${BR2_DL_DIR}" "${BR2_CCACHE_DIR}"
if [ -z "${BUILDROOT_SOURCE_DIR}" ]; then
    BUILDROOT_SOURCE_DIR="$("${SCRIPT_DIR}/buildroot-source.sh" prepare --defconfig "${DEFCONFIG}")"
fi
echo "==> BUILDROOT_SOURCE_DIR: ${BUILDROOT_SOURCE_DIR}"

if [ -n "${SUDERRA_BUILDROOT_SOURCE_IDENTITY_OUT:-}" ]; then
    mkdir -p "$(dirname -- "${SUDERRA_BUILDROOT_SOURCE_IDENTITY_OUT}")"
    python3 "${SCRIPT_DIR}/ci/buildroot-patch-identity.py" metadata \
        --source-sha "$(git -C "${PROJECT_ROOT}" rev-parse HEAD)" \
        --buildroot-dir "${BUILDROOT_SOURCE_DIR}" \
        > "${SUDERRA_BUILDROOT_SOURCE_IDENTITY_OUT}"
fi

make -C "${BUILDROOT_SOURCE_DIR}" BR2_EXTERNAL="${PROJECT_ROOT}" O="${OUTPUT_DIR}" "${DEFCONFIG}"
make -C "${BUILDROOT_SOURCE_DIR}" O="${OUTPUT_DIR}"

echo ""
echo "==> Build tamamlandı"
echo "==> Output: ${OUTPUT_DIR}/images/"
ls -lh "${OUTPUT_DIR}/images/" 2>/dev/null || echo "(images dizini henüz üretilmedi)"

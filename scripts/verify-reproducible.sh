#!/usr/bin/env bash
#
# Suderra OS — Reproducible build doğrulaması
#
# İki bağımsız build çalıştırır, sonuçların SHA256 eşleşmesini kontrol eder.
# Reproducible Builds standard'ı + SLSA L3 için kritik.
#
# Kullanım:
#   ./scripts/verify-reproducible.sh suderra_qemu_x86_64_defconfig

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

DEFCONFIG="${1:?Kullanım: $0 <defconfig>}"

OUT_A="${PROJECT_ROOT}/output/${DEFCONFIG}-repro-a"
OUT_B="${PROJECT_ROOT}/output/${DEFCONFIG}-repro-b"

echo "==> Reproducible build doğrulaması: ${DEFCONFIG}"
echo "==> Build A: ${OUT_A}"
echo "==> Build B: ${OUT_B}"

# Temizle
rm -rf "${OUT_A}" "${OUT_B}"

# Build A
echo ""
echo "==> Build A başlatılıyor..."
SUDERRA_HOST_OUTPUT_DIR="${OUT_A}" "${SCRIPT_DIR}/build-in-docker.sh" "${DEFCONFIG}"

# Build B (farklı çalıştırma)
echo ""
echo "==> Build B başlatılıyor..."
SUDERRA_HOST_OUTPUT_DIR="${OUT_B}" "${SCRIPT_DIR}/build-in-docker.sh" "${DEFCONFIG}"

# Hash karşılaştırma
echo ""
echo "==> Hash karşılaştırma"

FAIL=0
COMPARE_COUNT=0
IMAGES_A="${OUT_A}/${DEFCONFIG}/images"
IMAGES_B="${OUT_B}/${DEFCONFIG}/images"
for img in \
    "${IMAGES_A}/"*.img \
    "${IMAGES_A}/"*.img.xz \
    "${IMAGES_A}/MANIFEST.txt" \
    "${IMAGES_A}/manifest.json" \
    "${IMAGES_A}/manifest.sig"; do
    [ -f "${img}" ] || continue
    COMPARE_COUNT=$((COMPARE_COUNT + 1))
    name=$(basename "${img}")
    other="${IMAGES_B}/${name}"
    if [ ! -f "${other}" ]; then
        echo "FAIL: ${name} Build B'de yok"
        FAIL=1
        continue
    fi
    HASH_A=$(sha256sum "${img}" | awk '{print $1}')
    HASH_B=$(sha256sum "${other}" | awk '{print $1}')
    if [ "${HASH_A}" = "${HASH_B}" ]; then
        echo "PASS: ${name} (${HASH_A:0:16}...)"
    else
        echo "FAIL: ${name}"
        echo "  A: ${HASH_A}"
        echo "  B: ${HASH_B}"
        # diffoscope ile detaylı diff (varsa)
        if command -v diffoscope >/dev/null 2>&1; then
            echo "==> diffoscope karşılaştırma:"
            diffoscope "${img}" "${other}" --max-report-size 100000 || true
        fi
        FAIL=1
    fi
done

if [ "${COMPARE_COUNT}" -eq 0 ]; then
    echo "FAIL: karşılaştırılacak release artifact bulunamadı (${IMAGES_A})"
    FAIL=1
fi

if [ "${FAIL}" -ne 0 ]; then
    echo ""
    echo "==> Reproducible build BAŞARISIZ"
    echo "==> Sebep araştır: SOURCE_DATE_EPOCH, locale, timestamp embed, random seed"
    exit 1
fi

echo ""
echo "==> Reproducible build BAŞARILI"

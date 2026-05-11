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

OUT_A="${PROJECT_ROOT}/output/${DEFCONFIG}-build-a"
OUT_B="${PROJECT_ROOT}/output/${DEFCONFIG}-build-b"

echo "==> Reproducible build doğrulaması: ${DEFCONFIG}"
echo "==> Build A: ${OUT_A}"
echo "==> Build B: ${OUT_B}"

# Temizle
rm -rf "${OUT_A}" "${OUT_B}"

# Build A
echo ""
echo "==> Build A başlatılıyor..."
OUTPUT_DIR="${OUT_A}" "${SCRIPT_DIR}/build-in-docker.sh" "${DEFCONFIG}"

# Build B (farklı çalıştırma)
echo ""
echo "==> Build B başlatılıyor..."
OUTPUT_DIR="${OUT_B}" "${SCRIPT_DIR}/build-in-docker.sh" "${DEFCONFIG}"

# Hash karşılaştırma
echo ""
echo "==> Hash karşılaştırma"

FAIL=0
for img in "${OUT_A}/images/"*.img; do
    [ -f "${img}" ] || continue
    name=$(basename "${img}")
    other="${OUT_B}/images/${name}"
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

if [ "${FAIL}" -ne 0 ]; then
    echo ""
    echo "==> Reproducible build BAŞARISIZ"
    echo "==> Sebep araştır: SOURCE_DATE_EPOCH, locale, timestamp embed, random seed"
    exit 1
fi

echo ""
echo "==> Reproducible build BAŞARILI"

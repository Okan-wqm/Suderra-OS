#!/usr/bin/env bash
#
# Suderra OS — CycloneDX SBOM üretimi
#
# Faz 5'te tam implementasyon. Şu an iskelet:
#   - Buildroot legal-info/manifest.csv'yi okur
#   - CycloneDX 1.5 JSON üretir
#   - Opsiyonel: SPDX 2.3 JSON üretir
#
# Kullanım:
#   ./scripts/gen-sbom.sh <defconfig>
#   ./scripts/gen-sbom.sh suderra_x86_64_defconfig

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

DEFCONFIG="${1:?Kullanım: $0 <defconfig>}"
OUTPUT_DIR="${PROJECT_ROOT}/output/${DEFCONFIG}"
MANIFEST="${OUTPUT_DIR}/legal-info/manifest.csv"
SBOM_OUT="${OUTPUT_DIR}/sbom.cyclonedx.json"
SBOM_SPDX_OUT="${OUTPUT_DIR}/sbom.spdx.json"

if [ ! -f "${MANIFEST}" ]; then
    echo "ERROR: Buildroot manifest yok: ${MANIFEST}"
    echo "Önce build edin: ./scripts/build-in-docker.sh ${DEFCONFIG}"
    exit 1
fi

# Tercih edilen araç: syft (Anchore). Eğer yoksa fallback parser.
if command -v syft >/dev/null 2>&1; then
    echo "==> syft ile SBOM üretiliyor"
    syft "${OUTPUT_DIR}/target" \
        -o "cyclonedx-json=${SBOM_OUT}" \
        -o "spdx-json=${SBOM_SPDX_OUT}"
else
    echo "==> syft yok, Buildroot manifest'ten basit dönüşüm"
    # TODO Faz 5: Python wrapper ile CycloneDX 1.5 schema'ya uygun JSON üret
    # Şu anda placeholder
    cat > "${SBOM_OUT}" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [{"vendor": "Suderra", "name": "gen-sbom.sh", "version": "0.1.0"}],
    "component": {
      "type": "operating-system",
      "name": "suderra-os",
      "version": "${SUDERRA_VERSION:-v0.1.0-alpha}"
    }
  },
  "components": []
}
EOF
    echo "WARNING: Faz 5'te detaylı SBOM üretimi eklenecek. Şu anda placeholder."
fi

echo "==> SBOM yazıldı:"
echo "    CycloneDX: ${SBOM_OUT}"
[ -f "${SBOM_SPDX_OUT}" ] && echo "    SPDX:      ${SBOM_SPDX_OUT}"

# Boyut + paket sayısı
if command -v jq >/dev/null 2>&1 && [ -f "${SBOM_OUT}" ]; then
    PKG_COUNT=$(jq '.components | length' "${SBOM_OUT}")
    echo "    Paket sayısı: ${PKG_COUNT}"
fi

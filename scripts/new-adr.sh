#!/usr/bin/env bash
#
# Suderra OS — Yeni ADR (Architecture Decision Record) şablonu oluştur
#
# Kullanım:
#   ./scripts/new-adr.sh "Karar başlığı"

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

TITLE="${1:?Kullanım: $0 \"Karar başlığı\"}"

ADR_DIR="${PROJECT_ROOT}/docs/architecture"
TEMPLATE="${ADR_DIR}/ADR-template.md"

if [ ! -f "${TEMPLATE}" ]; then
    echo "ERROR: ADR template yok: ${TEMPLATE}"
    exit 1
fi

# En son ADR numarasını bul
LAST_NUM=$(find "${ADR_DIR}" -maxdepth 1 -name 'ADR-[0-9]*.md' -type f \
    | sed -E 's/.*ADR-([0-9]+)-.*/\1/' \
    | sort -n \
    | tail -1)

NEXT_NUM=$(printf "%04d" $((10#${LAST_NUM:-0} + 1)))

# Başlığı dosya adına çevir (lowercase, kebab-case)
SLUG=$(echo "${TITLE}" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g' \
    | sed -E 's/(^-+|-+$)//g')

ADR_FILE="${ADR_DIR}/ADR-${NEXT_NUM}-${SLUG}.md"

if [ -f "${ADR_FILE}" ]; then
    echo "ERROR: ${ADR_FILE} zaten var"
    exit 1
fi

DATE=$(date +%Y-%m-%d)

# Template'i kopyala ve değişkenleri doldur
sed -e "s|^# ADR-NNNN: <Karar başlığı>|# ADR-${NEXT_NUM}: ${TITLE}|" \
    -e "s|YYYY-MM-DD|${DATE}|" \
    "${TEMPLATE}" > "${ADR_FILE}"

echo "==> Yeni ADR oluşturuldu: ${ADR_FILE}"
echo ""
echo "Sonraki adımlar:"
echo "  1. ${ADR_FILE} dosyasını düzenle"
echo "  2. PR aç"
echo "  3. CHANGELOG.md güncelle"

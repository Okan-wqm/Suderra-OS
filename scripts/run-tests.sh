#!/usr/bin/env bash
#
# Suderra OS — Tüm test suite'lerini koştur
#
# Kullanım:
#   ./scripts/run-tests.sh                   # Hepsi
#   ./scripts/run-tests.sh qemu              # Sadece QEMU
#   ./scripts/run-tests.sh security          # Sadece security
#   ./scripts/run-tests.sh installer         # Sadece USB installer

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

CATEGORY="${1:-all}"
FAILED=0

run_category() {
    local cat="$1"
    local dir="${PROJECT_ROOT}/tests/${cat}"
    if [ ! -d "${dir}" ]; then
        return
    fi
    echo "==> ${cat} testleri"
    for test in "${dir}"/*.sh; do
        [ -f "${test}" ] || continue
        echo "  - $(basename "${test}")"
        if ! bash "${test}"; then
            FAILED=1
            echo "    FAIL"
        else
            echo "    OK"
        fi
    done
}

case "${CATEGORY}" in
    all)
        run_category qemu
        run_category installer
        run_category security
        run_category ota
        ;;
    qemu|installer|security|ota)
        run_category "${CATEGORY}"
        ;;
    *)
        echo "ERROR: Bilinmeyen kategori: ${CATEGORY}"
        echo "Kullanım: $0 [all|qemu|installer|security|ota]"
        exit 1
        ;;
esac

if [ "${FAILED}" -ne 0 ]; then
    echo ""
    echo "==> Bazı testler başarısız"
    exit 1
fi

echo ""
echo "==> Tüm testler geçti"

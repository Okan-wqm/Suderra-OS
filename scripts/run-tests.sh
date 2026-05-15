#!/usr/bin/env bash
#
# Suderra OS — Tüm test suite'lerini koştur
#
# Kullanım:
#   ./scripts/run-tests.sh                   # Hepsi
#   ./scripts/run-tests.sh qemu              # Sadece QEMU
#   ./scripts/run-tests.sh security          # Sadece security
#   ./scripts/run-tests.sh installer         # Sadece USB installer
#   ./scripts/run-tests.sh image-contracts   # Build matrix/image contracts

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

CATEGORY="${1:-all}"
FAILED=0
SKIPPED=0
if [ -n "${SUDERRA_FAIL_ON_SKIP+x}" ]; then
    FAIL_ON_SKIP="${SUDERRA_FAIL_ON_SKIP}"
elif [ "${CI:-}" = "true" ]; then
    FAIL_ON_SKIP="1"
else
    FAIL_ON_SKIP="0"
fi

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
        set +e
        bash "${test}"
        status="$?"
        set -e
        case "${status}" in
            0)
                echo "    OK"
                ;;
            77)
                SKIPPED=$((SKIPPED + 1))
                if [ "${FAIL_ON_SKIP}" = "1" ]; then
                    FAILED=1
                    echo "    SKIP treated as FAIL"
                else
                    echo "    SKIP"
                fi
                ;;
            *)
                FAILED=1
                echo "    FAIL"
                ;;
        esac
    done
}

case "${CATEGORY}" in
    all)
        run_category image-contracts
        run_category qemu
        run_category installer
        run_category security
        run_category ota
        ;;
    qemu|installer|security|ota|image-contracts)
        run_category "${CATEGORY}"
        ;;
    *)
        echo "ERROR: Bilinmeyen kategori: ${CATEGORY}"
        echo "Kullanım: $0 [all|qemu|installer|security|ota|image-contracts]"
        exit 1
        ;;
esac

if [ "${FAILED}" -ne 0 ]; then
    echo ""
    echo "==> Bazı testler başarısız"
    exit 1
fi

echo ""
if [ "${SKIPPED}" -gt 0 ]; then
    echo "==> Tüm zorunlu testler geçti (${SKIPPED} skipped)"
else
    echo "==> Tüm testler geçti"
fi

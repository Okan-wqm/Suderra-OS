#!/usr/bin/env bash
#
# Suderra OS — Lokal lint (CI ile aynı kurallar)
#
# Kullanım:
#   ./scripts/lint.sh

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

cd "${PROJECT_ROOT}"

FAILED=0

# ShellCheck
if command -v shellcheck >/dev/null 2>&1; then
    echo "==> shellcheck"
    find scripts board/suderra/common tests -name '*.sh' -type f -print0 2>/dev/null \
        | xargs -0 -r shellcheck --severity=warning || FAILED=1
else
    echo "WARN: shellcheck yüklü değil, atlanıyor (apt install shellcheck)"
fi

# Markdown lint
if command -v markdownlint-cli2 >/dev/null 2>&1; then
    echo "==> markdownlint-cli2"
    markdownlint-cli2 "**/*.md" "#buildroot/**" "#output/**" "#dl/**" || FAILED=1
else
    echo "WARN: markdownlint-cli2 yüklü değil, atlanıyor"
fi

# Gitleaks (eğer kurulu ise)
if command -v gitleaks >/dev/null 2>&1; then
    echo "==> gitleaks"
    gitleaks detect --source . --no-banner || FAILED=1
else
    echo "WARN: gitleaks yüklü değil, atlanıyor"
fi

# YAML lint
if command -v yamllint >/dev/null 2>&1; then
    echo "==> yamllint"
    yamllint -c .yamllint.yml .github ci || FAILED=1
else
    echo "WARN: yamllint yüklü değil, atlanıyor (pip install yamllint)"
fi

if [ "${FAILED}" -ne 0 ]; then
    echo ""
    echo "==> Lint başarısız"
    exit 1
fi

echo ""
echo "==> Tüm lint kontrolleri geçti"

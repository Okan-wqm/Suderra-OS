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
SKIPPED=0
ALLOW_MISSING_TOOLS="${SUDERRA_LINT_ALLOW_MISSING_TOOLS:-0}"

if [ "${SUDERRA_LINT_STRICT:-1}" = "0" ]; then
    ALLOW_MISSING_TOOLS=1
fi

missing_tool() {
    tool="$1"
    install_hint="$2"
    if [ "${ALLOW_MISSING_TOOLS}" = "1" ]; then
        echo "WARN: ${tool} yüklü değil, atlanıyor (${install_hint})"
        SKIPPED=$((SKIPPED + 1))
    else
        echo "ERROR: ${tool} is required (${install_hint})"
        FAILED=1
    fi
}

echo "==> build matrix contracts"
python3 scripts/ci/validate-build-matrix.py validate || FAILED=1

if command -v actionlint >/dev/null 2>&1; then
    echo "==> actionlint"
    actionlint || FAILED=1
else
    missing_tool "actionlint" "https://github.com/rhysd/actionlint"
fi

# ShellCheck
if command -v shellcheck >/dev/null 2>&1; then
    echo "==> shellcheck"
    {
        find scripts board/suderra/common tests -name '*.sh' -type f -print 2>/dev/null
        find board/suderra/common/rootfs-overlay/usr/sbin -type f -print 2>/dev/null
        printf '%s\n' package/suderra-os-installer/suderra-os-install
    } | sort -u | xargs -r shellcheck --severity=warning || FAILED=1
else
    missing_tool "shellcheck" "apt install shellcheck"
fi

# Markdown lint
if command -v markdownlint-cli2 >/dev/null 2>&1; then
    echo "==> markdownlint-cli2"
    markdownlint-cli2 "**/*.md" "#buildroot/**" "#output/**" "#dl/**" || FAILED=1
else
    missing_tool "markdownlint-cli2" "npm install -g markdownlint-cli2"
fi

# Gitleaks (eğer kurulu ise)
if command -v gitleaks >/dev/null 2>&1; then
    echo "==> gitleaks"
    gitleaks detect --source . --no-banner || FAILED=1
else
    missing_tool "gitleaks" "https://github.com/gitleaks/gitleaks"
fi

# YAML lint
if command -v yamllint >/dev/null 2>&1; then
    echo "==> yamllint"
    yamllint -c .yamllint.yml .github ci || FAILED=1
else
    missing_tool "yamllint" "pip install yamllint"
fi

if command -v hadolint >/dev/null 2>&1; then
    echo "==> hadolint"
    hadolint ci/Dockerfile || FAILED=1
else
    missing_tool "hadolint" "https://github.com/hadolint/hadolint"
fi

if [ "${FAILED}" -ne 0 ]; then
    echo ""
    echo "==> Lint başarısız"
    exit 1
fi

echo ""
if [ "${SKIPPED}" -gt 0 ]; then
    echo "==> Lint tamamlandı (${SKIPPED} kontrol atlandı)"
else
    echo "==> Tüm lint kontrolleri geçti"
fi

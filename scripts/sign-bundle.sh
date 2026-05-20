#!/usr/bin/env bash
#
# Suderra OS — RAUC bundle imzalama + cosign artifact attestation
#
# Faz 4'te tam implementasyon. İki seviye:
#   1. RAUC native signing (X.509 + RSA-4096) — bundle içinde
#   2. Sigstore cosign signing — release artifact için (SLSA L2/L3 gereği)
#
# Kullanım:
#   ./scripts/sign-bundle.sh <bundle.raucb>

set -euo pipefail
IFS=$'\n\t'

BUNDLE="${1:?Kullanım: $0 <bundle.raucb>}"
KEYS_DIR="${SUDERRA_TRUST_ROOTS_DIR:-${SUDERRA_KEYS_DIR:-${HOME}/.suderra-keys/dev}}"
PROD_MODE=0
if [ "${SUDERRA_SIGNING_MODE:-}" = "prod" ] || [ "${SUDERRA_RELEASE_TIER:-}" = "production" ]; then
    PROD_MODE=1
fi

warn_or_fail() {
    if [ "${PROD_MODE}" -eq 1 ]; then
        echo "ERROR: $*" >&2
        exit 1
    fi
    echo "WARNING: $*" >&2
}

if [ ! -f "${BUNDLE}" ]; then
    echo "ERROR: Bundle yok: ${BUNDLE}"
    exit 1
fi

if [ "${PROD_MODE}" -eq 1 ]; then
    if [ -f "${KEYS_DIR}/rauc-signing.key" ] || [ -f "${KEYS_DIR}/cosign.key" ]; then
        echo "ERROR: production signing rejects file-backed private keys; use PKCS#11/HSM provider evidence" >&2
        exit 1
    fi
    if [ -z "${SUDERRA_RAUC_PKCS11_URI:-}" ]; then
        echo "ERROR: production signing requires SUDERRA_RAUC_PKCS11_URI" >&2
        exit 1
    fi
    echo "ERROR: production PKCS#11 RAUC signing provider is not implemented yet" >&2
    exit 1
fi

# 1. RAUC re-sign (eğer bundle henüz imzasız ise)
if [ -f "${KEYS_DIR}/rauc-signing.key" ]; then
    RAUC_READY=1
    if [ ! -f "${KEYS_DIR}/rauc-signing.crt" ]; then
        warn_or_fail "RAUC signing cert yok: ${KEYS_DIR}/rauc-signing.crt"
        RAUC_READY=0
    fi
    if ! command -v rauc >/dev/null 2>&1; then
        warn_or_fail "rauc yüklü değil"
        RAUC_READY=0
    fi
    if [ "${RAUC_READY}" -eq 1 ]; then
        echo "==> RAUC bundle imzalama: ${BUNDLE}"
        # rauc bundle resign zaten imzalı bundle'ı yeniden imzalar
        rauc resign \
            --cert="${KEYS_DIR}/rauc-signing.crt" \
            --key="${KEYS_DIR}/rauc-signing.key" \
            "${BUNDLE}" \
            "${BUNDLE}.signed"
        mv "${BUNDLE}.signed" "${BUNDLE}"
    fi
else
    warn_or_fail "RAUC signing key yok: ${KEYS_DIR}/rauc-signing.key"
fi

# 2. Cosign signing (SLSA Level 2+)
# Üretimde keyless OIDC + Sigstore transparency log kullanılır
if command -v cosign >/dev/null 2>&1; then
    echo "==> Cosign artifact signing: ${BUNDLE}"
    # Keyless (OIDC) — CI ortamında
    if [ "${CI:-false}" = "true" ]; then
        cosign sign-blob \
            --yes \
            --output-signature="${BUNDLE}.sig" \
            --output-certificate="${BUNDLE}.cert" \
            "${BUNDLE}"
    else
        # Lokal (key-based, dev)
        if [ -f "${KEYS_DIR}/cosign.key" ]; then
            cosign sign-blob \
                --yes \
                --key="${KEYS_DIR}/cosign.key" \
                --output-signature="${BUNDLE}.sig" \
                "${BUNDLE}"
        else
            warn_or_fail "cosign.key yok, atlıyor"
        fi
    fi
else
    warn_or_fail "cosign yüklü değil (https://docs.sigstore.dev/cosign/installation/)"
fi

echo "==> İmzalama tamamlandı: ${BUNDLE}"
ls -lh "${BUNDLE}"* 2>/dev/null || true

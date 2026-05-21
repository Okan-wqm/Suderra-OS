#!/usr/bin/env bash
#
# Suderra OS — RAUC bundle imzalama + cosign artifact attestation
#
# İki seviye:
#   1. RAUC native signing (X.509 + RSA-4096 veya PKCS#11 URI) — bundle içinde
#   2. Sigstore cosign signing — release artifact için (SLSA L2/L3 gereği)
#
# Kullanım:
#   ./scripts/sign-bundle.sh <bundle.raucb>

set -euo pipefail
IFS=$'\n\t'

BUNDLE="${1:?Kullanım: $0 <bundle.raucb>}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
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

resolve_rauc() {
    if [ -n "${SUDERRA_RAUC:-}" ]; then
        if [ ! -x "${SUDERRA_RAUC}" ]; then
            echo "ERROR: SUDERRA_RAUC executable değil: ${SUDERRA_RAUC}" >&2
            exit 1
        fi
        printf '%s\n' "${SUDERRA_RAUC}"
        return 0
    fi
    if [ -n "${HOST_DIR:-}" ] && [ -x "${HOST_DIR}/bin/rauc" ]; then
        printf '%s\n' "${HOST_DIR}/bin/rauc"
        return 0
    fi
    if command -v rauc >/dev/null 2>&1; then
        command -v rauc
        return 0
    fi
    return 1
}

production_signing_evidence() {
    local evidence="${SUDERRA_HSM_SIGNING_EVIDENCE:-}"
    if [ -z "${evidence}" ] || [ ! -s "${evidence}" ]; then
        echo "ERROR: production signing requires SUDERRA_HSM_SIGNING_EVIDENCE" >&2
        exit 1
    fi
    python3 "${SCRIPT_DIR}/evidence/validate-hsm-signing-evidence.py" validate \
        "${evidence}" \
        --pkcs11-uri "${SUDERRA_RAUC_PKCS11_URI}" \
        --certificate "${SUDERRA_RAUC_SIGNING_CERT}" \
        --artifact-role "rauc-bundle" \
        --artifact-sha256 "$(sha256sum "${BUNDLE}" | awk '{print $1}')" \
        --require-production \
        >/dev/null
}

require_pkcs11_key_uri() {
    local uri="$1"
    case "${uri}" in
        pkcs11:*object=*|pkcs11:*id=*)
            ;;
        pkcs11:*)
            echo "ERROR: production signing PKCS#11 URI must identify a key with object= or id=" >&2
            exit 1
            ;;
        *)
            echo "ERROR: production signing requires a pkcs11: URI" >&2
            exit 1
            ;;
    esac
}

if [ "${PROD_MODE}" -eq 1 ]; then
    if [ -f "${KEYS_DIR}/rauc-signing.key" ] || [ -f "${KEYS_DIR}/cosign.key" ]; then
        echo "ERROR: production signing rejects file-backed private keys; use PKCS#11/HSM provider evidence" >&2
        exit 1
    fi
    if [ -z "${SUDERRA_RAUC_PKCS11_URI:-}" ]; then
        echo "ERROR: production signing requires SUDERRA_RAUC_PKCS11_URI" >&2
        exit 1
    fi
    require_pkcs11_key_uri "${SUDERRA_RAUC_PKCS11_URI}"
    if [ -z "${SUDERRA_RAUC_SIGNING_CERT:-}" ] || [ ! -s "${SUDERRA_RAUC_SIGNING_CERT}" ]; then
        echo "ERROR: production signing requires SUDERRA_RAUC_SIGNING_CERT" >&2
        exit 1
    fi
    if [ -z "${SUDERRA_RAUC_KEYRING:-}" ] || [ ! -s "${SUDERRA_RAUC_KEYRING}" ]; then
        echo "ERROR: production signing requires SUDERRA_RAUC_KEYRING to verify device trust" >&2
        exit 1
    fi
    RAUC_TOOL="$(resolve_rauc)" || {
        echo "ERROR: production signing requires rauc host tool" >&2
        exit 1
    }
    production_signing_evidence
    echo "==> RAUC bundle HSM/PKCS#11 imzalama: ${BUNDLE}"
    "${RAUC_TOOL}" resign \
        --cert="${SUDERRA_RAUC_SIGNING_CERT}" \
        --key="${SUDERRA_RAUC_PKCS11_URI}" \
        "${BUNDLE}" \
        "${BUNDLE}.signed"
    mv "${BUNDLE}.signed" "${BUNDLE}"
    "${RAUC_TOOL}" info --keyring="${SUDERRA_RAUC_KEYRING}" "${BUNDLE}" >/dev/null
fi

# 1. RAUC re-sign (eğer bundle henüz imzasız ise)
if [ "${PROD_MODE}" -eq 0 ] && [ -f "${KEYS_DIR}/rauc-signing.key" ]; then
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
elif [ "${PROD_MODE}" -eq 0 ]; then
    warn_or_fail "RAUC signing key yok: ${KEYS_DIR}/rauc-signing.key"
fi

# 2. Cosign signing (SLSA Level 2+)
# Üretimde keyless OIDC + Sigstore transparency log kullanılır. Key-based
# cosign only dev mode is allowed.
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

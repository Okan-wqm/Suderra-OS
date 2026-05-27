#!/usr/bin/env bash
#
# Validate a Suderra trust-root keyring before expensive image builds.

set -euo pipefail
IFS=$'\n\t'

usage() {
    cat >&2 <<EOF
Usage: $0 <keyring-dir> [--expected-profile <ci|dev|prod>] [--require-installer-signing] [--forbid-installer-signing] [--check-installer-env]
EOF
}

KEYS_DIR="${1:-}"
if [ -z "${KEYS_DIR}" ]; then
    usage
    exit 2
fi
shift

EXPECTED_PROFILE=""
REQUIRE_INSTALLER_SIGNING=0
FORBID_INSTALLER_SIGNING=0
CHECK_INSTALLER_ENV=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --expected-profile)
            [ "$#" -ge 2 ] || {
                usage
                exit 2
            }
            EXPECTED_PROFILE="$2"
            shift
            ;;
        --require-installer-signing)
            REQUIRE_INSTALLER_SIGNING=1
            ;;
        --forbid-installer-signing)
            FORBID_INSTALLER_SIGNING=1
            ;;
        --check-installer-env)
            CHECK_INSTALLER_ENV=1
            ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

if [ "${REQUIRE_INSTALLER_SIGNING}" -eq 1 ] && [ "${FORBID_INSTALLER_SIGNING}" -eq 1 ]; then
    usage
    exit 2
fi

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_file() {
    local path="$1"
    [ -e "${path}" ] || die "required Suderra trust-root file missing: ${path}"
    [ -f "${path}" ] || die "required Suderra trust-root path is not a regular file: ${path}"
    [ -r "${path}" ] || die "required Suderra trust-root file is not readable: ${path}"
    [ -s "${path}" ] || die "required Suderra trust-root file is empty: ${path}"
}

validate_raw_ed25519_public_key() {
    local path="$1"
    local bytes

    require_file "${path}"
    bytes="$(wc -c < "${path}" | tr -d ' ')"
    if [ "${bytes}" = "32" ]; then
        return 0
    fi
    if [ "${bytes}" = "64" ] && LC_ALL=C grep -Eq '^[0-9a-fA-F]{64}$' "${path}"; then
        return 0
    fi
    die "invalid raw/hex Ed25519 public key: ${path}"
}

[ -d "${KEYS_DIR}" ] || die "Suderra trust-root directory does not exist: ${KEYS_DIR}"
[ -x "${KEYS_DIR}" ] || die "Suderra trust-root directory is not traversable: ${KEYS_DIR}"

for required in \
    suderra-keys.profile \
    rauc-signing.crt \
    verity-signing.crt \
    installer-payload.ed25519.pub \
    os-update-manifest.ed25519.pub \
    edge-artifact.ed25519.pub; do
    require_file "${KEYS_DIR}/${required}"
done

profile="$(cat "${KEYS_DIR}/suderra-keys.profile")"
case "${profile}" in
    ci|dev|prod) ;;
    *) die "suderra-keys.profile must be one of ci, dev, prod; got '${profile}'" ;;
esac
if [ -n "${EXPECTED_PROFILE}" ] && [ "${profile}" != "${EXPECTED_PROFILE}" ]; then
    die "suderra-keys.profile contains '${profile}', expected '${EXPECTED_PROFILE}'"
fi

if command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "${KEYS_DIR}/rauc-signing.crt" -noout >/dev/null 2>&1 ||
        die "invalid X.509 certificate: ${KEYS_DIR}/rauc-signing.crt"
    openssl x509 -in "${KEYS_DIR}/verity-signing.crt" -noout >/dev/null 2>&1 ||
        die "invalid X.509 certificate: ${KEYS_DIR}/verity-signing.crt"
    openssl pkey -pubin -in "${KEYS_DIR}/installer-payload.ed25519.pub" -noout >/dev/null 2>&1 ||
        die "invalid Ed25519 public key: ${KEYS_DIR}/installer-payload.ed25519.pub"
    openssl pkey -pubin -in "${KEYS_DIR}/edge-artifact.ed25519.pub" -noout >/dev/null 2>&1 ||
        die "invalid Ed25519 public key: ${KEYS_DIR}/edge-artifact.ed25519.pub"
fi
validate_raw_ed25519_public_key "${KEYS_DIR}/os-update-manifest.ed25519.pub"

if [ "${REQUIRE_INSTALLER_SIGNING}" -eq 1 ]; then
    require_file "${KEYS_DIR}/installer-payload.key"
    if command -v openssl >/dev/null 2>&1; then
        openssl pkey -in "${KEYS_DIR}/installer-payload.key" -noout >/dev/null 2>&1 ||
            die "invalid Ed25519 private key: ${KEYS_DIR}/installer-payload.key"
    fi
fi

if [ "${FORBID_INSTALLER_SIGNING}" -eq 1 ]; then
    if [ -e "${KEYS_DIR}/installer-payload.key" ]; then
        die "installer payload private key is forbidden in this trust-root set: ${KEYS_DIR}/installer-payload.key"
    fi
    if find "${KEYS_DIR}" -maxdepth 1 -type f -name '*.key' | grep -q .; then
        die "private key files are forbidden in this trust-root set"
    fi
fi

if [ "${CHECK_INSTALLER_ENV}" -eq 1 ]; then
    if [ -n "${SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY:-}" ]; then
        require_file "${SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY}"
        if command -v openssl >/dev/null 2>&1; then
            openssl pkey -in "${SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY}" -noout >/dev/null 2>&1 ||
                die "invalid installer payload signing key: ${SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY}"
        fi
    fi
    if [ -n "${SUDERRA_INSTALLER_PAYLOAD_PUBKEY:-}" ]; then
        require_file "${SUDERRA_INSTALLER_PAYLOAD_PUBKEY}"
        if command -v openssl >/dev/null 2>&1; then
            openssl pkey -pubin -in "${SUDERRA_INSTALLER_PAYLOAD_PUBKEY}" -noout >/dev/null 2>&1 ||
                die "invalid installer payload public key: ${SUDERRA_INSTALLER_PAYLOAD_PUBKEY}"
        fi
    fi
fi

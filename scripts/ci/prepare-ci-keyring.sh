#!/usr/bin/env bash
#
# Generate an ephemeral CI/lab Suderra trust-root set.
#
# This script intentionally refuses to create production-profiled material.
# Production keys must come from the external signing/HSM path; CI keys exist
# only to build dev/lab artifacts that exercise the trust-root plumbing.

set -euo pipefail
IFS=$'\n\t'

KEYS_DIR="${1:?Usage: $0 <keys-dir> [profile]}"
PROFILE="${2:-ci}"

if [ "${PROFILE}" = "prod" ]; then
    echo "ERROR: prepare-ci-keyring.sh may not generate prod-profiled keys." >&2
    exit 1
fi

mkdir -p "${KEYS_DIR}"

profile_file="${KEYS_DIR}/suderra-keys.profile"
if [ -s "${profile_file}" ]; then
    existing_profile="$(cat "${profile_file}")"
    if [ "${existing_profile}" != "${PROFILE}" ]; then
        echo "ERROR: ${profile_file} contains '${existing_profile}', expected '${PROFILE}'." >&2
        exit 1
    fi
fi
printf '%s\n' "${PROFILE}" > "${profile_file}"

generate_cert() {
    local key_path="$1"
    local cert_path="$2"
    local bits="$3"
    local subject="$4"

    if [ -s "${key_path}" ] && [ -s "${cert_path}" ]; then
        return 0
    fi

    openssl req -newkey "rsa:${bits}" -nodes \
        -keyout "${key_path}" \
        -x509 -sha256 -days 14 \
        -out "${cert_path}" \
        -subj "${subject}" >/dev/null 2>&1
}

generate_ed25519() {
    local key_path="$1"
    local pub_path="$2"

    if [ ! -s "${key_path}" ]; then
        openssl genpkey -algorithm ED25519 -out "${key_path}" >/dev/null 2>&1
    fi
    openssl pkey -in "${key_path}" -pubout -out "${pub_path}" >/dev/null 2>&1
}

generate_cert \
    "${KEYS_DIR}/rauc-signing.key" \
    "${KEYS_DIR}/rauc-signing.crt" \
    4096 \
    "/CN=Suderra CI RAUC/"

generate_cert \
    "${KEYS_DIR}/verity-signing.key" \
    "${KEYS_DIR}/verity-signing.crt" \
    3072 \
    "/CN=Suderra CI Verity/"

generate_ed25519 \
    "${KEYS_DIR}/installer-payload.key" \
    "${KEYS_DIR}/installer-payload.ed25519.pub"

generate_ed25519 \
    "${KEYS_DIR}/edge-artifact.key" \
    "${KEYS_DIR}/edge-artifact.ed25519.pub"

chmod 0600 "${KEYS_DIR}"/*.key
chmod 0644 "${KEYS_DIR}"/*.crt "${KEYS_DIR}"/*.pub "${profile_file}"

for required in \
    rauc-signing.crt \
    verity-signing.crt \
    installer-payload.ed25519.pub \
    edge-artifact.ed25519.pub; do
    if [ ! -s "${KEYS_DIR}/${required}" ]; then
        echo "ERROR: failed to create ${KEYS_DIR}/${required}" >&2
        exit 1
    fi
done

echo "Prepared ${PROFILE} Suderra CI keyring: ${KEYS_DIR}"

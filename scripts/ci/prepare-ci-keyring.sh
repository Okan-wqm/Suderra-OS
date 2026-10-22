#!/usr/bin/env bash
#
# Materialize an ephemeral CI/lab Suderra trust-root set.
#
# Production keys must come from the external signing/HSM path. CI keys exist
# only to build dev/lab artifacts and to exercise trust-root plumbing.
#
# Edge keys (ADR-048 DEC-3.9): one Ed25519 key per purpose and epoch, a CI
# fleet-root, the CI MQTT test-broker CA and the CI trust-anchor bundle signed
# by that fleet-root, under <keys-dir>/edge/ (scripts/ci/edge-dev-keys.py).
# They are never the contract's TEST-ONLY keys.

set -euo pipefail
IFS=$'\n\t'

usage() {
    cat >&2 <<EOF
Usage: $0 <keys-dir> [profile] [--installer-public-only|--installer-private-required]

Environment:
  SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64   Base64 PEM public key for public-only/base jobs.
  SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64  Base64 PEM private key for payload signing jobs.
  SUDERRA_EDGE_TENANT_IDS                       Comma-separated tenant UUIDs of the CI
                                                trust-anchor bundle's tenant_scope (default:
                                                kept from an existing bundle, else one random).
EOF
}

KEYS_DIR="${1:-}"
if [ -z "${KEYS_DIR}" ]; then
    usage
    exit 2
fi
shift

PROFILE="ci"
if [ "$#" -gt 0 ]; then
    case "$1" in
        --*)
            ;;
        *)
            PROFILE="$1"
            shift
            ;;
    esac
fi

INSTALLER_MODE="ephemeral"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --installer-public-only)
            INSTALLER_MODE="public-only"
            ;;
        --installer-private-required)
            INSTALLER_MODE="private-required"
            ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

if [ "${PROFILE}" = "prod" ]; then
    echo "ERROR: prepare-ci-keyring.sh may not generate prod-profiled keys." >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

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

decode_b64() {
    local name="$1"
    local output="$2"
    local value="${!name:-}"

    if [ -z "${value}" ]; then
        echo "ERROR: ${name} must be set." >&2
        exit 1
    fi
    if ! printf '%s' "${value}" | base64 -d > "${output}" 2>/dev/null; then
        echo "ERROR: ${name} is not valid base64." >&2
        exit 1
    fi
}

generate_cert() {
    local key_path="$1"
    local cert_path="$2"
    local bits="$3"
    local subject="$4"

    if [ -s "${cert_path}" ]; then
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

generate_raw_ed25519_public_hex() {
    local key_path="$1"
    local pub_path="$2"

    if [ ! -s "${key_path}" ]; then
        openssl genpkey -algorithm ED25519 -out "${key_path}" >/dev/null 2>&1
    fi
    openssl pkey -in "${key_path}" -pubout -outform DER 2>/dev/null |
        tail -c 32 |
        od -An -tx1 -v |
        tr -d ' \n' > "${pub_path}"
}

canonicalize_public_key() {
    local input="$1"
    local output="$2"

    openssl pkey -pubin -in "${input}" -pubout -out "${output}" >/dev/null 2>&1
}

materialize_installer_public() {
    local encoded="${TMPDIR}/installer-payload.input.pub"

    decode_b64 SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64 "${encoded}"
    canonicalize_public_key "${encoded}" "${KEYS_DIR}/installer-payload.ed25519.pub" || {
        echo "ERROR: SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64 is not a valid PEM public key." >&2
        exit 1
    }
}

materialize_installer_private() {
    local expected="${TMPDIR}/installer-payload.expected.pub"

    decode_b64 SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64 "${KEYS_DIR}/installer-payload.key"
    chmod 0600 "${KEYS_DIR}/installer-payload.key"
    if ! openssl pkey -in "${KEYS_DIR}/installer-payload.key" -noout >/dev/null 2>&1; then
        echo "ERROR: SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64 is not a valid PEM private key." >&2
        exit 1
    fi
    openssl pkey -in "${KEYS_DIR}/installer-payload.key" -pubout \
        -out "${KEYS_DIR}/installer-payload.ed25519.pub" >/dev/null 2>&1

    if [ -n "${SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64:-}" ]; then
        decode_b64 SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64 "${expected}.input"
        canonicalize_public_key "${expected}.input" "${expected}" || {
            echo "ERROR: SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64 is not a valid PEM public key." >&2
            exit 1
        }
        if ! cmp -s "${expected}" "${KEYS_DIR}/installer-payload.ed25519.pub"; then
            echo "ERROR: configured installer payload public key does not match private signing key." >&2
            exit 1
        fi
    fi
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

# The escrow key of the /data recovery keys (ADR-048 DEC-14.3): CI images only
# need the public half; a public-only set loses the private one below.
if [ ! -s "${KEYS_DIR}/recovery-escrow.key" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
        -out "${KEYS_DIR}/recovery-escrow.key" >/dev/null 2>&1
fi
openssl pkey -in "${KEYS_DIR}/recovery-escrow.key" -pubout \
    -out "${KEYS_DIR}/recovery-escrow.pub.pem" >/dev/null 2>&1

case "${INSTALLER_MODE}" in
    ephemeral)
        generate_ed25519 \
            "${KEYS_DIR}/installer-payload.key" \
            "${KEYS_DIR}/installer-payload.ed25519.pub"
        ;;
    public-only)
        materialize_installer_public
        ;;
    private-required)
        materialize_installer_private
        ;;
esac

edge_args=(generate --keys-dir "${KEYS_DIR}" --profile "${PROFILE}" --days 14)
IFS=',' read -r -a edge_tenants <<<"${SUDERRA_EDGE_TENANT_IDS:-}"
for tenant in "${edge_tenants[@]}"; do
    [ -n "${tenant}" ] && edge_args+=(--tenant-id "${tenant}")
done
python3 -I "${SCRIPT_DIR}/edge-dev-keys.py" "${edge_args[@]}"

generate_raw_ed25519_public_hex \
    "${KEYS_DIR}/os-update-manifest.key" \
    "${KEYS_DIR}/os-update-manifest.ed25519.pub"

if [ "${INSTALLER_MODE}" = "public-only" ]; then
    find "${KEYS_DIR}" -type f -name '*.key' -delete
elif compgen -G "${KEYS_DIR}/*.key" >/dev/null; then
    chmod 0600 "${KEYS_DIR}"/*.key
fi
chmod 0644 "${KEYS_DIR}"/*.crt "${KEYS_DIR}"/*.pub "${KEYS_DIR}/recovery-escrow.pub.pem" "${profile_file}"
edge_verify=(verify --keys-dir "${KEYS_DIR}")
[ "${INSTALLER_MODE}" = "public-only" ] && edge_verify+=(--public-only)
python3 -I "${SCRIPT_DIR}/edge-dev-keys.py" "${edge_verify[@]}"

for required in \
    rauc-signing.crt \
    verity-signing.crt \
    installer-payload.ed25519.pub \
    os-update-manifest.ed25519.pub \
    recovery-escrow.pub.pem \
    edge/trust-anchors.dsse.json; do
    if [ ! -s "${KEYS_DIR}/${required}" ]; then
        echo "ERROR: failed to create ${KEYS_DIR}/${required}" >&2
        exit 1
    fi
done

if [ "${INSTALLER_MODE}" = "public-only" ] && find "${KEYS_DIR}" -type f -name '*.key' | grep -q .; then
    echo "ERROR: public-only installer keyring contains private keys." >&2
    exit 1
fi

echo "Prepared ${PROFILE} Suderra CI keyring (${INSTALLER_MODE}): ${KEYS_DIR}"

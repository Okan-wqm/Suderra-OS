#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

KEYS_DIR="${TMPDIR}/keys"

"${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null
"${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${KEYS_DIR}" --expected-profile ci --require-installer-signing

for required in \
    suderra-keys.profile \
    rauc-signing.crt \
    verity-signing.crt \
    installer-payload.key \
    installer-payload.ed25519.pub \
    os-update-manifest.key \
    os-update-manifest.ed25519.pub \
    edge-artifact.key \
    edge-artifact.ed25519.pub; do
    test -s "${KEYS_DIR}/${required}"
done

grep -qx 'ci' "${KEYS_DIR}/suderra-keys.profile"
openssl x509 -in "${KEYS_DIR}/rauc-signing.crt" -noout -subject | grep -q 'Suderra CI RAUC'
openssl x509 -in "${KEYS_DIR}/verity-signing.crt" -noout -subject | grep -q 'Suderra CI Verity'
test "$(stat -c '%a' "${KEYS_DIR}/installer-payload.key")" = "600"
test "$(stat -c '%a' "${KEYS_DIR}/os-update-manifest.key")" = "600"
test "$(stat -c '%a' "${KEYS_DIR}/edge-artifact.key")" = "600"
grep -Eq '^[0-9a-f]{64}$' "${KEYS_DIR}/os-update-manifest.ed25519.pub"

if "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${TMPDIR}/prod" prod >/dev/null 2>&1; then
    echo "prepare-ci-keyring.sh unexpectedly generated prod keys" >&2
    exit 1
fi

PUBLIC_PRIVATE_DIR="${TMPDIR}/public-private"
PUBLIC_ONLY_DIR="${TMPDIR}/public-only"
PRIVATE_ONLY_DIR="${TMPDIR}/private-required"
MISMATCH_DIR="${TMPDIR}/mismatch"
mkdir -p "${PUBLIC_PRIVATE_DIR}"
openssl genpkey -algorithm ED25519 -out "${PUBLIC_PRIVATE_DIR}/installer-payload.key" >/dev/null 2>&1
openssl pkey -in "${PUBLIC_PRIVATE_DIR}/installer-payload.key" -pubout \
    -out "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub" >/dev/null 2>&1
PUBLIC_B64="$(base64 -w0 "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub")"
PRIVATE_B64="$(base64 -w0 "${PUBLIC_PRIVATE_DIR}/installer-payload.key")"

SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64="${PUBLIC_B64}" \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${PUBLIC_ONLY_DIR}" ci --installer-public-only >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${PUBLIC_ONLY_DIR}" --expected-profile ci --forbid-installer-signing
test -s "${PUBLIC_ONLY_DIR}/installer-payload.ed25519.pub"
test -s "${PUBLIC_ONLY_DIR}/os-update-manifest.ed25519.pub"
if find "${PUBLIC_ONLY_DIR}" -maxdepth 1 -type f -name '*.key' | grep -q .; then
    echo "prepare-ci-keyring.sh public-only mode wrote private key material" >&2
    exit 1
fi
cmp -s "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub" "${PUBLIC_ONLY_DIR}/installer-payload.ed25519.pub"

SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64="${PUBLIC_B64}" \
SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64="${PRIVATE_B64}" \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${PRIVATE_ONLY_DIR}" ci --installer-private-required >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${PRIVATE_ONLY_DIR}" --expected-profile ci --require-installer-signing
cmp -s "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub" "${PRIVATE_ONLY_DIR}/installer-payload.ed25519.pub"
grep -Eq '^[0-9a-f]{64}$' "${PRIVATE_ONLY_DIR}/os-update-manifest.ed25519.pub"

openssl genpkey -algorithm ED25519 -out "${TMPDIR}/wrong-installer-payload.key" >/dev/null 2>&1
WRONG_PRIVATE_B64="$(base64 -w0 "${TMPDIR}/wrong-installer-payload.key")"
if SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64="${PUBLIC_B64}" \
    SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64="${WRONG_PRIVATE_B64}" \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${MISMATCH_DIR}" ci --installer-private-required \
        >/dev/null 2>"${TMPDIR}/mismatch.err"; then
    echo "prepare-ci-keyring.sh accepted mismatched installer payload keys" >&2
    exit 1
fi
grep -q 'does not match private signing key' "${TMPDIR}/mismatch.err"

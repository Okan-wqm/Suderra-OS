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
    edge-artifact.key \
    edge-artifact.ed25519.pub; do
    test -s "${KEYS_DIR}/${required}"
done

grep -qx 'ci' "${KEYS_DIR}/suderra-keys.profile"
openssl x509 -in "${KEYS_DIR}/rauc-signing.crt" -noout -subject | grep -q 'Suderra CI RAUC'
openssl x509 -in "${KEYS_DIR}/verity-signing.crt" -noout -subject | grep -q 'Suderra CI Verity'
test "$(stat -c '%a' "${KEYS_DIR}/installer-payload.key")" = "600"
test "$(stat -c '%a' "${KEYS_DIR}/edge-artifact.key")" = "600"

if "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${TMPDIR}/prod" prod >/dev/null 2>&1; then
    echo "prepare-ci-keyring.sh unexpectedly generated prod keys" >&2
    exit 1
fi

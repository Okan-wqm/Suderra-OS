#!/usr/bin/env bash
#
# No image may trust the Suderra edge contract's TEST-ONLY keys (ADR-048 DEC-3.9,
# DEC-25.1, Suderra-OS ADR-0008).
#
# The vendored contract signs its fixtures with Ed25519 keys anyone can derive
# from published seed labels. Dev and CI images pin the keys of
# scripts/gen-dev-keys.sh and scripts/ci/prepare-ci-keyring.sh instead, so the
# contract keys must appear nowhere an image could pick them up:
#   1. no tracked file outside contracts/suderra-edge/ (board overlays, package
#      inputs, key-generation scripts, signer configs) holds their material;
#   2. package/suderra-keys runs the same deny-list over SUDERRA_TRUST_ROOTS_DIR
#      before it installs any key, so a build fails instead of pinning one;
#   3. any built rootfs under output/*/target is clean;
#   4. the checker really refuses a planted key (self-test).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="${ROOT}/scripts/ci/check-no-contract-test-keys.py"
KEYS_MK="${ROOT}/package/suderra-keys/suderra-keys.mk"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECKER}" ] || fail "missing scripts/ci/check-no-contract-test-keys.py"

python3 -B "${CHECKER}" --repo || fail "contract TEST-ONLY key material in a tracked file"

grep -qE 'check-no-contract-test-keys\.py --tree "\$\(SUDERRA_TRUST_ROOTS_DIR\)"' "${KEYS_MK}" \
    || fail "package/suderra-keys must run check-no-contract-test-keys.py --tree on SUDERRA_TRUST_ROOTS_DIR"
guard_line="$(grep -n 'check-no-contract-test-keys\.py' "${KEYS_MK}" | head -n1 | cut -d: -f1)"
install_line="$(grep -n '\$(INSTALL)' "${KEYS_MK}" | head -n1 | cut -d: -f1)"
[ "${guard_line}" -lt "${install_line}" ] \
    || fail "package/suderra-keys installs a key before the TEST-ONLY deny-list runs"

shopt -s nullglob
for target in "${ROOT}"/output/*/target; do
    python3 -B "${CHECKER}" --tree "${target}" \
        || fail "built rootfs ${target#"${ROOT}"/} contains contract TEST-ONLY key material"
done
shopt -u nullglob

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
python3 -B - "${ROOT}" "${TMP}" <<'PY'
import base64
import json
import sys
from pathlib import Path

root, out = Path(sys.argv[1]), Path(sys.argv[2])
keyring = sorted((root / "contracts/suderra-edge").glob("v*/test-keys/keyring.json"))[-1]
key = json.loads(keyring.read_text(encoding="utf-8"))["keys"][0]
spki = bytes.fromhex("302a300506032b6570032100") + base64.b64decode(key["public_key"])
pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode() + "\n-----END PUBLIC KEY-----\n"
(out / "edge-release").mkdir()
(out / "edge-release" / "1.pub").write_text(pem, encoding="ascii")
PY
if python3 -B "${CHECKER}" --tree "${TMP}" 2>/dev/null; then
    fail "the checker accepted a planted contract TEST-ONLY key"
fi

echo "contracts-test-keys-not-pinned: no contract TEST-ONLY key outside contracts/suderra-edge/, suderra-keys refuses them"

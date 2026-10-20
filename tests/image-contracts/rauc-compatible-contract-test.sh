#!/usr/bin/env bash
#
# One RAUC compatible per board (ADR-048 DEC-8.3; EI-045).
#
# boards.json rauc_compatible is the vocabulary. The OTA target contract
# (ci/evidence-contract.yml) must carry exactly that value for every board
# image; post-build.sh writes it into /etc/rauc/system.conf and the bundle
# tool signs it into every bundle, so neither keeps a literal of its own.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/scripts/ci/rauc-compatible.py"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

python3 -I "${TOOL}" --root "${ROOT}" check

# Device side: both system.conf variants carry only the placeholder.
for conf in system.conf system.conf.arm; do
    f="${ROOT}/package/suderra-rauc-config/${conf}"
    [ "$(grep -c '^compatible=' "${f}")" -eq 1 ] || fail "${conf} must have exactly one compatible line"
    grep -qx 'compatible=@SUDERRA_RAUC_COMPATIBLE@' "${f}" ||
        fail "${conf} must take its compatible from post-build (placeholder), not a literal"
done
grep -q 'scripts/ci/rauc-compatible.py' "${ROOT}/board/suderra/common/post-build.sh" ||
    fail "post-build.sh must fill the RAUC compatible through scripts/ci/rauc-compatible.py"

# Bundle side: the compatible is an argument from the OTA target contract.
CRB="${ROOT}/scripts/create-rauc-bundle.sh"
if grep -nE '^compatible=[a-z]' "${CRB}"; then
    fail "create-rauc-bundle.sh must not hard-code a compatible"
fi
# shellcheck disable=SC2016 # the literal text ${compatible} is what is matched
[ "$(grep -c '^compatible=\${compatible}$' "${CRB}")" -eq 2 ] ||
    fail "both bundle manifests must use the compatible argument"
grep -q 'policy\["compatible"\]' "${ROOT}/scripts/evidence/produce-ota-artifacts.py" ||
    fail "produce-ota-artifacts.py must pass the OTA target's compatible to the bundle tool"
if bash "${CRB}" x86 /nonexistent 1.0.0 /tmp/x.raucb >/dev/null 2>&1; then
    fail "create-rauc-bundle.sh accepted a call without a compatible"
fi
out="$(SUDERRA_RAUC_SIGNING_KEY=/nonexistent SUDERRA_RAUC_SIGNING_CERT=/nonexistent \
    bash "${CRB}" arm /nonexistent 1.0.0 /tmp/x.raucb 'suderra-os-aarch64;x' 2>&1 || true)"
grep -q 'unsupported characters' <<<"${out}" || fail "create-rauc-bundle.sh accepted a malformed compatible"

# Each mutation of the contract on a scratch copy is rejected.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
fresh_copy() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree/contracts/suderra-edge/v1" "${WORK}/tree/ci"
    cp "${ROOT}/contracts/suderra-edge/v1/boards.json" "${WORK}/tree/contracts/suderra-edge/v1/"
    cp "${ROOT}/ci/evidence-contract.yml" "${WORK}/tree/ci/"
}
set_compatible() {
    python3 -I - "${WORK}/tree/ci/evidence-contract.yml" "$1" "$2" <<'PY'
import json, sys
path, target, value = sys.argv[1:]
data = json.load(open(path, encoding="utf-8"))
data["ota"]["targets"][target]["compatible"] = value
json.dump(data, open(path, "w", encoding="utf-8"), indent=2)
PY
}
expect_fail() {
    local label="$1" pattern="$2"
    shift 2
    local out
    if out="$("$@" 2>&1)"; then
        fail "${label}: accepted"
    fi
    grep -q -- "${pattern}" <<<"${out}" || { echo "${out}" >&2; fail "${label}: wrong reason"; }
    echo "  rejects: ${label}"
}

fresh_copy
set_compatible rpi4-prod-ab suderra-os-aarch64
expect_fail "rpi4 bundles under the shared aarch64 compatible" "differs from boards.json" \
    python3 -I "${TOOL}" --root "${WORK}/tree" check
expect_fail "rpi4 prod image built with the shared aarch64 compatible" "differs from boards.json" \
    python3 -I "${TOOL}" --root "${WORK}/tree" image suderra_aarch64_rpi4_prod_ab_defconfig

fresh_copy
set_compatible revpi4-prod-ab suderra-os-rpi4-cm4
expect_fail "RevPi image accepting rpi4 bundles" "differs from boards.json" \
    python3 -I "${TOOL}" --root "${WORK}/tree" image suderra_aarch64_revpi4_prod_ab_defconfig

fresh_copy
set_compatible x86_64 suderra-os-qemu-x86_64
expect_fail "boardless x86 image reusing the QEMU board's compatible" "reuses a board's compatible" \
    python3 -I "${TOOL}" --root "${WORK}/tree" image suderra_x86_64_defconfig

echo "RAUC compatible contract passed"

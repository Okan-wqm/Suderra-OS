#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/release-publication-manifest.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
RELEASE_DIR="${TMPDIR}/release"
mkdir -p "${RELEASE_DIR}"

printf 'evidence archive\n' >"${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst"
printf 'evidence archive signature\n' >"${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst.sig"
printf 'evidence archive certificate\n' >"${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst.cert"
printf 'image\n' >"${RELEASE_DIR}/suderra-qemu_x86_64.img.xz"
printf 'image signature\n' >"${RELEASE_DIR}/suderra-qemu_x86_64.img.xz.sig"
printf 'image certificate\n' >"${RELEASE_DIR}/suderra-qemu_x86_64.img.xz.cert"

python3 "${TOOL}" create \
    --version "${VERSION}" \
    --release-dir "${RELEASE_DIR}" \
    --output "${RELEASE_DIR}/release-publication-manifest.json" \
    --repository Okan-wqm/Suderra-OS \
    --workflow Release \
    --run-id 123456789 \
    --run-attempt 1 \
    >/dev/null

printf 'manifest signature\n' >"${RELEASE_DIR}/release-publication-manifest.json.sig"
printf 'manifest certificate\n' >"${RELEASE_DIR}/release-publication-manifest.json.cert"

python3 "${TOOL}" validate \
    "${RELEASE_DIR}/release-publication-manifest.json" \
    --release-dir "${RELEASE_DIR}" \
    --expected-version "${VERSION}" \
    --require-self-sidecars \
    >/dev/null

printf 'unmanifested byte\n' >"${RELEASE_DIR}/unexpected-debug.json"
if python3 "${TOOL}" validate \
    "${RELEASE_DIR}/release-publication-manifest.json" \
    --release-dir "${RELEASE_DIR}" \
    --expected-version "${VERSION}" \
    --require-self-sidecars \
    2>"${TMPDIR}/extra.err"; then
    echo "ERROR: publication manifest accepted an unlisted release file" >&2
    exit 1
fi
grep -q "missing release files" "${TMPDIR}/extra.err" || {
    echo "ERROR: extra release file failure did not cite missing release files" >&2
    cat "${TMPDIR}/extra.err" >&2
    exit 1
}
rm "${RELEASE_DIR}/unexpected-debug.json"

printf 'tampered\n' >"${RELEASE_DIR}/suderra-qemu_x86_64.img.xz"
if python3 "${TOOL}" validate \
    "${RELEASE_DIR}/release-publication-manifest.json" \
    --release-dir "${RELEASE_DIR}" \
    --expected-version "${VERSION}" \
    --require-self-sidecars \
    2>"${TMPDIR}/tampered.err"; then
    echo "ERROR: publication manifest accepted tampered release bytes" >&2
    exit 1
fi
grep -q "sha256 does not match" "${TMPDIR}/tampered.err" || {
    echo "ERROR: tamper failure did not cite sha256 mismatch" >&2
    cat "${TMPDIR}/tampered.err" >&2
    exit 1
}

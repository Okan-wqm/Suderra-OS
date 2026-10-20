#!/usr/bin/env bash
#
# The vendored Suderra edge contract pin names real source bytes (ADR-048
# DEC-25.2, Suderra-OS ADR-0008).
#
# contracts-vendor-digest-test.sh proves the vendored tree matches its own
# SHA256SUMS and the pin, but a hand edit of files, SHA256SUMS and the pin
# together would pass it. This test closes that: for every vendored version it
# fetches SHA256SUMS at the pinned source_commit from the pinned source_repo
# (public on GitHub) and requires its digest to equal the pin. Without network
# it is skipped locally (exit 77) and fails in CI, where run-tests.sh treats a
# skip as a failure.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PIN="${ROOT}/contracts/suderra-edge.digest"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${PIN}" ] || fail "missing pin file contracts/suderra-edge.digest"

pin_value() {
    local key="$1"
    [ "$(grep -cE "^${key}=" "${PIN}" || true)" = "1" ] || fail "pin must set ${key} exactly once"
    grep -E "^${key}=" "${PIN}" | cut -d= -f2-
}

repo="$(pin_value source_repo)"
path="$(pin_value source_path)"
commit="$(pin_value source_commit)"
[[ "${repo}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "pin source_repo is not owner/name"
[[ "${path}" =~ ^[A-Za-z0-9_./-]+$ ]] || fail "pin source_path is not a plain path"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail "pin source_commit is not a full commit SHA"
command -v curl >/dev/null || fail "curl is required"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

checked=0
for version_dir in "${ROOT}"/contracts/suderra-edge/v*/; do
    version="$(basename -- "${version_dir%/}")"
    url="https://raw.githubusercontent.com/${repo}/${commit}/${path}/${version}/SHA256SUMS"
    if ! curl --fail --silent --show-error --location --max-time 60 --retry 3 \
        --output "${TMP}/${version}.SHA256SUMS" "${url}"; then
        if [ "${CI:-}" = "true" ]; then
            fail "cannot fetch ${url}; the pinned source commit must be pushed to ${repo}"
        fi
        echo "SKIP: cannot reach ${url} (offline?)"
        exit 77
    fi
    source_digest="$(sha256sum "${TMP}/${version}.SHA256SUMS" | cut -d' ' -f1)"
    [ "${source_digest}" = "$(pin_value "${version}_sha256sums_sha256")" ] \
        || fail "${version}: SHA256SUMS at ${repo}@${commit} has digest ${source_digest}, the pin says otherwise"
    cmp -s "${TMP}/${version}.SHA256SUMS" "${version_dir}SHA256SUMS" \
        || fail "${version}: vendored SHA256SUMS differs from ${repo}@${commit}"
    checked=$((checked + 1))
done
[ "${checked}" -gt 0 ] || fail "no contracts/suderra-edge/v<N>/ directory"

echo "contracts-vendor-source: ${checked} vendored contract version(s) match ${repo}@${commit}"

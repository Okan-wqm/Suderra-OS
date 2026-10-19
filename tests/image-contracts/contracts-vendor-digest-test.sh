#!/usr/bin/env bash
#
# Vendored Suderra edge contract (ADR-048 DEC-25, Suderra-OS ADR-0008).
#
# contracts/suderra-edge/ is an exact copy of aquaculture_platform
# contracts/suderra-edge/, pinned by contracts/suderra-edge.digest. Every
# version directory's SHA256SUMS must match its files, list exactly those
# files and hash to the pinned digest, and its VERSION must equal the pin; a
# hand edit of the vendored tree, or a re-vendor without a new pin, fails here.
# boards.json is the one board vocabulary, so it must also classify every
# ci/build-matrix.yml target exactly once, as a board image or an excluded
# image: a new defconfig without a board-map row fails here, not on a device.
#
# Re-vendor from aquaculture_platform with
#   scripts/edge/vendor-contracts-to-suderra-os.sh <path-to-Suderra-OS>
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
VENDOR="${ROOT}/contracts/suderra-edge"
PIN="${ROOT}/contracts/suderra-edge.digest"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${PIN}" ] || fail "missing pin file contracts/suderra-edge.digest"
[ -d "${VENDOR}" ] || fail "missing vendored contracts/suderra-edge/"

pin_value() {
    local key="$1"
    [ "$(grep -cE "^${key}=" "${PIN}" || true)" = "1" ] || fail "pin must set ${key} exactly once"
    grep -E "^${key}=" "${PIN}" | cut -d= -f2-
}

while IFS= read -r line; do
    case "${line}" in
        '#'*) ;;
        source_repo=*|source_path=*|source_commit=*) ;;
        v[0-9]*_version=*|v[0-9]*_sha256sums_sha256=*) ;;
        *) fail "unexpected line in pin: ${line}" ;;
    esac
done < "${PIN}"

[ "$(pin_value source_repo)" = "Okan-wqm/aquaculture_platform" ] || fail "pin source_repo is not Okan-wqm/aquaculture_platform"
[ "$(pin_value source_path)" = "contracts/suderra-edge" ] || fail "pin source_path is not contracts/suderra-edge"
pin_value source_commit | grep -qE '^[0-9a-f]{40}$' || fail "pin source_commit is not a full commit SHA"

stray="$(find "${VENDOR}" -mindepth 1 -maxdepth 1 ! -name 'v[0-9]*' -print)"
[ -z "${stray}" ] || fail "files outside a version directory in contracts/suderra-edge/: ${stray}"

versions=0
for version_dir in "${VENDOR}"/v*/; do
    version_dir="${version_dir%/}"
    version="$(basename -- "${version_dir}")"
    versions=$((versions + 1))
    [ -f "${version_dir}/SHA256SUMS" ] || fail "${version}/SHA256SUMS missing"

    (cd -- "${version_dir}" && sha256sum --check --strict --quiet SHA256SUMS) \
        || fail "${version}: a vendored file differs from its SHA256SUMS entry"
    listed="$(cut -d' ' -f3- "${version_dir}/SHA256SUMS")"
    present="$(cd -- "${version_dir}" && find . -type f ! -path ./SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort)"
    [ "${listed}" = "${present}" ] || fail "${version}/SHA256SUMS does not list exactly the vendored files"

    digest="$(sha256sum "${version_dir}/SHA256SUMS" | cut -d' ' -f1)"
    [ "$(pin_value "${version}_sha256sums_sha256")" = "${digest}" ] \
        || fail "${version}/SHA256SUMS digest ${digest} does not match the pin"
    [ "$(pin_value "${version}_version")" = "$(tr -d '\n' < "${version_dir}/VERSION")" ] \
        || fail "${version}/VERSION does not match the pin"
done
[ "${versions}" -gt 0 ] || fail "no contracts/suderra-edge/v<N>/ directory"
pinned_versions="$(grep -cE '^v[0-9]+_version=' "${PIN}")"
[ "${pinned_versions}" = "${versions}" ] || fail "pin names ${pinned_versions} versions, ${versions} are vendored"

python3 -B - "${ROOT}" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("build_matrix", root / "scripts/ci/validate-build-matrix.py")
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
targets = sorted(f"{row['name']} {row['target']}" for row in module.load_matrix()["defconfigs"])

for boards_path in sorted((root / "contracts/suderra-edge").glob("v*/boards.json")):
    boards = json.loads(boards_path.read_text())
    classified = [
        f"{image['defconfig']} {image['build_target']}"
        for board in boards["boards"]
        for image in board["os_images"]
    ] + [f"{image['defconfig']} {image['build_target']}" for image in boards["excluded_os_images"]]
    duplicates = sorted({item for item in classified if classified.count(item) > 1})
    if duplicates:
        raise SystemExit(f"ERROR: {boards_path.relative_to(root)} classifies twice: {duplicates}")
    missing = sorted(set(targets) - set(classified))
    stale = sorted(set(classified) - set(targets))
    if missing or stale:
        raise SystemExit(
            f"ERROR: {boards_path.relative_to(root)} disagrees with ci/build-matrix.yml; "
            f"unclassified targets: {missing}; classified but not in the matrix: {stale}"
        )
PY

echo "contracts-vendor-digest: ${versions} vendored contract version(s) match the pin and ci/build-matrix.yml"

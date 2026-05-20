#!/usr/bin/env bash
#
# Materialize and validate the Buildroot source used by Suderra OS builds.
#
# The checked-out buildroot/ submodule is the pinned upstream source of truth.
# Normal builds use an isolated source tree under output/.buildroot-src so
# build preparation never leaves the submodule dirty.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"

BUILDROOT_DIR="${BUILDROOT_DIR:-${PROJECT_ROOT}/buildroot}"
SOURCE_ROOT="${SUDERRA_BUILDROOT_SOURCE_ROOT:-${PROJECT_ROOT}/output/.buildroot-src}"
NATIVE_TAG="2025.05.3"
NATIVE_COMMIT="019201c6e007d80c1ab1bf65b98d9902bc767bdd"
NATIVE_RUST_VERSION="1.86.0"

usage() {
    cat <<EOF
Usage:
  $0 status
  $0 verify-native-rust
  $0 prepare [--defconfig NAME]
  $0 clean-managed
  $0 clean-managed-rust-patch
EOF
}

git_super() {
    git -C "${PROJECT_ROOT}" "$@"
}

git_buildroot() {
    git -C "${BUILDROOT_DIR}" "$@"
}

buildroot_index_sha() {
    git_super ls-tree HEAD buildroot | awk '{print $3}'
}

buildroot_head_sha() {
    git_buildroot rev-parse HEAD
}

require_submodule() {
    if [ ! -d "${BUILDROOT_DIR}" ]; then
        echo "ERROR: Buildroot submodule not found: ${BUILDROOT_DIR}" >&2
        exit 1
    fi
}

status_lines() {
    git_buildroot status --porcelain --untracked-files=all
}

is_pristine() {
    [ "$(buildroot_index_sha)" = "$(buildroot_head_sha)" ] && [ -z "$(status_lines)" ]
}

is_old_managed_rust_patch() {
    local expected actual
    expected=$'M package/rust-bin/rust-bin.hash\nM package/rust-bin/rust-bin.mk\nM package/rust/rust.hash\nM package/rust/rust.mk'
    actual="$(status_lines | sed 's/^ //g' | LC_ALL=C sort)"
    [ "${actual}" = "${expected}" ] || return 1
    grep -q '^RUST_VERSION = 1\.86\.0$' "${BUILDROOT_DIR}/package/rust/rust.mk"
    grep -q '^RUST_BIN_VERSION = 1\.86\.0$' "${BUILDROOT_DIR}/package/rust-bin/rust-bin.mk"
}

verify_native_rust() {
    require_submodule
    local expected_sha actual_sha tag
    expected_sha="$(buildroot_index_sha)"
    actual_sha="$(buildroot_head_sha)"
    tag="$(git_buildroot describe --tags --exact-match HEAD 2>/dev/null || true)"
    if [ "${expected_sha}" != "${actual_sha}" ]; then
        echo "ERROR: Buildroot submodule SHA drift detected: index=${expected_sha} actual=${actual_sha}" >&2
        exit 1
    fi
    if [ "${actual_sha}" != "${NATIVE_COMMIT}" ]; then
        echo "ERROR: Buildroot HEAD must be ${NATIVE_TAG} (${NATIVE_COMMIT}); got ${tag:-untagged} (${actual_sha})" >&2
        exit 1
    fi
    if [ -n "${tag}" ] && [ "${tag}" != "${NATIVE_TAG}" ]; then
        echo "ERROR: Buildroot HEAD tag must be ${NATIVE_TAG}; got ${tag}" >&2
        exit 1
    fi
    if [ -n "$(status_lines)" ]; then
        echo "ERROR: Buildroot submodule must be pristine" >&2
        status_lines >&2
        exit 1
    fi
    grep -q "^RUST_VERSION = ${NATIVE_RUST_VERSION}$" "${BUILDROOT_DIR}/package/rust/rust.mk" || {
        echo "ERROR: native Buildroot Rust package must be ${NATIVE_RUST_VERSION}" >&2
        exit 1
    }
    grep -q "^RUST_BIN_VERSION = ${NATIVE_RUST_VERSION}$" "${BUILDROOT_DIR}/package/rust-bin/rust-bin.mk" || {
        echo "ERROR: native Buildroot rust-bin package must be ${NATIVE_RUST_VERSION}" >&2
        exit 1
    }
}

status_cmd() {
    require_submodule
    if is_pristine; then
        echo "OK: buildroot submodule is pristine at $(buildroot_head_sha)"
        return 0
    fi
    if is_old_managed_rust_patch; then
        echo "INFO: buildroot contains only the old managed Rust 1.86 patch"
        echo "INFO: run $0 clean-managed-rust-patch before the 2025.05.3 migration"
        return 0
    fi
    echo "FAIL: buildroot has unexpected local changes" >&2
    status_lines >&2
    return 1
}

clean_managed_rust_patch() {
    require_submodule
    if ! is_old_managed_rust_patch; then
        echo "ERROR: refusing cleanup because buildroot is not exactly the old managed Rust patch state" >&2
        status_lines >&2
        exit 1
    fi
    git_buildroot restore -- \
        package/rust-bin/rust-bin.hash \
        package/rust-bin/rust-bin.mk \
        package/rust/rust.hash \
        package/rust/rust.mk
    if ! is_pristine; then
        echo "ERROR: Buildroot cleanup did not restore pristine state" >&2
        status_lines >&2
        exit 1
    fi
    echo "OK: removed old managed Rust patch from buildroot"
}

prepare_cmd() {
    require_submodule
    verify_native_rust >/dev/null
    local defconfig="manual"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --defconfig)
                defconfig="${2:?--defconfig requires a value}"
                shift 2
                ;;
            *)
                echo "ERROR: unknown prepare argument: $1" >&2
                exit 1
                ;;
        esac
    done
    local metadata effective base target source_sha index_sha
    source_sha="$(git_super rev-parse HEAD)"
    metadata="$(python3 "${PROJECT_ROOT}/scripts/ci/buildroot-patch-identity.py" metadata \
        --source-sha "${source_sha}" \
        --buildroot-dir "${BUILDROOT_DIR}")"
    effective="$(printf '%s\n' "${metadata}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["buildroot_effective_source_id"])')"
    base="${SOURCE_ROOT}/${effective}"
    mkdir -p "${base}"
    target="$(mktemp -d "${base}/${defconfig}.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
    index_sha="$(buildroot_index_sha)"
    git_buildroot archive --format=tar "${index_sha}" | tar -C "${target}" -xf -
    printf '%s\n' "${target}"
}

clean_managed() {
    case "${SOURCE_ROOT}" in
        "${PROJECT_ROOT}/output/.buildroot-src"|/tmp/*) ;;
        *)
            echo "ERROR: refusing to remove unexpected source root: ${SOURCE_ROOT}" >&2
            exit 1
            ;;
    esac
    rm -rf "${SOURCE_ROOT}"
    echo "OK: removed managed Buildroot source trees: ${SOURCE_ROOT}"
}

main() {
    command="${1:-}"
    [ -n "${command}" ] || {
        usage >&2
        exit 2
    }
    shift || true
    case "${command}" in
        status) status_cmd "$@" ;;
        verify-native-rust) verify_native_rust "$@" ;;
        prepare) prepare_cmd "$@" ;;
        clean-managed) clean_managed "$@" ;;
        clean-managed-rust-patch) clean_managed_rust_patch "$@" ;;
        --help|-h|help) usage ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"

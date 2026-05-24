#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_grep() {
    local pattern="$1"
    local file="$2"
    grep -q -- "${pattern}" "${PROJECT_ROOT}/${file}" || fail "${file} must contain ${pattern}"
}

[ -f "${PROJECT_ROOT}/host-tools/Cargo.toml" ] || fail "host-tools/Cargo.toml missing"
[ -f "${PROJECT_ROOT}/host-tools/Cargo.lock" ] || fail "host-tools/Cargo.lock missing"
[ -f "${PROJECT_ROOT}/host-tools/rust-toolchain.toml" ] || fail "host-tools/rust-toolchain.toml missing"
[ -f "${PROJECT_ROOT}/host-tools/deny.toml" ] || fail "host-tools/deny.toml missing"
[ -f "${PROJECT_ROOT}/host-tools/schema-compat/src/lib.rs" ] || fail "schema-compat crate missing"
[ -f "${PROJECT_ROOT}/host-tools/release-core/src/main.rs" ] || fail "release-core crate missing"

git -C "${PROJECT_ROOT}" ls-files --error-unmatch host-tools/Cargo.lock >/dev/null ||
    fail "host-tools/Cargo.lock must be tracked"
if git -C "${PROJECT_ROOT}" check-ignore -q host-tools/Cargo.lock; then
    fail "host-tools/Cargo.lock must be unignored"
fi

require_grep 'channel = "1.86.0"' "host-tools/rust-toolchain.toml"
require_grep '"schema-compat"' "host-tools/Cargo.toml"
require_grep '"release-core"' "host-tools/Cargo.toml"
require_grep 'directory: "/host-tools"' ".github/dependabot.yml"
require_grep 'Host Tools (fmt + clippy + test)' ".github/workflows/rust.yml"
require_grep 'host-tools/Cargo.lock' ".github/workflows/rust.yml"
require_grep 'working-directory: ./host-tools' ".github/workflows/rust.yml"

if rg -n 'host-tools' "${PROJECT_ROOT}/userspace" "${PROJECT_ROOT}/external.mk" \
    "${PROJECT_ROOT}/package" "${PROJECT_ROOT}/configs" >/tmp/suderra-host-tools-refs.txt; then
    cat /tmp/suderra-host-tools-refs.txt >&2
    fail "host-tools must not be referenced from userspace, Buildroot packages, external.mk, or defconfigs"
fi

if rg -n 'cargo run|cargo build|cargo install|cross build|rustup' \
    "${PROJECT_ROOT}/.github/workflows/release.yml" >/tmp/suderra-release-rust.txt; then
    cat /tmp/suderra-release-rust.txt >&2
    fail "release.yml must not build or install Rust tooling after preflight"
fi

require_grep 'host-tools)' "scripts/run-tests.sh"
require_grep 'release/suderra-installer-${{ needs.validate.outputs.version }}-x86_64' \
    ".github/workflows/release.yml"

echo "host tools governance contracts passed"

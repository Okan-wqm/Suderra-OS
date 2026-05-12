#!/usr/bin/env bash
#
# Apply Suderra-maintained patches to the checked-out Buildroot tree.
#
# The Buildroot submodule tracks upstream directly; local deltas that are not
# accepted upstream live under patches/buildroot so superproject commits never
# point at private or dirty submodule commits.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

BUILDROOT_DIR="${1:-${BUILDROOT_DIR:-${PROJECT_ROOT}/buildroot}}"
PATCH_DIR="${PROJECT_ROOT}/patches/buildroot"

if [ "${SUDERRA_SKIP_BUILDROOT_PATCHES:-0}" = "1" ]; then
    echo "==> Buildroot patch application skipped by SUDERRA_SKIP_BUILDROOT_PATCHES=1"
    exit 0
fi

if [ ! -d "${BUILDROOT_DIR}" ]; then
    echo "ERROR: Buildroot bulunamadı: ${BUILDROOT_DIR}" >&2
    exit 1
fi

if [ ! -d "${PATCH_DIR}" ]; then
    exit 0
fi

for patch in "${PATCH_DIR}"/*.patch; do
    [ -e "${patch}" ] || continue

    if git -C "${BUILDROOT_DIR}" apply --reverse --check "${patch}" >/dev/null 2>&1; then
        echo "==> Buildroot patch already applied: $(basename "${patch}")"
        continue
    fi

    echo "==> Applying Buildroot patch: $(basename "${patch}")"
    git -C "${BUILDROOT_DIR}" apply --check "${patch}"
    git -C "${BUILDROOT_DIR}" apply "${patch}"
done

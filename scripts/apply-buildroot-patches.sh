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

if [ ! -d "${BUILDROOT_DIR}" ]; then
    echo "ERROR: Buildroot bulunamadı: ${BUILDROOT_DIR}" >&2
    exit 1
fi

if [ ! -d "${PATCH_DIR}" ]; then
    exit 0
fi

PRE_PATCH_STATUS="$(git -C "${BUILDROOT_DIR}" status --porcelain --untracked-files=all)"
if [ -n "${PRE_PATCH_STATUS}" ]; then
    if python3 "${PROJECT_ROOT}/scripts/ci/buildroot-patch-identity.py" validate-applied \
        --source-sha "$(git -C "${PROJECT_ROOT}" rev-parse HEAD)" >/dev/null 2>&1; then
        echo "==> Buildroot patchset already applied and validated"
        exit 0
    fi
    echo "ERROR: Buildroot tree is dirty before Suderra patches are applied" >&2
    echo "${PRE_PATCH_STATUS}" >&2
    exit 1
fi

for patch in "${PATCH_DIR}"/*.patch; do
    [ -e "${patch}" ] || continue

    if git -C "${BUILDROOT_DIR}" apply --reverse --check "${patch}" >/dev/null 2>&1; then
        echo "==> Buildroot patch already applied: $(basename "${patch}")"
        continue
    elif git -C "${BUILDROOT_DIR}" apply --unidiff-zero --reverse --check "${patch}" >/dev/null 2>&1; then
        echo "==> Buildroot zero-context patch already applied: $(basename "${patch}")"
        continue
    fi

    echo "==> Applying Buildroot patch: $(basename "${patch}")"
    if git -C "${BUILDROOT_DIR}" apply --check "${patch}"; then
        git -C "${BUILDROOT_DIR}" apply "${patch}"
    else
        echo "==> Falling back to --unidiff-zero for $(basename "${patch}")"
        git -C "${BUILDROOT_DIR}" apply --unidiff-zero --check "${patch}"
        git -C "${BUILDROOT_DIR}" apply --unidiff-zero "${patch}"
    fi
done

python3 "${PROJECT_ROOT}/scripts/ci/buildroot-patch-identity.py" validate-applied \
    --source-sha "$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
DOCKERFILE="${PROJECT_ROOT}/ci/Dockerfile"
RESOURCE_CHECK="${PROJECT_ROOT}/scripts/ci/check-runner-resources.sh"
EXTERNAL_MK="${PROJECT_ROOT}/external.mk"

require_pattern() {
    local pattern="$1"
    local reason="$2"
    if ! grep -Eq "${pattern}" "${DOCKERFILE}"; then
        echo "ERROR: build container contract missing ${reason}" >&2
        exit 1
    fi
}

require_pattern 'ubuntu:24\.04@sha256:' 'pinned base image digest'
require_pattern 'libelf-dev' 'Linux objtool host elf headers'
require_pattern 'qemu-system-x86' 'x86 QEMU runtime gate'
require_pattern 'qemu-system-arm' 'ARM QEMU/runtime tooling'
require_pattern 'qemu-utils' 'image inspection/runtime utilities'
require_pattern 'parted' 'partition table image tooling'
require_pattern 'dosfstools' 'EFI/FAT image tooling'
require_pattern 'mtools' 'EFI/FAT image manipulation tooling'
require_pattern 'e2fsprogs' 'ext filesystem image tooling'
require_pattern 'openssl' 'signing and certificate tooling'
require_pattern 'shellcheck' 'strict shell lint tooling'
require_pattern 'sbsigntool' 'Secure Boot PE/COFF signature tooling'
require_pattern 'getent group dbus' 'dbus group preflight'
require_pattern 'groupadd -r dbus' 'dbus group creation'
require_pattern 'SHELL \["/bin/bash", "-o", "pipefail", "-c"\]' 'Dockerfile pipefail shell'
require_pattern '# hadolint ignore=DL3008' 'documented apt pinning exception'
grep -q 'source=${HOST_DL_DIR},target=/workspace/dl' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must bind repo-local dl/ for CI cache compatibility" >&2
        exit 1
    }
grep -q 'source=${HOST_OUTPUT_DIR},target=/workspace/output' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must bind host output storage for CI disk compatibility" >&2
        exit 1
    }
grep -q 'source=${HOST_CCACHE_DIR},target=/workspace/.ccache' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must bind repo-local .ccache/ for CI cache compatibility" >&2
        exit 1
    }
grep -q 'SUDERRA_HOST_KEYS_DIR' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must support explicit host keyring mounts" >&2
        exit 1
    }
grep -q 'SUDERRA_BUILDER_IMAGE' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must allow release builds to select a digest-pinned builder image" >&2
        exit 1
    }
grep -q 'SUDERRA_RELEASE_HERMETIC' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must expose a hermetic release mode" >&2
        exit 1
    }
grep -q 'requires SUDERRA_BUILDER_IMAGE pinned by digest' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: hermetic release mode must reject mutable builder tags" >&2
        exit 1
    }
grep -q 'SUDERRA_CONTAINER_KEYS_DIR' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must expose the container keyring path" >&2
        exit 1
    }
grep -q 'CONTAINER_KEYS_DIR="${SUDERRA_CONTAINER_KEYS_DIR:-/tmp/suderra-keys/current}"' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must default keyring mounts to /tmp, not /home/builder" >&2
        exit 1
    }
grep -q -- '--mount "type=bind,source=${HOST_KEYS_DIR},target=${CONTAINER_KEYS_DIR},readonly"' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must mount trust roots with explicit read-only bind semantics" >&2
        exit 1
    }
grep -q 'validate-trust-roots.sh' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must preflight trust roots before expensive builds" >&2
        exit 1
    }
grep -q 'SUDERRA_TRUST_ROOTS_DIR' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must pass a non-package-colliding Buildroot trust-root variable" >&2
        exit 1
    }
grep -q 'SUDERRA_INSTALLER_PAYLOAD_KEY_PROFILE' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must propagate installer payload key profile" >&2
        exit 1
    }
if grep -q -- '-e SUDERRA_KEYS_DIR=' "${PROJECT_ROOT}/scripts/build-in-docker.sh"; then
    echo "ERROR: build-in-docker must not export SUDERRA_KEYS_DIR into Buildroot scope" >&2
    exit 1
fi
grep -Eq '^SUDERRA_TRUST_ROOTS_DIR[[:space:]]*:=' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: external.mk must define SUDERRA_TRUST_ROOTS_DIR before package includes" >&2
        exit 1
    }
if grep -Eq '^SUDERRA_KEYS_DIR[[:space:]]*[:?]?=' "${EXTERNAL_MK}"; then
    echo "ERROR: external.mk must not assign SUDERRA_KEYS_DIR; Buildroot reserves it for the suderra-keys package" >&2
    exit 1
fi
grep -q '^export SUDERRA_TRUST_ROOTS_DIR' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: external.mk must export SUDERRA_TRUST_ROOTS_DIR into package builds" >&2
        exit 1
    }
if grep -R '\$(SUDERRA_KEYS_DIR)' "${PROJECT_ROOT}/package" --include='*.mk'; then
    echo "ERROR: package makefiles must not read SUDERRA_KEYS_DIR because it collides with Buildroot package variables" >&2
    exit 1
fi
grep -q 'SUDERRA_RESOURCE_PATH' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must support explicit build storage path" >&2
        exit 1
    }
grep -q 'SUDERRA_MIN_DISK_GIB' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must expose explicit disk threshold" >&2
        exit 1
    }
grep -q 'SUDERRA_MIN_MEM_GIB' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must expose explicit memory threshold" >&2
        exit 1
    }
grep -q 'SUDERRA_MIN_VCPU' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must expose explicit vCPU threshold" >&2
        exit 1
    }
grep -q 'MATRIX_PREBUILD_DEFCONFIGS' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must consume matrix prebuild contracts" >&2
        exit 1
    }
grep -q 'MATRIX_PAYLOAD_IMAGE_EXPORTS' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must consume matrix payload export contracts" >&2
        exit 1
    }
grep -q 'prepare-ci-keyring.sh' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must prepare CI trust roots before Buildroot image builds" >&2
        exit 1
    }
grep -q 'SUDERRA_CONTAINER_KEYS_DIR: /tmp/suderra-keys/current' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must use a container keyring path outside /home/builder" >&2
        exit 1
    }
grep -q 'Verify container trust-root visibility' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must validate trust-root visibility inside the build container" >&2
        exit 1
    }
if grep -q 'build-in-docker.sh' "${PROJECT_ROOT}/.github/workflows/release.yml"; then
    grep -q 'SUDERRA_CONTAINER_KEYS_DIR: /tmp/suderra-keys/current' "${PROJECT_ROOT}/.github/workflows/release.yml" ||
        {
            echo "ERROR: release workflow build jobs must use a container keyring path outside /home/builder" >&2
            exit 1
        }
    grep -q 'Verify container trust-root visibility' "${PROJECT_ROOT}/.github/workflows/release.yml" ||
        {
            echo "ERROR: release workflow build jobs must validate trust-root visibility inside the build container" >&2
            exit 1
        }
fi
if grep -R '/home/builder/.suderra-keys/current' \
    "${PROJECT_ROOT}/scripts/build-in-docker.sh" \
    "${PROJECT_ROOT}/.github/workflows/build.yml" \
    "${PROJECT_ROOT}/.github/workflows/release.yml"; then
    echo "ERROR: CI keyring mounts must not target /home/builder" >&2
    exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT
KEYS_DIR="${TMPDIR}/keys"
FAKE_BIN="${TMPDIR}/bin"
FAKE_DOCKER_LOG="${TMPDIR}/docker.log"
mkdir -p "${FAKE_BIN}" "${TMPDIR}/out" "${TMPDIR}/dl" "${TMPDIR}/ccache"
"${PROJECT_ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null

cat > "${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
    printf '%s\n' "${arg}" >> "${FAKE_DOCKER_LOG:?}"
done
printf -- '---\n' >> "${FAKE_DOCKER_LOG:?}"
case "${1:-}" in
    image|run|build)
        exit 0
        ;;
    *)
        echo "unexpected fake docker command: $*" >&2
        exit 2
        ;;
esac
EOF
chmod +x "${FAKE_BIN}/docker"

PATH="${FAKE_BIN}:${PATH}" \
FAKE_DOCKER_LOG="${FAKE_DOCKER_LOG}" \
SUDERRA_HOST_KEYS_DIR="${KEYS_DIR}" \
SUDERRA_CONTAINER_KEYS_DIR=/container/keys \
SUDERRA_EXPECTED_KEYS_PROFILE=ci \
SUDERRA_HOST_OUTPUT_DIR="${TMPDIR}/out" \
SUDERRA_HOST_DL_DIR="${TMPDIR}/dl" \
SUDERRA_HOST_CCACHE_DIR="${TMPDIR}/ccache" \
    bash "${PROJECT_ROOT}/scripts/build-in-docker.sh" suderra_qemu_x86_64_defconfig >/dev/null

grep -F -- "type=bind,source=${KEYS_DIR},target=/container/keys,readonly" "${FAKE_DOCKER_LOG}" >/dev/null ||
    {
        echo "ERROR: fake docker run did not receive the read-only keyring mount" >&2
        exit 1
    }
grep -F -- "SUDERRA_TRUST_ROOTS_DIR=/container/keys" "${FAKE_DOCKER_LOG}" >/dev/null ||
    {
        echo "ERROR: fake docker run did not receive SUDERRA_TRUST_ROOTS_DIR" >&2
        exit 1
    }
if grep -F -- "SUDERRA_KEYS_DIR=/container/keys" "${FAKE_DOCKER_LOG}" >/dev/null; then
    echo "ERROR: fake docker run exported legacy SUDERRA_KEYS_DIR into Buildroot scope" >&2
    exit 1
fi
if grep -F -- "target=/container/keys,rw" "${FAKE_DOCKER_LOG}" >/dev/null; then
    echo "ERROR: fake docker run mounted the keyring writable" >&2
    exit 1
fi

: > "${FAKE_DOCKER_LOG}"
if PATH="${FAKE_BIN}:${PATH}" \
    FAKE_DOCKER_LOG="${FAKE_DOCKER_LOG}" \
    SUDERRA_HOST_KEYS_DIR="${TMPDIR}/missing" \
    SUDERRA_CONTAINER_KEYS_DIR=/container/keys \
    SUDERRA_HOST_OUTPUT_DIR="${TMPDIR}/out" \
    SUDERRA_HOST_DL_DIR="${TMPDIR}/dl" \
    SUDERRA_HOST_CCACHE_DIR="${TMPDIR}/ccache" \
    bash "${PROJECT_ROOT}/scripts/build-in-docker.sh" suderra_qemu_x86_64_defconfig \
        >"${TMPDIR}/missing.out" 2>"${TMPDIR}/missing.err"; then
    echo "ERROR: build-in-docker accepted a missing explicit keyring" >&2
    exit 1
fi
grep -q 'Suderra keys directory does not exist' "${TMPDIR}/missing.err" ||
    {
        echo "ERROR: missing keyring failure did not explain the broken contract" >&2
        exit 1
    }
if [ -s "${FAKE_DOCKER_LOG}" ]; then
    echo "ERROR: build-in-docker touched docker before failing a missing keyring" >&2
    exit 1
fi

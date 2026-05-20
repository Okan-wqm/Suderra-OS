#!/usr/bin/env bash
#
# Suderra OS — Docker container içinde build (reproducible)
#
# Kullanım:
#   ./scripts/build-in-docker.sh <defconfig>
#   ./scripts/build-in-docker.sh --shell           # interactive shell

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

# Help
if [ "${1:-}" = "--help" ] || [ -z "${1:-}" ]; then
    cat <<EOF
Kullanım:
  $0 <defconfig>          # Build belirtilen defconfig
  $0 --shell              # Container içinde shell aç
  $0 --help               # Bu yardım

Mevcut defconfig'ler:
$(find "${PROJECT_ROOT}/configs/" -maxdepth 1 -type f -printf '  %f\n' | sort)

Çevre değişkenleri:
  SUDERRA_TRUST_ROOTS_DIR # Build sırasında kullanılacak trust-root keyring (varsayılan: ~/.suderra-keys/dev)
  SUDERRA_KEYS_DIR        # Legacy alias; wrapper tarafından SUDERRA_TRUST_ROOTS_DIR'e aktarılır
  SUDERRA_HOST_KEYS_DIR   # Container'a readonly mount edilecek host keyring dizini
  SUDERRA_CONTAINER_KEYS_DIR # Container içindeki keyring yolu (varsayılan: /tmp/suderra-keys/current)
  SOURCE_DATE_EPOCH       # Reproducible build için (varsayılan: git commit time)
  SUDERRA_BUILDROOT_SOURCE_IDENTITY_OUT # Optional source identity JSON path inside the container
  SUDERRA_REQUIRE_CLEAN_EXTERNAL # 1 ise BR2_EXTERNAL snapshot için dirty tree reddedilir
EOF
    exit 0
fi

HOST_DL_DIR="${SUDERRA_HOST_DL_DIR:-${PROJECT_ROOT}/dl}"
HOST_CCACHE_DIR="${SUDERRA_HOST_CCACHE_DIR:-${PROJECT_ROOT}/.ccache}"
HOST_OUTPUT_DIR="${SUDERRA_HOST_OUTPUT_DIR:-${PROJECT_ROOT}/output}"
BUILDER_IMAGE="${SUDERRA_BUILDER_IMAGE:-suderra-builder:latest}"
RELEASE_HERMETIC="${SUDERRA_RELEASE_HERMETIC:-0}"
mkdir -p "${HOST_DL_DIR}" "${HOST_CCACHE_DIR}" "${HOST_OUTPUT_DIR}"

if [ "${RELEASE_HERMETIC}" = "1" ]; then
    case "${BUILDER_IMAGE}" in
        *@sha256:*) ;;
        *)
            echo "ERROR: SUDERRA_RELEASE_HERMETIC=1 requires SUDERRA_BUILDER_IMAGE pinned by digest" >&2
            exit 1
            ;;
    esac
    if [ "${SUDERRA_ALLOW_RELEASE_CCACHE:-0}" != "1" ]; then
        echo "ERROR: release-hermetic builds must not use mutable ccache; set a verified cache policy before enabling it" >&2
        exit 1
    fi
fi

TRUST_ROOT_VALIDATOR="${PROJECT_ROOT}/scripts/ci/validate-trust-roots.sh"

# Trust roots are host-owned material mounted read-only into the container.
# Production builds must provide a prod-profiled directory from the release
# signing path; CI/dev builds may use generated ci/dev profiles.
HOST_KEYS_DIR="${SUDERRA_HOST_KEYS_DIR:-${SUDERRA_TRUST_ROOTS_DIR:-${SUDERRA_KEYS_DIR:-${HOME}/.suderra-keys/dev}}}"
CONTAINER_KEYS_DIR="${SUDERRA_CONTAINER_KEYS_DIR:-/tmp/suderra-keys/current}"

absolute_path() {
    local path="$1"
    local dir base

    if [ "${path}" != "${path#/}" ]; then
        printf '%s\n' "${path}"
        return 0
    fi

    dir="$(dirname -- "${path}")"
    base="$(basename -- "${path}")"
    if resolved_dir="$(cd -- "${dir}" 2>/dev/null && pwd)"; then
        printf '%s/%s\n' "${resolved_dir}" "${base}"
    elif [ "${dir}" != "${dir#/}" ]; then
        printf '%s/%s\n' "${dir}" "${base}"
    else
        printf '%s/%s/%s\n' "${PWD}" "${dir}" "${base}"
    fi
}

HOST_KEYS_DIR="$(absolute_path "${HOST_KEYS_DIR}")"

case "${CONTAINER_KEYS_DIR}" in
    /*) ;;
    *)
        echo "ERROR: SUDERRA_CONTAINER_KEYS_DIR must be an absolute container path: ${CONTAINER_KEYS_DIR}" >&2
        exit 1
        ;;
esac
case "${CONTAINER_KEYS_DIR}" in
    /home/builder|/home/builder/*)
        echo "ERROR: SUDERRA_CONTAINER_KEYS_DIR may not live under /home/builder." >&2
        echo "GitHub runner UIDs cannot reliably traverse that home directory; use /tmp/suderra-keys/current." >&2
        exit 1
        ;;
esac

if [ ! -d "${HOST_KEYS_DIR}" ]; then
    echo "ERROR: Suderra keys directory does not exist: ${HOST_KEYS_DIR}" >&2
    echo "Development keys: ./scripts/gen-dev-keys.sh" >&2
    echo "CI keys: scripts/ci/prepare-ci-keyring.sh \"\${SUDERRA_HOST_KEYS_DIR}\"" >&2
    exit 1
fi

VALIDATOR_ARGS=()
if [ -n "${SUDERRA_EXPECTED_KEYS_PROFILE:-}" ]; then
    VALIDATOR_ARGS+=(--expected-profile "${SUDERRA_EXPECTED_KEYS_PROFILE}")
fi
if [ "${SUDERRA_REQUIRE_INSTALLER_SIGNING:-0}" = "1" ]; then
    VALIDATOR_ARGS+=(--require-installer-signing)
fi

bash "${TRUST_ROOT_VALIDATOR}" "${HOST_KEYS_DIR}" "${VALIDATOR_ARGS[@]}"

KEYS_MOUNT_ARGS=(
    --mount "type=bind,source=${HOST_KEYS_DIR},target=${CONTAINER_KEYS_DIR},readonly"
)

DOCKER_USER_ARGS=(
    --user "$(id -u):$(id -g)"
    -e HOME=/tmp
)

# Reproducible build için ortam değişkenleri
SOURCE_DATE_EPOCH=$(git -C "${PROJECT_ROOT}" log -1 --format=%ct 2>/dev/null || echo "1704067200")
EXTRA_ENV=()
add_extra_env() {
    local name="$1"
    local value="${!name:-}"
    local suffix

    if [ -z "${value}" ]; then
        return 0
    fi

    case "${name}" in
        SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY|SUDERRA_INSTALLER_PAYLOAD_PUBKEY)
            case "${value}" in
                "${HOST_KEYS_DIR}"/*)
                    suffix="${value#"${HOST_KEYS_DIR}/"}"
                    value="${CONTAINER_KEYS_DIR}/${suffix}"
                    ;;
            esac
            ;;
    esac

    EXTRA_ENV+=("-e" "${name}=${value}")
}

for name in \
    SUDERRA_TARGET_IMAGE_XZ \
    SUDERRA_RPI4_TARGET_IMAGE_XZ \
    SUDERRA_REVPI4_TARGET_IMAGE_XZ \
    SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY \
    SUDERRA_INSTALLER_PAYLOAD_PUBKEY \
    SUDERRA_INSTALLER_PAYLOAD_KEY_PROFILE \
    SUDERRA_INSTALLER_PAYLOAD_EXPIRES_AT \
    SUDERRA_INSTALLER_KEY_EPOCH \
    SUDERRA_EXPECTED_KEYS_PROFILE \
    SUDERRA_REQUIRE_INSTALLER_SIGNING \
    SUDERRA_VERSION \
    SUDERRA_BUILD_ID \
    SUDERRA_VARIANT \
    SUDERRA_BUILDROOT_SOURCE_IDENTITY_OUT \
    SUDERRA_REQUIRE_CLEAN_EXTERNAL
do
    add_extra_env "${name}"
done

DOCKER_COMMON_ARGS=(
    --mount "type=bind,source=${PROJECT_ROOT},target=/workspace"
    --mount "type=bind,source=${HOST_OUTPUT_DIR},target=/workspace/output"
    --mount "type=bind,source=${HOST_DL_DIR},target=/workspace/dl"
    --mount "type=bind,source=${HOST_CCACHE_DIR},target=/workspace/.ccache"
    "${KEYS_MOUNT_ARGS[@]}"
    "${DOCKER_USER_ARGS[@]}"
    -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}"
    -e BR2_CCACHE_DIR=/workspace/.ccache
    -e SUDERRA_TRUST_ROOTS_DIR="${CONTAINER_KEYS_DIR}"
    "${EXTRA_ENV[@]}"
    -w /workspace
)

container_preflight_and_exec() {
    local container_cmd=("$@")

    docker run --rm \
        "${DOCKER_COMMON_ARGS[@]}" \
        "${BUILDER_IMAGE}" \
        /bin/bash -lc \
        'validator_args=(--check-installer-env); if [ -n "${SUDERRA_EXPECTED_KEYS_PROFILE:-}" ]; then validator_args+=(--expected-profile "${SUDERRA_EXPECTED_KEYS_PROFILE}"); fi; if [ "${SUDERRA_REQUIRE_INSTALLER_SIGNING:-0}" = "1" ]; then validator_args+=(--require-installer-signing); fi; bash /workspace/scripts/ci/validate-trust-roots.sh "${SUDERRA_TRUST_ROOTS_DIR:?}" "${validator_args[@]}"; exec "$@"' \
        bash "${container_cmd[@]}"
}

# Container imajı hazır mı?
if ! docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
    if [ "${RELEASE_HERMETIC}" = "1" ]; then
        echo "ERROR: release-hermetic builder image is not available locally: ${BUILDER_IMAGE}" >&2
        exit 1
    fi
    echo "==> suderra-builder container yok, build ediliyor..."
    docker build -t "${BUILDER_IMAGE}" "${PROJECT_ROOT}/ci/"
fi

# Shell modu
if [ "${1}" = "--shell" ]; then
    exec docker run --rm -it \
        "${DOCKER_COMMON_ARGS[@]}" \
        "${BUILDER_IMAGE}" \
        /bin/bash -lc \
        'validator_args=(--check-installer-env); if [ -n "${SUDERRA_EXPECTED_KEYS_PROFILE:-}" ]; then validator_args+=(--expected-profile "${SUDERRA_EXPECTED_KEYS_PROFILE}"); fi; if [ "${SUDERRA_REQUIRE_INSTALLER_SIGNING:-0}" = "1" ]; then validator_args+=(--require-installer-signing); fi; bash /workspace/scripts/ci/validate-trust-roots.sh "${SUDERRA_TRUST_ROOTS_DIR:?}" "${validator_args[@]}"; exec /bin/bash'
fi

# Build modu
DEFCONFIG="${1}"
echo "==> Suderra OS build (Docker): ${DEFCONFIG}"
echo "==> SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH}"

run_build() {
    container_preflight_and_exec /workspace/scripts/build.sh "${DEFCONFIG}"
}

if [ -n "${SUDERRA_DOCKER_BUILD_LOG:-}" ]; then
    mkdir -p "$(dirname "${SUDERRA_DOCKER_BUILD_LOG}")"
    set +e
    run_build 2>&1 | tee "${SUDERRA_DOCKER_BUILD_LOG}"
    status="${PIPESTATUS[0]}"
    set -e
    exit "${status}"
fi

run_build

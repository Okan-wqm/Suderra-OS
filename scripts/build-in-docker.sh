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

# Container imajı hazır mı?
if ! docker image inspect suderra-builder:latest >/dev/null 2>&1; then
    echo "==> suderra-builder container yok, build ediliyor..."
    docker build -t suderra-builder:latest "${PROJECT_ROOT}/ci/"
fi

HOST_DL_DIR="${SUDERRA_HOST_DL_DIR:-${PROJECT_ROOT}/dl}"
HOST_CCACHE_DIR="${SUDERRA_HOST_CCACHE_DIR:-${PROJECT_ROOT}/.ccache}"
HOST_OUTPUT_DIR="${SUDERRA_HOST_OUTPUT_DIR:-${PROJECT_ROOT}/output}"
mkdir -p "${HOST_DL_DIR}" "${HOST_CCACHE_DIR}" "${HOST_OUTPUT_DIR}"

# Trust roots are host-owned material mounted read-only into the container.
# Production builds must provide a prod-profiled directory from the release
# signing path; CI/dev builds may use generated ci/dev profiles.
HOST_KEYS_DIR="${SUDERRA_HOST_KEYS_DIR:-${SUDERRA_KEYS_DIR:-${HOME}/.suderra-keys/dev}}"
CONTAINER_KEYS_DIR="${SUDERRA_CONTAINER_KEYS_DIR:-/home/builder/.suderra-keys/current}"
KEYS_MOUNT_ARGS=()
if [ -d "${HOST_KEYS_DIR}" ]; then
    KEYS_MOUNT_ARGS=(-v "${HOST_KEYS_DIR}:${CONTAINER_KEYS_DIR}:ro")
elif [ -n "${SUDERRA_HOST_KEYS_DIR:-}" ] || [ -n "${SUDERRA_KEYS_DIR:-}" ]; then
    echo "ERROR: Suderra keys directory does not exist: ${HOST_KEYS_DIR}" >&2
    exit 1
fi

DOCKER_USER_ARGS=(
    --user "$(id -u):$(id -g)"
    -e HOME=/tmp
)

# Reproducible build için ortam değişkenleri
SOURCE_DATE_EPOCH=$(git -C "${PROJECT_ROOT}" log -1 --format=%ct 2>/dev/null || echo "1704067200")
EXTRA_ENV=()
for name in \
    SUDERRA_TARGET_IMAGE_XZ \
    SUDERRA_RPI4_TARGET_IMAGE_XZ \
    SUDERRA_REVPI4_TARGET_IMAGE_XZ \
    SUDERRA_INSTALLER_PAYLOAD_SIGN_KEY \
    SUDERRA_INSTALLER_PAYLOAD_PUBKEY \
    SUDERRA_INSTALLER_PAYLOAD_KEY_PROFILE \
    SUDERRA_INSTALLER_PAYLOAD_EXPIRES_AT \
    SUDERRA_INSTALLER_KEY_EPOCH \
    SUDERRA_VERSION \
    SUDERRA_BUILD_ID \
    SUDERRA_VARIANT
do
    if [ -n "${!name:-}" ]; then
        EXTRA_ENV+=("-e" "${name}=${!name}")
    fi
done

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
  SUDERRA_KEYS_DIR        # Build sırasında kullanılacak anahtarlar (varsayılan: ~/.suderra-keys/dev)
  SUDERRA_HOST_KEYS_DIR   # Container'a readonly mount edilecek host keyring dizini
  SUDERRA_CONTAINER_KEYS_DIR # Container içindeki keyring yolu
  SOURCE_DATE_EPOCH       # Reproducible build için (varsayılan: git commit time)
EOF
    exit 0
fi

# Shell modu
if [ "${1}" = "--shell" ]; then
    exec docker run --rm -it \
        -v "${PROJECT_ROOT}:/workspace:rw" \
        -v "${HOST_OUTPUT_DIR}:/workspace/output:rw" \
        -v "${HOST_DL_DIR}:/workspace/dl:rw" \
        -v "${HOST_CCACHE_DIR}:/workspace/.ccache:rw" \
        "${KEYS_MOUNT_ARGS[@]}" \
        "${DOCKER_USER_ARGS[@]}" \
        -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        -e BR2_CCACHE_DIR=/workspace/.ccache \
        -e SUDERRA_KEYS_DIR="${CONTAINER_KEYS_DIR}" \
        "${EXTRA_ENV[@]}" \
        -w /workspace \
        suderra-builder:latest \
        /bin/bash
fi

# Build modu
DEFCONFIG="${1}"
echo "==> Suderra OS build (Docker): ${DEFCONFIG}"
echo "==> SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH}"

run_build() {
    docker run --rm \
        -v "${PROJECT_ROOT}:/workspace:rw" \
        -v "${HOST_OUTPUT_DIR}:/workspace/output:rw" \
        -v "${HOST_DL_DIR}:/workspace/dl:rw" \
        -v "${HOST_CCACHE_DIR}:/workspace/.ccache:rw" \
        "${KEYS_MOUNT_ARGS[@]}" \
        "${DOCKER_USER_ARGS[@]}" \
        -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        -e BR2_CCACHE_DIR=/workspace/.ccache \
        -e SUDERRA_KEYS_DIR="${CONTAINER_KEYS_DIR}" \
        "${EXTRA_ENV[@]}" \
        -w /workspace \
        suderra-builder:latest \
        /workspace/scripts/build.sh "${DEFCONFIG}"
}

if [ -n "${SUDERRA_DOCKER_BUILD_LOG:-}" ]; then
    mkdir -p "$(dirname "${SUDERRA_DOCKER_BUILD_LOG}")"
    set +e
    run_build 2>&1 | tee "${SUDERRA_DOCKER_BUILD_LOG}"
    status="${PIPESTATUS[0]}"
    set -e
    exit "${status}"
fi

exec docker run --rm \
    -v "${PROJECT_ROOT}:/workspace:rw" \
    -v "${HOST_OUTPUT_DIR}:/workspace/output:rw" \
    -v "${HOST_DL_DIR}:/workspace/dl:rw" \
    -v "${HOST_CCACHE_DIR}:/workspace/.ccache:rw" \
    "${KEYS_MOUNT_ARGS[@]}" \
    "${DOCKER_USER_ARGS[@]}" \
    -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    -e BR2_CCACHE_DIR=/workspace/.ccache \
    -e SUDERRA_KEYS_DIR="${CONTAINER_KEYS_DIR}" \
    "${EXTRA_ENV[@]}" \
    -w /workspace \
    suderra-builder:latest \
    /workspace/scripts/build.sh "${DEFCONFIG}"

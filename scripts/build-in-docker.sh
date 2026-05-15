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

# Geliştirme anahtarları varsa mount et
KEYS_MOUNT_ARGS=()
if [ -d "${HOME}/.suderra-keys" ]; then
    KEYS_MOUNT_ARGS=(-v "${HOME}/.suderra-keys:/home/builder/.suderra-keys:ro")
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
$(ls -1 "${PROJECT_ROOT}/configs/" | sed 's/^/  /')

Çevre değişkenleri:
  SUDERRA_KEYS_DIR        # Build sırasında kullanılacak anahtarlar (varsayılan: ~/.suderra-keys/dev)
  SOURCE_DATE_EPOCH       # Reproducible build için (varsayılan: git commit time)
EOF
    exit 0
fi

# Shell modu
if [ "${1}" = "--shell" ]; then
    exec docker run --rm -it \
        -v "${PROJECT_ROOT}:/workspace:rw" \
        -v suderra-dl:/workspace/dl \
        -v suderra-ccache:/workspace/.ccache \
        "${KEYS_MOUNT_ARGS[@]}" \
        "${DOCKER_USER_ARGS[@]}" \
        -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        -e SUDERRA_KEYS_DIR=/home/builder/.suderra-keys/dev \
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
        -v suderra-dl:/workspace/dl \
        -v suderra-ccache:/workspace/.ccache \
        "${KEYS_MOUNT_ARGS[@]}" \
        "${DOCKER_USER_ARGS[@]}" \
        -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        -e SUDERRA_KEYS_DIR=/home/builder/.suderra-keys/dev \
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
    -v suderra-dl:/workspace/dl \
    -v suderra-ccache:/workspace/.ccache \
    "${KEYS_MOUNT_ARGS[@]}" \
    "${DOCKER_USER_ARGS[@]}" \
    -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    -e SUDERRA_KEYS_DIR=/home/builder/.suderra-keys/dev \
    "${EXTRA_ENV[@]}" \
    -w /workspace \
    suderra-builder:latest \
    /workspace/scripts/build.sh "${DEFCONFIG}"

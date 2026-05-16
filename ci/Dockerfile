# Suderra OS — Build Container
#
# Reproducible build için pinli Ubuntu 24.04 base.
# Buildroot 2024.11 LTS bağımlılıklarını içerir.
#
# Build:
#   docker build -t suderra-builder ci/
#
# Çalıştır:
#   ./scripts/build-in-docker.sh suderra_qemu_x86_64_defconfig

FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILDROOT_VERSION=2024.11

# Reproducible build için locale ve timezone sabitle
ENV LC_ALL=C
ENV TZ=UTC
ENV SOURCE_DATE_EPOCH=1704067200
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Buildroot core dependencies
    build-essential \
    git \
    libncurses-dev \
    rsync \
    bc \
    cpio \
    python3 \
    python3-pip \
    unzip \
    wget \
    bison \
    flex \
    gettext \
    libssl-dev \
    libelf-dev \
    file \
    # Cross-build helpers
    bash \
    perl \
    sed \
    binutils \
    diffutils \
    findutils \
    gawk \
    grep \
    gzip \
    make \
    patch \
    tar \
    which \
    xz-utils \
    # Image generation
    parted \
    dosfstools \
    mtools \
    e2fsprogs \
    # Signing / SBOM / dm-verity (production gate verification)
    openssl \
    cryptsetup-bin \
    # QEMU for testing
    qemu-system-x86 \
    qemu-system-arm \
    qemu-utils \
    # Quality / security
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Some upstream package install hooks attempt host-side chown when the
# container is run as root. Buildroot later enforces target permissions via
# fakeroot, but keeping expected system groups present prevents hidden install
# hook errors from polluting build evidence.
RUN set -eux; \
    getent group dbus >/dev/null || groupadd -r dbus

# Non-root build user (reproducible build için uid sabit)
RUN set -eux; \
    existing_group="$(getent group 1000 | cut -d: -f1 || true)"; \
    if [ -n "${existing_group}" ]; then \
        groupmod -n builder "${existing_group}"; \
    else \
        groupadd -g 1000 builder; \
    fi; \
    if id -u 1000 >/dev/null 2>&1; then \
        usermod -l builder -d /home/builder -m "$(getent passwd 1000 | cut -d: -f1)"; \
        usermod -g builder builder; \
    else \
        useradd -m -u 1000 -g 1000 -s /bin/bash builder; \
    fi

WORKDIR /workspace
USER builder

# Buildroot home cache dizini
ENV BR2_DL_DIR=/workspace/dl
ENV CCACHE_DIR=/workspace/.ccache

# Default komut: shell — script üzerinden override edilir
CMD ["/bin/bash"]

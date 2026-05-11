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

FROM ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILDROOT_VERSION=2024.11

# Reproducible build için locale ve timezone sabitle
ENV LC_ALL=C
ENV TZ=UTC
ENV SOURCE_DATE_EPOCH=1704067200

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
    # Signing / SBOM
    openssl \
    # QEMU for testing
    qemu-system-x86 \
    qemu-system-arm \
    qemu-utils \
    # Quality / security
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Non-root build user (reproducible build için uid sabit)
RUN groupadd -g 1000 builder && \
    useradd -m -u 1000 -g 1000 -s /bin/bash builder

WORKDIR /workspace
USER builder

# Buildroot home cache dizini
ENV BR2_DL_DIR=/workspace/dl
ENV CCACHE_DIR=/workspace/.ccache

# Default komut: shell — script üzerinden override edilir
CMD ["/bin/bash"]

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Builds pieces of the U-Boot Buildroot pins, for the tests that run the
# production boot logic (ADR-048 DEC-18; tests/qemu/arm-fit-signature-boot.sh,
# tests/image-contracts/arm-signed-fit-contract-test.sh):
#
#   uboot-build.sh tools <out-dir>
#       the host tools of that U-Boot (mkimage, dumpimage, fit_check_sign,
#       mkenvimage) into <out-dir>/bin. fit_check_sign is U-Boot's own FIT
#       signature verifier; Buildroot's host-uboot-tools installs it for the
#       image build, a plain distribution package does not.
#   uboot-build.sh qemu <out-dir> <default-env-file> [control]
#       the QEMU arm64 U-Boot with the shared production hardening fragment,
#       board/suderra/uboot/qemu-arm64.config and <default-env-file> as its
#       default environment: <out-dir>/qemu/u-boot.bin and .config, and
#       <out-dir>/src, the patched source the Kconfig symbols are read from.
#       The build is checked against the production policy
#       (check-uboot-config.py resolved) before it is compiled. With "control"
#       the environment is not checked and the build goes to <out-dir>/qemu-control:
#       the boot test uses it to show what the production environment's guard
#       prevents (an environment without it), never as a U-Boot to ship.
#   uboot-build.sh sandbox <out-dir> <default-env-file>
#       U-Boot's sandbox (a U-Boot that runs as a host process) with
#       <default-env-file> as its default environment: <out-dir>/sandbox/u-boot
#       and <out-dir>/sandbox/arch/sandbox/dts/sandbox.dtb. The image-contract
#       tests execute the production environment's scripts with it (the key
#       guard against fixture device trees, the A/B slot choice against a table
#       of counters), so what they prove is what U-Boot runs, not what a regex
#       reads. It has none of the production fragments: it is a test tool.
#
# The source is the tarball buildroot/boot/uboot names, fetched from
# SUDERRA_UBOOT_MIRROR (default: the site Buildroot uses), checked against the
# sha256 in buildroot/boot/uboot/uboot.hash on every use, and patched with
# board/suderra/uboot/patches exactly as Buildroot patches it. The tarball is
# cached in SUDERRA_UBOOT_CACHE (default ~/.cache/suderra-uboot).
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
HASH_FILE="${ROOT}/buildroot/boot/uboot/uboot.hash"
PATCH_DIR="${ROOT}/board/suderra/uboot/patches"
MIRROR="${SUDERRA_UBOOT_MIRROR:-https://ftp.denx.de/pub/u-boot}"
CACHE="${SUDERRA_UBOOT_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/suderra-uboot}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1 ($2)"
}

# The tarball line of uboot.hash: "sha256  <hash>  u-boot-<version>.tar.bz2".
IFS=' ' read -r _ SHA256 TARBALL < <(grep -E '^sha256 +[0-9a-f]{64} +u-boot-[0-9.]+\.tar\.bz2$' "${HASH_FILE}" || true)
[ -n "${SHA256:-}" ] && [ -n "${TARBALL:-}" ] || die "${HASH_FILE} names no u-boot tarball"

fetch_tarball() {
    local path="${CACHE}/${TARBALL}" part

    mkdir -p "${CACHE}"
    if [ ! -f "${path}" ]; then
        need curl "downloads the U-Boot source"
        part="$(mktemp "${CACHE}/${TARBALL}.XXXXXX")"
        curl -fsSL --retry 3 -o "${part}" "${MIRROR}/${TARBALL}" || {
            rm -f "${part}"
            die "could not download ${MIRROR}/${TARBALL}"
        }
        mv -f "${part}" "${path}"
    fi
    if ! printf '%s  %s\n' "${SHA256}" "${path}" | sha256sum -c --quiet - 2>/dev/null; then
        rm -f "${path}"
        die "${TARBALL} does not match the sha256 in ${HASH_FILE}; removed it from the cache"
    fi
    printf '%s\n' "${path}"
}

prepare_source() {
    local out="$1" tarball patch

    if [ -f "${out}/src/.suderra-prepared" ]; then
        return 0
    fi
    need patch "applies board/suderra/uboot/patches"
    tarball="$(fetch_tarball)"
    rm -rf "${out}/src"
    mkdir -p "${out}/src"
    tar -xjf "${tarball}" -C "${out}/src" --strip-components=1
    for patch in "${PATCH_DIR}"/*.patch; do
        [ -f "${patch}" ] || die "no patch in ${PATCH_DIR}"
        patch -s -p1 -d "${out}/src" < "${patch}" || die "${patch} does not apply to ${TARBALL}"
    done
    : > "${out}/src/.suderra-prepared"
}

build_tools() {
    local out="$1" cfg="$1/tools-build"

    need gcc "builds the U-Boot host tools"
    need make "builds the U-Boot host tools"
    need bison "U-Boot's Kconfig and dtc"
    need flex "U-Boot's Kconfig and dtc"
    prepare_source "${out}"
    rm -rf "${cfg}"
    mkdir -p "${cfg}" "${out}/bin"
    make -s -C "${out}/src" O="${cfg}" tools-only_defconfig >/dev/null
    # The capsule tool needs gnutls headers that the build host may not have.
    sed -i 's/^CONFIG_TOOLS_MKEFICAPSULE=y$/# CONFIG_TOOLS_MKEFICAPSULE is not set/' "${cfg}/.config"
    make -s -C "${out}/src" O="${cfg}" olddefconfig >/dev/null
    make -s -C "${out}/src" O="${cfg}" -j"$(nproc)" tools-only >/dev/null
    install -m 0755 "${cfg}/tools/mkimage" "${cfg}/tools/dumpimage" "${cfg}/tools/fit_check_sign" \
        "${cfg}/tools/mkenvimage" "${out}/bin/"
    echo "==> U-Boot host tools in ${out}/bin"
}

build_qemu() {
    local out="$1" envfile="$2" mode="${3:-production}" cfg="$1/qemu"
    local hardening="${ROOT}/board/suderra/uboot/hardening.config"
    local qemu_frag="${ROOT}/board/suderra/uboot/qemu-arm64.config"
    local envfrag="${out}/qemu-env.config"

    need aarch64-linux-gnu-gcc "gcc-aarch64-linux-gnu"
    need make "builds U-Boot"
    need bison "U-Boot's Kconfig and dtc"
    need flex "U-Boot's Kconfig and dtc"
    need swig "U-Boot's pylibfdt"
    [ -f "${envfile}" ] || die "no default environment file: ${envfile}"
    case "${mode}" in
        production) ;;
        control) cfg="${out}/qemu-control" ;;
        *) die "unknown mode ${mode}: production or control" ;;
    esac
    prepare_source "${out}"
    rm -rf "${cfg}"
    mkdir -p "${cfg}"
    printf 'CONFIG_USE_DEFAULT_ENV_FILE=y\nCONFIG_DEFAULT_ENV_FILE="%s"\n' "$(readlink -f "${envfile}")" > "${envfrag}"
    make -s -C "${out}/src" O="${cfg}" qemu_arm64_defconfig CROSS_COMPILE=aarch64-linux-gnu- >/dev/null
    # The same merge Buildroot's kconfig-package does: the fragments on top of
    # the board defconfig, then olddefconfig.
    "${out}/src/scripts/kconfig/merge_config.sh" -m -O "${cfg}" "${cfg}/.config" \
        "${hardening}" "${qemu_frag}" "${envfrag}" >/dev/null 2>&1
    make -s -C "${out}/src" O="${cfg}" olddefconfig CROSS_COMPILE=aarch64-linux-gnu- >/dev/null
    if [ "${mode}" = production ]; then
        python3 -I "${ROOT}/scripts/ci/check-uboot-config.py" --root "${ROOT}" resolved \
            --profile qemu-test --fragments "${hardening}" "${qemu_frag}" --env-file "${envfile}" \
            --uboot-tree "${out}/src" --dotconfig "${cfg}/.config"
    fi
    make -s -C "${out}/src" O="${cfg}" -j"$(nproc)" CROSS_COMPILE=aarch64-linux-gnu- >/dev/null
    [ -s "${cfg}/u-boot.bin" ] || die "the QEMU U-Boot build left no u-boot.bin"
    echo "==> QEMU U-Boot: ${cfg}/u-boot.bin"
}

build_sandbox() {
    local out="$1" envfile="$2" cfg="$1/sandbox"
    local envfrag="${out}/sandbox-env.config" frag="${out}/sandbox-test.config"

    need gcc "builds the U-Boot sandbox"
    need make "builds the U-Boot sandbox"
    need bison "U-Boot's Kconfig and dtc"
    need flex "U-Boot's Kconfig and dtc"
    need swig "U-Boot's pylibfdt"
    [ -f "${envfile}" ] || die "no default environment file: ${envfile}"
    prepare_source "${out}"
    rm -rf "${cfg}"
    mkdir -p "${cfg}"
    printf 'CONFIG_USE_DEFAULT_ENV_FILE=y\nCONFIG_DEFAULT_ENV_FILE="%s"\n' "$(readlink -f "${envfile}")" > "${envfrag}"
    # No SDL (a display the tests never use) and no EFI capsule tool (it needs
    # gnutls headers the build host may not have).
    printf '# CONFIG_VIDEO_SANDBOX_SDL is not set\n# CONFIG_EFI_CAPSULE_AUTHENTICATE is not set\n# CONFIG_TOOLS_MKEFICAPSULE is not set\n' > "${frag}"
    make -s -C "${out}/src" O="${cfg}" sandbox_defconfig >/dev/null
    "${out}/src/scripts/kconfig/merge_config.sh" -m -O "${cfg}" "${cfg}/.config" "${frag}" "${envfrag}" >/dev/null 2>&1
    make -s -C "${out}/src" O="${cfg}" olddefconfig >/dev/null
    make -s -C "${out}/src" O="${cfg}" -j"$(nproc)" >/dev/null
    [ -x "${cfg}/u-boot" ] || die "the sandbox build left no u-boot"
    [ -s "${cfg}/arch/sandbox/dts/sandbox.dtb" ] || die "the sandbox build left no sandbox.dtb"
    echo "==> U-Boot sandbox: ${cfg}/u-boot"
}

case "${1:-}" in
    tools)
        [ "$#" -eq 2 ] || die "usage: uboot-build.sh tools <out-dir>"
        mkdir -p "$2"
        build_tools "$(cd -- "$2" && pwd)"
        ;;
    qemu)
        [ "$#" -eq 3 ] || [ "$#" -eq 4 ] || die "usage: uboot-build.sh qemu <out-dir> <default-env-file> [control]"
        mkdir -p "$2"
        build_qemu "$(cd -- "$2" && pwd)" "$3" "${4:-production}"
        ;;
    sandbox)
        [ "$#" -eq 3 ] || die "usage: uboot-build.sh sandbox <out-dir> <default-env-file>"
        mkdir -p "$2"
        build_sandbox "$(cd -- "$2" && pwd)" "$3"
        ;;
    *)
        die "usage: uboot-build.sh tools <out-dir> | qemu <out-dir> <default-env-file> [control] | sandbox <out-dir> <default-env-file>"
        ;;
esac

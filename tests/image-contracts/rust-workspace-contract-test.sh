#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
EXTERNAL_MK="${ROOT}/external.mk"
LOCKFILE="${ROOT}/userspace/Cargo.lock"
TOOLCHAIN="${ROOT}/userspace/rust-toolchain.toml"
WORKSPACE="${ROOT}/userspace/Cargo.toml"

grep -q 'SUDERRA_RUST_WORKSPACE_BUILD' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: external.mk must define a shared Rust workspace build contract" >&2
        exit 1
    }
grep -q 'RUSTC_TARGET_NAME' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: Rust workspace contract must use Buildroot RUSTC_TARGET_NAME" >&2
        exit 1
    }
grep -q 'TARGET_CONFIGURE_OPTS' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: Rust workspace contract must inherit Buildroot target toolchain env" >&2
        exit 1
    }
grep -q 'PKG_CARGO_ENV' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: Rust workspace contract must inherit Buildroot cargo env" >&2
        exit 1
    }
grep -q 'CARGO_TARGET_DIR="$(@D)/cargo-target"' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: Rust workspace builds must write package-local cargo outputs" >&2
        exit 1
    }
grep -q -- '--locked' "${EXTERNAL_MK}" ||
    {
        echo "ERROR: Rust workspace builds must honor Cargo.lock" >&2
        exit 1
    }
test -f "${LOCKFILE}" ||
    {
        echo "ERROR: userspace/Cargo.lock must be present for fail-closed Rust builds" >&2
        exit 1
    }
grep -q 'channel = "1.86.0"' "${TOOLCHAIN}" ||
    {
        echo "ERROR: userspace/rust-toolchain.toml must pin Rust 1.86.0" >&2
        exit 1
    }
grep -q 'rust-version = "1.86"' "${WORKSPACE}" ||
    {
        echo "ERROR: userspace/Cargo.toml must declare rust-version 1.86" >&2
        exit 1
    }
git -C "${ROOT}/buildroot" show HEAD:package/rust/rust.mk | grep -q 'RUST_VERSION = 1.86.0' ||
    {
        echo "ERROR: Buildroot native rust package must be version 1.86.0" >&2
        exit 1
    }
git -C "${ROOT}/buildroot" show HEAD:package/rust-bin/rust-bin.mk | grep -q 'RUST_BIN_VERSION = 1.86.0' ||
    {
        echo "ERROR: Buildroot native rust-bin package must be version 1.86.0" >&2
        exit 1
    }
git -C "${ROOT}/buildroot" show HEAD:package/pkg-download.mk | grep -q 'BR_FMT_VERSION_cargo = -cargo4' ||
    {
        echo "ERROR: Buildroot 2025.05.3 cargo vendor archive format must be cargo4" >&2
        exit 1
    }
grep -q 'BR2_PACKAGE_SUDERRA_EDGE_AGENT_CARGO4_HASH_REVALIDATED' \
    "${ROOT}/package/suderra-edge-agent/Config.in" ||
    {
        echo "ERROR: suderra-edge-agent must stay gated until its cargo4 hash is revalidated" >&2
        exit 1
    }
if grep -R '^BR2_PACKAGE_SUDERRA_EDGE_AGENT=y' "${ROOT}/configs"; then
    echo "ERROR: suderra-edge-agent cannot be enabled until its Buildroot 2025.05 cargo4 hash is revalidated" >&2
    exit 1
fi
if grep -R 'Rust 1\.85' "${ROOT}/docs/dev/rust-workspace.md" "${ROOT}/userspace/README.md" "${ROOT}/docs/architecture/ARCHITECTURE.md"; then
    echo "ERROR: active Rust docs must not describe Rust 1.85 as the current pin" >&2
    exit 1
fi
git -C "${ROOT}" ls-files --error-unmatch userspace/Cargo.lock >/dev/null ||
    {
        echo "ERROR: userspace/Cargo.lock must be tracked in git" >&2
        exit 1
    }
git -C "${ROOT}" check-ignore -q userspace/Cargo.lock &&
    {
        echo "ERROR: userspace/Cargo.lock must not be ignored" >&2
        exit 1
    }

for mk in \
    "${ROOT}/package/suderra-os-installer/suderra-os-installer.mk" \
    "${ROOT}/package/suderra-firstboot/suderra-firstboot.mk"; do
    grep -q 'SUDERRA_RUST_WORKSPACE_BUILD' "${mk}" ||
        {
            echo "ERROR: ${mk} must use the shared Rust workspace build contract" >&2
            exit 1
        }
    grep -q 'cargo-target/$(RUSTC_TARGET_NAME)/release' "${mk}" ||
        {
            echo "ERROR: ${mk} must install from the package-local Buildroot Rust target dir" >&2
            exit 1
        }
done

for config in \
    "${ROOT}/package/suderra-os-installer/Config.in" \
    "${ROOT}/package/suderra-firstboot/Config.in"; do
    grep -q 'depends on BR2_PACKAGE_HOST_RUSTC_TARGET_ARCH_SUPPORTS' "${config}" ||
        {
            echo "ERROR: ${config} must be gated on Rust target support" >&2
            exit 1
        }
    grep -q 'depends on BR2_TOOLCHAIN_HAS_THREADS' "${config}" ||
        {
            echo "ERROR: ${config} must be gated on thread support for Rust binaries" >&2
            exit 1
        }
    grep -q 'select BR2_PACKAGE_HOST_RUSTC' "${config}" ||
        {
            echo "ERROR: ${config} must select Buildroot host-rustc" >&2
            exit 1
        }
done

if grep -R 'BR2_RUSTC_TARGET_NAME' "${ROOT}/package" --include='*.mk'; then
    echo "ERROR: package makefiles must not use BR2_RUSTC_TARGET_NAME; use RUSTC_TARGET_NAME" >&2
    exit 1
fi
if grep -R '^[[:space:]]*cargo build' "${ROOT}/package" --include='*.mk'; then
    echo "ERROR: package makefiles must not invoke bare cargo without Buildroot env" >&2
    exit 1
fi

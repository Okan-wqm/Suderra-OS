#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

WORKSPACE="${SUDERRA_RESOURCE_PATH:-${GITHUB_WORKSPACE:-$(pwd)}}"
MIN_DISK_GIB="${SUDERRA_MIN_DISK_GIB:-20}"
MIN_MEM_GIB="${SUDERRA_MIN_MEM_GIB:-3}"
MIN_VCPU="${SUDERRA_MIN_VCPU:-1}"
PARALLEL_JOBS="${SUDERRA_PARALLEL_JOBS:-1}"

# Disk is the single shared workspace partition: every parallel build job
# stages downloads, sysroots and output trees side-by-side, so the contract
# scales linearly. Memory and vCPU are per-job runner resources that the
# scheduler enforces at the runner level, not on the shared partition.
required_disk_gib=$((MIN_DISK_GIB * PARALLEL_JOBS))

available_disk_kib="$(df -Pk "${WORKSPACE}" | awk 'NR == 2 {print $4}')"
available_mem_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
available_vcpu="$(nproc)"
min_disk_kib=$((required_disk_gib * 1024 * 1024))
min_mem_kib=$((MIN_MEM_GIB * 1024 * 1024))

echo "Runner resource contract:"
echo "  workspace: ${WORKSPACE}"
echo "  disk_available_gib: $((available_disk_kib / 1024 / 1024))"
echo "  memory_available_gib: $((available_mem_kib / 1024 / 1024))"
echo "  vcpu_available: ${available_vcpu}"
echo "  required_disk_gib: ${required_disk_gib} (per-job ${MIN_DISK_GIB} × ${PARALLEL_JOBS} parallel)"
echo "  required_memory_gib: ${MIN_MEM_GIB}"
echo "  required_vcpu: ${MIN_VCPU}"

if [ "${available_disk_kib}" -lt "${min_disk_kib}" ]; then
    echo "::error::Runner has insufficient workspace disk for full Buildroot image builds"
    exit 1
fi

if [ "${available_mem_kib}" -lt "${min_mem_kib}" ]; then
    echo "::error::Runner has insufficient available memory for full Buildroot image builds"
    exit 1
fi

if [ "${available_vcpu}" -lt "${MIN_VCPU}" ]; then
    echo "::error::Runner has insufficient vCPU capacity for the target Buildroot jlevel contract"
    exit 1
fi

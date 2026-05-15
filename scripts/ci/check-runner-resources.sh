#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
MIN_DISK_GIB="${SUDERRA_MIN_DISK_GIB:-20}"
MIN_MEM_GIB="${SUDERRA_MIN_MEM_GIB:-3}"
MIN_VCPU="${SUDERRA_MIN_VCPU:-1}"

available_disk_kib="$(df -Pk "${WORKSPACE}" | awk 'NR == 2 {print $4}')"
available_mem_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
available_vcpu="$(nproc)"
min_disk_kib=$((MIN_DISK_GIB * 1024 * 1024))
min_mem_kib=$((MIN_MEM_GIB * 1024 * 1024))

echo "Runner resource contract:"
echo "  workspace: ${WORKSPACE}"
echo "  disk_available_gib: $((available_disk_kib / 1024 / 1024))"
echo "  memory_available_gib: $((available_mem_kib / 1024 / 1024))"
echo "  vcpu_available: ${available_vcpu}"
echo "  required_disk_gib: ${MIN_DISK_GIB}"
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

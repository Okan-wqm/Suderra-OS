#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# GitHub-hosted Ubuntu runners carry large SDK/toolchain payloads that Suderra
# Buildroot image jobs do not use. Free them before enforcing disk contracts.
if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    echo "Not running in GitHub Actions; skipping hosted-runner disk cleanup."
    exit 0
fi

echo "Runner disk before cleanup:"
df -h / /mnt 2>/dev/null || df -h /

remove_path() {
    local path="$1"
    if [ -e "${path}" ]; then
        echo "Removing ${path}"
        sudo rm -rf "${path}"
    fi
}

remove_path /usr/share/dotnet
remove_path /usr/local/lib/android
remove_path /opt/ghc
remove_path /opt/hostedtoolcache/CodeQL
remove_path /usr/local/share/boost
remove_path /usr/local/.ghcup

if command -v docker >/dev/null 2>&1; then
    docker system prune -af --volumes || true
fi

sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

echo "Runner disk after cleanup:"
df -h / /mnt 2>/dev/null || df -h /

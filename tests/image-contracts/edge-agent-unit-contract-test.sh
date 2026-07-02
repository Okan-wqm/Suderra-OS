#!/usr/bin/env bash
#
# Edge Agent systemd unit sertleştirme sözleşmesi.
#
# Suderra-OS tek iş yükü çalıştırır: suderra-agent (IEC 62443 SL-2 hedefli).
# Paketlenen unit, upstream'in (aquaculture_platform/sens-api-gateway/systemd/)
# yük taşıyan sertleştirme direktiflerini korumak zorundadır — buradaki her
# token bilinçli bir savunma katmanıdır ve sessizce düşmesi saha cihazını
# zayıflatır.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT="${ROOT}/package/suderra-edge-agent/suderra-agent.service"

[ -f "${UNIT}" ] || {
    echo "ERROR: packaged edge-agent unit missing: ${UNIT}" >&2
    exit 1
}

# Yük taşıyan sertleştirme direktifleri (FR1/FR2/FR3/FR4/FR6/FR7 eşlemesi
# upstream unit yorumlarında).
for token in \
    'Type=notify' \
    'WatchdogSec=' \
    'User=suderra' \
    'UMask=0077' \
    'LimitCORE=0' \
    'MemoryMax=' \
    'CPUQuota=' \
    'TasksMax=' \
    'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
    'NoNewPrivileges=true' \
    'ProtectSystem=strict' \
    'ProtectHome=true' \
    'PrivateTmp=true' \
    'ProtectKernelTunables=true' \
    'ProtectKernelModules=true' \
    'ProtectKernelLogs=true' \
    'ProtectClock=true' \
    'ProtectProc=invisible' \
    'RestrictNamespaces=true' \
    'RestrictSUIDSGID=true' \
    'RestrictRealtime=true' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK' \
    'LockPersonality=true' \
    'MemoryDenyWriteExecute=true' \
    'SystemCallArchitectures=native' \
    'SystemCallFilter=@system-service' \
    'DevicePolicy=closed' \
    'StandardInput=null'
do
    grep -qF "${token}" "${UNIT}" || {
        echo "ERROR: edge-agent unit missing load-bearing hardening directive: ${token}" >&2
        exit 1
    }
done

# Donanım watchdog'unun tek sahibi suderra-watchdog daemon'udur; agent
# sd-notify kullanır. Agent'a /dev/watchdog erişimi geri gelirse, ele
# geçirilmiş bir agent magic-close'suz open/close ile cihazı resetleyebilir.
if grep -qE '^DeviceAllow=.*/dev/watchdog' "${UNIT}"; then
    echo "ERROR: edge-agent unit must not grant /dev/watchdog (owned by suderra-watchdog)" >&2
    exit 1
fi

# Sandbox'ı gevşeten tehlikeli direktifler hiç girmemeli.
for forbidden in \
    'PrivateDevices=false' \
    'ProtectSystem=false' \
    'NoNewPrivileges=false' \
    'User=root'
do
    if grep -qF "${forbidden}" "${UNIT}"; then
        echo "ERROR: edge-agent unit contains forbidden directive: ${forbidden}" >&2
        exit 1
    fi
done

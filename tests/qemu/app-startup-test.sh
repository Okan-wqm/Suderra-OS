#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
RAUC_HEALTH="${ROOT}/package/suderra-rauc-config/suderra-rauc-health-gate"
RAUC_MARK_GOOD_UNIT="${ROOT}/package/suderra-rauc-config/suderra-rauc-mark-good.service"
OTA_MARK_GOOD_UNIT="${ROOT}/package/suderra-ota/suderra-ota-mark-good.service"

grep -q 'enable_unit_if_present "suderra-agent.service"' "${POST_BUILD}" || {
    echo "ERROR: optional agent startup must only be enabled when the unit exists" >&2
    exit 1
}
if grep -q 'ln -sfn ../suderra-agent.service' "${POST_BUILD}"; then
    echo "ERROR: post-build must not create a dangling suderra-agent.service startup link" >&2
    exit 1
fi
grep -q 'systemctl is-active --quiet suderra-agent.service' "${RAUC_HEALTH}" || {
    echo "ERROR: RAUC health gate must verify agent startup when the agent unit is installed" >&2
    exit 1
}
grep -q 'RequiresMountsFor=/data /boot' "${RAUC_MARK_GOOD_UNIT}" || {
    echo "ERROR: mark-good startup must require durable /data and /boot" >&2
    exit 1
}
grep -q 'suderra-ota mark-good --skip-rauc' "${OTA_MARK_GOOD_UNIT}" || {
    echo "ERROR: OTA mark-good startup must persist rollback floor after RAUC mark-good" >&2
    exit 1
}

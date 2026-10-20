#!/usr/bin/env bash
#
# Agent startup and the single mark-good path (ADR-048 DEC-1.5, DEC-6.8).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
AGENT_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service"
RAUC_HEALTH="${ROOT}/package/suderra-rauc-config/suderra-rauc-health-gate"
RAUC_MARK_GOOD_UNIT="${ROOT}/package/suderra-rauc-config/suderra-rauc-mark-good.service"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# post-build enables only units that exist (a missing one fails the build),
# never through a hand-made, possibly dangling link.
grep -q 'enable_unit suderra-agent.service multi-user.target' "${POST_BUILD}" ||
    fail "post-build must enable the agent unit through enable_unit"
grep -q 'is not in the rootfs; it cannot be enabled' "${POST_BUILD}" ||
    fail "enable_unit must fail the build for a unit that is not in the rootfs"
if grep -q 'ln -sfn ../suderra-agent.service' "${POST_BUILD}"; then
    fail "post-build must not create a dangling suderra-agent.service startup link"
fi

# The agent starts once an install receipt exists, and root re-verifies the
# release before every start.
grep -qx 'ConditionPathExists=/data/suderra/os/edge/receipt.json' "${AGENT_UNIT}" ||
    fail "the agent unit must start once the root installer recorded an install receipt"
grep -qx 'ExecStartPre=+/usr/bin/suderra-installer edge verify-current' "${AGENT_UNIT}" ||
    fail "the agent unit must re-verify the release as root before every start"

grep -q 'systemctl is-active --quiet suderra-agent.service' "${RAUC_HEALTH}" ||
    fail "RAUC health gate must verify agent startup when the agent unit is installed"
grep -q 'RequiresMountsFor=/data /boot' "${RAUC_MARK_GOOD_UNIT}" ||
    fail "mark-good startup must require durable /data and /boot"
OTA_MARK_GOOD_UNIT="${ROOT}/package/suderra-ota/suderra-ota-mark-good.service"
grep -q 'ExecStart=/usr/bin/suderra-ota mark-good' "${OTA_MARK_GOOD_UNIT}" ||
    fail "OTA mark-good startup must let suderra-ota own RAUC mark-good"
if grep -q -- '--skip-rauc' "${OTA_MARK_GOOD_UNIT}"; then
    fail "OTA mark-good startup must not bypass RAUC mark-good ownership"
fi

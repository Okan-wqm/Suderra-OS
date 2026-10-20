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
RAUC_MARK_GOOD="${ROOT}/package/suderra-rauc-config/suderra-rauc-mark-good"
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

# Health gate: OS always, agent only after the verified activation receipt;
# the predicate is suderra-installer health check, not an instant is-active.
grep -q '/usr/bin/suderra-installer health check' "${RAUC_HEALTH}" ||
    fail "the RAUC health gate must call the OS and agent predicate"
if grep -q 'systemctl is-active' "${RAUC_HEALTH}"; then
    fail "the RAUC health gate must not judge the agent by an instant is-active"
fi
grep -q 'RequiresMountsFor=/data /boot' "${RAUC_MARK_GOOD_UNIT}" ||
    fail "mark-good startup must require durable /data and /boot"
grep -q 'ReadWritePaths=.*/run/suderra ' "${RAUC_MARK_GOOD_UNIT}" ||
    fail "mark-good must let the health predicate write its result under /run/suderra"

# One mark-good path: suderra-ota mark-good runs only from
# suderra-rauc-mark-good, after the health gate.
[ ! -e "${ROOT}/package/suderra-ota/suderra-ota-mark-good.service" ] ||
    fail "suderra-ota must not ship its own mark-good unit"
if grep -R -l '/usr/bin/suderra-ota mark-good' "${ROOT}/package" "${ROOT}/board" |
        grep -v -x "${RAUC_MARK_GOOD}"; then
    fail "suderra-ota mark-good may run only from suderra-rauc-mark-good"
fi
gate_line="$(grep -n 'suderra-rauc-health-gate' "${RAUC_MARK_GOOD}" | sed -n '$p' | cut -d: -f1)"
mark_line="$(grep -n '/usr/bin/suderra-ota mark-good' "${RAUC_MARK_GOOD}" | sed -n '1p' | cut -d: -f1)"
if [ -z "${gate_line}" ] || [ -z "${mark_line}" ] || [ "${gate_line}" -ge "${mark_line}" ]; then
    fail "suderra-rauc-mark-good must run the health gate before suderra-ota mark-good"
fi

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# QEMU edge e2e probe contract (static; ADR-048 P0 exit test).
#
# The probe gives the QEMU e2e tests a root-side observation and sandbox-run
# channel over the virtio-serial port org.suderra.e2e.0. It is a test
# affordance of the dev QEMU image only: this test keeps it out of every
# other image (the QEMU prod_ab image and every hardware board), keeps it
# from starting without the hypervisor's port, and keeps it to a fixed list
# of named probes. Its runtime behaviour is exercised by
# tests/qemu/edge-provisioning-e2e.py and friends in the edge-e2e CI job.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
PROBE="${OVERLAY}/usr/sbin/suderra-e2e-probe"
UNIT="${OVERLAY}/etc/systemd/system/suderra-e2e-probe.service"
RULE="${OVERLAY}/usr/lib/udev/rules.d/90-suderra-e2e-probe.rules"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for f in "${PROBE}" "${UNIT}" "${RULE}"; do
    [ -f "${f}" ] || fail "missing ${f#"${ROOT}"/}"
done

# 1. Only the dev QEMU image keeps it; every other image deletes all three.
python3 - "${POST_BUILD}" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
block = re.search(
    r'^if \[ "\$\{DEFCONFIG_NAME\}" = suderra_qemu_x86_64 \] && '
    r'config_enabled BR2_PACKAGE_SUDERRA_VARIANT_DEV; then\n'
    r'(?P<keep>.*?)\nelse\n(?P<drop>.*?)\nfi\n', text, re.M | re.S)
if block is None:
    sys.exit("post-build.sh must keep the e2e probe only for the dev suderra_qemu_x86_64 image")
if "rm -f" in block["keep"]:
    sys.exit("the dev QEMU branch must not delete the probe")
for path in ("usr/sbin/suderra-e2e-probe",
             "etc/systemd/system/suderra-e2e-probe.service",
             "usr/lib/udev/rules.d/90-suderra-e2e-probe.rules"):
    if path not in block["drop"]:
        sys.exit(f"post-build.sh must delete {path} from every other image")
if re.search(r"(enable_unit|preset_enable)\s+suderra-e2e-probe", text):
    sys.exit("the e2e probe is never enabled; only the hypervisor's port starts it")
PY

# 2. It starts only on the hypervisor's port, never by itself.
grep -qx 'ConditionPathExists=/dev/virtio-ports/org.suderra.e2e.0' "${UNIT}" ||
    fail "the probe unit must require the virtio-serial port"
grep -q '^\[Install\]' "${UNIT}" && fail "the probe unit must have no [Install] section"
grep -q 'ATTR{name}=="org.suderra.e2e.0"' "${RULE}" ||
    fail "the udev rule must match only the org.suderra.e2e.0 port"
grep -q 'ENV{SYSTEMD_WANTS}+="suderra-e2e-probe.service"' "${RULE}" ||
    fail "the udev rule must be what starts the probe"

# 3. A fixed list of named probes; anything else is refused, nothing read from
# the port is executed.
for probe in facts journal-agent journal-worker journal-activation journal-all \
    nft-smoke sandbox-agent sandbox-request sandbox-install; do
    grep -qE "^        ${probe}\) " "${PROBE}" || fail "probe ${probe} is missing"
done
grep -q '^        \*) emit error "unknown probe"; return 2 ;;' "${PROBE}" ||
    fail "an unknown probe name must be refused"
python3 - "${PROBE}" <<'PY'
import re
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
code = [l for l in lines if not l.lstrip().startswith("#")]
if any(re.search(r"\beval\b", l) for l in code):
    sys.exit("the probe must not eval anything")
# What the port delivers is ${line}, split into ${id} and ${name}: ${name}
# only selects a probe in run_probe's case, ${id} is only echoed back.
allowed = {
    'id="${line%% *}"',
    'name="${line#* }"',
    '(run_probe "${name}") >&3 2>/dev/null',
}
for l in code:
    stripped = l.strip()
    if ("${line" in stripped or "${name}" in stripped) and stripped not in allowed \
            and not stripped.startswith("while IFS= read -r line"):
        sys.exit(f"port input used outside the probe dispatch: {stripped}")
if not any(l.strip() == 'case "$1" in' for l in code[[i for i, l in enumerate(code) if l.startswith("run_probe()")][0]:]):
    sys.exit("run_probe must dispatch on a fixed case list")
PY

# 4. The tests the probe serves exist.
for t in edge-provisioning-e2e.py edge-readonly-sandbox-test.py nft-ruleset-smoke-test.py \
    fake_cloud.py edge_qemu.py; do
    [ -f "${ROOT}/tests/qemu/${t}" ] || fail "tests/qemu/${t} is missing"
done

sh -n "${PROBE}"
echo "edge e2e probe contract passed"

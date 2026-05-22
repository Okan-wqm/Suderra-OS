#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

BUILD_WORKFLOW="${PROJECT_ROOT}/.github/workflows/build.yml"

grep -q 'SUDERRA_REQUIRE_CLEAN_EXTERNAL: "1"' "${BUILD_WORKFLOW}" || {
    echo "ERROR: Build workflow must require a clean BR2_EXTERNAL tree" >&2
    exit 1
}

if grep -q 'payload-artifacts' "${BUILD_WORKFLOW}"; then
    echo "ERROR: payload job must not stage downloaded image artifacts inside the repo tree" >&2
    exit 1
fi

grep -q 'payload_inputs_root="${SUDERRA_HOST_OUTPUT_DIR}/payload-inputs"' "${BUILD_WORKFLOW}" || {
    echo "ERROR: payload job must stage input artifacts under CI storage/output" >&2
    exit 1
}

grep -q '^  build-payload-base:' "${BUILD_WORKFLOW}" || {
    echo "ERROR: Build workflow must split installer base build from payload assembly" >&2
    exit 1
}

grep -q 'SUDERRA_USB_INSTALLER_BASE_ONLY: "1"' "${BUILD_WORKFLOW}" || {
    echo "ERROR: installer base job must use USB installer base-only post-image mode" >&2
    exit 1
}

grep -q 'package-usb-installer-payload.py' "${BUILD_WORKFLOW}" || {
    echo "ERROR: payload job must assemble final installer without rerunning Buildroot" >&2
    exit 1
}

grep -q 'genimage-payload-packager.cfg' "${BUILD_WORKFLOW}" || {
    echo "ERROR: payload-only assembly must use the dedicated genimage packager contract" >&2
    exit 1
}

grep -q 'payload-inputs-manifest.py create' "${BUILD_WORKFLOW}" || {
    echo "ERROR: payload job must emit a digest-bound payload input manifest" >&2
    exit 1
}

grep -q 'buildroot-build-evidence.py collect' "${BUILD_WORKFLOW}" || {
    echo "ERROR: Build workflow must collect Buildroot timing/cache evidence" >&2
    exit 1
}

for subject in \
    '.build-time.log' \
    '.build-performance.json' \
    '.payload-inputs.json' \
    '.payload-package.json'; do
    grep -q "${subject}" "${BUILD_WORKFLOW}" || {
        echo "ERROR: Build attestations must include ${subject}" >&2
        exit 1
    }
done

if grep -q 'Build image (payload packaging run)' "${BUILD_WORKFLOW}"; then
    echo "ERROR: payload job must not keep the old full Buildroot packaging step" >&2
    exit 1
fi

grep -q 'genimage-base.cfg' "${PROJECT_ROOT}/board/suderra/common/post-image.sh" || {
    echo "ERROR: post-image must support base-only USB installer image generation" >&2
    exit 1
}

grep -q 'image payload.ext4' "${PROJECT_ROOT}/board/suderra/aarch64-rpi4-usb-installer/genimage-payload-packager.cfg" || {
    echo "ERROR: payload packager genimage config must create payload.ext4" >&2
    exit 1
}

if git -C "${PROJECT_ROOT}" check-ignore -q payload-inputs/sample.img.xz; then
    echo "ERROR: repo-local payload-inputs must not be ignored; CI should stage them outside the source tree" >&2
    exit 1
fi

cat >"${TMPDIR}/build-time.log" <<'EOF'
1.000000000:start:download            : host-example
1.500000000:end  :download            : host-example
2.000000000:start:build               : host-example
5.250000000:end  :build               : host-example
6.000000000:start:build               : linux
9.000000000:end  :build               : linux
EOF
mkdir -p "${TMPDIR}/ccache"
printf 'cache-object\n' >"${TMPDIR}/ccache/object"

python3 "${PROJECT_ROOT}/scripts/ci/buildroot-build-evidence.py" collect \
    --defconfig suderra_qemu_x86_64_defconfig \
    --build-time-log "${TMPDIR}/build-time.log" \
    --build-time-copy "${TMPDIR}/build-logs/suderra_qemu_x86_64_defconfig.build-time.log" \
    --ccache-dir "${TMPDIR}/ccache" \
    --output "${TMPDIR}/build-logs/suderra_qemu_x86_64_defconfig.build-performance.json"

python3 "${PROJECT_ROOT}/scripts/ci/buildroot-build-evidence.py" validate \
    "${TMPDIR}/build-logs/suderra_qemu_x86_64_defconfig.build-performance.json"

python3 -m py_compile \
    "${PROJECT_ROOT}/scripts/ci/buildroot-build-evidence.py" \
    "${PROJECT_ROOT}/scripts/ci/payload-inputs-manifest.py" \
    "${PROJECT_ROOT}/scripts/ci/package-usb-installer-payload.py"

python3 - "${TMPDIR}/build-logs/suderra_qemu_x86_64_defconfig.build-performance.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["schema_version"] == "suderra.buildroot-build-performance.v1"
assert payload["build_time_log"]["present"] is True
assert payload["timing"]["status"] == "collected"
assert payload["timing"]["completed_step_count"] == 3
assert payload["timing"]["top_packages"][0]["name"] == "host-example"
assert payload["ccache"]["present"] is True
assert payload["ccache"]["file_count"] == 1
PY

python3 - "${TMPDIR}/build-logs/suderra_qemu_x86_64_defconfig.build-performance.json" "${TMPDIR}/build-performance-malformed.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["timing"]["status"] = "corrupt"
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${PROJECT_ROOT}/scripts/ci/buildroot-build-evidence.py" validate \
    "${TMPDIR}/build-performance-malformed.json" 2>"${TMPDIR}/build-performance-malformed.err"; then
    echo "ERROR: Buildroot performance evidence accepted malformed timing status" >&2
    exit 1
fi
grep -q 'timing.status' "${TMPDIR}/build-performance-malformed.err" || {
    echo "ERROR: malformed performance evidence failure did not identify timing.status" >&2
    cat "${TMPDIR}/build-performance-malformed.err" >&2
    exit 1
}

printf 'rpi4-payload\n' >"${TMPDIR}/rpi4.img.xz"
printf 'revpi4-payload\n' >"${TMPDIR}/revpi4.img.xz"
SOURCE_SHA="1111111111111111111111111111111111111111"
python3 "${PROJECT_ROOT}/scripts/ci/payload-inputs-manifest.py" create \
    --defconfig suderra_aarch64_rpi4_usb_installer_defconfig \
    --source-sha "${SOURCE_SHA}" \
    --run-id 12345 \
    --run-attempt 1 \
    --output "${TMPDIR}/payload-inputs.json" \
    --input "suderra_aarch64_rpi4_defconfig:suderra-rpi4-target.img.xz:${TMPDIR}/rpi4.img.xz" \
    --input "suderra_aarch64_revpi4_defconfig:suderra-revpi4-target.img.xz:${TMPDIR}/revpi4.img.xz"

python3 "${PROJECT_ROOT}/scripts/ci/payload-inputs-manifest.py" validate \
    "${TMPDIR}/payload-inputs.json"

python3 - "${TMPDIR}/payload-inputs.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["schema_version"] == "suderra.payload-inputs.v1"
assert payload["source_sha"] == "1111111111111111111111111111111111111111"
assert [item["artifact"] for item in payload["inputs"]] == [
    "suderra-revpi4-target.img.xz",
    "suderra-rpi4-target.img.xz",
]
for item in payload["inputs"]:
    assert not item["artifact_path"].startswith("/")
    assert ".." not in item["artifact_path"]
PY

python3 - "${TMPDIR}/payload-inputs.json" "${TMPDIR}/payload-inputs-tampered.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["inputs"][0]["bytes"] += 1
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${PROJECT_ROOT}/scripts/ci/payload-inputs-manifest.py" validate \
    "${TMPDIR}/payload-inputs-tampered.json" 2>"${TMPDIR}/tampered.err"; then
    echo "ERROR: payload input manifest accepted tampered canonical input content" >&2
    exit 1
fi
grep -q 'inputs_sha256' "${TMPDIR}/tampered.err" || {
    echo "ERROR: tampered payload input failure did not identify inputs_sha256" >&2
    cat "${TMPDIR}/tampered.err" >&2
    exit 1
}

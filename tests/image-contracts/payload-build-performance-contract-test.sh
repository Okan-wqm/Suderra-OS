#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

FAST_WORKFLOW="${PROJECT_ROOT}/.github/workflows/build.yml"
IMAGE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/image-build.yml"

grep -q '^name: Build$' "${FAST_WORKFLOW}" || {
    echo "ERROR: fast required workflow must stay named Build" >&2
    exit 1
}
if grep -q 'Build image (full Buildroot run)' "${FAST_WORKFLOW}" ||
    grep -q '^  build-payload-base:' "${FAST_WORKFLOW}" ||
    grep -q '^  build-payload:' "${FAST_WORKFLOW}" ||
    grep -q '^  qemu-smoke-test:' "${FAST_WORKFLOW}"; then
    echo "ERROR: fast Build workflow must not run full image, payload, or QEMU jobs" >&2
    exit 1
fi

grep -q '^name: Image Build$' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: heavy workflow must be named Image Build" >&2
    exit 1
}
grep -q '^  build-payload-base:' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build must split installer base build from payload assembly" >&2
    exit 1
}
grep -q 'usb-installer-base-manifest.py create' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build must create a USB installer base manifest" >&2
    exit 1
}
grep -q 'usb-installer-base-' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build must upload digest-bound USB installer base artifacts" >&2
    exit 1
}
grep -q -- '--base-manifest' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: payload packager must consume the base manifest" >&2
    exit 1
}
grep -q -- '--payload-inputs-manifest' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: payload packager must consume the payload-input manifest" >&2
    exit 1
}
grep -q 'mkdir -p output' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: payload packager docker run must pre-create /workspace/output mountpoint" >&2
    exit 1
}
grep -q 'image-build-contract.py create' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build must publish an image build contract" >&2
    exit 1
}
grep -q 'build-performance-budget.py validate-buildroot' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build must enforce Buildroot performance evidence budgets" >&2
    exit 1
}
grep -q 'build-performance-budget.py validate-payload' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build must enforce payload packaging budget" >&2
    exit 1
}

python3 -B -m py_compile \
    "${PROJECT_ROOT}/scripts/ci/buildroot-build-evidence.py" \
    "${PROJECT_ROOT}/scripts/ci/payload-inputs-manifest.py" \
    "${PROJECT_ROOT}/scripts/ci/package-usb-installer-payload.py" \
    "${PROJECT_ROOT}/scripts/ci/usb-installer-base-manifest.py" \
    "${PROJECT_ROOT}/scripts/ci/image-build-contract.py" \
    "${PROJECT_ROOT}/scripts/ci/build-performance-budget.py"

python3 - "${PROJECT_ROOT}" "${TMPDIR}/image-contract-flat" <<'PY'
import importlib.util
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
tmp = Path(sys.argv[2])
artifact_root = tmp / "artifacts"
spec = importlib.util.spec_from_file_location(
    "validate_build_matrix",
    root / "scripts" / "ci" / "validate-build-matrix.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
matrix = module.load_matrix(root / "ci" / "build-matrix.yml")
for row in matrix["defconfigs"]:
    if not row.get("release"):
        continue
    defconfig = row["name"]
    for artifact in module.expected_artifacts(row):
        path = artifact_root / f"{defconfig}-image" / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{defconfig}:{artifact}\n", encoding="utf-8")
    evidence = [
        f"{defconfig}.log",
        f"{defconfig}.warnings.json",
        f"{defconfig}.source-identity.json",
        f"{defconfig}.build-time.log",
        f"{defconfig}.build-performance.json",
    ]
    if row.get("prebuild_defconfigs"):
        evidence.extend(
            [
                f"{defconfig}.payload-inputs.json",
                f"{defconfig}.payload-package.json",
                f"{defconfig}.usb-installer-base.json",
            ]
        )
    for artifact in evidence:
        path = artifact_root / f"{defconfig}-build-logs" / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{defconfig}:{artifact}\n", encoding="utf-8")
for arch in ("x86_64", "aarch64"):
    for artifact in (f"suderra-installer-{arch}", f"suderra-installer-{arch}.sha256"):
        path = artifact_root / f"installer-{arch}" / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{arch}:{artifact}\n", encoding="utf-8")
contract = tmp / "image-build-contract.json"
subprocess.run(
    [
        sys.executable,
        str(root / "scripts" / "ci" / "image-build-contract.py"),
        "create",
        "--source-sha",
        "1111111111111111111111111111111111111111",
        "--workflow-ref",
        "refs/heads/main",
        "--run-id",
        "12345",
        "--run-attempt",
        "1",
        "--artifact-root",
        str(artifact_root),
        "--output",
        str(contract),
    ],
    check=True,
)
subprocess.run(
    [
        sys.executable,
        str(root / "scripts" / "ci" / "image-build-contract.py"),
        "validate",
        str(contract),
        "--artifact-root",
        str(artifact_root),
        "--workflow-path",
        ".github/workflows/image-build.yml",
        "--source-sha",
        "1111111111111111111111111111111111111111",
        "--source-run-id",
        "12345",
        "--source-run-attempt",
        "1",
    ],
    check=True,
)
PY

mkdir -p "${TMPDIR}/base" "${TMPDIR}/out" "${TMPDIR}/keys" "${TMPDIR}/bin" "${TMPDIR}/logs"
printf 'boot base\n' >"${TMPDIR}/base/boot.vfat"
printf 'rootfs base\n' >"${TMPDIR}/base/rootfs.ext4"
printf 'rpi4 payload\n' | xz -c >"${TMPDIR}/rpi4.img.xz"
printf 'revpi4 payload\n' | xz -c >"${TMPDIR}/revpi4.img.xz"
openssl genpkey -algorithm ED25519 -out "${TMPDIR}/keys/installer-payload.key" >/dev/null 2>&1
openssl pkey -in "${TMPDIR}/keys/installer-payload.key" -pubout \
    -out "${TMPDIR}/keys/installer-payload.ed25519.pub" >/dev/null 2>&1

cat >"${TMPDIR}/bin/genimage" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --outputpath)
            output="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done
test -n "${output}"
cat "${output}/manifest.json" "${output}/manifest.sig" \
    "${output}/suderra-rpi4-target.img.xz" \
    "${output}/suderra-revpi4-target.img.xz" > "${output}/payload.ext4"
cat "${output}/boot.vfat" "${output}/rootfs.ext4" "${output}/payload.ext4" \
    > "${output}/suderra-pi-cm4-revpi-usb-installer.img"
EOF
chmod 0755 "${TMPDIR}/bin/genimage"

python3 "${PROJECT_ROOT}/scripts/ci/payload-inputs-manifest.py" create \
    --defconfig suderra_aarch64_rpi4_usb_installer_defconfig \
    --source-sha 1111111111111111111111111111111111111111 \
    --run-id 12345 \
    --run-attempt 1 \
    --output "${TMPDIR}/logs/payload-inputs.json" \
    --input "suderra_aarch64_rpi4_defconfig:suderra-rpi4-target.img.xz:${TMPDIR}/rpi4.img.xz" \
    --input "suderra_aarch64_revpi4_defconfig:suderra-revpi4-target.img.xz:${TMPDIR}/revpi4.img.xz"

printf '{"schema_version":"suderra.buildroot-source-identity.v2"}\n' >"${TMPDIR}/logs/source-identity.json"
printf '{"schema_version":"suderra.buildroot-build-performance.v1","build_time_log":{"present":true,"sha256":"%064d","bytes":1},"timing":{"status":"collected","completed_step_count":1},"ccache":{"present":true,"file_count":1,"total_bytes":1}}\n' 0 \
    >"${TMPDIR}/logs/build-performance.json"

python3 "${PROJECT_ROOT}/scripts/ci/usb-installer-base-manifest.py" create \
    --defconfig suderra_aarch64_rpi4_usb_installer_defconfig \
    --target pi-cm4-revpi-usb-installer \
    --source-sha 1111111111111111111111111111111111111111 \
    --workflow-ref refs/heads/main \
    --run-id 12345 \
    --run-attempt 1 \
    --source-date-epoch 1704067200 \
    --source-identity "${TMPDIR}/logs/source-identity.json" \
    --genimage-cfg "${PROJECT_ROOT}/board/suderra/aarch64-rpi4-usb-installer/genimage-base.cfg" \
    --public-key "${TMPDIR}/keys/installer-payload.ed25519.pub" \
    --build-evidence "${TMPDIR}/logs/build-performance.json" \
    --base-dir "${TMPDIR}/base" \
    --output "${TMPDIR}/logs/usb-installer-base.json"

PATH="${TMPDIR}/bin:${PATH}" python3 "${PROJECT_ROOT}/scripts/ci/package-usb-installer-payload.py" \
    --base-dir "${TMPDIR}/base" \
    --base-manifest "${TMPDIR}/logs/usb-installer-base.json" \
    --payload-inputs-manifest "${TMPDIR}/logs/payload-inputs.json" \
    --output-dir "${TMPDIR}/out" \
    --genimage-cfg "${PROJECT_ROOT}/board/suderra/aarch64-rpi4-usb-installer/genimage-payload-packager.cfg" \
    --rpi4-image "${TMPDIR}/rpi4.img.xz" \
    --revpi4-image "${TMPDIR}/revpi4.img.xz" \
    --sign-key "${TMPDIR}/keys/installer-payload.key" \
    --public-key "${TMPDIR}/keys/installer-payload.ed25519.pub" \
    --expires-at "2026-12-31T00:00:00Z" \
    --key-epoch 1 \
    --source-date-epoch 1704067200 \
    --evidence-output "${TMPDIR}/logs/payload-package.json" >/dev/null

for artifact in \
    manifest.json \
    manifest.sig \
    payload.ext4 \
    suderra-pi-cm4-revpi-usb-installer.img \
    suderra-pi-cm4-revpi-usb-installer.img.xz; do
    test -s "${TMPDIR}/out/${artifact}" || {
        echo "ERROR: packager did not create ${artifact}" >&2
        exit 1
    }
done

python3 - "${TMPDIR}/out/manifest.json" "${TMPDIR}/out/manifest.canonical" <<'PY'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
assert payload["payloads"][0]["image_path"] == "suderra-rpi4-target.img.xz"
assert payload["payloads"][1]["image_path"] == "suderra-revpi4-target.img.xz"
PY
openssl pkeyutl -verify -rawin -pubin \
    -inkey "${TMPDIR}/keys/installer-payload.ed25519.pub" \
    -sigfile "${TMPDIR}/out/manifest.sig" \
    -in "${TMPDIR}/out/manifest.canonical" >/dev/null

python3 - "${TMPDIR}/logs/payload-package.json" <<'PY'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["schema_version"] == "suderra.usb-installer-payload-package.v1"
assert len(payload["base_manifest_sha256"]) == 64
assert len(payload["payload_inputs_sha256"]) == 64
assert payload["partition_digest_map"]["payload.ext4"]
PY

cp "${TMPDIR}/base/boot.vfat" "${TMPDIR}/base/boot.vfat.good"
printf 'boot evil\n' >"${TMPDIR}/base/boot.vfat"
if PATH="${TMPDIR}/bin:${PATH}" python3 "${PROJECT_ROOT}/scripts/ci/package-usb-installer-payload.py" \
    --base-dir "${TMPDIR}/base" \
    --base-manifest "${TMPDIR}/logs/usb-installer-base.json" \
    --payload-inputs-manifest "${TMPDIR}/logs/payload-inputs.json" \
    --output-dir "${TMPDIR}/out-negative" \
    --genimage-cfg "${PROJECT_ROOT}/board/suderra/aarch64-rpi4-usb-installer/genimage-payload-packager.cfg" \
    --rpi4-image "${TMPDIR}/rpi4.img.xz" \
    --revpi4-image "${TMPDIR}/revpi4.img.xz" \
    --sign-key "${TMPDIR}/keys/installer-payload.key" \
    --public-key "${TMPDIR}/keys/installer-payload.ed25519.pub" \
    --expires-at "2026-12-31T00:00:00Z" \
    --key-epoch 1 >/dev/null 2>"${TMPDIR}/negative.err"; then
    echo "ERROR: packager accepted tampered base bytes" >&2
    exit 1
fi
grep -q 'base file sha mismatch' "${TMPDIR}/negative.err" || {
    cat "${TMPDIR}/negative.err" >&2
    exit 1
}

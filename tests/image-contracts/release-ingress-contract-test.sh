#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/release-ingress.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
BUILDROOT_INDEX_SHA="$(git -C "${PROJECT_ROOT}" ls-tree HEAD buildroot | awk '{print $3}')"

python3 - "${TMPDIR}" "${VERSION}" "${SOURCE_SHA}" "${BUILDROOT_INDEX_SHA}" "${PROJECT_ROOT}" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
version = sys.argv[2]
source_sha = sys.argv[3]
buildroot_index_sha = sys.argv[4]
project_root = Path(sys.argv[5])
artifact_root = root / "build-artifacts"

def write_artifact(rel: str, payload: bytes) -> tuple[int, str]:
    path = artifact_root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return len(payload), hashlib.sha256(payload).hexdigest()


def write_json(rel: str, payload: dict) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

entries = []
for artifact, payload in (
    ("disk.img.xz", b"qemu image\n"),
    ("MANIFEST.txt", b"manifest\n"),
):
    rel = f"suderra_qemu_x86_64_defconfig-image/{artifact}"
    size, digest = write_artifact(rel, payload)
    entries.append(
        {
            "defconfig": "suderra_qemu_x86_64_defconfig",
            "target": "qemu-x86_64",
            "artifact": artifact,
            "path": rel,
            "bytes": size,
            "sha256": digest,
        }
    )

build_evidence = []
for artifact, payload, role in (
    ("build-logs/suderra_qemu_x86_64_defconfig.log", b"build log\n", "build-log"),
    (
        "build-logs/suderra_qemu_x86_64_defconfig.warnings.json",
        b'{"summary":{"policy_errors":0}}\n',
        "warning-classifier-evidence",
    ),
):
    rel = f"suderra_qemu_x86_64_defconfig-build-logs/{artifact}"
    size, digest = write_artifact(rel, payload)
    build_evidence.append(
        {
            "role": role,
            "defconfig": "suderra_qemu_x86_64_defconfig",
            "target": "qemu-x86_64",
            "artifact": artifact,
            "path": rel,
            "bytes": size,
            "sha256": digest,
        }
    )

installers = []
for arch in ("x86_64", "aarch64"):
    for artifact, payload, role in (
        (f"suderra-installer-{arch}", f"installer {arch}\n".encode(), "installer"),
        (f"suderra-installer-{arch}.sha256", f"{'a' * 64}  suderra-installer-{arch}\n".encode(), "checksum"),
    ):
        rel = f"installer-{arch}/{artifact}"
        size, digest = write_artifact(rel, payload)
        installers.append(
            {
                "role": role,
                "arch": arch,
                "artifact": artifact,
                "path": rel,
                "bytes": size,
                "sha256": digest,
            }
        )

contract_payload = b'{"schema_version":"suderra.image-build-contract.v1"}\n'
contract_size, contract_digest = write_artifact("image-build-contract/image-build-contract.json", contract_payload)
metadata = json.loads(
    subprocess.check_output(
        [
            sys.executable,
            str(project_root / "scripts" / "ci" / "buildroot-patch-identity.py"),
            "metadata",
            "--source-sha",
            source_sha,
        ],
        text=True,
    )
)
binding_metadata = dict(metadata)
binding_metadata["buildroot_source_identity_schema_version"] = binding_metadata.pop("schema_version")

binding = {
    "schema_version": "suderra.release-input-binding.v2",
    "profile": "release-candidate",
    "version": version,
    "source_sha": source_sha,
    "source_run_id": "123456789",
    "source_run_attempt": "1",
    "build_workflow_name": "Image Build",
    "build_workflow_path": ".github/workflows/image-build.yml",
    "matrix_path": "ci/build-matrix.yml",
    "matrix_sha256": hashlib.sha256((project_root / "ci/build-matrix.yml").read_bytes()).hexdigest(),
    "artifacts": entries,
    "build_evidence": build_evidence,
    "installers": installers,
    "image_build_contract": {
        "role": "image-build-contract",
        "path": "image-build-contract/image-build-contract.json",
        "bytes": contract_size,
        "sha256": contract_digest,
    },
    "userspace_cargo_lock_sha256": hashlib.sha256((project_root / "userspace" / "Cargo.lock").read_bytes()).hexdigest(),
    "userspace_rust_toolchain_sha256": hashlib.sha256((project_root / "userspace" / "rust-toolchain.toml").read_bytes()).hexdigest(),
    "release_targets": [],
    "generated_at": "2026-05-13T00:00:00Z",
}
binding.update(binding_metadata)
path = root / "release-inputs" / version / "release-candidate.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")

targets = ("qemu-x86_64", "rpi4", "pi-cm4-revpi-usb-installer", "revpi4")
write_json(
    f"release-governance/{version}/audit-log.json",
    {
        "schema_version": "suderra.audit-log-snapshot.v1",
        "status": "collected",
        "source_kind": "manual-org-export",
        "organization": "Okan-wqm",
        "repository": "Okan-wqm/Suderra-OS",
        "collector": {"identity": "contract", "run_id": "123456789"},
        "lookback_window": {
            "start": "2026-04-24T00:00:00Z",
            "end": "2026-05-24T00:00:00Z",
            "days": 30
        },
        "query": "repo:Okan-wqm/Suderra-OS",
        "event_count": 0,
        "events_sha256": "a" * 64,
        "raw_export": {
            "path": "audit-log.raw.json",
            "bytes": 2,
            "sha256": "e" * 64
        },
        "replay": {"status": "passed", "unapproved_events": []},
        "unapproved_governance_changes": False,
    },
)
write_json(
    f"release-governance/{version}/station-registry.json",
    {"schema_version": "suderra.lab-station-registry.v1", "stations": []},
)
write_json(f"release-lab-input/{version}/qemu-x86_64/qemu.json", {"schema_version": "suderra.qemu-acceptance.v4"})
for target in ("rpi4", "pi-cm4-revpi-usb-installer", "revpi4"):
    write_json(f"release-lab-input/{version}/{target}/lab.json", {"schema_version": "suderra.lab-evidence.v3"})
for target in targets:
    write_json(
        f"release-approvals/{version}/{target}.json",
        {
            "schema_version": "suderra.release-approval.v2",
            "version": version,
            "target": target,
            "source_sha": source_sha,
        },
    )
    write_json(
        f"release-reproducibility/{version}/{target}.json",
        {
            "schema_version": "suderra.reproducibility.v1",
            "version": version,
            "target": target,
            "source_sha": source_sha,
            "source_run_id": "123456789",
        },
    )
PY

python3 "${PROJECT_ROOT}/scripts/evidence/operator-evidence-ingress.py" create \
    --input-root "${TMPDIR}" \
    --output "${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-image-build-run-id "123456789" \
    --source-image-build-run-attempt "1" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Evidence Ingress" \
    --run-id "222222222" \
    --run-attempt "1" \
    --actor "contract" \
    --bundle-url "https://operator-evidence.example.test/operator-evidence.tar.gz" \
    --bundle-sha256 "b${SOURCE_SHA:1:39}bbbbbbbbbbbbbbbbbbbbbbbb" \
    --bundle-signature-sha256 "c${SOURCE_SHA:1:39}cccccccccccccccccccccccc" \
    --bundle-certificate-sha256 "d${SOURCE_SHA:1:39}dddddddddddddddddddddddd" \
    --bundle-certificate-identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/operator-evidence.yml@refs/heads/main" \
    --bundle-certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle-allowed-host "operator-evidence.example.test" \
    >/dev/null
printf 'signature\n' >"${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json.sig"
printf 'certificate\n' >"${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json.cert"

python3 "${TOOL}" create \
    --binding-manifest "${TMPDIR}/release-inputs/${VERSION}/release-candidate.json" \
    --artifact-root "${TMPDIR}/build-artifacts" \
    --input-root "${TMPDIR}" \
    --output "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Preflight" \
    --run-id "987654321" \
    --run-attempt "1" \
    --actor "contract" \
    >/dev/null

python3 "${TOOL}" validate \
    "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    --artifact-root "${TMPDIR}/build-artifacts" \
    --input-root "${TMPDIR}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    >/dev/null

cp "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    "${TMPDIR}/release-ingress/${VERSION}/missing-evidence-ingress.json"
python3 - "${TMPDIR}/release-ingress/${VERSION}/missing-evidence-ingress.json" "${VERSION}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
manifest_path = f"release-ingress/{version}/evidence-ingress-manifest.json"
payload["files"] = [item for item in payload["files"] if item.get("path") != manifest_path]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/release-ingress/${VERSION}/missing-evidence-ingress.json" \
    --artifact-root "${TMPDIR}/build-artifacts" \
    --input-root "${TMPDIR}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    2>"${TMPDIR}/missing-evidence-ingress.err"; then
    echo "ERROR: ingress manifest accepted missing operator evidence ingress record" >&2
    exit 1
fi
grep -q "operator evidence ingress manifest" "${TMPDIR}/missing-evidence-ingress.err" || {
    echo "ERROR: missing evidence ingress failure did not cite operator evidence ingress" >&2
    cat "${TMPDIR}/missing-evidence-ingress.err" >&2
    exit 1
}

cp "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    "${TMPDIR}/release-ingress/${VERSION}/wrong-evidence-role.json"
python3 - "${TMPDIR}/release-ingress/${VERSION}/wrong-evidence-role.json" "${VERSION}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
manifest_path = f"release-ingress/{version}/evidence-ingress-manifest.json"
for item in payload["files"]:
    if item.get("path") == manifest_path:
        item["role"] = "preflight-input"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/release-ingress/${VERSION}/wrong-evidence-role.json" \
    --artifact-root "${TMPDIR}/build-artifacts" \
    --input-root "${TMPDIR}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    2>"${TMPDIR}/wrong-evidence-role.err"; then
    echo "ERROR: ingress manifest accepted a wrong operator evidence ingress role" >&2
    exit 1
fi
grep -q "preflight input path role" "${TMPDIR}/wrong-evidence-role.err" || {
    echo "ERROR: wrong evidence role failure did not cite role binding" >&2
    cat "${TMPDIR}/wrong-evidence-role.err" >&2
    exit 1
}

cp "${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    "${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json.bak"
python3 - "${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["source_sha"] = "f" * 40
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    --artifact-root "${TMPDIR}/build-artifacts" \
    --input-root "${TMPDIR}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    2>"${TMPDIR}/wrong-evidence-source.err"; then
    echo "ERROR: ingress manifest accepted a mismatched operator evidence source SHA" >&2
    exit 1
fi
grep -q "source_sha" "${TMPDIR}/wrong-evidence-source.err" || {
    echo "ERROR: wrong evidence source failure did not cite source_sha" >&2
    cat "${TMPDIR}/wrong-evidence-source.err" >&2
    exit 1
}
mv "${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json.bak" \
    "${TMPDIR}/release-ingress/${VERSION}/evidence-ingress-manifest.json"

printf 'tampered\n' >"${TMPDIR}/build-artifacts/suderra_qemu_x86_64_defconfig-image/disk.img.xz"
if python3 "${TOOL}" validate \
    "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    --artifact-root "${TMPDIR}/build-artifacts" \
    --input-root "${TMPDIR}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    2>"${TMPDIR}/tampered.err"; then
    echo "ERROR: ingress manifest accepted tampered artifact bytes" >&2
    exit 1
fi
grep -q "sha256" "${TMPDIR}/tampered.err" || {
    echo "ERROR: tampered ingress failure did not cite sha256" >&2
    cat "${TMPDIR}/tampered.err" >&2
    exit 1
}

python3 - "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["files"][0]["path"] = "../escape.img.xz"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
    2>"${TMPDIR}/path.err"; then
    echo "ERROR: ingress manifest accepted path traversal" >&2
    exit 1
fi
grep -q "must be relative" "${TMPDIR}/path.err" || {
    echo "ERROR: path traversal failure did not identify relative path contract" >&2
    cat "${TMPDIR}/path.err" >&2
    exit 1
}

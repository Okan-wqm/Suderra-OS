#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
BUILDROOT_INDEX_SHA="$(git -C "${PROJECT_ROOT}" ls-tree HEAD buildroot | awk '{print $3}')"

python3 - "${TMPDIR}" "${VERSION}" "${SOURCE_SHA}" "${BUILDROOT_INDEX_SHA}" "${PROJECT_ROOT}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
version = sys.argv[2]
source_sha = sys.argv[3]
buildroot_index_sha = sys.argv[4]
project_root = Path(sys.argv[5])

def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def write_evidence(path: Path, text: str) -> str:
    payload = text.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()

def write_json(path: Path, payload: object) -> None:
    write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

write_json(
    root / "release-governance" / version / "governance-policy-validation.json",
    {
        "schema_version": "suderra.github-governance-validation.v1",
        "status": "passed",
        "failures": [],
        "warnings": [],
    },
)

qemu_root = root / "release-lab-input" / version / "qemu-x86_64"
serial_sha = write_evidence(qemu_root / "serial.log", "serial boot evidence\n")
qmp_sha = write_evidence(qemu_root / "qmp.json", "qmp events\n")
stderr_sha = write_evidence(qemu_root / "qemu-stderr.log", "qemu stderr evidence\n")
qemu_checks = {
    name: {
        "status": "passed",
        "evidence": f"{name} semantic evidence",
        "source": "contract-fixture",
    }
    for name in (
        "boot",
        "systemd",
        "zero-failed-units",
        "no-kernel-panic",
        "no-emergency-mode",
        "os-release",
        "kernel",
        "rootfs",
        "network",
        "firstboot-idempotence",
        "lockdown-transition",
        "listeners",
        "firewall",
    )
}
write_json(
    qemu_root / "qemu.json",
    {
        "schema_version": "suderra.qemu-acceptance.v3",
        "version": version,
        "target": "qemu-x86_64",
        "source_sha": source_sha,
        "generated_at": "2026-05-13T00:00:00Z",
        "image": "suderra-qemu-x86_64.img",
        "image_sha256": "a" * 64,
        "qemu_version": "QEMU emulator version contract-test",
        "firmware": "OVMF_CODE.fd",
        "firmware_sha256": "b" * 64,
        "status": "passed",
        "logs": [
            {"role": "serial", "path": "serial.log", "sha256": serial_sha},
            {"role": "qmp-events", "path": "qmp.json", "sha256": qmp_sha},
            {"role": "qemu-stderr", "path": "qemu-stderr.log", "sha256": stderr_sha},
        ],
        "checks": qemu_checks,
        "guest_facts": {
            "os_release": {"ID": "suderra"},
            "kernel": "contract-test",
            "rootfs": {"partlabel": "rootfs"},
            "network": {"state": "up"},
            "listeners": [],
            "firewall": {"nft": "loaded"},
            "firstboot": {"idempotent": True},
            "lockdown": {"status": "locked"},
        },
    },
)

required_lab_checks = (
    "board-identity",
    "artifact-hash",
    "flash-transcript",
    "full-readback-hash",
    "serial-boot-log",
    "post-install-boot",
    "partitions",
    "root-data-mounts",
    "network",
    "listeners",
    "failed-units",
    "thermal",
    "watchdog",
)
boards_by_target = {
    "rpi4": ("raspberry-pi-4-model-b", "cm4-lite-sd", "cm4-emmc-io-board"),
    "pi-cm4-revpi-usb-installer": (
        "raspberry-pi-4-model-b",
        "cm4-lite-sd",
        "cm4-emmc-io-board",
        "revpi-connect-4",
    ),
    "revpi4": ("revpi-connect-4",),
}
negative_tests = (
    "no-target-disk",
    "ambiguous-targets",
    "usb-target-without-override",
    "tampered-payload",
    "bad-signature",
    "expired-manifest",
    "wrong-board",
    "small-target",
    "rollback-floor-violation",
)
for target, boards in boards_by_target.items():
    lab_root = root / "release-lab-input" / version / target
    devices = []
    for board in boards:
        log = f"logs/{board}.log"
        log_sha = write_evidence(lab_root / log, f"{board} serial transcript\n")
        checks = {}
        names = list(required_lab_checks)
        if board == "revpi-connect-4":
            names.append("revpi-io")
        for check in names:
            evidence = f"checks/{board}-{check}.log"
            evidence_sha = write_evidence(lab_root / evidence, f"{board} {check} evidence\n")
            checks[check] = {
                "status": "passed",
                "evidence": evidence,
                "evidence_sha256": evidence_sha,
                "command": f"collect {check}",
                "expected": "passed",
                "observed": "passed",
                "parsed_result": "passed",
            }
        devices.append(
            {
                "board": board,
                "serial": f"{board}-serial",
                "sku": "contract-sku",
                "storage_serial": f"{board}-storage",
                "uart_adapter": "uart-contract",
                "power_supply": "contract-5v-3a",
                "boot_firmware": "contract-firmware",
                "operator": "contract",
                "tested_at": "2026-05-13T00:00:00Z",
                "status": "passed",
                "logs": [{"path": log, "sha256": log_sha}],
                "device_identity": {
                    "model": board,
                    "compatible": f"suderra,{board}",
                    "storage_by_id": f"/dev/disk/by-id/{board}",
                    "storage_serial": f"{board}-storage",
                    "root_partuuid": f"{board}-partuuid",
                },
                "readback": {
                    "scope": "full",
                    "bytes_read": 1048576,
                    "expected_sha256": "e" * 64,
                    "actual_sha256": "e" * 64,
                    "command": "sha256sum full image readback",
                },
                "checks": checks,
            }
        )
    lab = {
        "schema_version": "suderra.lab-evidence.v3",
        "version": version,
        "target": target,
        "generated_at": "2026-05-13T00:00:00Z",
        "lab_id": "contract-lab",
        "operator": "contract",
        "station": {
            "station_id": "contract-station",
            "fixture_id": "contract-fixture",
            "operator_id": "contract",
            "trusted_key_fingerprint": "contract-key",
            "clock": "ntp-synchronized",
            "tool_versions": {"suderra-lab": "contract"},
        },
        "artifact_binding": {
            "version": version,
            "source_sha": source_sha,
            "source_run_id": "123456789",
            "release_assets_sha256": "f" * 64,
        },
        "devices": devices,
        "negative_tests": [],
    }
    if target == "pi-cm4-revpi-usb-installer":
        for name in negative_tests:
            evidence = f"negative/{name}.log"
            evidence_sha = write_evidence(lab_root / evidence, f"{name} closed-fail evidence\n")
            lab["negative_tests"].append(
                {
                    "name": name,
                    "failure_code": f"expected-{name}",
                    "status": "passed",
                    "evidence": evidence,
                    "evidence_sha256": evidence_sha,
                    "write_prevention": {"target_hash_unchanged": True},
                }
            )
    write_json(lab_root / "lab.json", lab)

for target in ("qemu-x86_64", "rpi4", "pi-cm4-revpi-usb-installer", "revpi4"):
    write_json(
        root / "release-approvals" / version / f"{target}.json",
        {
            "schema_version": "suderra.release-approval.v1",
            "version": version,
            "target": target,
            "status": "approved",
            "approver": "contract",
            "approved_at": "2026-05-13T00:00:00Z",
            "decision": "approve alpha residual risk",
        },
    )
    write(root / "release-reproducibility" / version / f"{target}.log", "reproducibility matched\n")

for scan in (
    "actionlint",
    "shellcheck",
    "yamllint",
    "markdownlint",
    "hadolint",
    "gitleaks",
    "rust-fmt",
    "rust-clippy",
    "rust-test",
    "cargo-deny",
    "trivy",
    "grype",
):
    write_json(root / "release-security" / version / f"{scan}.json", {"scan": scan, "status": "passed"})

binding_artifacts = []
for target, artifact in (
    ("qemu-x86_64", "disk.img"),
    ("rpi4", "suderra-rpi4-target.img"),
    ("pi-cm4-revpi-usb-installer", "suderra-pi-cm4-revpi-usb-installer.img"),
    ("revpi4", "suderra-revpi4-target.img"),
):
    binding_artifacts.append(
        {
            "defconfig": f"contract-{target}",
            "target": target,
            "artifact": artifact,
            "path": f"{target}/{artifact}",
            "bytes": 1024,
            "sha256": "1" * 64,
        }
    )
write_json(
    root / "release-inputs" / version / "release-candidate.json",
    {
        "schema_version": "suderra.release-input-binding.v1",
        "profile": "release-candidate",
        "version": version,
        "source_sha": source_sha,
        "source_run_id": "123456789",
        "source_run_attempt": "1",
        "build_workflow_name": "Build",
        "matrix_path": "ci/build-matrix.yml",
        "matrix_sha256": hashlib.sha256((project_root / "ci/build-matrix.yml").read_bytes()).hexdigest(),
        "buildroot_index_sha": buildroot_index_sha,
        "artifacts": binding_artifacts,
        "release_targets": [],
        "generated_at": "2026-05-13T00:00:00Z",
    },
)
PY

python3 "${PROJECT_ROOT}/scripts/evidence/validate-release-inputs.py" \
    --version "${VERSION}" \
    --release-tier alpha \
    --root "${TMPDIR}" \
    --profile release-candidate \
    --binding-manifest "${TMPDIR}/release-inputs/${VERSION}/release-candidate.json" \
    --source-sha "${SOURCE_SHA}" \
    --check-files \
    >/dev/null

python3 - "${TMPDIR}/release-lab-input/${VERSION}/qemu-x86_64/qemu.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["checks"].pop("firstboot-idempotence")
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${PROJECT_ROOT}/scripts/evidence/validate-release-inputs.py" \
    --version "${VERSION}" \
    --release-tier alpha \
    --root "${TMPDIR}" \
    --profile release-candidate \
    --binding-manifest "${TMPDIR}/release-inputs/${VERSION}/release-candidate.json" \
    --source-sha "${SOURCE_SHA}" \
    --check-files \
    2>"${TMPDIR}/release-inputs.err"; then
    echo "ERROR: release input preflight accepted incomplete QEMU checks" >&2
    exit 1
fi
grep -q "firstboot-idempotence" "${TMPDIR}/release-inputs.err" || {
    echo "ERROR: release input preflight did not report missing QEMU check" >&2
    cat "${TMPDIR}/release-inputs.err" >&2
    exit 1
}

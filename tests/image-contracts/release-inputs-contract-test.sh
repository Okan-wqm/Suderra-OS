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
import subprocess
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
            "schema_version": "suderra.release-approval.v2",
            "version": version,
            "target": target,
            "source_sha": source_sha,
            "approvals": [
                {
                    "role": "release-owner",
                    "name": "contract",
                    "approved_at": "2026-05-13T00:00:00Z",
                    "ticket": "TEST-APPROVAL",
                },
                {
                    "role": "security-compliance",
                    "name": "contract-security",
                    "approved_at": "2026-05-13T00:00:00Z",
                    "ticket": "TEST-APPROVAL",
                }
            ],
            "residual_risk": {
                "status": "accepted",
                "items": [
                    {
                        "id": "RR-ALPHA-001",
                        "severity": "high",
                        "description": "Alpha release intentionally lacks production gates.",
                        "mitigation": "Keep release prerelease-only.",
                        "owner": "release-owner@example.com",
                        "ticket": "TEST-APPROVAL",
                    }
                ],
                "accepted_by": "release-owner@example.com",
                "accepted_at": "2026-05-13T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            },
            "release_decision": {
                "status": "approved_with_residual_risk",
                "decided_by": "contract",
                "decided_at": "2026-05-13T00:00:00Z",
                "rationale": "approve alpha residual risk",
            },
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
    write_json(
        root / "release-security" / version / f"{scan}.json",
        {
            "schema_version": "suderra.release-security-report.v1",
            "version": version,
            "source_sha": source_sha,
            "source_run_id": "123456789",
            "scan": scan,
            "status": "passed",
            "generated_at": "2026-05-13T00:00:00Z",
            "tool": scan,
            "tool_version": "contract",
            "evidence_type": "contract-log",
            "evidence_sha256": hashlib.sha256(f"{scan} passed\n".encode("utf-8")).hexdigest(),
            "severity_counts": {"critical": 0, "high": 0},
        },
    )

binding_artifacts = []
build_evidence = []
for defconfig, target, artifacts in (
    ("suderra_qemu_x86_64_defconfig", "qemu-x86_64", ("disk.img", "disk.img.xz", "MANIFEST.txt")),
    (
        "suderra_aarch64_rpi4_defconfig",
        "rpi4",
        ("suderra-rpi4-target.img", "suderra-rpi4-target.img.xz", "MANIFEST.txt"),
    ),
    (
        "suderra_aarch64_rpi4_usb_installer_defconfig",
        "pi-cm4-revpi-usb-installer",
        (
            "suderra-pi-cm4-revpi-usb-installer.img",
            "suderra-pi-cm4-revpi-usb-installer.img.xz",
            "MANIFEST.txt",
            "manifest.json",
            "manifest.sig",
        ),
    ),
    (
        "suderra_aarch64_revpi4_defconfig",
        "revpi4",
        ("suderra-revpi4-target.img", "suderra-revpi4-target.img.xz", "MANIFEST.txt"),
    ),
):
    for artifact in artifacts:
        digest = "a" * 64 if target == "qemu-x86_64" and artifact == "disk.img" else hashlib.sha256(
            f"{defconfig}:{artifact}".encode("utf-8")
        ).hexdigest()
        binding_artifacts.append(
            {
                "defconfig": defconfig,
                "target": target,
                "artifact": artifact,
                "path": f"{defconfig}-image/{artifact}",
                "bytes": 1024,
                "sha256": digest,
            }
        )
    for artifact, role in (
        (f"build-logs/{defconfig}.log", "build-log"),
        (f"build-logs/{defconfig}.warnings.json", "warning-classifier-evidence"),
    ):
        build_evidence.append(
            {
                "role": role,
                "defconfig": defconfig,
                "target": target,
                "artifact": artifact,
                "path": f"{defconfig}-build-logs/{artifact}",
                "bytes": 128,
                "sha256": hashlib.sha256(f"{defconfig}:{artifact}".encode("utf-8")).hexdigest(),
            }
        )
installers = []
for arch in ("x86_64", "aarch64"):
    for artifact, role in (
        (f"suderra-installer-{arch}", "installer"),
        (f"suderra-installer-{arch}.sha256", "checksum"),
    ):
        installers.append(
            {
                "role": role,
                "arch": arch,
                "artifact": artifact,
                "path": f"installer-{arch}/{artifact}",
                "bytes": 256,
                "sha256": hashlib.sha256(f"{arch}:{artifact}".encode("utf-8")).hexdigest(),
            }
        )
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
binding = {
    "schema_version": "suderra.release-input-binding.v1",
    "profile": "release-candidate",
    "version": version,
    "source_sha": source_sha,
    "source_run_id": "123456789",
    "source_run_attempt": "1",
    "build_workflow_name": "Build",
    "matrix_path": "ci/build-matrix.yml",
    "matrix_sha256": hashlib.sha256((project_root / "ci/build-matrix.yml").read_bytes()).hexdigest(),
    "artifacts": binding_artifacts,
    "build_evidence": build_evidence,
    "installers": installers,
    "userspace_cargo_lock_sha256": hashlib.sha256((project_root / "userspace" / "Cargo.lock").read_bytes()).hexdigest(),
    "userspace_rust_toolchain_sha256": hashlib.sha256((project_root / "userspace" / "rust-toolchain.toml").read_bytes()).hexdigest(),
    "release_targets": [],
    "generated_at": "2026-05-13T00:00:00Z",
}
binding.update(metadata)
write_json(
    root / "release-inputs" / version / "release-candidate.json",
    binding,
)
ingress_files = []
for source, items in (
    ("build-artifact", binding_artifacts),
    ("build-evidence", build_evidence),
):
    for item in items:
        ingress_files.append(
            {
                "source": source,
                "role": item.get("role", "release-image" if item["artifact"].endswith((".img", ".img.xz")) else "build-artifact"),
                "defconfig": item["defconfig"],
                "target": item["target"],
                "artifact": item["artifact"],
                "path": item["path"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            }
        )
for item in installers:
    ingress_files.append(
        {
            "source": "installer-artifact",
            "role": item["role"],
            "defconfig": f"installer-{item['arch']}",
            "target": item["arch"],
            "artifact": item["artifact"],
            "path": item["path"],
            "bytes": item["bytes"],
            "sha256": item["sha256"],
        }
    )
write_json(
    root / "release-ingress" / version / "ingress-manifest.json",
    {
        "schema_version": "suderra.release-ingress.v1",
        "version": version,
        "profile": "release-candidate",
        "source_sha": source_sha,
        "source_run_id": "123456789",
        "source_run_attempt": "1",
        "build_workflow_name": "Build",
        "matrix_sha256": hashlib.sha256((project_root / "ci/build-matrix.yml").read_bytes()).hexdigest(),
        "buildroot_index_sha": metadata["buildroot_index_sha"],
        "buildroot_patchset_sha256": metadata["buildroot_patchset_sha256"],
        "buildroot_patch_files": metadata["buildroot_patch_files"],
        "buildroot_effective_source_id": metadata["buildroot_effective_source_id"],
        "buildroot_expected_patched": metadata["buildroot_expected_patched"],
        "producer": {
            "provider": "github-actions",
            "repository": "Okan-wqm/Suderra-OS",
            "workflow": "Release Preflight",
            "run_id": "987654321",
            "run_attempt": "1",
            "actor": "contract",
        },
        "generated_at": "2026-05-13T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "schema_roles": {
            "approval": "suderra.release-approval.v2",
            "binding_manifest": "suderra.release-input-binding.v1",
            "lab_input": "suderra.lab-evidence.v3",
            "qemu_input": "suderra.qemu-acceptance.v3",
            "release_evidence": "suderra.release-evidence.v3",
        },
        "files": ingress_files,
    },
)
PY

python3 "${PROJECT_ROOT}/scripts/evidence/validate-release-inputs.py" \
    --version "${VERSION}" \
    --release-tier alpha \
    --root "${TMPDIR}" \
    --profile release-candidate \
    --binding-manifest "${TMPDIR}/release-inputs/${VERSION}/release-candidate.json" \
    --ingress-manifest "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
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
    --ingress-manifest "${TMPDIR}/release-ingress/${VERSION}/ingress-manifest.json" \
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

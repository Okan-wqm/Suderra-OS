#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/release-evidence.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

EVIDENCE="${TMPDIR}/release-evidence/v9.9.9/qemu-x86_64/evidence.json"

python3 "${TOOL}" schema > "${TMPDIR}/schema.json"
python3 - "${TMPDIR}/schema.json" <<'PY'
import json
import sys

schema = json.loads(open(sys.argv[1], encoding="utf-8").read())
boards = schema["required_hardware_boards_by_target"]
expected = {
    "raspberry-pi-4-model-b",
    "cm4-lite-sd",
    "cm4-emmc-io-board",
    "revpi-connect-4",
}
actual = set(boards["pi-cm4-revpi-usb-installer"])
if actual != expected:
    raise SystemExit(f"USB installer hardware coverage mismatch: {sorted(actual)}")
PY
python3 "${TOOL}" generate \
    --version v9.9.9 \
    --target qemu-x86_64 \
    --output "${EVIDENCE}" \
    >/dev/null

python3 "${TOOL}" validate "${EVIDENCE}" >/dev/null

if python3 "${TOOL}" validate "${EVIDENCE}" --require-pass 2>"${TMPDIR}/blocked.err"; then
    echo "ERROR: generated blocked evidence unexpectedly passed release-ready validation" >&2
    exit 1
fi

if ! grep -q "release-ready evidence" "${TMPDIR}/blocked.err"; then
    echo "ERROR: release-ready failure did not explain missing evidence" >&2
    cat "${TMPDIR}/blocked.err" >&2
    exit 1
fi

python3 - "${EVIDENCE}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

evidence_path = Path(sys.argv[1])
root = evidence_path.parent
data = json.loads(evidence_path.read_text(encoding="utf-8"))


def write_bytes(rel: str, payload: bytes) -> tuple[str, int]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def write_text(rel: str, payload: str) -> tuple[str, int]:
    return write_bytes(rel, payload.encode("utf-8"))


def write_machine_record(name: str, log_rel: str, log_sha256: str, log_bytes: int) -> dict:
    record_rel = f"machine/{name}.json"
    subjects = [
        {
            "name": data["artifacts"][0]["name"],
            "sha256": data["artifacts"][0]["sha256"] or "6" * 64,
            "bytes": data["artifacts"][0]["bytes"] or 1,
        }
    ]
    source_sha = data["source"]["git_commit"]
    source_ref = f"refs/tags/{data['version']}"
    record = {
        "schema_version": "suderra.machine-verification.v3",
        "name": name,
        "status": "passed",
        "generated_at": data["generated_at"],
        "identity": "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/release.yml@refs/tags/v9.9.9",
        "issuer": "https://token.actions.githubusercontent.com",
        "source": {
            "repository": "Okan-wqm/Suderra-OS",
            "workflow": "Release",
            "run_id": data["source"]["ci"]["run_id"],
            "run_attempt": data["source"]["ci"]["run_attempt"],
            "ref": source_ref,
            "source_sha": source_sha,
        },
        "log": {
            "path": Path(log_rel).name,
            "sha256": log_sha256,
            "bytes": log_bytes,
        },
        "subjects": subjects,
    }
    material_refs = []
    if name == "attestations":
        record["verified_subjects"] = [{"name": item["name"], "sha256": item["sha256"]} for item in subjects]
        attestation_payload = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                for item in subjects
            ],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "repository": "Okan-wqm/Suderra-OS",
                        "ref": source_ref,
                        "run_id": data["source"]["ci"]["run_id"],
                        "run_attempt": data["source"]["ci"]["run_attempt"],
                        "source_sha": source_sha,
                    },
                    "resolvedDependencies": [
                        {
                            "uri": "git+https://github.com/Okan-wqm/Suderra-OS",
                            "digest": {"gitCommit": source_sha},
                        }
                    ],
                },
                "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}},
            },
        }
        material_rel = f"machine/attestations/{data['artifacts'][0]['name']}.json"
        material_sha, material_bytes = write_text(material_rel, json.dumps(attestation_payload, sort_keys=True) + "\n")
        material_refs.append({"path": material_rel, "sha256": material_sha, "bytes": material_bytes})
        record["verification_material"] = {
            "kind": "github-artifact-attestation-dsse",
            "files": [
                {
                    "path": f"{data['artifacts'][0]['name']}.json",
                    "sha256": material_sha,
                    "bytes": material_bytes,
                    "subjects": record["verified_subjects"],
                    "provenance": [
                        {
                            "predicate_type": "https://slsa.dev/provenance/v1",
                            "builder_id": "https://github.com/actions/runner/github-hosted",
                            "source_repository": "Okan-wqm/Suderra-OS",
                            "source_ref": source_ref,
                            "source_run_id": data["source"]["ci"]["run_id"],
                            "source_run_attempt": data["source"]["ci"]["run_attempt"],
                            "source_sha": source_sha,
                            "materials": attestation_payload["predicate"]["buildDefinition"]["resolvedDependencies"],
                        }
                    ],
                }
            ],
        }
    digest, size = write_text(record_rel, json.dumps(record, sort_keys=True) + "\n")
    result = {"path": record_rel, "sha256": digest, "bytes": size}
    if material_refs:
        result["materials"] = material_refs
    return result


def reproducibility_payload(data: dict, comparison: str) -> dict:
    digest = hashlib.sha256(f"{data['target']}:reproducible".encode("utf-8")).hexdigest()
    return {
        "schema_version": "suderra.reproducibility.v1",
        "version": data["version"],
        "target": data["target"],
        "source_sha": data["source"]["git_commit"],
        "source_run_id": data["source"]["ci"]["run_id"],
        "status": "passed",
        "generated_at": data["generated_at"],
        "comparison": comparison,
        "artifact_comparisons": [
            {
                "artifact": f"{data['target']}.img.xz",
                "status": "matched",
                "reference_sha256": digest,
                "rebuild_sha256": digest,
            }
        ],
        "logs": [],
    }

data["source"]["git_commit"] = "0123456789abcdef0123456789abcdef01234567"
data["source"]["dirty"] = False
data["source"]["ci"]["run_id"] = "123456789"
data["source"]["ci"]["run_attempt"] = "1"

for artifact in data["artifacts"]:
    digest, size = write_bytes(artifact["path"], b"synthetic release artifact\n")
    artifact["sha256"] = digest
    artifact["bytes"] = size
    artifact["signature"]["verified"] = True
    artifact["provenance"]["verified"] = True
    write_text(artifact["signature"]["path"], "synthetic cosign signature\n")
    write_text(artifact["signature"]["certificate"], "synthetic cosign certificate\n")
    write_text(artifact["provenance"]["path"], "synthetic provenance\n")

asset_manifest = {
    "schema_version": "suderra.release-assets.v1",
    "version": data["version"],
    "generated_at": data["generated_at"],
    "source": data["source"],
    "matrix_sha256": "0" * 64,
    "buildroot_index_sha": "160000 commit buildroot " + "1" * 40,
    "files": [
        {
            "name": artifact["name"],
            "role": artifact["role"],
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
        }
        for artifact in data["artifacts"]
    ],
}
data["asset_manifest"]["sha256"], _ = write_text(
    data["asset_manifest"]["path"],
    json.dumps(asset_manifest, sort_keys=True) + "\n",
)
data["asset_manifest"]["verified"] = True

sbom_payload = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"name": "busybox", "version": "contract"}],
}
sbom_digest, _ = write_text(
    data["sbom"]["path"],
    json.dumps(sbom_payload, sort_keys=True) + "\n",
)
data["sbom"]["sha256"] = sbom_digest
data["sbom"]["component_count"] = 1
data["sbom"]["signature_verified"] = True
data["vex"] = {
    "status": "present",
    "path": "vex/suderra.vex.json",
    "sha256": None,
    "signature_verified": True,
}
data["vex"]["sha256"], _ = write_text(
    data["vex"]["path"],
    json.dumps({"vex": "contract-fixture", "statements": []}, sort_keys=True) + "\n",
)
data["reproducibility"]["status"] = "passed"
data["reproducibility"]["comparison"] = "independent rebuild matched release artifact"
data["reproducibility"]["logs"] = ["preflight/reproducibility/reproducibility.json"]

for scan in data["security_scans"]:
    scan["status"] = "passed"
    scan["report"] = f"security/{scan['name']}.json"

for name, check in data["machine_verification"].items():
    check["status"] = "passed"
    check["logs"] = [f"machine/{name}.log"]

data["build_evidence"] = {
    "status": "passed",
    "logs": [
        {
            "path": "build/suderra_qemu_x86_64_defconfig.log",
            "sha256": None,
            "bytes": None,
        }
    ],
    "source_identity": [
        {
            "path": "build/suderra_qemu_x86_64_defconfig.source-identity.json",
            "sha256": None,
            "bytes": None,
        }
    ],
    "warnings": [
        {
            "path": "build/suderra_qemu_x86_64_defconfig.warnings.json",
            "sha256": None,
            "bytes": None,
        }
    ],
}
source_identity = {
    "schema_version": "suderra.buildroot-source-identity.v2",
    "buildroot_expected_patched": False,
    "buildroot_index_sha": "019201c6e007d80c1ab1bf65b98d9902bc767bdd",
    "buildroot_patch_files": [],
    "buildroot_patchset_sha256": "2" * 64,
    "buildroot_rust_bin_version": "1.86.0",
    "buildroot_rust_version": "1.86.0",
    "buildroot_source_mode": "clean-native",
    "buildroot_upstream_ref": "2025.05.3",
}
source_identity["buildroot_effective_source_id"] = hashlib.sha256(
    (
        "buildroot-source-identity-v2\n"
        f"index:{source_identity['buildroot_index_sha']}\n"
        f"upstream-ref:{source_identity['buildroot_upstream_ref']}\n"
        f"source-mode:{source_identity['buildroot_source_mode']}\n"
        f"patchset:{source_identity['buildroot_patchset_sha256']}\n"
        "diff-identity:none\n"
    ).encode("utf-8")
).hexdigest()
source_identity["suderra_source_sha"] = data["source"]["git_commit"]
source_identity["suderra_external_tree_sha256"] = "3" * 64
source_identity["suderra_external_dirty_paths"] = []
source_identity["suderra_release_source_id"] = hashlib.sha256(
    (
        "suderra-release-source-identity-v1\n"
        f"source:{source_identity['suderra_source_sha']}\n"
        f"external-tree:{source_identity['suderra_external_tree_sha256']}\n"
        f"buildroot-effective:{source_identity['buildroot_effective_source_id']}\n"
    ).encode("utf-8")
).hexdigest()
for item, text in (
    (data["build_evidence"]["logs"][0], "synthetic build log\n"),
    (
        data["build_evidence"]["warnings"][0],
        '{"summary":{"owned":0,"third-party":0},"failing":[],"policy_errors":[]}\n',
    ),
    (data["build_evidence"]["source_identity"][0], json.dumps(source_identity, sort_keys=True) + "\n"),
):
    digest, size = write_text(item["path"], text)
    item["sha256"] = digest
    item["bytes"] = size

data["governance"]["retention_years"] = 7
data["governance"]["approval_model"] = "enterprise-two-role"
for name, check in data["governance"]["checks"].items():
    check["status"] = "passed"
    check["evidence"] = f"governance/{name}.json"

data["qemu"]["status"] = "passed"
data["qemu"]["logs"] = ["qemu/boot.log"]
data["qemu"]["checks"] = [
    "boot",
    "systemd",
    "zero-failed-units",
    "no-kernel-panic",
    "no-emergency-mode",
    "os-release",
    "kernel",
    "rootfs",
    "firstboot-idempotence",
    "network",
    "lockdown-transition",
    "listeners",
    "firewall",
]
data["qemu"]["image"] = "suderra-qemu_x86_64.img"
data["qemu"]["image_sha256"] = "4" * 64
data["qemu"]["firmware"] = "OVMF_CODE.fd"
data["qemu"]["firmware_sha256"] = "5" * 64
data["qemu"]["semantic_checks"] = {
    name: {"status": "passed", "evidence": "contract evidence", "source": "contract"}
    for name in data["qemu"]["checks"]
}
qemu_semantic = {
    "schema_version": "suderra.qemu-semantic.v1",
    "os_release": {"ID": "suderra"},
    "kernel": {"release": "contract"},
    "rootfs": {"partlabel": "rootfs"},
    "failed_units": {"count": 0, "lines": []},
    "network": {"state": "up"},
    "listeners": [],
    "firewall": {"loaded": True},
    "firstboot": {"done_marker": True},
    "lockdown": {"status": "locked"},
}
data["qemu"]["guest_facts"] = qemu_semantic
termination = {
    "mode": "exited",
    "exit_status": 0,
    "signal": None,
    "killed": False,
    "timeout": False,
    "qmp_quit_sent": True,
    "qmp_quit_ack": True,
    "reason": "contract fixture exited cleanly",
    "acceptable": True,
}
data["qemu"]["check_details"] = data["qemu"]["semantic_checks"]
data["qemu"]["validation_profile"] = "release-candidate"
data["qemu"]["failure_class"] = "none"
data["qemu"]["execution"] = {
    "schema_version": "suderra.qemu-acceptance.v4",
    "profile": "release-candidate",
    "qemu_exit_status": 0,
    "termination": termination,
    "failure_class": "none",
    "result": "passed",
}
qemu_input = {
    "schema_version": "suderra.qemu-acceptance.v4",
    "version": data["version"],
    "target": data["target"],
    "source_sha": data["source"]["git_commit"],
    "generated_at": data["generated_at"],
    "image": data["qemu"]["image"],
    "image_sha256": data["qemu"]["image_sha256"],
    "qemu_version": "QEMU emulator version contract",
    "firmware": data["qemu"]["firmware"],
    "firmware_sha256": data["qemu"]["firmware_sha256"],
    "status": "passed",
    "profile": "release-candidate",
    "failure_class": "none",
    "qemu_exit_status": 0,
    "termination": termination,
    "logs": [],
    "checks": data["qemu"]["semantic_checks"],
    "guest_facts": data["qemu"]["guest_facts"],
}
for role, rel, payload in (
    ("serial", "qemu/input/serial.log", "synthetic serial\n"),
    ("qmp-events", "qemu/input/qmp-events.json", "[]\n"),
    ("qemu-stderr", "qemu/input/qemu-stderr.log", ""),
    ("qemu-semantic", "qemu/input/qemu-semantic.json", json.dumps(qemu_semantic, sort_keys=True) + "\n"),
):
    digest, _ = write_text(rel, payload)
    qemu_input["logs"].append({"role": role, "path": Path(rel).name, "sha256": digest})
qemu_digest, qemu_size = write_text("qemu/input/qemu.json", json.dumps(qemu_input, sort_keys=True) + "\n")
data["qemu"]["input"] = {"path": "qemu/input/qemu.json", "sha256": qemu_digest, "bytes": qemu_size}

data["approvals"] = [
    {
        "role": "release-owner",
        "name": "Contract Test",
        "approved_at": "2026-05-13T00:00:00Z",
        "ticket": "TEST-1",
    },
    {
        "role": "security-compliance",
        "name": "Contract Security",
        "approved_at": "2026-05-13T00:00:00Z",
        "ticket": "TEST-1",
    }
]
data["release_decision"] = {
    "status": "approved",
    "decided_by": "Contract Test",
    "decided_at": "2026-05-13T00:00:00Z",
    "rationale": "Synthetic contract fixture.",
}
approval_input = {
    "schema_version": "suderra.release-approval.v2",
    "version": data["version"],
    "target": data["target"],
    "source_sha": data["source"]["git_commit"],
    "approvals": data["approvals"],
    "residual_risk": data["residual_risk"],
    "release_decision": data["release_decision"],
}
approval_digest, approval_size = write_text(
    "preflight/approval.json",
    json.dumps(approval_input, sort_keys=True) + "\n",
)
data["preflight_inputs"]["approval"] = {
    "path": "preflight/approval.json",
    "sha256": approval_digest,
    "bytes": approval_size,
}

for rel in data["reproducibility"]["logs"]:
    digest, size = write_text(
        rel,
        json.dumps(reproducibility_payload(data, data["reproducibility"]["comparison"]), sort_keys=True) + "\n",
    )
    data["preflight_inputs"]["reproducibility"] = {"path": rel, "sha256": digest, "bytes": size}
for scan in data["security_scans"]:
    raw_rel = f"preflight/security/raw/{scan['name']}.json"
    raw_payload = scan["name"] + " passed\n"
    raw_digest, raw_size = write_text(raw_rel, raw_payload)
    report_payload = {
        "schema_version": "suderra.release-security-report.v1",
        "version": data["version"],
        "source_sha": data["source"]["git_commit"],
        "source_run_id": data["source"]["ci"]["run_id"],
        "scan": scan["name"],
        "status": "passed",
        "generated_at": data["generated_at"],
        "tool": scan["name"],
        "tool_version": "contract",
        "evidence_type": "contract-log",
        "evidence_path": raw_rel,
        "evidence_sha256": raw_digest,
        "evidence_bytes": raw_size,
        "severity_counts": {"critical": 0, "high": 0},
    }
    digest, size = write_text(scan["report"], json.dumps(report_payload, sort_keys=True) + "\n")
    data["preflight_inputs"]["security_reports"].append(
        {"name": scan["name"], "path": scan["report"], "sha256": digest, "bytes": size}
    )
    data["preflight_inputs"].setdefault("security_raw_evidence", []).append(
        {
            "name": scan["name"],
            "source_path": raw_rel,
            "path": raw_rel,
            "sha256": raw_digest,
            "bytes": raw_size,
            "report_sha256": raw_digest,
            "report_bytes": raw_size,
        }
    )
for name, check in data["machine_verification"].items():
    for rel in check["logs"]:
        digest, size = write_text(rel, "synthetic machine verification transcript\n")
        record_ref = write_machine_record(name, rel, digest, size)
        if "materials" in record_ref:
            check["materials"] = record_ref.pop("materials")
        check["record"] = record_ref
for name, check in data["governance"]["checks"].items():
    payload = {"status": "passed"}
    if name == "policy_validation":
        payload["schema_version"] = "suderra.github-governance-validation.v2"
    write_text(check["evidence"], json.dumps(payload, sort_keys=True) + "\n")
for rel in data["qemu"]["logs"]:
    write_text(rel, "synthetic QEMU serial and journal evidence\n")

subject_id = (
    f"suderra-release:{data['version']}:{data['target']}:"
    f"{data['source']['git_commit']}:{data['source']['ci']['run_id']}"
)
release_input_payload = {
    "schema_version": "suderra.release-input-binding.v2",
    "version": data["version"],
    "profile": "production-candidate",
    "source_sha": data["source"]["git_commit"],
    "source_run_id": data["source"]["ci"]["run_id"],
}
input_digest, input_size = write_text(
    "preflight/release-inputs/production-candidate.json",
    json.dumps(release_input_payload, sort_keys=True) + "\n",
)
data["preflight_inputs"]["release_input"] = {
    "profile": "production-candidate",
    "path": "preflight/release-inputs/production-candidate.json",
    "sha256": input_digest,
    "bytes": input_size,
}
input_node_id = f"{subject_id}:release-input-binding"
subject_graph = {
    "schema_version": "suderra.release-subject-graph.v1",
    "version": data["version"],
    "profile": "production-candidate",
    "subjects": [],
    "evidence_nodes": [
        {
            "node_id": input_node_id,
            "subject_id": subject_id,
            "target": data["target"],
            "role": "release-input-binding",
            "path": f"release-inputs/{data['version']}/production-candidate.json",
            "schema_role": "binding_manifest",
            "schema_version": "suderra.release-input-binding.v2",
            "required": True,
            "producer": "prepare-release-inputs.py",
            "sha256": input_digest,
            "bytes": input_size,
        }
    ],
    "evidence_edges": [
        {
            "from": subject_id,
            "to": input_node_id,
            "relationship": "requires",
            "role": "release-input-binding",
        }
    ],
    "required_paths": [f"release-inputs/{data['version']}/production-candidate.json"],
    "retention_closure": {
        "policy_id": "suderra-enterprise-7y-immutable-evidence",
        "required_exports": [
            "release-inputs",
            "release-subject-graph",
            "release-runtime",
            "release-signing",
            "release-lab-input",
            "release-governance",
            "release-reproducibility",
            "release-security",
            "release-retention",
            "release-ota",
        ],
    },
}
subject_targets = [
    data["target"],
    "x86_64",
    "qemu-x86_64-prod-ab",
    "rpi4",
    "pi-cm4-revpi-usb-installer",
    "revpi4",
]
for idx, target in enumerate(dict.fromkeys(subject_targets)):
    target_subject_id = (
        f"suderra-release:{data['version']}:{target}:"
        f"{data['source']['git_commit']}:{data['source']['ci']['run_id']}"
    )
    artifact_sha = data["artifacts"][0]["sha256"] if target == data["target"] else f"{idx + 1:x}" * 64
    artifact_bytes = data["artifacts"][0]["bytes"] if target == data["target"] else 8 + idx
    subject_graph["subjects"].append(
        {
            "subject_id": target_subject_id,
            "version": data["version"],
            "target": target,
            "source_sha": data["source"]["git_commit"],
            "source_run_id": data["source"]["ci"]["run_id"],
            "raw_image_sha256": artifact_sha,
            "raw_image_bytes": artifact_bytes,
            "compressed_artifact_sha256": artifact_sha,
            "compressed_artifact_bytes": artifact_bytes,
        }
    )
digest, size = write_text("subject-graph/release-subject-graph.json", json.dumps(subject_graph, sort_keys=True) + "\n")
data["subject_graph"] = {"path": "subject-graph/release-subject-graph.json", "sha256": digest, "bytes": size}

role_bindings = {
    "schema_version": "suderra.governance-role-bindings.v1",
    "version": data["version"],
    "bindings": [
        {
            "role": "release-owner",
            "github_subject": "suderra-release-owners",
            "subject_type": "team",
            "github_node_id": "TEAM_release",
            "source_snapshot_sha256": "a" * 64,
            "permission_snapshot_sha256": "1" * 64,
            "environment_reviewer_binding_sha256": "2" * 64,
            "effective_permission": "admin",
        },
        {
            "role": "security-owner",
            "github_subject": "suderra-security-owners",
            "subject_type": "team",
            "github_node_id": "TEAM_security",
            "source_snapshot_sha256": "b" * 64,
            "permission_snapshot_sha256": "3" * 64,
            "environment_reviewer_binding_sha256": "4" * 64,
            "effective_permission": "admin",
        },
    ],
}
digest, size = write_text("governance/role-bindings.json", json.dumps(role_bindings, sort_keys=True) + "\n")
data["governance_role_bindings"] = {"path": "governance/role-bindings.json", "sha256": digest, "bytes": size}

retention_exports = [
    "release-inputs",
    "release-subject-graph",
    "release-runtime",
    "release-signing",
    "release-lab-input",
    "release-governance",
    "release-reproducibility",
    "release-security",
    "release-retention",
    "release-ota",
]
retention_replay = [
    "release-input-binding",
    "runtime-suite",
    "hsm-signing-manifest",
    "station-acquisition",
    "scanner-raw-replay",
    "governance-snapshot",
    "publication-manifest",
]
retention = {
    "schema_version": "suderra.retention-manifest.v1",
    "policy_id": "suderra-enterprise-7y-immutable-evidence",
    "version": data["version"],
    "source_sha": data["source"]["git_commit"],
    "source_run_id": data["source"]["ci"]["run_id"],
    "store_class": "immutable-encrypted-evidence-archive",
    "retention_years": 7,
    "exports": [{"name": name, "path": name} for name in retention_exports],
    "restore_replay_tests": [{"name": name, "status": "passed"} for name in retention_replay],
    "kms_key_id": "kms-contract",
    "custody_chain": "custody-contract",
    "access_log": "access-log-contract",
    "archive_object_uri": "s3://suderra-evidence/v9.9.9/archive.tar.zst",
    "archive_object_version_id": "version-contract",
    "archive_object_sha256": "c" * 64,
    "retention_lock_mode": "compliance",
    "retain_until": "2033-05-13T00:00:00Z",
    "legal_hold_status": "available",
    "legal_hold_id": "legal-hold-contract",
    "access_log_sha256": "d" * 64,
    "restore_job_id": "restore-contract",
    "restored_archive_sha256": "c" * 64,
    "replay_validator_output_sha256": "f" * 64,
    "custody_events": [
        {
            "event_id": "custody-contract-1",
            "event_type": "archive-written",
            "actor": "retention-exporter",
            "occurred_at": "2026-05-13T00:00:00Z",
            "evidence_sha256": "c" * 64,
        }
    ],
}
digest, size = write_text("retention/retention-manifest.json", json.dumps(retention, sort_keys=True) + "\n")
data["retention_manifest"] = {"path": "retention/retention-manifest.json", "sha256": digest, "bytes": size}

evidence_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${EVIDENCE}" --require-pass --check-files --validate-subject-graph >/dev/null

MISSING_SUBJECT_GRAPH="${TMPDIR}/missing-subject-graph/v9.9.9/qemu-x86_64/evidence.json"
mkdir -p "$(dirname "${MISSING_SUBJECT_GRAPH}")"
cp -a "$(dirname "${EVIDENCE}")/." "$(dirname "${MISSING_SUBJECT_GRAPH}")/"
python3 - "${MISSING_SUBJECT_GRAPH}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["subject_graph"] = None
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate "${MISSING_SUBJECT_GRAPH}" --require-pass --check-files 2>"${TMPDIR}/subject-graph.err"; then
    echo "ERROR: release evidence accepted missing subject graph" >&2
    exit 1
fi
grep -q "subject_graph" "${TMPDIR}/subject-graph.err" || {
    echo "ERROR: missing subject graph failure did not cite subject_graph" >&2
    cat "${TMPDIR}/subject-graph.err" >&2
    exit 1
}

MISSING_MACHINE_RECORD="${TMPDIR}/missing-machine-record/v9.9.9/qemu-x86_64/evidence.json"
mkdir -p "$(dirname "${MISSING_MACHINE_RECORD}")"
cp -a "$(dirname "${EVIDENCE}")/." "$(dirname "${MISSING_MACHINE_RECORD}")/"
python3 - "${MISSING_MACHINE_RECORD}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["machine_verification"]["cosign"]["record"] = None
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate "${MISSING_MACHINE_RECORD}" --require-pass --check-files 2>"${TMPDIR}/machine-record.err"; then
    echo "ERROR: release evidence accepted log-only machine verification" >&2
    exit 1
fi
grep -q "machine_verification.cosign.record" "${TMPDIR}/machine-record.err" || {
    echo "ERROR: missing machine record failure did not cite the structured record" >&2
    cat "${TMPDIR}/machine-record.err" >&2
    exit 1
}

if python3 "${TOOL}" validate "${EVIDENCE}" --release-tier alpha --require-pass --check-files 2>"${TMPDIR}/tier.err"; then
    echo "ERROR: GA evidence unexpectedly validated with alpha release tier" >&2
    exit 1
fi
if ! grep -q "release tier must be production" "${TMPDIR}/tier.err"; then
    echo "ERROR: release tier mismatch did not fail closed" >&2
    cat "${TMPDIR}/tier.err" >&2
    exit 1
fi

REQUIRED_BYPASS="${TMPDIR}/release-evidence/v9.9.9/qemu-x86_64-required-bypass/evidence.json"
mkdir -p "$(dirname "${REQUIRED_BYPASS}")"
cp "${EVIDENCE}" "${REQUIRED_BYPASS}"
python3 - "${REQUIRED_BYPASS}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["qemu"]["required"] = False
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate "${REQUIRED_BYPASS}" --require-pass --check-files 2>"${TMPDIR}/required.err"; then
    echo "ERROR: release evidence accepted a matrix-required QEMU bypass" >&2
    exit 1
fi
if ! grep -q "matrix-derived requirement" "${TMPDIR}/required.err"; then
    echo "ERROR: required-gate bypass failure did not cite matrix-derived requirement" >&2
    cat "${TMPDIR}/required.err" >&2
    exit 1
fi

ALPHA="${TMPDIR}/release-evidence/v9.9.9-alpha.1/qemu-x86_64/evidence.json"
python3 "${TOOL}" generate \
    --version v9.9.9-alpha.1 \
    --target qemu-x86_64 \
    --output "${ALPHA}" \
    >/dev/null

python3 - "${ALPHA}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

evidence_path = Path(sys.argv[1])
root = evidence_path.parent
data = json.loads(evidence_path.read_text(encoding="utf-8"))


def write_text(rel: str, payload: str) -> tuple[str, int]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = payload.encode("utf-8")
    path.write_bytes(payload_bytes)
    return hashlib.sha256(payload_bytes).hexdigest(), len(payload_bytes)


def write_machine_record(name: str, log_rel: str, log_sha256: str, log_bytes: int) -> dict:
    record_rel = f"machine/{name}.json"
    subjects = [
        {
            "name": data["artifacts"][0]["name"],
            "sha256": data["artifacts"][0]["sha256"] or "6" * 64,
            "bytes": data["artifacts"][0]["bytes"] or 1,
        }
    ]
    source_sha = data["source"]["git_commit"]
    source_ref = f"refs/tags/{data['version']}"
    record = {
        "schema_version": "suderra.machine-verification.v3",
        "name": name,
        "status": "passed",
        "generated_at": data["generated_at"],
        "identity": "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/release.yml@refs/tags/v9.9.9-alpha.1",
        "issuer": "https://token.actions.githubusercontent.com",
        "source": {
            "repository": "Okan-wqm/Suderra-OS",
            "workflow": "Release",
            "run_id": data["source"]["ci"]["run_id"],
            "run_attempt": data["source"]["ci"]["run_attempt"],
            "ref": source_ref,
            "source_sha": source_sha,
        },
        "log": {
            "path": Path(log_rel).name,
            "sha256": log_sha256,
            "bytes": log_bytes,
        },
        "subjects": subjects,
    }
    material_refs = []
    if name == "attestations":
        record["verified_subjects"] = [{"name": item["name"], "sha256": item["sha256"]} for item in subjects]
        attestation_payload = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                for item in subjects
            ],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "repository": "Okan-wqm/Suderra-OS",
                        "ref": source_ref,
                        "run_id": data["source"]["ci"]["run_id"],
                        "run_attempt": data["source"]["ci"]["run_attempt"],
                        "source_sha": source_sha,
                    },
                    "resolvedDependencies": [
                        {
                            "uri": "git+https://github.com/Okan-wqm/Suderra-OS",
                            "digest": {"gitCommit": source_sha},
                        }
                    ],
                },
                "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}},
            },
        }
        material_rel = f"machine/attestations/{data['artifacts'][0]['name']}.json"
        material_sha, material_bytes = write_text(material_rel, json.dumps(attestation_payload, sort_keys=True) + "\n")
        material_refs.append({"path": material_rel, "sha256": material_sha, "bytes": material_bytes})
        record["verification_material"] = {
            "kind": "github-artifact-attestation-dsse",
            "files": [
                {
                    "path": f"{data['artifacts'][0]['name']}.json",
                    "sha256": material_sha,
                    "bytes": material_bytes,
                    "subjects": record["verified_subjects"],
                    "provenance": [
                        {
                            "predicate_type": "https://slsa.dev/provenance/v1",
                            "builder_id": "https://github.com/actions/runner/github-hosted",
                            "source_repository": "Okan-wqm/Suderra-OS",
                            "source_ref": source_ref,
                            "source_run_id": data["source"]["ci"]["run_id"],
                            "source_run_attempt": data["source"]["ci"]["run_attempt"],
                            "source_sha": source_sha,
                            "materials": attestation_payload["predicate"]["buildDefinition"]["resolvedDependencies"],
                        }
                    ],
                }
            ],
        }
    digest, size = write_text(record_rel, json.dumps(record, sort_keys=True) + "\n")
    result = {"path": record_rel, "sha256": digest, "bytes": size}
    if material_refs:
        result["materials"] = material_refs
    return result


def reproducibility_payload(data: dict, comparison: str) -> dict:
    digest = hashlib.sha256(f"{data['target']}:reproducible".encode("utf-8")).hexdigest()
    return {
        "schema_version": "suderra.reproducibility.v1",
        "version": data["version"],
        "target": data["target"],
        "source_sha": data["source"]["git_commit"],
        "source_run_id": data["source"]["ci"]["run_id"],
        "status": "passed",
        "generated_at": data["generated_at"],
        "comparison": comparison,
        "artifact_comparisons": [
            {
                "artifact": f"{data['target']}.img.xz",
                "status": "matched",
                "reference_sha256": digest,
                "rebuild_sha256": digest,
            }
        ],
        "logs": [],
    }


data["source"]["git_commit"] = "0123456789abcdef0123456789abcdef01234567"
data["source"]["dirty"] = False
data["source"]["ci"]["run_id"] = "123456789"
data["source"]["ci"]["run_attempt"] = "1"

for artifact in data["artifacts"]:
    digest, size = write_text(artifact["path"], "alpha image artifact\n")
    artifact["sha256"] = digest
    artifact["bytes"] = size
    artifact["signature"]["verified"] = True
    artifact["provenance"]["verified"] = True
    write_text(artifact["signature"]["path"], "synthetic alpha cosign signature\n")
    write_text(artifact["signature"]["certificate"], "synthetic alpha cosign certificate\n")
    write_text(artifact["provenance"]["path"], "synthetic alpha provenance\n")

asset_manifest = {
    "schema_version": "suderra.release-assets.v1",
    "version": data["version"],
    "generated_at": data["generated_at"],
    "source": data["source"],
    "matrix_sha256": "0" * 64,
    "buildroot_index_sha": "160000 commit buildroot " + "1" * 40,
    "files": [
        {
            "name": artifact["name"],
            "role": artifact["role"],
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
        }
        for artifact in data["artifacts"]
    ],
}
data["asset_manifest"]["sha256"], _ = write_text(
    data["asset_manifest"]["path"],
    json.dumps(asset_manifest, sort_keys=True) + "\n",
)
data["asset_manifest"]["verified"] = True

sbom_payload = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"name": "busybox", "version": "alpha"}],
}
data["sbom"]["sha256"], _ = write_text(
    data["sbom"]["path"],
    json.dumps(sbom_payload, sort_keys=True) + "\n",
)
data["sbom"]["component_count"] = 1
data["sbom"]["signature_verified"] = True
data["vex"]["status"] = "not_collected"
data["reproducibility"]["status"] = "passed"
data["reproducibility"]["comparison"] = "single alpha candidate build accepted with residual risk"
data["reproducibility"]["logs"] = ["preflight/reproducibility/reproducibility.json"]

for scan in data["security_scans"]:
    scan["status"] = "passed"
    scan["report"] = f"security/{scan['name']}.json"

for name, check in data["machine_verification"].items():
    check["status"] = "passed"
    check["logs"] = [f"machine/{name}.log"]

data["build_evidence"] = {
    "status": "passed",
    "logs": [
        {
            "path": "build/suderra_qemu_x86_64_defconfig.log",
            "sha256": None,
            "bytes": None,
        }
    ],
    "source_identity": [
        {
            "path": "build/suderra_qemu_x86_64_defconfig.source-identity.json",
            "sha256": None,
            "bytes": None,
        }
    ],
    "warnings": [
        {
            "path": "build/suderra_qemu_x86_64_defconfig.warnings.json",
            "sha256": None,
            "bytes": None,
        }
    ],
}
source_identity = {
    "schema_version": "suderra.buildroot-source-identity.v2",
    "buildroot_expected_patched": False,
    "buildroot_index_sha": "019201c6e007d80c1ab1bf65b98d9902bc767bdd",
    "buildroot_patch_files": [],
    "buildroot_patchset_sha256": "2" * 64,
    "buildroot_rust_bin_version": "1.86.0",
    "buildroot_rust_version": "1.86.0",
    "buildroot_source_mode": "clean-native",
    "buildroot_upstream_ref": "2025.05.3",
}
source_identity["buildroot_effective_source_id"] = hashlib.sha256(
    (
        "buildroot-source-identity-v2\n"
        f"index:{source_identity['buildroot_index_sha']}\n"
        f"upstream-ref:{source_identity['buildroot_upstream_ref']}\n"
        f"source-mode:{source_identity['buildroot_source_mode']}\n"
        f"patchset:{source_identity['buildroot_patchset_sha256']}\n"
        "diff-identity:none\n"
    ).encode("utf-8")
).hexdigest()
source_identity["suderra_source_sha"] = data["source"]["git_commit"]
source_identity["suderra_external_tree_sha256"] = "3" * 64
source_identity["suderra_external_dirty_paths"] = []
source_identity["suderra_release_source_id"] = hashlib.sha256(
    (
        "suderra-release-source-identity-v1\n"
        f"source:{source_identity['suderra_source_sha']}\n"
        f"external-tree:{source_identity['suderra_external_tree_sha256']}\n"
        f"buildroot-effective:{source_identity['buildroot_effective_source_id']}\n"
    ).encode("utf-8")
).hexdigest()
for item, text in (
    (data["build_evidence"]["logs"][0], "synthetic alpha build log\n"),
    (
        data["build_evidence"]["warnings"][0],
        '{"summary":{"owned":0,"third-party":0},"failing":[],"policy_errors":[]}\n',
    ),
    (data["build_evidence"]["source_identity"][0], json.dumps(source_identity, sort_keys=True) + "\n"),
):
    digest, size = write_text(item["path"], text)
    item["sha256"] = digest
    item["bytes"] = size

data["governance"]["retention_years"] = 7
data["governance"]["approval_model"] = "enterprise-two-role"
for name, check in data["governance"]["checks"].items():
    check["status"] = "passed"
    check["evidence"] = f"governance/{name}.json"

data["qemu"]["status"] = "passed"
data["qemu"]["logs"] = ["qemu/boot.log"]
data["qemu"]["checks"] = [
    "boot",
    "systemd",
    "zero-failed-units",
    "no-kernel-panic",
    "no-emergency-mode",
    "os-release",
    "kernel",
    "rootfs",
    "firstboot-idempotence",
    "network",
    "lockdown-transition",
    "listeners",
    "firewall",
]
data["qemu"]["image"] = "suderra-qemu_x86_64.img"
data["qemu"]["image_sha256"] = "4" * 64
data["qemu"]["firmware"] = "OVMF_CODE.fd"
data["qemu"]["firmware_sha256"] = "5" * 64
data["qemu"]["semantic_checks"] = {
    name: {"status": "passed", "evidence": "contract evidence", "source": "contract"}
    for name in data["qemu"]["checks"]
}
qemu_semantic = {
    "schema_version": "suderra.qemu-semantic.v1",
    "os_release": {"ID": "suderra"},
    "kernel": {"release": "contract"},
    "rootfs": {"partlabel": "rootfs"},
    "failed_units": {"count": 0, "lines": []},
    "network": {"state": "up"},
    "listeners": [],
    "firewall": {"loaded": True},
    "firstboot": {"done_marker": True},
    "lockdown": {"status": "locked"},
}
data["qemu"]["guest_facts"] = qemu_semantic
termination = {
    "mode": "exited",
    "exit_status": 0,
    "signal": None,
    "killed": False,
    "timeout": False,
    "qmp_quit_sent": True,
    "qmp_quit_ack": True,
    "reason": "contract fixture exited cleanly",
    "acceptable": True,
}
data["qemu"]["check_details"] = data["qemu"]["semantic_checks"]
data["qemu"]["validation_profile"] = "release-candidate"
data["qemu"]["failure_class"] = "none"
data["qemu"]["execution"] = {
    "schema_version": "suderra.qemu-acceptance.v4",
    "profile": "release-candidate",
    "qemu_exit_status": 0,
    "termination": termination,
    "failure_class": "none",
    "result": "passed",
}
qemu_input = {
    "schema_version": "suderra.qemu-acceptance.v4",
    "version": data["version"],
    "target": data["target"],
    "source_sha": data["source"]["git_commit"],
    "generated_at": data["generated_at"],
    "image": data["qemu"]["image"],
    "image_sha256": data["qemu"]["image_sha256"],
    "qemu_version": "QEMU emulator version contract",
    "firmware": data["qemu"]["firmware"],
    "firmware_sha256": data["qemu"]["firmware_sha256"],
    "status": "passed",
    "profile": "release-candidate",
    "failure_class": "none",
    "qemu_exit_status": 0,
    "termination": termination,
    "logs": [],
    "checks": data["qemu"]["semantic_checks"],
    "guest_facts": data["qemu"]["guest_facts"],
}
for role, rel, payload in (
    ("serial", "qemu/input/serial.log", "synthetic serial\n"),
    ("qmp-events", "qemu/input/qmp-events.json", "[]\n"),
    ("qemu-stderr", "qemu/input/qemu-stderr.log", ""),
    ("qemu-semantic", "qemu/input/qemu-semantic.json", json.dumps(qemu_semantic, sort_keys=True) + "\n"),
):
    digest, _ = write_text(rel, payload)
    qemu_input["logs"].append({"role": role, "path": Path(rel).name, "sha256": digest})
qemu_digest, qemu_size = write_text("qemu/input/qemu.json", json.dumps(qemu_input, sort_keys=True) + "\n")
data["qemu"]["input"] = {"path": "qemu/input/qemu.json", "sha256": qemu_digest, "bytes": qemu_size}
data["approvals"] = [
    {
        "role": "release-owner",
        "name": "Contract Test",
        "approved_at": "2026-05-13T00:00:00Z",
        "ticket": "TEST-ALPHA",
    },
    {
        "role": "security-compliance",
        "name": "Contract Security",
        "approved_at": "2026-05-13T00:00:00Z",
        "ticket": "TEST-ALPHA",
    }
]
data["residual_risk"] = {
    "status": "accepted",
    "items": [
        {
            "id": "RR-ALPHA-001",
            "severity": "high",
            "description": "Alpha evidence intentionally lacks production signing controls.",
            "mitigation": "Keep release draft/prerelease and block GA promotion.",
            "owner": "release-owner@example.com",
            "ticket": "TEST-ALPHA",
        }
    ],
    "accepted_by": "release-owner@example.com",
    "accepted_at": "2026-05-13T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z",
}
data["release_decision"] = {
    "status": "approved_with_residual_risk",
    "decided_by": "Contract Test",
    "decided_at": "2026-05-13T00:00:00Z",
    "rationale": "Synthetic alpha contract fixture.",
}
approval_input = {
    "schema_version": "suderra.release-approval.v2",
    "version": data["version"],
    "target": data["target"],
    "source_sha": data["source"]["git_commit"],
    "approvals": data["approvals"],
    "residual_risk": data["residual_risk"],
    "release_decision": data["release_decision"],
}
approval_digest, approval_size = write_text(
    "preflight/approval.json",
    json.dumps(approval_input, sort_keys=True) + "\n",
)
data["preflight_inputs"]["approval"] = {
    "path": "preflight/approval.json",
    "sha256": approval_digest,
    "bytes": approval_size,
}

for rel in data["reproducibility"]["logs"]:
    digest, size = write_text(
        rel,
        json.dumps(reproducibility_payload(data, data["reproducibility"]["comparison"]), sort_keys=True) + "\n",
    )
    data["preflight_inputs"]["reproducibility"] = {"path": rel, "sha256": digest, "bytes": size}
for scan in data["security_scans"]:
    raw_rel = f"preflight/security/raw/{scan['name']}.json"
    raw_payload = scan["name"] + " passed\n"
    raw_digest, raw_size = write_text(raw_rel, raw_payload)
    report_payload = {
        "schema_version": "suderra.release-security-report.v1",
        "version": data["version"],
        "source_sha": data["source"]["git_commit"],
        "source_run_id": data["source"]["ci"]["run_id"],
        "scan": scan["name"],
        "status": "passed",
        "generated_at": data["generated_at"],
        "tool": scan["name"],
        "tool_version": "contract",
        "evidence_type": "contract-log",
        "evidence_path": raw_rel,
        "evidence_sha256": raw_digest,
        "evidence_bytes": raw_size,
        "severity_counts": {"critical": 0, "high": 0},
    }
    digest, size = write_text(scan["report"], json.dumps(report_payload, sort_keys=True) + "\n")
    data["preflight_inputs"]["security_reports"].append(
        {"name": scan["name"], "path": scan["report"], "sha256": digest, "bytes": size}
    )
    data["preflight_inputs"].setdefault("security_raw_evidence", []).append(
        {
            "name": scan["name"],
            "source_path": raw_rel,
            "path": raw_rel,
            "sha256": raw_digest,
            "bytes": raw_size,
            "report_sha256": raw_digest,
            "report_bytes": raw_size,
        }
    )
for name, check in data["machine_verification"].items():
    for rel in check["logs"]:
        digest, size = write_text(rel, "synthetic alpha machine verification transcript\n")
        record_ref = write_machine_record(name, rel, digest, size)
        if "materials" in record_ref:
            check["materials"] = record_ref.pop("materials")
        check["record"] = record_ref
for name, check in data["governance"]["checks"].items():
    payload = {"status": "passed"}
    if name == "policy_validation":
        payload["schema_version"] = "suderra.github-governance-validation.v2"
    write_text(check["evidence"], json.dumps(payload, sort_keys=True) + "\n")
for rel in data["qemu"]["logs"]:
    write_text(rel, "synthetic QEMU alpha evidence\n")

subject_id = (
    f"suderra-release:{data['version']}:{data['target']}:"
    f"{data['source']['git_commit']}:{data['source']['ci']['run_id']}"
)
subject_graph = {
    "schema_version": "suderra.release-subject-graph.v1",
    "version": data["version"],
    "profile": "release-candidate",
    "subjects": [
        {
            "subject_id": subject_id,
            "version": data["version"],
            "target": data["target"],
            "defconfig": data["target_contract"]["defconfig"],
            "source_sha": data["source"]["git_commit"],
            "source_run_id": data["source"]["ci"]["run_id"],
            "compressed_artifact_sha256": data["artifacts"][0]["sha256"],
            "compressed_artifact_bytes": data["artifacts"][0]["bytes"],
        }
    ],
}
digest, size = write_text("subject-graph/release-subject-graph.json", json.dumps(subject_graph, sort_keys=True) + "\n")
data["subject_graph"] = {"path": "subject-graph/release-subject-graph.json", "sha256": digest, "bytes": size}

role_bindings = {
    "schema_version": "suderra.governance-role-bindings.v1",
    "version": data["version"],
    "bindings": [
        {
            "role": "release-owner",
            "github_subject": "suderra-release-owners",
            "subject_type": "team",
            "github_node_id": "TEAM_release",
            "source_snapshot_sha256": "a" * 64,
            "permission_snapshot_sha256": "1" * 64,
            "environment_reviewer_binding_sha256": "2" * 64,
            "effective_permission": "admin",
        },
        {
            "role": "security-owner",
            "github_subject": "suderra-security-owners",
            "subject_type": "team",
            "github_node_id": "TEAM_security",
            "source_snapshot_sha256": "b" * 64,
            "permission_snapshot_sha256": "3" * 64,
            "environment_reviewer_binding_sha256": "4" * 64,
            "effective_permission": "admin",
        },
    ],
}
digest, size = write_text("governance/role-bindings.json", json.dumps(role_bindings, sort_keys=True) + "\n")
data["governance_role_bindings"] = {"path": "governance/role-bindings.json", "sha256": digest, "bytes": size}

retention_exports = [
    "release-inputs",
    "release-subject-graph",
    "release-runtime",
    "release-signing",
    "release-lab-input",
    "release-governance",
    "release-reproducibility",
    "release-security",
    "release-retention",
    "release-ota",
]
retention_replay = [
    "release-input-binding",
    "runtime-suite",
    "hsm-signing-manifest",
    "station-acquisition",
    "scanner-raw-replay",
    "governance-snapshot",
    "publication-manifest",
]
retention = {
    "schema_version": "suderra.retention-manifest.v1",
    "policy_id": "suderra-enterprise-7y-immutable-evidence",
    "version": data["version"],
    "source_sha": data["source"]["git_commit"],
    "source_run_id": data["source"]["ci"]["run_id"],
    "store_class": "immutable-encrypted-evidence-archive",
    "retention_years": 7,
    "exports": [{"name": name, "path": name} for name in retention_exports],
    "restore_replay_tests": [{"name": name, "status": "passed"} for name in retention_replay],
    "kms_key_id": "kms-contract",
    "custody_chain": "custody-contract",
    "access_log": "access-log-contract",
    "archive_object_uri": "s3://suderra-evidence/v9.9.9-alpha.1/archive.tar.zst",
    "archive_object_version_id": "version-contract",
    "archive_object_sha256": "c" * 64,
    "retention_lock_mode": "compliance",
    "retain_until": "2033-05-13T00:00:00Z",
    "legal_hold_status": "available",
    "legal_hold_id": "legal-hold-contract",
    "access_log_sha256": "d" * 64,
    "restore_job_id": "restore-contract",
    "restored_archive_sha256": "c" * 64,
    "replay_validator_output_sha256": "f" * 64,
    "custody_events": [
        {
            "event_id": "custody-contract-1",
            "event_type": "archive-written",
            "actor": "retention-exporter",
            "occurred_at": "2026-05-13T00:00:00Z",
            "evidence_sha256": "c" * 64,
        }
    ],
}
digest, size = write_text("retention/retention-manifest.json", json.dumps(retention, sort_keys=True) + "\n")
data["retention_manifest"] = {"path": "retention/retention-manifest.json", "sha256": digest, "bytes": size}

evidence_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${ALPHA}" --release-tier alpha --require-pass --check-files >/dev/null

BROKEN="${TMPDIR}/release-evidence/v9.9.9/wrong-target/evidence.json"
mkdir -p "$(dirname "${BROKEN}")"
cp "${EVIDENCE}" "${BROKEN}"
if python3 "${TOOL}" validate "${BROKEN}" 2>"${TMPDIR}/path.err"; then
    echo "ERROR: evidence in the wrong target directory unexpectedly validated" >&2
    exit 1
fi

if ! grep -q "target directory" "${TMPDIR}/path.err"; then
    echo "ERROR: path contract failure did not mention target directory mismatch" >&2
    cat "${TMPDIR}/path.err" >&2
    exit 1
fi

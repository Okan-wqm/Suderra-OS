#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" validate

python3 - "${PROJECT_ROOT}" <<'PY'
import json
import hashlib
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
validator = root / "scripts" / "ci" / "validate-build-matrix.py"
evidence_contract_spec = importlib.util.spec_from_file_location(
    "evidence_contract",
    root / "scripts" / "evidence" / "evidence_contract.py",
)
matrix_spec = importlib.util.spec_from_file_location("validate_build_matrix", validator)
assert evidence_contract_spec is not None and evidence_contract_spec.loader is not None
assert matrix_spec is not None and matrix_spec.loader is not None
evidence_contract = importlib.util.module_from_spec(evidence_contract_spec)
validate_build_matrix = importlib.util.module_from_spec(matrix_spec)
evidence_contract_spec.loader.exec_module(evidence_contract)
matrix_spec.loader.exec_module(validate_build_matrix)

contract = evidence_contract.load_contract(root / "ci" / "evidence-contract.yml")
matrix = validate_build_matrix.load_matrix(root / "ci" / "build-matrix.yml")
join_errors = evidence_contract.validate_matrix_join(matrix, contract)
if join_errors:
    raise SystemExit("evidence contract/build matrix join errors:\n" + "\n".join(join_errors))
production_ready_matrix = json.loads(json.dumps(matrix))
for row in production_ready_matrix["defconfigs"]:
    if row.get("production_required"):
        row["production_ready"] = True
        break
else:
    raise SystemExit("expected at least one production_required target")
production_ready_errors = evidence_contract.validate_matrix_join(production_ready_matrix, contract)
if not any("production_ready=false" in item for item in production_ready_errors):
    raise SystemExit("evidence contract/build matrix join must keep production_required targets at production_ready=false")
bad_matrix = json.loads(json.dumps(matrix))
for row in bad_matrix["defconfigs"]:
    if row.get("target") == "x86_64":
        row["signing"] = "unsigned-lab"
bad_errors = evidence_contract.validate_matrix_join(bad_matrix, contract)
if not any("signing_required" in item for item in bad_errors):
    raise SystemExit("evidence contract/build matrix join failed to reject unsigned production signing")

missing_target_matrix = json.loads(json.dumps(matrix))
missing_target_matrix["defconfigs"] = [
    row for row in missing_target_matrix["defconfigs"] if row.get("target") != "x86_64"
]
missing_target_errors = evidence_contract.validate_matrix_join(missing_target_matrix, contract)
if not any("target x86_64 is missing" in item for item in missing_target_errors):
    raise SystemExit("evidence contract/build matrix join failed closed target coverage")

release_mismatch_matrix = json.loads(json.dumps(matrix))
for row in release_mismatch_matrix["defconfigs"]:
    if row.get("target") == "qemu-x86_64":
        row["release"] = False
release_mismatch_errors = evidence_contract.validate_matrix_join(release_mismatch_matrix, contract)
if not any("release_public" in item for item in release_mismatch_errors):
    raise SystemExit("evidence contract/build matrix join failed to reject release_public mismatch")

runtime_contract = json.loads(json.dumps(contract))
runtime_contract["runtime"]["suite_targets"]["x86_64"] = []
runtime_errors = evidence_contract.validate_matrix_join(matrix, runtime_contract)
if not any("runtime_required" in item for item in runtime_errors):
    raise SystemExit("evidence contract/build matrix join failed to require runtime suite mapping")

signing_contract = json.loads(json.dumps(contract))
signing_contract["signing"]["role_bindings"] = {}
signing_errors = evidence_contract.validate_matrix_join(matrix, signing_contract)
if not any("signing manifest role binding" in item for item in signing_errors):
    raise SystemExit("evidence contract/build matrix join failed to require signing manifest role bindings")

hardware_contract = json.loads(json.dumps(contract))
hardware_contract["hardware"].pop("subject_binding")
hardware_errors = evidence_contract.validate_matrix_join(matrix, hardware_contract)
if not any("hardware.subject_binding" in item for item in hardware_errors):
    raise SystemExit("evidence contract/build matrix join failed to require hardware subject binding")

subject_policy = evidence_contract.subject_policy(contract)
if subject_policy["schema_version"] != contract["schema_versions"]["release_subject_graph"]:
    raise SystemExit("subject graph schema must be governed by the evidence contract")
retention_policy = evidence_contract.retention_policy(contract)
if retention_policy["policy_id"] != "suderra-enterprise-7y-immutable-evidence":
    raise SystemExit("retention policy must be governed by the evidence contract")
rc_profile = evidence_contract.profile_policy("rc-evidence-dry-run", contract)
if rc_profile.get("release_authorizing") is not False or rc_profile.get("publication_allowed") is not False:
    raise SystemExit("rc-evidence-dry-run must be non-promotable")
if rc_profile.get("strict_artifact_binding") is not True or rc_profile.get("gap_report_required") is not True:
    raise SystemExit("rc-evidence-dry-run must require strict artifact binding and a gap report")

join_cli = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/evidence_contract.py"),
        "validate-join",
        "--matrix",
        str(root / "ci/build-matrix.yml"),
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if join_cli.returncode != 0:
    raise SystemExit(join_cli.stderr or join_cli.stdout)

subject_plan = json.loads(
    subprocess.check_output(
        [
            "python3",
            str(root / "scripts/evidence/evidence_contract.py"),
            "subject-plan",
            "--version",
            "v9.9.9",
            "--target",
            "x86_64",
            "--source-sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--source-run-id",
            "123456789",
        ],
        text=True,
    )
)
if subject_plan["schema_version"] != "suderra.release-subject-graph.v1":
    raise SystemExit("subject-plan must emit the canonical subject graph schema")
if subject_plan["subject_id"] != "suderra-release:v9.9.9:x86_64:0123456789abcdef0123456789abcdef01234567:123456789":
    raise SystemExit("subject-plan emitted a non-canonical subject_id")
if subject_plan["required_evidence"]["release-signing"] != "release-signing/v9.9.9/x86_64/signing-manifest.json":
    raise SystemExit("subject-plan must point release-signing at signing-manifest.json")
if subject_plan["required_evidence"]["release-inputs"] != "release-inputs/v9.9.9/release-candidate.json":
    raise SystemExit("subject-plan must use profile-aware release input binding paths")
if not subject_plan.get("evidence_nodes") or not subject_plan.get("evidence_edges"):
    raise SystemExit("subject-plan must expose graph evidence nodes and edges")
if any(not node.get("schema_role") or not node.get("schema_version") for node in subject_plan["evidence_nodes"]):
    raise SystemExit("subject-plan evidence nodes must expose schema role and version")
if "release-subject-graph" not in subject_plan["retention_closure"]["required_exports"]:
    raise SystemExit("subject-plan retention closure must include release-subject-graph")

runtime_plan = json.loads(
    subprocess.check_output(
        [
            "python3",
            str(root / "scripts/evidence/evidence_contract.py"),
            "runtime-plan",
            "--version",
            "v9.9.9",
            "--target",
            "x86_64",
            "--source-sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--source-run-id",
            "123456789",
            "--source-run-attempt",
            "1",
            "--defconfig",
            "suderra_x86_64",
            "--image",
            "disk.img",
            "--release-artifact",
            "suderra-os-v9.9.9-x86_64.img.xz",
            "--raw-image-sha256",
            "a" * 64,
            "--artifact-digest",
            "b" * 64,
            "--ovmf-code",
            "OVMF_CODE.fd",
            "--ovmf-vars",
            "OVMF_VARS.enrolled.fd",
            "--ovmf-enrollment-mode",
            "secure-boot-enrolled",
            "--ovmf-enrolled-vars-sha256",
            "c" * 64,
            "--secure-boot-db-sha256",
            "d" * 64,
            "--swtpm-state",
            "swtpm",
        ],
        text=True,
    )
)
if runtime_plan["ovmf_enrollment_mode"] != "secure-boot-enrolled":
    raise SystemExit("runtime-plan must carry the OVMF enrollment mode")
if runtime_plan["ovmf_enrolled_vars_sha256"] != "c" * 64:
    raise SystemExit("runtime-plan must carry the enrolled OVMF vars digest")
if runtime_plan["secure_boot_db_sha256"] != "d" * 64:
    raise SystemExit("runtime-plan must carry the Secure Boot db digest")
if runtime_plan["artifact_digest"] != "b" * 64:
    raise SystemExit("runtime-plan must accept --artifact-digest as the public compressed artifact digest")
if runtime_plan["compressed_artifact_sha256"] != "b" * 64:
    raise SystemExit("runtime-plan artifact digest alias must populate compressed_artifact_sha256")
if not runtime_plan.get("scenarios"):
    raise SystemExit("runtime-plan must emit governed runtime scenarios")

missing_runtime_arg = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/evidence_contract.py"),
        "runtime-plan",
        "--version",
        "v9.9.9",
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if missing_runtime_arg.returncode == 0:
    raise SystemExit("runtime-plan accepted missing required arguments")
if "Traceback" in (missing_runtime_arg.stderr + missing_runtime_arg.stdout):
    raise SystemExit("runtime-plan missing argument must fail through argparse, not traceback")

strict_subject_plan = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/evidence_contract.py"),
        "subject-plan",
        "--version",
        "v9.9.9",
        "--profile",
        "production-candidate",
        "--target",
        "x86_64",
        "--source-sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--source-run-id",
        "123456789",
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if strict_subject_plan.returncode == 0:
    raise SystemExit("production-candidate subject-plan accepted digestless artifact identity")
if "raw-image-sha256" not in (strict_subject_plan.stderr + strict_subject_plan.stdout):
    raise SystemExit("digestless production subject-plan failure did not cite raw image digest")

rc_subject_plan = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/evidence_contract.py"),
        "subject-plan",
        "--version",
        "v9.9.9-rc.1",
        "--profile",
        "rc-evidence-dry-run",
        "--target",
        "qemu-x86_64",
        "--source-sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--source-run-id",
        "123456789",
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if rc_subject_plan.returncode == 0:
    raise SystemExit("rc-evidence-dry-run subject-plan accepted digestless artifact identity")

retention_plan = json.loads(
    subprocess.check_output(
        [
            "python3",
            str(root / "scripts/evidence/evidence_contract.py"),
            "retention-plan",
            "--version",
            "v9.9.9",
            "--source-sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--source-run-id",
            "123456789",
        ],
        text=True,
    )
)
if retention_plan["schema_version"] != "suderra.retention-manifest.v1":
    raise SystemExit("retention-plan must emit the retention manifest schema")
if "scanner-raw-replay" not in retention_plan["required_replay"]:
    raise SystemExit("retention-plan must require replay coverage")
retention_exports = {item["name"] for item in retention_plan["required_exports"]}
if not {"release-inputs", "release-subject-graph"} <= retention_exports:
    raise SystemExit("retention-plan must preserve release inputs and subject graph")

output_tree_plan = json.loads(
    subprocess.check_output(
        [
            "python3",
            str(root / "scripts/evidence/evidence_contract.py"),
            "output-tree-plan",
            "--version",
            "v9.9.9-rc.1",
            "--profile",
            "rc-evidence-dry-run",
        ],
        text=True,
    )
)
if output_tree_plan["release_authorizing"] is not False or output_tree_plan["publication_allowed"] is not False:
    raise SystemExit("output-tree-plan must preserve non-promotable RC dry-run semantics")
required_outputs = {item["name"] for item in output_tree_plan["outputs"] if item["required"]}
if "release-dry-run" not in required_outputs or "release-subject-graph" not in required_outputs:
    raise SystemExit("rc-evidence-dry-run output-tree-plan must require dry-run and subject graph outputs")
dry_run_output = next(item for item in output_tree_plan["outputs"] if item["name"] == "release-dry-run")
if (
    dry_run_output["promotable"] is not False
    or dry_run_output["operator_ingress_allowed"] is not False
    or dry_run_output["dry_run_input_allowed"] is not True
):
    raise SystemExit("release-dry-run output tree must remain non-promotable, blocked from operator ingress, and explicit dry-run input")

tmp = root / "test-results" / "rc-dry-run-contract"
if tmp.exists():
    import shutil
    shutil.rmtree(tmp)
tmp.mkdir(parents=True)
version = "v9.9.9-rc.1"
source_sha = "0123456789abcdef0123456789abcdef01234567"
artifacts = []
artifact_root = tmp / "build-artifacts"
for row in matrix["defconfigs"]:
    if not row.get("release"):
        continue
    for artifact in validate_build_matrix.expected_artifacts(row):
        rel = Path(f"{row['name']}-image/{artifact}")
        path = artifact_root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        content = f"{row['name']}:{artifact}:rc-dry-run\n".encode("utf-8")
        path.write_bytes(content)
        artifacts.append(
            {
                "defconfig": row["name"],
                "target": row["target"],
                "artifact": artifact,
                "path": rel.as_posix(),
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
contract_rel = Path("image-build-contract/image-build-contract.json")
contract_path = artifact_root / contract_rel
contract_path.parent.mkdir(parents=True, exist_ok=True)
contract_content = b'{"schema_version":"suderra.image-build-contract.v1"}\n'
contract_path.write_bytes(contract_content)
contract_sha = hashlib.sha256(contract_content).hexdigest()
binding = {
    "schema_version": "suderra.release-input-binding.v2",
    "profile": "rc-evidence-dry-run",
    "version": version,
    "source_sha": source_sha,
    "source_run_id": "123456789",
    "source_run_attempt": "1",
    "artifacts": artifacts,
    "installers": [],
    "image_build_contract": {
        "path": "image-build-contract/image-build-contract.json",
        "bytes": len(contract_content),
        "sha256": contract_sha,
    },
}
binding_path = tmp / "release-inputs" / version / "rc-evidence-dry-run.json"
binding_path.parent.mkdir(parents=True)
binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
subject_graph_path = tmp / "release-subject-graph" / version / "release-subject-graph.json"
subject_graph = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/prepare-release-inputs.py"),
        "subject-graph",
        "--binding-manifest",
        str(binding_path),
        "--input-root",
        str(tmp),
        "--output",
        str(subject_graph_path),
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if subject_graph.returncode != 0:
    raise SystemExit(subject_graph.stderr or subject_graph.stdout)
governance_root = tmp / "release-governance" / version
governance_root.mkdir(parents=True)
(governance_root / "governance-policy-validation.json").write_text(
    json.dumps(
        {
            "schema_version": "suderra.github-governance-validation.v2",
            "status": "passed",
            "failures": [],
            "warnings": [],
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
governance_validation_digest = hashlib.sha256(
    (governance_root / "governance-policy-validation.json").read_bytes()
).hexdigest()
(governance_root / "snapshot-manifest.json").write_text(
    json.dumps(
        {
            "schema_version": "suderra.github-governance-snapshot-manifest.v1",
            "version": version,
            "repository": "Okan-wqm/Suderra-OS",
            "files": [{"name": "governance-policy-validation.json", "sha256": governance_validation_digest}],
            "failures": [],
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
create_rc = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/rc-evidence-dry-run.py"),
        "create",
        "--binding-manifest",
        str(binding_path),
        "--input-root",
        str(tmp),
        "--output-root",
        str(tmp / "release-dry-run"),
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if create_rc.returncode != 0:
    raise SystemExit(create_rc.stderr or create_rc.stdout)
validate_rc = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/rc-evidence-dry-run.py"),
        "validate",
        str(tmp / "release-dry-run" / version / "bundle-manifest.json"),
        "--input-root",
        str(tmp),
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if validate_rc.returncode != 0:
    raise SystemExit(validate_rc.stderr or validate_rc.stdout)
dry_run_report = json.loads((tmp / "release-dry-run" / version / "dry-run-report.json").read_text(encoding="utf-8"))
if dry_run_report["release_authorizing"] is not False or dry_run_report["production_ready"] is not False:
    raise SystemExit("RC dry-run report must remain non-promotable and production_ready=false")
gaps = json.loads((tmp / "release-dry-run" / version / "gaps.json").read_text(encoding="utf-8"))
if gaps["status"] != "blocked_for_production" or not gaps["gaps"]:
    raise SystemExit("RC dry-run must preserve production evidence gaps as blockers")
runtime_gaps = json.loads((tmp / "release-dry-run" / version / "plans/runtime-plan/gaps.json").read_text(encoding="utf-8"))
if runtime_gaps["status"] != "blocked_for_production" or not runtime_gaps["runtime_targets"]:
    raise SystemExit("RC dry-run must preserve runtime-plan blockers without fake runtime evidence")
bundle_manifest = json.loads((tmp / "release-dry-run" / version / "bundle-manifest.json").read_text(encoding="utf-8"))
if bundle_manifest["release_authorizing"] is not False or bundle_manifest["production_ready"] is not False:
    raise SystemExit("RC dry-run bundle manifest must remain non-promotable and production_ready=false")
external_roles = {item["role"] for item in bundle_manifest["external_refs"]}
if {"release-input-binding", "release-subject-graph", "governance-snapshot-manifest", "governance-policy-validation"} - external_roles:
    raise SystemExit("RC dry-run bundle manifest must digest-bind release inputs, subject graph, and governance refs")
if any(field in dry_run_report for field in ("binding_manifest", "subject_graph", "governance_refs", "plans", "digests", "gap_report")):
    raise SystemExit("RC dry-run report must not duplicate canonical bundle-manifest state")
gaps_path = tmp / "release-dry-run" / version / "gaps.json"
original_gaps = gaps_path.read_text(encoding="utf-8")
gaps_path.write_text(original_gaps.replace("blocked_for_production", "tampered", 1), encoding="utf-8")
tampered_validate = subprocess.run(
    [
        "python3",
        str(root / "scripts/evidence/rc-evidence-dry-run.py"),
        "validate",
        str(tmp / "release-dry-run" / version / "bundle-manifest.json"),
        "--input-root",
        str(tmp),
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
gaps_path.write_text(original_gaps, encoding="utf-8")
if tampered_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a tampered digest-bound gap report")

bundle_path = tmp / "release-dry-run" / version / "bundle-manifest.json"
original_bundle_text = bundle_path.read_text(encoding="utf-8")
original_graph_text = subject_graph_path.read_text(encoding="utf-8")


def run_bundle_validation() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python3",
            str(root / "scripts/evidence/rc-evidence-dry-run.py"),
            "validate",
            str(bundle_path),
            "--input-root",
            str(tmp),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def rewrite_external_ref(role: str, file_path: Path) -> None:
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    data = file_path.read_bytes()
    for item in payload["external_refs"]:
        if item["role"] == role:
            item["bytes"] = len(data)
            item["sha256"] = hashlib.sha256(data).hexdigest()
            break
    else:
        raise SystemExit(f"missing external ref role {role}")
    bundle_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rewrite_member_ref(role: str, file_path: Path) -> None:
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    data = file_path.read_bytes()
    rel = file_path.relative_to(bundle_path.parent).as_posix()
    for item in payload["members"]:
        if item["role"] == role and item["path"] == rel:
            item["bytes"] = len(data)
            item["sha256"] = hashlib.sha256(data).hexdigest()
            break
    else:
        raise SystemExit(f"missing member role/path {role}:{rel}")
    bundle_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


graph_payload = json.loads(original_graph_text)
graph_payload["subjects"][0]["subject_id"] = "suderra-release:tampered-subject"
subject_graph_path.write_text(json.dumps(graph_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_external_ref("release-subject-graph", subject_graph_path)
semantic_graph_validate = run_bundle_validation()
subject_graph_path.write_text(original_graph_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if semantic_graph_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a digest-bound but semantically wrong subject graph")

path_tamper = json.loads(original_bundle_text)
path_tamper["members"][0]["path"] = "../escape.json"
bundle_path.write_text(json.dumps(path_tamper, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path_tamper_validate = run_bundle_validation()
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if path_tamper_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a path traversal bundle member")

zero_digest_tamper = json.loads(original_bundle_text)
zero_digest_tamper["external_refs"][0]["sha256"] = "0" * 64
bundle_path.write_text(json.dumps(zero_digest_tamper, indent=2, sort_keys=True) + "\n", encoding="utf-8")
zero_digest_validate = run_bundle_validation()
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if zero_digest_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted an all-zero external reference digest")

inventory_path = tmp / "release-dry-run" / version / "digests/image-build-artifacts.json"
original_inventory_text = inventory_path.read_text(encoding="utf-8")
inventory_payload = json.loads(original_inventory_text)
inventory_payload["artifacts"][0]["bytes"] += 1
inventory_path.write_text(json.dumps(inventory_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_member_ref("image-build-artifact-digests", inventory_path)
inventory_validate = run_bundle_validation()
inventory_path.write_text(original_inventory_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if inventory_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a digest-bound but binding-mismatched artifact inventory")


def assert_inventory_mutation_rejected(label: str, mutate) -> None:
    inventory_path.write_text(original_inventory_text, encoding="utf-8")
    bundle_path.write_text(original_bundle_text, encoding="utf-8")
    payload = json.loads(original_inventory_text)
    mutate(payload)
    inventory_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rewrite_member_ref("image-build-artifact-digests", inventory_path)
    result = run_bundle_validation()
    inventory_path.write_text(original_inventory_text, encoding="utf-8")
    bundle_path.write_text(original_bundle_text, encoding="utf-8")
    if result.returncode == 0:
        raise SystemExit(f"RC dry-run validator accepted inventory mutation: {label}")


assert_inventory_mutation_rejected(
    "missing binding artifact",
    lambda payload: payload["artifacts"].pop(0),
)


def add_extra_inventory_artifact(payload: dict) -> None:
    extra_content = b"extra inventory artifact\n"
    extra_rel = Path("extra-inventory/extra.img")
    extra_path = artifact_root / extra_rel
    extra_path.parent.mkdir(parents=True, exist_ok=True)
    extra_path.write_bytes(extra_content)
    first = dict(payload["artifacts"][0])
    first.update(
        {
            "artifact": "extra.img",
            "path": extra_rel.as_posix(),
            "bytes": len(extra_content),
            "sha256": hashlib.sha256(extra_content).hexdigest(),
        }
    )
    payload["artifacts"].append(first)


assert_inventory_mutation_rejected("extra inventory artifact", add_extra_inventory_artifact)


assert_inventory_mutation_rejected(
    "wrong sha",
    lambda payload: payload["artifacts"][0].update({"sha256": "f" * 64}),
)
assert_inventory_mutation_rejected(
    "unsafe path",
    lambda payload: payload["artifacts"][0].update({"path": "../escape.img"}),
)
assert_inventory_mutation_rejected(
    "all-zero inventory digest",
    lambda payload: payload["artifacts"][0].update({"sha256": "0" * 64}),
)

first_inventory_record = json.loads(original_inventory_text)["artifacts"][0]
build_artifact_path = artifact_root / first_inventory_record["path"]
original_build_artifact_bytes = build_artifact_path.read_bytes()
build_artifact_path.write_bytes(original_build_artifact_bytes + b"tampered\n")
artifact_replay_validate = run_bundle_validation()
build_artifact_path.write_bytes(original_build_artifact_bytes)
if artifact_replay_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted tampered build-artifacts bytes")

subject_plan_path = tmp / "release-dry-run" / version / "plans/subject-plan/qemu-x86_64.json"
original_subject_plan_text = subject_plan_path.read_text(encoding="utf-8")
subject_plan_payload = json.loads(original_subject_plan_text)
subject_plan_payload["evidence_edges"][0]["relationship"] = "requires"
subject_plan_path.write_text(json.dumps(subject_plan_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_member_ref("subject-plan", subject_plan_path)
subject_plan_validate = run_bundle_validation()
subject_plan_path.write_text(original_subject_plan_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if subject_plan_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a subject-plan edge mismatch")

graph_payload = json.loads(original_graph_text)
graph_payload["subjects"] = [item for item in graph_payload["subjects"] if item["target"] != "qemu-x86_64"]
subject_graph_path.write_text(json.dumps(graph_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_external_ref("release-subject-graph", subject_graph_path)
missing_subject_validate = run_bundle_validation()
subject_graph_path.write_text(original_graph_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if missing_subject_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a missing graph subject")

graph_payload = json.loads(original_graph_text)
for item in graph_payload["subjects"]:
    if item["target"] == "qemu-x86_64":
        item["artifacts"]["compressed_release_artifact"]["sha256"] = "e" * 64
        break
subject_graph_path.write_text(json.dumps(graph_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_external_ref("release-subject-graph", subject_graph_path)
wrong_digest_validate = run_bundle_validation()
subject_graph_path.write_text(original_graph_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if wrong_digest_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a graph/plan artifact digest mismatch")

graph_payload = json.loads(original_graph_text)
qemu_subject = next(item for item in graph_payload["subjects"] if item["target"] == "qemu-x86_64")
qemu_subject_id = qemu_subject["subject_id"]
extra_node = {
    "node_id": f"{qemu_subject_id}:extra-node",
    "subject_id": qemu_subject_id,
    "target": "qemu-x86_64",
    "role": "extra-evidence",
    "path": "release-extra/v9.9.9-rc.1/qemu-x86_64.json",
    "schema_role": "extra_evidence",
    "schema_version": "suderra.extra.v1",
    "required": False,
    "producer": "contract-negative-test",
}
graph_payload["evidence_nodes"].append(extra_node)
graph_payload["evidence_edges"].append(
    {
        "from": qemu_subject_id,
        "to": extra_node["node_id"],
        "relationship": "observes",
        "role": "extra-evidence",
    }
)
subject_graph_path.write_text(json.dumps(graph_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_external_ref("release-subject-graph", subject_graph_path)
extra_graph_node_validate = run_bundle_validation()
subject_graph_path.write_text(original_graph_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if extra_graph_node_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted an extra graph node/edge not present in subject-plan")

subject_plan_payload = json.loads(original_subject_plan_text)
subject_plan_payload["required_evidence"].pop(0)
subject_plan_path.write_text(json.dumps(subject_plan_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_member_ref("subject-plan", subject_plan_path)
missing_required_validate = run_bundle_validation()
subject_plan_path.write_text(original_subject_plan_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if missing_required_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a subject-plan required_evidence mismatch")

subject_plan_payload = json.loads(original_subject_plan_text)
subject_plan_payload["retention_closure"]["policy_id"] = "tampered-policy"
subject_plan_path.write_text(json.dumps(subject_plan_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
rewrite_member_ref("subject-plan", subject_plan_path)
retention_validate = run_bundle_validation()
subject_plan_path.write_text(original_subject_plan_text, encoding="utf-8")
bundle_path.write_text(original_bundle_text, encoding="utf-8")
if retention_validate.returncode == 0:
    raise SystemExit("RC dry-run validator accepted a subject-plan retention closure mismatch")


def matrix_defconfigs(selector: str) -> set[str]:
    payload = subprocess.check_output(
        ["python3", str(validator), "github-matrix", "--selector", selector],
        text=True,
    )
    return {entry["defconfig"] for entry in json.loads(payload)["include"]}


base = matrix_defconfigs("ci_build_base")
payload = matrix_defconfigs("ci_build_payload")
fast = matrix_defconfigs("fast_required")
image_base = matrix_defconfigs("image_build_base")
image_payload = matrix_defconfigs("image_build_payload")
image_qemu = matrix_defconfigs("image_build_qemu")
release_base = matrix_defconfigs("release_base")
release_payload = matrix_defconfigs("release_payload")

expected_base = {
    "suderra_qemu_x86_64_defconfig",
    "suderra_aarch64_rpi4_defconfig",
    "suderra_aarch64_revpi4_defconfig",
}
expected_payload = {"suderra_aarch64_rpi4_usb_installer_defconfig"}

if base != expected_base:
    raise SystemExit(f"ci_build_base mismatch: {sorted(base)}")
if payload != expected_payload:
    raise SystemExit(f"ci_build_payload mismatch: {sorted(payload)}")
if fast != expected_base | expected_payload:
    raise SystemExit(f"fast_required mismatch: {sorted(fast)}")
if image_base != expected_base:
    raise SystemExit(f"image_build_base mismatch: {sorted(image_base)}")
if image_payload != expected_payload:
    raise SystemExit(f"image_build_payload mismatch: {sorted(image_payload)}")
if image_qemu != {"suderra_qemu_x86_64_defconfig"}:
    raise SystemExit(f"image_build_qemu mismatch: {sorted(image_qemu)}")
expected_release_base = {
    "suderra_qemu_x86_64_defconfig",
    "suderra_aarch64_rpi4_defconfig",
    "suderra_aarch64_revpi4_defconfig",
}
if release_base != expected_release_base:
    raise SystemExit(f"release_base mismatch: {sorted(release_base)}")
if release_payload != expected_payload:
    raise SystemExit(f"release_payload mismatch: {sorted(release_payload)}")
if base & payload:
    raise SystemExit(f"base/payload matrix overlap: {sorted(base & payload)}")
if image_base & image_payload:
    raise SystemExit(f"image base/payload matrix overlap: {sorted(image_base & image_payload)}")
if release_base & release_payload:
    raise SystemExit(f"release base/payload matrix overlap: {sorted(release_base & release_payload)}")

legacy_text = subprocess.check_output(
    ["git", "-C", str(root / "buildroot"), "show", "HEAD:Config.in.legacy"],
    text=True,
)
legacy_symbols = set(re.findall(r"^config (BR2_[A-Za-z0-9_]+)$", legacy_text, flags=re.MULTILINE))
selected_legacy: list[str] = []
selected_re = re.compile(r"^(BR2_[A-Za-z0-9_]+)=(y|m|\".+\"|[1-9].*)$")
hash_dir = root / "board" / "suderra" / "buildroot-hashes"
linux_hash = hash_dir / "linux" / "linux.hash"
kernel_hash_dir_config = (
    'BR2_GLOBAL_PATCH_DIR="$(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra/buildroot-hashes"'
)
kernel_tarball_re = re.compile(r'^BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=".*?([^/"]+\.tar\.gz)"$')
custom_kernel_errors: list[str] = []
for config in sorted((root / "configs").glob("*_defconfig")):
    config_lines = config.read_text(encoding="utf-8").splitlines()
    stripped_lines = [line.strip() for line in config_lines]
    for line_no, line in enumerate(config_lines, start=1):
        match = selected_re.match(line.strip())
        if match and match.group(1) in legacy_symbols:
            selected_legacy.append(f"{config.relative_to(root)}:{line_no}:{line.strip()}")

    if "BR2_LINUX_KERNEL_CUSTOM_TARBALL=y" not in stripped_lines:
        continue
    location_lines = [
        line for line in stripped_lines if line.startswith("BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=")
    ]
    if len(location_lines) != 1:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} must define exactly one custom kernel tarball location"
        )
        continue
    if "BR2_DOWNLOAD_FORCE_CHECK_HASHES=y" not in stripped_lines:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} must enable BR2_DOWNLOAD_FORCE_CHECK_HASHES"
        )
    if kernel_hash_dir_config not in stripped_lines:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} must set BR2_GLOBAL_PATCH_DIR to board/suderra/buildroot-hashes"
        )
    tarball_match = kernel_tarball_re.match(location_lines[0])
    if not tarball_match:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} custom kernel tarball location must end in a .tar.gz basename"
        )
        continue
    tarball = tarball_match.group(1)
    if not linux_hash.is_file():
        custom_kernel_errors.append(f"{linux_hash.relative_to(root)} is required")
        continue
    hash_pattern = re.compile(rf"^sha256\s+([0-9a-f]{{64}})\s+{re.escape(tarball)}$", re.MULTILINE)
    hash_match = hash_pattern.search(linux_hash.read_text(encoding="utf-8"))
    if not hash_match:
        custom_kernel_errors.append(
            f"{linux_hash.relative_to(root)} must contain a sha256 entry for {tarball}"
        )
    elif hash_match.group(1) == "0" * 64:
        custom_kernel_errors.append(
            f"{linux_hash.relative_to(root)} contains a placeholder digest for {tarball}"
        )
if selected_legacy:
    raise SystemExit("legacy Buildroot Kconfig symbols selected:\n" + "\n".join(selected_legacy))
if custom_kernel_errors:
    raise SystemExit("custom kernel tarballs must be hash-checked:\n" + "\n".join(custom_kernel_errors))
PY

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" \
    candidate-readiness --tag v0.1.0-alpha.1 >/dev/null

if python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" \
    production-readiness --tag v0.1.0 >/dev/null 2>&1; then
    echo "ERROR: production readiness unexpectedly passed while production blockers remain" >&2
    exit 1
fi

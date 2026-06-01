#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""AST-level contract checks for release workflows."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
from typing import Any

import yaml


class GithubActionsLoader(yaml.SafeLoader):
    pass


for first, resolvers in list(GithubActionsLoader.yaml_implicit_resolvers.items()):
    GithubActionsLoader.yaml_implicit_resolvers[first] = [
        (tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"
    ]


def load_workflow(path: Path) -> dict[str, Any]:
    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=GithubActionsLoader)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: workflow must parse to an object")
    return payload


def load_evidence_contract(root: Path) -> Any:
    path = root / "scripts" / "evidence" / "evidence_contract.py"
    spec = importlib.util.spec_from_file_location("evidence_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def step_text(job: dict[str, Any]) -> str:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return ""
    chunks: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        for field in ("name", "uses", "run"):
            value = step.get(field)
            if isinstance(value, str):
                chunks.append(value)
    return "\n".join(chunks)


def all_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []
    steps: list[dict[str, Any]] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []):
            if isinstance(step, dict):
                steps.append(step)
    return steps


def upload_artifact_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step
        for step in all_steps(workflow)
        if isinstance(step.get("uses"), str) and str(step["uses"]).startswith("actions/upload-artifact@")
    ]


def download_artifact_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step
        for step in all_steps(workflow)
        if isinstance(step.get("uses"), str) and str(step["uses"]).startswith("actions/download-artifact@")
    ]


def normalized_path_lines(value: Any) -> set[str]:
    if isinstance(value, str):
        return {line.strip() for line in value.splitlines() if line.strip()}
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def step_with_name(workflow: dict[str, Any], name: str) -> dict[str, Any] | None:
    matches = [step for step in all_steps(workflow) if step.get("name") == name]
    return matches[0] if len(matches) == 1 else None


def require_step(
    workflow: dict[str, Any],
    failures: list[str],
    name: str,
    *,
    if_expr: str | None = None,
    run_tokens: tuple[str, ...] = (),
) -> dict[str, Any] | None:
    step = step_with_name(workflow, name)
    fail_if(step is None, failures, f"workflow missing step {name}")
    if step is None:
        return None
    if if_expr is not None:
        fail_if(step.get("if") != if_expr, failures, f"{name}: if guard mismatch")
    run = step.get("run")
    run_text = run if isinstance(run, str) else ""
    for token in run_tokens:
        fail_if(token not in run_text, failures, f"{name}: missing run token {token}")
    return step


def require_upload(
    workflow: dict[str, Any],
    failures: list[str],
    artifact_name: str,
    expected_paths: set[str],
) -> None:
    matches = [
        step
        for step in upload_artifact_steps(workflow)
        if isinstance(step.get("with"), dict) and step["with"].get("name") == artifact_name
    ]
    fail_if(len(matches) != 1, failures, f"expected exactly one upload-artifact step named {artifact_name}")
    if not matches:
        return
    actual_paths = normalized_path_lines(matches[0].get("with", {}).get("path"))
    fail_if(actual_paths != expected_paths, failures, f"upload-artifact {artifact_name} path list mismatch")


def require_download(
    workflow: dict[str, Any],
    failures: list[str],
    artifact_name: str,
    expected_path: str,
) -> None:
    matches = [
        step
        for step in download_artifact_steps(workflow)
        if isinstance(step.get("with"), dict) and step["with"].get("name") == artifact_name
    ]
    fail_if(not matches, failures, f"expected at least one download-artifact step named {artifact_name}")
    if not matches:
        return
    for step in matches:
        fail_if(step.get("with", {}).get("path") != expected_path, failures, f"download-artifact {artifact_name} path mismatch")


def output_root_upload_paths(evidence_contract: Any, *, contract: dict[str, Any]) -> set[str]:
    return {f"{root}/" for root in evidence_contract.output_tree_roots(contract=contract)}


def release_tag_upload_paths(evidence_contract: Any, *, contract: dict[str, Any]) -> set[str]:
    return {f"{root}/" for root in evidence_contract.release_tag_allowed_roots(contract=contract)}


def fail_if(condition: bool, failures: list[str], message: str) -> None:
    if condition:
        failures.append(message)


def verify_release(root: Path, failures: list[str]) -> None:
    release = load_workflow(root / ".github/workflows/release.yml")
    evidence_contract = load_evidence_contract(root)
    contract = evidence_contract.load_contract(root / "ci/evidence-contract.yml")
    on = release.get("on")
    fail_if(not isinstance(on, dict) or on.get("push", {}).get("tags") != ["v*"], failures, "release.yml must trigger only v* tag pushes")
    fail_if(isinstance(on, dict) and "workflow_dispatch" in on, failures, "release.yml must not support workflow_dispatch")
    fail_if(
        release.get("permissions") != {"actions": "read", "contents": "read"},
        failures,
        "release.yml top-level permissions must be actions: read and contents: read",
    )
    concurrency = release.get("concurrency")
    fail_if(not isinstance(concurrency, dict) or concurrency.get("group") != "release-${{ github.ref_name }}", failures, "release.yml concurrency group mismatch")
    jobs = release.get("jobs")
    if not isinstance(jobs, dict):
        failures.append("release.yml jobs must be an object")
        return
    for name in ("validate", "governance", "preflight-binding", "input-preflight", "release-stage", "release-sign", "publish"):
        fail_if(name not in jobs, failures, f"release.yml missing job {name}")
    governance = jobs.get("governance", {})
    fail_if(
        set(as_list(governance.get("needs"))) != {"validate", "preflight-binding"},
        failures,
        "governance job must need validate and preflight-binding",
    )
    input_preflight = jobs.get("input-preflight", {})
    fail_if(
        set(as_list(input_preflight.get("needs"))) != {"validate", "governance", "preflight-binding"},
        failures,
        "input-preflight job dependencies must bind validate/governance/preflight-binding",
    )
    sign = jobs.get("release-sign", {})
    publish = jobs.get("publish", {})
    fail_if(sign.get("environment", {}).get("name") != "release-sign", failures, "release-sign job must use release-sign environment")
    fail_if(publish.get("environment", {}).get("name") != "release-publish", failures, "publish job must use release-publish environment")
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        perms = job.get("permissions", {})
        if not isinstance(perms, dict):
            perms = {}
        if perms.get("contents") == "write":
            fail_if(job_name != "publish", failures, f"{job_name}: only publish may request contents: write")
        if perms.get("id-token") == "write":
            fail_if(job_name not in {"release-sign", "publish", "governance"}, failures, f"{job_name}: unexpected id-token write")
        if perms.get("attestations") == "write":
            fail_if(job_name != "release-sign", failures, f"{job_name}: only release-sign may request attestations: write")
    release_text = step_text(jobs.get("release-stage", {})) + "\n" + step_text(jobs.get("publish", {}))
    fail_if("build-in-docker.sh" in release_text or "cargo build" in release_text, failures, "release workflow must not rebuild release bytes")
    governance_text = step_text(governance)
    for token in (
        "validate-governance-drift-replay.py select-run",
        "validate-governance-drift-replay.py validate",
        "governance-drift-${drift_run_id}",
        "cosign verify-blob",
    ):
        fail_if(token not in governance_text, failures, f"governance replay step missing token {token}")
    require_step(
        release,
        failures,
        "Download bound release preflight artifact",
        run_tokens=(
            "preflight-artifact-name.txt",
            "gh run download",
            "--name \"${artifact_name}\"",
            "validate-release-tag-binding.py validate-cross-binding",
        ),
    )
    require_step(
        release,
        failures,
        "Resolve approved release preflight",
        run_tokens=(
            "validate-release-tag-binding.py parse",
            "validate-release-tag-binding.py validate-run",
            "release-tag-binding.json",
            "SUDERRA_RELEASE_TAG_SIGNING_FINGERPRINTS",
        ),
    )
    tag_paths = release_tag_upload_paths(evidence_contract, contract=contract)
    require_upload(
        release,
        failures,
        "release-governance-inputs-${{ needs.validate.outputs.version }}",
        {
            "release-governance/${{ needs.validate.outputs.version }}/audit-log.json",
            "release-governance/${{ needs.validate.outputs.version }}/station-registry.json",
            "release-governance/${{ needs.validate.outputs.version }}/role-bindings.json",
        },
    )
    require_upload(
        release,
        failures,
        "release-inputs-${{ needs.validate.outputs.version }}",
        tag_paths | {"release-tag-binding.json", "tag-annotation.txt", "preflight-run.json", "preflight-artifacts.json"},
    )
    require_upload(release, failures, "release-governance-${{ needs.validate.outputs.version }}", {"release-governance/"})
    require_upload(release, failures, "staged-release-${{ needs.validate.outputs.version }}", tag_paths | {"release/"})
    require_upload(release, failures, "signed-release-${{ needs.validate.outputs.version }}", {"release/", "release-evidence-generated/"})
    require_upload(
        release,
        failures,
        "post-publication-verification-${{ needs.validate.outputs.version }}",
        {"post-publication-verification/"},
    )
    for artifact_name, path_value in (
        ("release-governance-inputs-${{ needs.validate.outputs.version }}", "."),
        ("release-governance-${{ needs.validate.outputs.version }}", "."),
        ("release-inputs-${{ needs.validate.outputs.version }}", "."),
        ("staged-release-${{ needs.validate.outputs.version }}", "."),
        ("signed-release-${{ needs.validate.outputs.version }}", "signed-release/"),
    ):
        require_download(release, failures, artifact_name, path_value)


def verify_preflight(root: Path, failures: list[str]) -> None:
    path = root / ".github/workflows/release-preflight.yml"
    workflow = load_workflow(path)
    raw = path.read_text(encoding="utf-8")
    on = workflow.get("on", {})
    inputs = on.get("workflow_dispatch", {}).get("inputs", {}) if isinstance(on, dict) else {}
    if not isinstance(inputs, dict):
        failures.append("release-preflight.yml workflow_dispatch inputs must be an object")
        return
    for field in ("version", "source_sha", "source_run_id", "profile"):
        fail_if(field not in inputs, failures, f"release-preflight.yml missing input {field}")
    profile_options = inputs.get("profile", {}).get("options", [])
    for profile in ("technical-dry-run", "rc-evidence-dry-run", "release-candidate", "production-candidate"):
        fail_if(profile not in profile_options, failures, f"release-preflight.yml missing profile option {profile}")
    text = step_text({"steps": [step for job in workflow.get("jobs", {}).values() if isinstance(job, dict) for step in job.get("steps", [])]})
    for token in (
        "actions/checkout",
        ".github/workflows/image-build.yml",
        "rc-evidence-dry-run.py create",
        "rc-evidence-dry-run.py validate",
        "bundle-manifest.json",
    ):
        fail_if(token not in text, failures, f"release-preflight.yml missing structural token {token}")
    fail_if("ref: ${{ inputs.source_sha }}" not in raw, failures, "release-preflight.yml checkout must pin inputs.source_sha")
    fail_if("gh run download" in text and "--dir build-artifacts\n" in text, failures, "release-preflight must not download whole Image Build runs")
    evidence_contract = load_evidence_contract(root)
    contract = evidence_contract.load_contract(root / "ci/evidence-contract.yml")
    expected_upload_paths = {"source-run.json"} | output_root_upload_paths(evidence_contract, contract=contract)
    for profile in ("rc-evidence-dry-run", "release-candidate", "production-candidate"):
        output_plan = evidence_contract.output_tree_plan(
            version="contract-version",
            profile=profile,
            contract=contract,
        )
        plan_paths = {"source-run.json"} | {
            f"{Path(str(item['path'])).parts[0]}/"
            for item in output_plan["outputs"]
            if isinstance(item, dict) and isinstance(item.get("path"), str) and Path(str(item["path"])).parts
        }
        fail_if(plan_paths != expected_upload_paths, failures, f"release-preflight.yml output-tree-plan root drift for {profile}")
    require_upload(
        workflow,
        failures,
        "release-preflight-${{ inputs.profile }}-${{ inputs.version }}-${{ inputs.source_sha }}",
        expected_upload_paths,
    )
    require_step(
        workflow,
        failures,
        "Download operator evidence ingress artifact",
        if_expr="${{ inputs.profile == 'release-candidate' || inputs.profile == 'production-candidate' }}",
        run_tokens=("rei-${VERSION}-${SOURCE_SHA}-${SOURCE_RUN_ID}-${SOURCE_RUN_ATTEMPT}", "gh run download", "--name \"${artifact_name}\""),
    )
    require_step(
        workflow,
        failures,
        "Create RC evidence dry-run bundle",
        if_expr="${{ inputs.profile == 'rc-evidence-dry-run' }}",
        run_tokens=("rc-evidence-dry-run.py create", "rc-evidence-dry-run.py validate", "--input-root ."),
    )
    require_step(
        workflow,
        failures,
        "Create scanner-native security evidence",
        if_expr="${{ inputs.profile == 'production-candidate' }}",
        run_tokens=("collect-scanner-native-evidence.py",),
    )
    require_step(
        workflow,
        failures,
        "Initialize technical dry-run skeletons",
        if_expr="${{ inputs.profile == 'technical-dry-run' }}",
        run_tokens=("prepare-release-inputs.py init",),
    )


def verify_evidence_ingress(root: Path, failures: list[str]) -> None:
    workflow = load_workflow(root / ".github/workflows/release-evidence-ingress.yml")
    evidence_contract = load_evidence_contract(root)
    contract = evidence_contract.load_contract(root / "ci/evidence-contract.yml")
    inputs = workflow.get("on", {}).get("workflow_dispatch", {}).get("inputs", {})
    for field in ("operator_bundle_url", "operator_bundle_sha256", "operator_bundle_signature_url", "operator_bundle_certificate_url"):
        fail_if(field not in inputs, failures, f"release-evidence-ingress.yml missing input {field}")
    for forbidden in ("operator_bundle_allowed_host", "operator_bundle_certificate_identity", "operator_bundle_certificate_oidc_issuer"):
        fail_if(forbidden in inputs, failures, f"release-evidence-ingress.yml must not accept trust input {forbidden}")
    text = step_text({"steps": [step for job in workflow.get("jobs", {}).values() if isinstance(job, dict) for step in job.get("steps", [])]})
    for token in ("SUDERRA_OPERATOR_BUNDLE_ALLOWED_HOST", "cosign verify-blob", "operator-evidence-ingress.py stage", "cosign sign-blob"):
        fail_if(token not in text, failures, f"release-evidence-ingress.yml missing token {token}")
    fail_if("--location" in text, failures, "release-evidence-ingress.yml curl must not follow redirects")
    operator_roots = {f"{root_name}/" for root_name in evidence_contract.operator_ingress_allowed_roots(contract=contract)}
    require_upload(
        workflow,
        failures,
        "rei-${{ inputs.version }}-${{ inputs.source_sha }}-${{ inputs.source_image_build_run_id }}-${{ inputs.source_image_build_run_attempt }}",
        operator_roots
        | {
            "release-ingress/${{ inputs.version }}/evidence-ingress-manifest.json",
            "release-ingress/${{ inputs.version }}/evidence-ingress-manifest.json.sig",
            "release-ingress/${{ inputs.version }}/evidence-ingress-manifest.json.cert",
            "operator-bundle-download/operator-evidence.tar",
            "operator-bundle-download/operator-evidence.tar.sig",
            "operator-bundle-download/operator-evidence.tar.cert",
        },
    )


def verify_governance_drift(root: Path, failures: list[str]) -> None:
    path = root / ".github/workflows/governance-drift.yml"
    workflow = load_workflow(path)
    raw = path.read_text(encoding="utf-8")
    on = workflow.get("on", {})
    fail_if(not isinstance(on, dict) or "schedule" not in on or "workflow_dispatch" not in on, failures, "governance-drift.yml must be scheduled and manual")
    jobs = workflow.get("jobs", {})
    text = step_text({"steps": [step for job in jobs.values() if isinstance(job, dict) for step in job.get("steps", [])]})
    for token in ("drift-run-manifest.json", "suderra.governance-drift-run-manifest.v1", "cosign sign-blob"):
        fail_if(token not in text, failures, f"governance-drift.yml missing token {token}")
    fail_if("governance-drift-${{ github.run_id }}" not in raw, failures, "governance-drift.yml artifact name must bind github.run_id")
    require_upload(
        workflow,
        failures,
        "governance-drift-${{ github.run_id }}",
        {"release-governance/drift/${{ github.run_id }}/"},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()
    failures: list[str] = []
    try:
        verify_release(root, failures)
        verify_preflight(root, failures)
        verify_evidence_ingress(root, failures)
        verify_governance_drift(root, failures)
    except Exception as exc:
        failures.append(str(exc))
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("validated release workflow AST contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

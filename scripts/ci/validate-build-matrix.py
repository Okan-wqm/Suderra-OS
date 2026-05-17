#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate and emit Suderra OS Buildroot target matrices.

The project intentionally keeps ci/build-matrix.yml small enough to parse with
the Python standard library. This avoids adding PyYAML to every lint/build job
just to read the target contract.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "ci" / "build-matrix.yml"

TARGET_FIELDS = {
    "name",
    "target",
    "arch",
    "artifact",
    "release_artifact",
    "expected_artifacts",
    "qemu_test",
    "ci_build",
    "release",
    "timeout_minutes",
    "build_step_timeout_minutes",
    "min_disk_gib",
    "min_mem_gib",
    "min_vcpu",
    "build_jlevel",
    "prebuild_defconfigs",
    "payload_image_exports",
    "production_required",
    "production_ready",
    "profile",
    "boot_mode",
    "partition_table",
    "root_partition",
    "root_identity",
    "genimage",
    "post_image_arg",
    "signing",
    "acceptance",
    "blocker",
    "description",
}

VALID_ARCHES = {"x86_64", "aarch64"}
VALID_TABLES = {"gpt", "mbr"}
BOOLEAN_SELECTORS = {"ci_build", "qemu_test", "release", "production_required"}
MATRIX_SELECTORS = BOOLEAN_SELECTORS | {
    "ci_build_base",
    "ci_build_payload",
    "release_base",
    "release_payload",
}
SAFE_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
GENIMAGE_LABEL_LIMITS = {
    "vfat": 11,
    "ext2": 16,
    "ext3": 16,
    "ext4": 16,
}


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:idx].rstrip()
    return line.rstrip()


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if re.fullmatch(r"[0-9]+", value):
        return int(value)
    return value


def parse_key_value(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"expected key/value entry: {text!r}")
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def load_matrix(path: Path = MATRIX_PATH) -> dict[str, Any]:
    data: dict[str, Any] = {
        "defconfigs": [],
        "variants": [],
        "security_scans": [],
    }
    section: str | None = None
    current: dict[str, Any] | None = None
    pending_key: str | None = None

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = strip_comment(raw)
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()

        if indent == 0 and text.endswith(":"):
            section = text[:-1]
            data.setdefault(section, [])
            current = None
            pending_key = None
            continue

        if section in {"defconfigs", "variants"}:
            if indent == 2 and text.startswith("- "):
                current = {}
                data[section].append(current)
                rest = text[2:].strip()
                if rest:
                    key, value = parse_key_value(rest)
                    current[key] = parse_scalar(value)
                pending_key = None
                continue
            if indent == 4 and current is not None:
                key, value = parse_key_value(text)
                if value:
                    current[key] = parse_scalar(value)
                    pending_key = None
                else:
                    current[key] = []
                    pending_key = key
                continue
            if indent == 6 and text.startswith("- ") and current is not None and pending_key:
                current[pending_key].append(parse_scalar(text[2:].strip()))
                continue

        if section == "security_scans" and indent == 2 and text.startswith("- "):
            data[section].append(parse_scalar(text[2:].strip()))
            continue

        raise ValueError(f"unsupported YAML subset at {path}:{lineno}: {raw}")

    return data


def bool_field(target: dict[str, Any], field: str) -> bool:
    value = target.get(field)
    if not isinstance(value, bool):
        raise ValueError(f"{target.get('name', '<unknown>')}: {field} must be true/false")
    return value


def release_rename_base(release_artifact: str) -> str:
    return release_artifact[:-3] if release_artifact.endswith(".xz") else release_artifact


def sbom_base(release_artifact: str) -> str:
    if release_artifact.endswith(".img.xz"):
        return release_artifact[: -len(".img.xz")]
    return release_rename_base(release_artifact)


def payload_manifest_base(release_artifact: str) -> str:
    return sbom_base(release_artifact)


def expected_artifacts(target: dict[str, Any]) -> list[str]:
    artifacts = target.get("expected_artifacts")
    if not isinstance(artifacts, list):
        return []
    return [str(artifact) for artifact in artifacts]


def list_field(target: dict[str, Any], field: str) -> list[str]:
    value = target.get(field)
    if not isinstance(value, list):
        raise ValueError(f"{target.get('name', '<unknown>')}: {field} must be a list")
    return [str(item) for item in value]


def read_config(defconfig: str) -> str:
    return (ROOT / "configs" / defconfig).read_text(encoding="utf-8")


def post_script_args(config: str) -> str | None:
    match = re.search(r'^BR2_ROOTFS_POST_SCRIPT_ARGS="([^"]+)"$', config, re.MULTILINE)
    return match.group(1) if match else None


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def genimage_label_errors(name: str, path: Path, text: str) -> list[str]:
    errors: list[str] = []
    block_stack: list[str | None] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = strip_comment(raw).strip()
        if not line:
            continue

        if re.fullmatch(r"}\s*", line):
            if block_stack:
                block_stack.pop()
            continue

        block_match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)(?:\s+[A-Za-z0-9_.-]+)?\s*\{",
            line,
        )
        if block_match:
            block_kind = block_match.group(1)
            block_stack.append(block_kind if block_kind in GENIMAGE_LABEL_LIMITS else None)
            continue

        label_match = re.fullmatch(r"""label\s*=\s*["']([^"']*)["']""", line)
        if not label_match:
            continue

        filesystem = next((block for block in reversed(block_stack) if block), None)
        if not filesystem:
            continue

        label = label_match.group(1)
        limit = GENIMAGE_LABEL_LIMITS[filesystem]
        if len(label) > limit:
            errors.append(
                f"{name}: genimage {display_path(path)}:{lineno} "
                f"{filesystem} label {label!r} is {len(label)} characters; max is {limit}"
            )

    return errors


def genimage_partition_table_errors(
    name: str,
    expected: str,
    path: Path,
    text: str,
) -> list[str]:
    errors: list[str] = []
    matches = [
        (lineno, match.group(1))
        for lineno, line in enumerate(text.splitlines(), start=1)
        if (
            match := re.search(
                r"""^\s*partition-table-type\s*=\s*["']([^"']+)["']""",
                line,
            )
        )
    ]

    if not matches:
        return [
            f"{name}: genimage {display_path(path)} "
            f"must declare partition-table-type={expected!r}"
        ]

    for lineno, actual in matches:
        if actual not in VALID_TABLES:
            errors.append(
                f"{name}: genimage {display_path(path)}:{lineno} uses unsupported "
                f"partition-table-type {actual!r}; expected one of {sorted(VALID_TABLES)}"
            )
        elif actual != expected:
            errors.append(
                f"{name}: genimage {display_path(path)}:{lineno} partition-table-type "
                f"{actual!r} does not match matrix partition_table {expected!r}"
            )

    return errors


def validate(strict_production_variant: bool = False) -> int:
    matrix = load_matrix()
    errors: list[str] = []
    names: set[str] = set()
    targets: set[str] = set()
    targets_by_name = {
        str(target.get("name", "")): target
        for target in matrix["defconfigs"]
        if str(target.get("name", ""))
    }

    for target in matrix["defconfigs"]:
        name = str(target.get("name", ""))
        target_name = str(target.get("target", ""))
        missing = sorted(TARGET_FIELDS - set(target))
        if missing:
            errors.append(f"{name or '<unknown>'}: missing fields: {', '.join(missing)}")
            continue

        if name in names:
            errors.append(f"{name}: duplicate defconfig entry")
        names.add(name)

        if target_name in targets:
            errors.append(f"{name}: duplicate target id {target_name}")
        targets.add(target_name)

        if target["arch"] not in VALID_ARCHES:
            errors.append(f"{name}: unsupported arch {target['arch']}")

        if target["partition_table"] not in VALID_TABLES:
            errors.append(f"{name}: unsupported partition_table {target['partition_table']}")

        artifact_contract = target["expected_artifacts"]
        if not isinstance(artifact_contract, list) or not artifact_contract:
            errors.append(f"{name}: expected_artifacts must be a non-empty list")
        elif target["artifact"] not in artifact_contract:
            errors.append(f"{name}: artifact must also be listed in expected_artifacts")
        for artifact in artifact_contract if isinstance(artifact_contract, list) else []:
            if not isinstance(artifact, str) or not SAFE_ARTIFACT_RE.fullmatch(artifact):
                errors.append(f"{name}: unsafe expected artifact name {artifact!r}")

        for field in ("qemu_test", "ci_build", "release", "production_required", "production_ready"):
            try:
                bool_field(target, field)
            except ValueError as exc:
                errors.append(str(exc))

        timeout_minutes = target["timeout_minutes"]
        if not isinstance(timeout_minutes, int):
            errors.append(f"{name}: timeout_minutes must be an integer")
        elif not 30 <= timeout_minutes <= 360:
            errors.append(f"{name}: timeout_minutes must be between 30 and 360")

        build_step_timeout_minutes = target["build_step_timeout_minutes"]
        if not isinstance(build_step_timeout_minutes, int):
            errors.append(f"{name}: build_step_timeout_minutes must be an integer")
        elif not 30 <= build_step_timeout_minutes <= 350:
            errors.append(f"{name}: build_step_timeout_minutes must be between 30 and 350")
        elif isinstance(timeout_minutes, int) and build_step_timeout_minutes > timeout_minutes - 10:
            errors.append(f"{name}: build_step_timeout_minutes must leave at least 10 minutes for log upload")

        resource_ranges = {
            "min_disk_gib": (20, 200),
            "min_mem_gib": (2, 64),
            "min_vcpu": (1, 128),
            "build_jlevel": (1, 128),
        }
        for field, (lower, upper) in resource_ranges.items():
            value = target[field]
            if not isinstance(value, int):
                errors.append(f"{name}: {field} must be an integer")
            elif not lower <= value <= upper:
                errors.append(f"{name}: {field} must be between {lower} and {upper}")
        if isinstance(target["build_jlevel"], int) and isinstance(target["min_vcpu"], int):
            if target["build_jlevel"] > target["min_vcpu"]:
                errors.append(f"{name}: build_jlevel must not exceed min_vcpu")
        if isinstance(target["build_jlevel"], int) and isinstance(target["min_mem_gib"], int):
            if target["min_mem_gib"] < max(4, target["build_jlevel"] + 2):
                errors.append(f"{name}: min_mem_gib is too low for build_jlevel")

        try:
            prebuild_defconfigs = list_field(target, "prebuild_defconfigs")
            payload_image_exports = list_field(target, "payload_image_exports")
        except ValueError as exc:
            errors.append(str(exc))
            prebuild_defconfigs = []
            payload_image_exports = []

        for prebuild in prebuild_defconfigs:
            if prebuild == name:
                errors.append(f"{name}: prebuild_defconfigs must not include itself")
            if prebuild not in targets_by_name:
                errors.append(f"{name}: unknown prebuild defconfig {prebuild}")

        for export in payload_image_exports:
            match = re.fullmatch(r"(SUDERRA_[A-Z0-9_]+_TARGET_IMAGE_XZ)=([^:=]+):([^:=/]+)", export)
            if not match:
                errors.append(f"{name}: unsafe payload_image_exports entry {export!r}")
                continue
            _env_name, prebuild, artifact = match.groups()
            prebuild_target = targets_by_name.get(prebuild)
            if prebuild not in prebuild_defconfigs:
                errors.append(f"{name}: payload export {export!r} must reference prebuild_defconfigs")
            elif prebuild_target and artifact not in expected_artifacts(prebuild_target):
                errors.append(f"{name}: payload export {export!r} references non-contract artifact")

        config_path = ROOT / "configs" / name
        if not config_path.is_file():
            errors.append(f"{name}: missing configs/{name}")
            continue

        genimage_path = ROOT / str(target["genimage"])
        if not genimage_path.is_file():
            errors.append(f"{name}: missing genimage contract {target['genimage']}")
        else:
            genimage_contract = genimage_path.read_text(encoding="utf-8")
            if re.search(r"^\s*partition-label\s*=", genimage_contract, re.MULTILINE):
                errors.append(
                    f"{name}: genimage {target['genimage']} uses unsupported partition-label; "
                    "GPT labels come from partition section names"
                )
            errors.extend(genimage_label_errors(name, genimage_path, genimage_contract))
            errors.extend(
                genimage_partition_table_errors(
                    name,
                    str(target["partition_table"]),
                    genimage_path,
                    genimage_contract,
                )
            )

        config = read_config(name)
        actual_arg = post_script_args(config)
        if actual_arg != target["post_image_arg"]:
            errors.append(
                f"{name}: BR2_ROOTFS_POST_SCRIPT_ARGS={actual_arg!r}, "
                f"expected {target['post_image_arg']!r}"
            )

        jlevel = re.search(r"^BR2_JLEVEL=([0-9]+)$", config, re.MULTILINE)
        if not jlevel:
            errors.append(f"{name}: BR2_JLEVEL must be explicit for reproducible resource use")
        elif int(jlevel.group(1)) != target["build_jlevel"]:
            errors.append(
                f"{name}: BR2_JLEVEL={jlevel.group(1)} does not match "
                f"build_jlevel={target['build_jlevel']}"
            )

        if "BR2_CCACHE=y" not in config:
            errors.append(f"{name}: BR2_CCACHE must be enabled for CI cache effectiveness")

        if "BR2_PACKAGE_SYSTEMD_BOOTCTL=" in config:
            errors.append(f"{name}: BR2_PACKAGE_SYSTEMD_BOOTCTL is not a Buildroot symbol")

        has_dev_variant = "BR2_PACKAGE_SUDERRA_VARIANT_DEV=y" in config
        has_prod_variant = "BR2_PACKAGE_SUDERRA_VARIANT_PROD=y" in config
        if has_dev_variant == has_prod_variant:
            errors.append(f"{name}: exactly one Suderra OS variant must be selected")

        if "BR2_TARGET_ROOTFS_EXT2_BLOCKS=" in config:
            errors.append(f"{name}: legacy BR2_TARGET_ROOTFS_EXT2_BLOCKS must not be used")

        if (
            "BR2_TARGET_ROOTFS_EXT2=y" in config
            and not re.search(r'^BR2_TARGET_ROOTFS_EXT2_SIZE="[^"]+"$', config, re.MULTILINE)
        ):
            errors.append(f"{name}: ext rootfs image size must be explicit")

        if target["ci_build"] and "BR2_PACKAGE_HOST_GENIMAGE=y" not in config:
            errors.append(f"{name}: ci_build target must select BR2_PACKAGE_HOST_GENIMAGE=y")

        if target["production_required"] and not target["production_ready"] and not target["blocker"]:
            errors.append(f"{name}: production blocker must be documented while production_ready=false")

        if strict_production_variant and target["production_required"] and not has_prod_variant:
            errors.append(
                f"{name}: production_required target must select "
                "BR2_PACKAGE_SUDERRA_VARIANT_PROD (strict mode)"
            )

        if target["production_ready"]:
            if not has_prod_variant:
                errors.append(f"{name}: production_ready target must select BR2_PACKAGE_SUDERRA_VARIANT_PROD")
            signing = str(target["signing"])
            root_identity = str(target["root_identity"])
            if signing in {"unsigned-lab", "unsupported", "production-required"}:
                errors.append(f"{name}: production_ready target must name concrete signing material")
            if "mutated" in root_identity or root_identity in {"template", "installer-rootfs"}:
                errors.append(f"{name}: production_ready target must not rely on mutable root identity")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"validated {len(matrix['defconfigs'])} Buildroot target contract(s)")
    return 0


def target_matches_selector(target: dict[str, Any], selector: str) -> bool:
    prebuilds = list_field(target, "prebuild_defconfigs")
    if selector in BOOLEAN_SELECTORS:
        return bool(target.get(selector, False))
    if selector == "ci_build_base":
        return bool(target.get("ci_build", False)) and not prebuilds
    if selector == "ci_build_payload":
        return bool(target.get("ci_build", False)) and bool(prebuilds)
    if selector == "release_base":
        return bool(target.get("release", False)) and not prebuilds
    if selector == "release_payload":
        return bool(target.get("release", False)) and bool(prebuilds)
    raise ValueError(f"unsupported selector: {selector}")


def github_matrix(selector: str) -> int:
    matrix = load_matrix()
    include = []
    for target in matrix["defconfigs"]:
        if not target_matches_selector(target, selector):
            continue
        release_artifact = str(target["release_artifact"])
        release_base = release_artifact[:-3] if release_artifact.endswith(".xz") else release_artifact
        include.append(
            {
                "name": target["target"],
                "target": target["target"],
                "defconfig": target["name"],
                "arch": target["arch"],
                "artifact": target["artifact"],
                "release": release_base,
                "release_artifact": release_artifact,
                "signing": target["signing"],
                "timeout_minutes": target["timeout_minutes"],
                "build_step_timeout_minutes": target["build_step_timeout_minutes"],
                "min_disk_gib": target["min_disk_gib"],
                "min_mem_gib": target["min_mem_gib"],
                "min_vcpu": target["min_vcpu"],
                "build_jlevel": target["build_jlevel"],
                "prebuild_defconfigs": " ".join(list_field(target, "prebuild_defconfigs")),
                "payload_image_exports": " ".join(list_field(target, "payload_image_exports")),
                "expected_artifacts": " ".join(expected_artifacts(target)),
                "profile": target["profile"],
                "boot_mode": target["boot_mode"],
            }
        )

    print(json.dumps({"include": include}, separators=(",", ":")))
    return 0


def production_readiness(tag: str | None) -> int:
    matrix = load_matrix()
    blockers = [
        target
        for target in matrix["defconfigs"]
        if bool(target.get("production_required")) and not bool(target.get("production_ready"))
    ]
    if blockers:
        release_kind = "pre-release" if tag and "-" in tag else "release"
        print(f"Production {release_kind} is blocked by unfinished target contracts:", file=sys.stderr)
        for target in blockers:
            print(
                f"- {target['name']}: {target['blocker']}",
                file=sys.stderr,
            )
        return 1

    print("production readiness matrix is satisfied")
    return 0


def candidate_readiness(tag: str | None) -> int:
    if not tag:
        print("ERROR: candidate-readiness requires --tag", file=sys.stderr)
        return 2
    if "-" not in tag:
        return production_readiness(tag)

    matrix = load_matrix()
    blockers = [
        target
        for target in matrix["defconfigs"]
        if bool(target.get("production_required")) and not bool(target.get("production_ready"))
    ]
    release_targets = [target for target in matrix["defconfigs"] if bool(target.get("release"))]
    missing_blockers = [
        target
        for target in release_targets
        if bool(target.get("production_required"))
        and not bool(target.get("production_ready"))
        and not str(target.get("blocker", "")).strip()
    ]
    if missing_blockers:
        print("Candidate release has production-required targets without blocker rationale:", file=sys.stderr)
        for target in missing_blockers:
            print(f"- {target['name']}", file=sys.stderr)
        return 1

    print(f"candidate pre-release allowed with documented production blockers for {tag}")
    for target in blockers:
        print(f"- {target['name']}: {target['blocker']}")
    return 0


def target_by_defconfig(matrix: dict[str, Any], defconfig: str) -> dict[str, Any] | None:
    for target in matrix["defconfigs"]:
        if target.get("name") == defconfig:
            return target
    return None


def verify_artifacts(defconfig: str, images_dir: Path | None) -> int:
    matrix = load_matrix()
    target = target_by_defconfig(matrix, defconfig)
    if target is None:
        print(f"ERROR: unknown defconfig in matrix: {defconfig}", file=sys.stderr)
        return 1
    if images_dir is None:
        images_dir = ROOT / "output" / defconfig / "images"
    missing = [
        artifact
        for artifact in expected_artifacts(target)
        if not (images_dir / artifact).is_file()
    ]
    if missing:
        print(f"ERROR: {defconfig} missing expected image artifacts:", file=sys.stderr)
        for artifact in missing:
            print(f"- {images_dir / artifact}", file=sys.stderr)
        return 1
    print(f"validated {len(expected_artifacts(target))} artifact(s) for {defconfig}")
    return 0


def release_files(version: str, release_dir: Path, signed: bool) -> int:
    matrix = load_matrix()
    errors: list[str] = []
    release_targets = [target for target in matrix["defconfigs"] if bool(target.get("release"))]

    for target in release_targets:
        release_artifact = str(target["release_artifact"])
        rename_base = release_rename_base(release_artifact)
        required = [
            release_artifact,
            f"{release_artifact}.sha256",
            f"{rename_base}.manifest.txt",
            f"{sbom_base(release_artifact)}.cyclonedx.json",
        ]
        expected = set(expected_artifacts(target))
        control_base = payload_manifest_base(release_artifact)
        if "manifest.json" in expected:
            required.append(f"{control_base}.payload-manifest.json")
        if "manifest.sig" in expected:
            required.append(f"{control_base}.payload-manifest.sig")
        for artifact in required:
            path = release_dir / artifact
            if not path.is_file() or path.stat().st_size <= 0:
                errors.append(f"missing release file for {target['name']}: {artifact}")

    for arch in ("x86_64", "aarch64"):
        for suffix in ("", ".sha256"):
            artifact = f"suderra-installer-{version}-{arch}{suffix}"
            path = release_dir / artifact
            if not path.is_file() or path.stat().st_size <= 0:
                errors.append(f"missing installer release file: {artifact}")

    if signed:
        for artifact in ("manifest.json", "SHA256SUMS"):
            path = release_dir / artifact
            if not path.is_file() or path.stat().st_size <= 0:
                errors.append(f"missing signed release control file: {artifact}")
        for path in release_dir.iterdir():
            if not path.is_file() or path.name.endswith((".sig", ".cert")):
                continue
            for suffix in (".sig", ".cert"):
                signed_path = release_dir / f"{path.name}{suffix}"
                if not signed_path.is_file() or signed_path.stat().st_size <= 0:
                    errors.append(f"missing signature material for {path.name}: {signed_path.name}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"validated release file completeness for {len(release_targets)} target(s)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument(
        "--strict-production-variant",
        action="store_true",
        help=(
            "Reject production_required defconfigs that do not select "
            "BR2_PACKAGE_SUDERRA_VARIANT_PROD. Faz 3 wire-up'a kadar default'ta kapalı."
        ),
    )

    matrix_parser = subparsers.add_parser("github-matrix")
    matrix_parser.add_argument(
        "--selector",
        choices=sorted(MATRIX_SELECTORS),
        required=True,
    )

    readiness_parser = subparsers.add_parser("production-readiness")
    readiness_parser.add_argument("--tag")

    candidate_parser = subparsers.add_parser("candidate-readiness")
    candidate_parser.add_argument("--tag", required=True)

    artifacts_parser = subparsers.add_parser("verify-artifacts")
    artifacts_parser.add_argument("--defconfig", required=True)
    artifacts_parser.add_argument("--images-dir", type=Path)

    release_files_parser = subparsers.add_parser("release-files")
    release_files_parser.add_argument("--version", required=True)
    release_files_parser.add_argument("--release-dir", type=Path, required=True)
    release_files_parser.add_argument("--signed", action="store_true")

    args = parser.parse_args()
    if args.command == "validate":
        return validate(strict_production_variant=args.strict_production_variant)
    if args.command == "github-matrix":
        return github_matrix(args.selector)
    if args.command == "production-readiness":
        return production_readiness(args.tag)
    if args.command == "candidate-readiness":
        return candidate_readiness(args.tag)
    if args.command == "verify-artifacts":
        return verify_artifacts(args.defconfig, args.images_dir)
    if args.command == "release-files":
        return release_files(args.version, args.release_dir, args.signed)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Pre-tag/pre-publish release input readiness gate."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"


def run(args: list[str]) -> list[str]:
    result = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode == 0:
        return []
    return [line for line in result.stderr.splitlines() if line.strip()] or [result.stdout.strip()]


def read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_matrix(path: Path) -> dict[str, Any]:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_matrix(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-tier", choices=("alpha", "production"), required=True)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check-files", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []
    inferred_tier = "alpha" if "-" in args.version else "production"
    if args.release_tier != inferred_tier:
        failures.append(f"release tier must be {inferred_tier} for version {args.version}")
    governance_report = args.root / "release-governance" / args.version / "governance-policy-validation.json"
    governance = read_json(governance_report)
    if not isinstance(governance, dict) or governance.get("status") != "passed":
        failures.append(f"governance policy validation missing or failed: {governance_report}")

    lab_args = [
        sys.executable,
        "scripts/evidence/validate-lab-input.py",
        "validate-matrix",
        "--version",
        args.version,
        "--root",
        str(args.root / "release-lab-input"),
        "--require-pass",
    ]
    if args.check_files:
        lab_args.append("--check-files")
    failures.extend(run(lab_args))

    matrix = load_matrix(args.matrix)
    for row in matrix.get("defconfigs", []):
        if row.get("release") and row.get("qemu_test"):
            qemu = args.root / "release-lab-input" / args.version / str(row["target"]) / "qemu.json"
            qemu_args = [
                sys.executable,
                "scripts/evidence/validate-qemu-input.py",
                str(qemu),
                "--require-pass",
            ]
            if args.check_files:
                qemu_args.append("--check-files")
            failures.extend(run(qemu_args))
        if row.get("release"):
            target = str(row["target"])
            approval = args.root / "release-approvals" / args.version / f"{target}.json"
            repro = args.root / "release-reproducibility" / args.version / f"{target}.log"
            if not approval.is_file():
                failures.append(f"missing approval input: {approval}")
            if not repro.is_file() or repro.stat().st_size <= 0:
                failures.append(f"missing reproducibility input: {repro}")
    for scan in matrix.get("security_scans", []):
        report = args.root / "release-security" / args.version / f"{scan}.json"
        if not report.is_file() or report.stat().st_size <= 0:
            failures.append(f"missing release security report: {report}")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated release inputs for {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

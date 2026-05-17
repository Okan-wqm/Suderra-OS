#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate SARIF files before GitHub upload.

Security scanners occasionally leave truncated or empty SARIF when a scan fails
early. Uploading that file hides the scanner failure behind an upload error, so
CI validates the basic SARIF contract first and keeps diagnostics fail-closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.is_file():
        return [f"{path}: file does not exist"]
    if path.stat().st_size <= 0:
        return [f"{path}: file is empty"]
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    except OSError as exc:
        return [f"{path}: cannot read file: {exc}"]

    if not isinstance(payload, dict):
        return [f"{path}: SARIF root must be an object"]
    if payload.get("version") != "2.1.0":
        errors.append(f"{path}: version must be 2.1.0")
    runs = payload.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append(f"{path}: runs must be a non-empty list")
        return errors
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"{path}: runs[{index}] must be an object")
            continue
        tool = run.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            errors.append(f"{path}: runs[{index}].tool.driver is required")
        results = run.get("results")
        if results is not None and not isinstance(results, list):
            errors.append(f"{path}: runs[{index}].results must be a list when present")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", nargs="+", type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    for sarif in args.sarif:
        errors.extend(validate(sarif))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"validated {len(args.sarif)} SARIF file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

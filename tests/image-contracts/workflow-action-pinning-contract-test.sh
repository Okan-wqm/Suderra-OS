#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

python3 - "${PROJECT_ROOT}/.github/workflows" <<'PY'
import re
import sys
from pathlib import Path

workflow_root = Path(sys.argv[1])
uses_re = re.compile(r"uses:\s*['\"]?([^'\"\s#]+)")
sha_re = re.compile(r"^[0-9a-f]{40}$")
failures: list[str] = []

for workflow in sorted(workflow_root.glob("*.yml")):
    for line_no, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
        match = uses_re.search(line)
        if not match:
            continue
        value = match.group(1)
        if value.startswith("./") or value.startswith(".github/"):
            continue
        if "@" not in value:
            failures.append(f"{workflow}:{line_no}: action reference has no @ref: {value}")
            continue
        _, ref = value.rsplit("@", 1)
        if not sha_re.fullmatch(ref):
            failures.append(f"{workflow}:{line_no}: action ref must be a full commit SHA: {value}")

if failures:
    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    raise SystemExit(1)
PY

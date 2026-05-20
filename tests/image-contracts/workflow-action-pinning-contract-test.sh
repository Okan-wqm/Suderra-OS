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
        if value == "ossf/scorecard-action@ff5dd8929f96a8a4dc67d13f32b8c75057829621":
            failures.append(
                f"{workflow}:{line_no}: ossf/scorecard-action must pin the peeled v2.4.0 commit, "
                "not the annotated tag object SHA"
            )
        if value == "github/codeql-action/upload-sarif@7c1e4cf0b20d7c1872b26569c00ba908797a59bf":
            failures.append(
                f"{workflow}:{line_no}: github/codeql-action/upload-sarif must pin the peeled v4 commit, "
                "not the annotated tag object SHA"
            )
        annotated_tag_objects = {
            "actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661": "v3",
            "DavidAnson/markdownlint-cli2-action@fa0cd0f1a052f54da593c83860f2292982f5d142": "v23.2.0",
            "ibiqlik/action-yamllint@ae1abb2821b567e96742aa776f7b62c9b6a26bc8": "v3",
            "sigstore/cosign-installer@1aa8e0f2454b781fbf0fbf306a4c9533a0c57409": "v3.7.0",
        }
        if value in annotated_tag_objects:
            failures.append(
                f"{workflow}:{line_no}: {value} is annotated tag object {annotated_tag_objects[value]}; "
                "pin the peeled commit SHA"
            )

if failures:
    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    raise SystemExit(1)
PY

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

cat > "${TMPDIR}/valid.sarif" <<'JSON'
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "contract-scanner",
          "rules": []
        }
      },
      "results": []
    }
  ]
}
JSON

python3 "${PROJECT_ROOT}/scripts/ci/validate-sarif.py" "${TMPDIR}/valid.sarif" >/dev/null

printf '{' > "${TMPDIR}/truncated.sarif"
if python3 "${PROJECT_ROOT}/scripts/ci/validate-sarif.py" "${TMPDIR}/truncated.sarif" >/dev/null 2>&1; then
    echo "ERROR: truncated SARIF unexpectedly validated" >&2
    exit 1
fi

cat > "${TMPDIR}/empty-runs.sarif" <<'JSON'
{"version": "2.1.0", "runs": []}
JSON
if python3 "${PROJECT_ROOT}/scripts/ci/validate-sarif.py" "${TMPDIR}/empty-runs.sarif" >/dev/null 2>&1; then
    echo "ERROR: empty SARIF runs unexpectedly validated" >&2
    exit 1
fi

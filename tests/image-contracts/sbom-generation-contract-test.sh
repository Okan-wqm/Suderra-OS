#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
DEFCONFIG="sbom-contract-test"
OUTPUT_DIR="${PROJECT_ROOT}/output/${DEFCONFIG}"

cleanup() {
    rm -rf "${OUTPUT_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUTPUT_DIR}/legal-info"
cat > "${OUTPUT_DIR}/legal-info/manifest.csv" <<'CSV'
package,version,license,license files,source archive,source site
busybox,1.36.1,GPL-2.0-only,LICENSE,busybox-1.36.1.tar.bz2,https://busybox.net/downloads/
openssl,3.2.2,Apache-2.0,LICENSE.txt,openssl-3.2.2.tar.gz,https://www.openssl.org/source/
CSV

SUDERRA_SBOM_TOOL=manifest SUDERRA_VERSION=v9.9.9-test \
    "${PROJECT_ROOT}/scripts/gen-sbom.sh" "${DEFCONFIG}" >/dev/null

python3 - "${OUTPUT_DIR}/sbom.cyclonedx.json" "${OUTPUT_DIR}/sbom.spdx.json" <<'PY'
import json
import sys

cyclonedx = json.loads(open(sys.argv[1], encoding="utf-8").read())
spdx = json.loads(open(sys.argv[2], encoding="utf-8").read())

components = cyclonedx.get("components")
assert isinstance(components, list)
assert len(components) == 2
assert {component["name"] for component in components} == {"busybox", "openssl"}
assert all(component.get("purl", "").startswith("pkg:generic/") for component in components)
assert cyclonedx["metadata"]["component"]["version"] == "v9.9.9-test"

packages = spdx.get("packages")
assert isinstance(packages, list)
assert len(packages) == 2
assert {package["name"] for package in packages} == {"busybox", "openssl"}
PY

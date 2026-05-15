#!/usr/bin/env bash
#
# Suderra OS — CycloneDX/SPDX SBOM üretimi
#
# Kullanım:
#   ./scripts/gen-sbom.sh <defconfig>
#   ./scripts/gen-sbom.sh suderra_x86_64_defconfig

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd )"

DEFCONFIG="${1:?Kullanım: $0 <defconfig>}"
OUTPUT_DIR="${PROJECT_ROOT}/output/${DEFCONFIG}"
MANIFEST="${OUTPUT_DIR}/legal-info/manifest.csv"
SBOM_OUT="${OUTPUT_DIR}/sbom.cyclonedx.json"
SBOM_SPDX_OUT="${OUTPUT_DIR}/sbom.spdx.json"

if [ ! -f "${MANIFEST}" ]; then
    echo "ERROR: Buildroot manifest yok: ${MANIFEST}"
    echo "Önce build edin: ./scripts/build-in-docker.sh ${DEFCONFIG}"
    exit 1
fi

# Tercih edilen araç: syft (Anchore). Eğer yoksa Buildroot legal-info
# manifest'inden deterministik CycloneDX/SPDX dokümanları üret.
SBOM_TOOL="${SUDERRA_SBOM_TOOL:-auto}"
if { [ "${SBOM_TOOL}" = "auto" ] || [ "${SBOM_TOOL}" = "syft" ]; } &&
    command -v syft >/dev/null 2>&1 &&
    [ -d "${OUTPUT_DIR}/target" ]; then
    echo "==> syft ile SBOM üretiliyor"
    syft "${OUTPUT_DIR}/target" \
        -o "cyclonedx-json=${SBOM_OUT}" \
        -o "spdx-json=${SBOM_SPDX_OUT}"
else
    if [ "${SBOM_TOOL}" = "syft" ]; then
        echo "ERROR: SUDERRA_SBOM_TOOL=syft requested but syft or target rootfs is unavailable" >&2
        exit 1
    fi

    echo "==> Buildroot legal-info manifest'ten SBOM üretiliyor"
    python3 - "${MANIFEST}" "${SBOM_OUT}" "${SBOM_SPDX_OUT}" "${DEFCONFIG}" "${SUDERRA_VERSION:-v0.1.0-alpha}" <<'PY'
import csv
import hashlib
import json
import re
import sys
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path


manifest_path = Path(sys.argv[1])
cyclonedx_path = Path(sys.argv[2])
spdx_path = Path(sys.argv[3])
defconfig = sys.argv[4]
version = sys.argv[5]


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_header(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def first(row: dict[str, str], *names: str) -> str:
    normalized = {normalize_header(key): value.strip() for key, value in row.items() if key is not None}
    for name in names:
        value = normalized.get(normalize_header(name), "")
        if value:
            return value
    return ""


def component_bom_ref(name: str, version_value: str) -> str:
    raw = f"{name}@{version_value}" if version_value else name
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-") or "package"
    return f"pkg-{safe}-{digest}"


def purl(name: str, version_value: str) -> str:
    quoted_name = urllib.parse.quote(name, safe="")
    if version_value:
        return f"pkg:generic/{quoted_name}@{urllib.parse.quote(version_value, safe='')}"
    return f"pkg:generic/{quoted_name}"


def spdx_id(name: str, version_value: str) -> str:
    raw = f"{name}-{version_value}" if version_value else name
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", raw).strip("-") or "Package"
    return f"SPDXRef-Package-{safe[:80]}"


def spdx_license(value: str) -> str:
    if not value:
        return "NOASSERTION"
    if re.fullmatch(r"[A-Za-z0-9.+()\- ]+(?:WITH [A-Za-z0-9.+()\- ]+)?", value):
        return value
    return "NOASSERTION"


with manifest_path.open(newline="", encoding="utf-8") as fh:
    reader = csv.DictReader(fh)
    if not reader.fieldnames:
        raise SystemExit(f"ERROR: empty Buildroot manifest: {manifest_path}")
    rows = list(reader)

components: list[dict[str, object]] = []
spdx_packages: list[dict[str, object]] = []
seen: set[tuple[str, str]] = set()

for row in rows:
    name = first(row, "package", "pkg", "name", "package name")
    if not name or name.lower() in {"package", "name"}:
        continue
    version_value = first(row, "version", "package version")
    dedupe_key = (name, version_value)
    if dedupe_key in seen:
        continue
    seen.add(dedupe_key)

    license_value = first(row, "license", "licenses", "license expression")
    license_files = first(row, "license files", "license_file", "licensefile", "license files hash")
    source_archive = first(row, "source archive", "source", "source file", "sourcefile", "archive")
    source_site = first(row, "site", "url", "source site", "source url", "download url")
    component: dict[str, object] = {
        "type": "library",
        "bom-ref": component_bom_ref(name, version_value),
        "name": name,
        "version": version_value or "NOASSERTION",
        "purl": purl(name, version_value),
        "properties": [
            {"name": "suderra:buildroot:defconfig", "value": defconfig},
            {"name": "suderra:buildroot:source_archive", "value": source_archive or "NOASSERTION"},
            {"name": "suderra:buildroot:license_files", "value": license_files or "NOASSERTION"},
        ],
    }
    if license_value:
        component["licenses"] = [{"license": {"name": license_value}}]
    if source_site:
        component["externalReferences"] = [{"type": "distribution", "url": source_site}]
    components.append(component)

    spdx_packages.append(
        {
            "name": name,
            "SPDXID": spdx_id(name, version_value),
            "versionInfo": version_value or "NOASSERTION",
            "downloadLocation": source_site or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": spdx_license(license_value),
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl(name, version_value),
                }
            ],
        }
    )

if not components:
    raise SystemExit(f"ERROR: Buildroot manifest has no package rows: {manifest_path}")

timestamp = now_utc()
cyclonedx = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": timestamp,
        "tools": [{"vendor": "Suderra", "name": "gen-sbom.sh", "version": "1"}],
        "component": {
            "type": "operating-system",
            "name": "suderra-os",
            "version": version,
        },
    },
    "components": components,
}
spdx = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"suderra-os-{defconfig}",
    "documentNamespace": f"https://suderra-os.invalid/spdx/{defconfig}/{uuid.uuid4()}",
    "creationInfo": {
        "created": timestamp,
        "creators": ["Tool: Suderra gen-sbom.sh"],
    },
    "packages": spdx_packages,
}

cyclonedx_path.parent.mkdir(parents=True, exist_ok=True)
spdx_path.parent.mkdir(parents=True, exist_ok=True)
cyclonedx_path.write_text(json.dumps(cyclonedx, indent=2, sort_keys=True) + "\n", encoding="utf-8")
spdx_path.write_text(json.dumps(spdx, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"    Paket sayısı: {len(components)}")
PY
fi

echo "==> SBOM yazıldı:"
echo "    CycloneDX: ${SBOM_OUT}"
[ -f "${SBOM_SPDX_OUT}" ] && echo "    SPDX:      ${SBOM_SPDX_OUT}"

# Boyut + paket sayısı
PKG_COUNT="$(python3 - "${SBOM_OUT}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    doc = json.load(fh)
components = doc.get("components")
if not isinstance(components, list):
    raise SystemExit("ERROR: CycloneDX SBOM has no components array")
print(len(components))
PY
)"
if [ "${PKG_COUNT}" -le 0 ]; then
    echo "ERROR: SBOM component list is empty" >&2
    exit 1
fi
echo "    Paket sayısı doğrulandı: ${PKG_COUNT}"

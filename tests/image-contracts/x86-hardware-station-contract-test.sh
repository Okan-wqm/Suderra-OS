#!/usr/bin/env bash
#
# x86_64 donanım lab istasyon sözleşmesi (PR-B9, hermetik).
#
# Turnkey donanım hazırlığı: fiziksel koşu donanım geldiğinde yapılır, ama
# üretim yolunu ŞİMDİ kanıtlarız:
#   1. Committable industrial-x86_64 station registry ŞABLONU, gerçek
#      validate-lab-input.py check_station_registry'sini strict profilde GEÇER.
#   2. Bozulmuş registry (eksik adaptör / yanlış şema) REDDEDİLİR.
#   3. Validator x86_required_checks + x86_required_negative_tests'i SSOT'tan
#      bağlar (yani gerçek kanıtta bunlar zorlanacak).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${ROOT}" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts" / "evidence"))
spec = importlib.util.spec_from_file_location(
    "validate_lab_input", root / "scripts" / "evidence" / "validate-lab-input.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

example = root / "docs" / "operations" / "lab-station-registry.industrial-x86_64.example.json"
registry = json.loads(example.read_text(encoding="utf-8"))
assert registry["schema_version"] == mod.STATION_REGISTRY_SCHEMA_VERSION, "registry schema mismatch"
station_entry = registry["stations"][0]
assert "x86_64" in station_entry["allowed_targets"], "template must allow x86_64"

# x86 enforcement constants must be wired from the SSOT and non-empty.
assert set(mod.REQUIRED_X86_HARDWARE_CHECKS) >= {
    "tpm-presence", "secure-boot-enforced", "rauc-rollback",
    "dm-verity-tamper-rejection", "boot-tamper-rejection", "power-cycle-transcript",
}, f"x86 hardware checks not wired: {mod.REQUIRED_X86_HARDWARE_CHECKS}"
assert set(mod.REQUIRED_X86_NEGATIVE_TESTS) >= {
    "dm-verity-rootfs-tamper", "secure-boot-unsigned-uki", "rauc-health-rollback",
}, f"x86 negative tests not wired: {mod.REQUIRED_X86_NEGATIVE_TESTS}"

# The x86 adapter roles the runbook requires must all be present.
required_roles = {"flash", "readback", "uart", "power", "storage", "tpm", "secure-boot", "rauc", "tamper"}
assert required_roles <= set(station_entry["adapter_inventory"]), \
    f"template missing adapter roles: {required_roles - set(station_entry['adapter_inventory'])}"

profile = "production-candidate"
assert profile in mod.STRICT_PROFILES, f"expected strict profile, got {mod.STRICT_PROFILES}"

payload = {
    "target": "x86_64",
    "station": {"station_id": station_entry["station_id"], "fixture_id": station_entry["fixture_id"]},
    "devices": [{"device_identity": {"storage_by_id": station_entry["allowed_storage_by_id"][0]}}],
}

def registry_errors(reg):
    errs = []
    mod.check_station_registry(errs, payload, reg, station_entry["public_key_sha256"], profile)
    return errs

# 1. The committed template must be a structurally valid registry (strict).
errs = registry_errors(registry)
assert errs == [], f"template registry must pass check_station_registry: {errs}"

# 2. Wrong schema version -> rejected.
bad_schema = json.loads(example.read_text(encoding="utf-8"))
bad_schema["schema_version"] = "suderra.lab-station-registry.v0"
assert registry_errors(bad_schema), "wrong registry schema must be rejected"

# 3. Empty adapter inventory -> rejected.
bad_adapters = json.loads(example.read_text(encoding="utf-8"))
bad_adapters["stations"][0]["adapter_inventory"] = {}
assert any("adapter_inventory" in e for e in registry_errors(bad_adapters)), \
    "empty adapter inventory must be rejected"

# 4. Adapter with a non-64-hex binary_sha256 -> rejected.
bad_sha = json.loads(example.read_text(encoding="utf-8"))
bad_sha["stations"][0]["adapter_inventory"]["tpm"]["binary_sha256"] = "not-a-sha"
assert registry_errors(bad_sha), "invalid adapter binary_sha256 must be rejected"

print("x86 hardware station contract passed")
PY

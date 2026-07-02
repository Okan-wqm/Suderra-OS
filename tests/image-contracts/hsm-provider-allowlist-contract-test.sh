#!/usr/bin/env bash
#
# HSM provider/model allowlist sözleşmesi (PR-B5, hermetik).
#
# SoftHSM reddi gerekli ama YETERLİ değil: production imzalama vetted bir
# donanım token'ında koşmalı. Bu test, --require-production altında onaylı
# provider'ın allowlist kontrolünü GEÇTİĞİNİ ve onaysız/SoftHSM provider'ın
# allowlist ihlaliyle REDDEDİLDİĞİNİ, allowlist'in SSOT'tan (evidence-contract)
# geldiğini kanıtlar.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${ROOT}" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts" / "evidence"))
spec = importlib.util.spec_from_file_location(
    "validate_hsm_signing_evidence",
    root / "scripts" / "evidence" / "validate-hsm-signing-evidence.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Allowlist must be loaded from the SSOT and enforced.
assert mod.APPROVED_PROVIDER_ALLOWLIST, "allowlist must be non-empty (from evidence-contract.yml)"
assert mod.APPROVED_PROVIDER_ALLOWLIST_ENFORCED, "allowlist enforcement flag must be on"
assert "yubihsm" in mod.APPROVED_PROVIDER_ALLOWLIST, "expected a vetted provider in the allowlist"

ALLOWLIST_MARK = "approved allowlist"


def failures_for(provider, manufacturer, model):
    payload = {
        "schema_version": mod.SCHEMA_VERSION,
        "provider": provider,
        "mode": "production",
        "hardware_backed": True,
        "hsm_serial": "SERIAL123",
        "token": {
            "label": "prod-token",
            "manufacturer": manufacturer,
            "model": model,
            "serial": "SERIAL123",
            "module_sha256": "a" * 64,
        },
    }
    return mod.validate(
        payload,
        evidence_path=Path("/nonexistent"),
        pkcs11_uri="pkcs11:token=prod;object=signing;id=%01",
        certificate=Path("/nonexistent"),
        require_production=True,
    )


# Unapproved provider -> allowlist failure present.
bad = failures_for("Bogus Software Co", "Bogus", "Model-X")
assert any(ALLOWLIST_MARK in f for f in bad), f"unapproved provider must trip allowlist; got {bad}"

# SoftHSM -> allowlist failure present (and the SoftHSM negative control too).
soft = failures_for("SoftHSM", "SoftHSM project", "softhsm2")
assert any(ALLOWLIST_MARK in f for f in soft), "SoftHSM must trip allowlist"

# Approved provider -> NO allowlist failure (other unrelated failures may exist).
ok = failures_for("YubiHSM 2", "Yubico", "YubiHSM 2")
assert not any(ALLOWLIST_MARK in f for f in ok), f"approved provider must pass allowlist; got {ok}"

# Approval via token manufacturer even if provider string is generic.
ok2 = failures_for("hardware token", "Thales", "Luna Network HSM")
assert not any(ALLOWLIST_MARK in f for f in ok2), f"approved token manufacturer must pass; got {ok2}"

print("HSM provider allowlist contract passed")
PY

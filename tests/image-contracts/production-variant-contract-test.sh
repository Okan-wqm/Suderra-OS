#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT
POST_IMAGE="${PROJECT_ROOT}/board/suderra/common/post-image.sh"
POST_BUILD="${PROJECT_ROOT}/board/suderra/common/post-build.sh"
SIGN_BUNDLE="${PROJECT_ROOT}/scripts/sign-bundle.sh"
CREATE_RAUC_BUNDLE="${PROJECT_ROOT}/scripts/create-rauc-bundle.sh"
HSM_EVIDENCE="${PROJECT_ROOT}/scripts/evidence/validate-hsm-signing-evidence.py"
EVIDENCE_CONTRACT="${PROJECT_ROOT}/ci/evidence-contract.yml"

grep -q 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${POST_IMAGE}"
grep -q 'BR2 Suderra variant.*conflicts with SUDERRA_VARIANT' "${POST_IMAGE}"
grep -q 'requires BR2_CONFIG or SUDERRA_VARIANT' "${POST_IMAGE}"
grep -q 'SUDERRA_VARIANT must be dev or prod' "${POST_IMAGE}"
grep -q 'production variant requires SUDERRA_SIGNING_MODE=prod' "${POST_IMAGE}"
grep -q 'export SUDERRA_SIGNING_MODE="prod"' "${POST_IMAGE}"
grep -q 'enforce_production_contract' "${POST_IMAGE}"
grep -q 'SUDERRA_INSTALLER_PAYLOAD_PUBKEY must point to the pinned Ed25519 public key' "${POST_IMAGE}"
grep -q 'openssl pkeyutl -verify -rawin -pubin' "${POST_IMAGE}"

grep -q 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${POST_BUILD}"
grep -q 'BR2 Suderra variant.*conflicts with SUDERRA_VARIANT' "${POST_BUILD}"
grep -q 'requires BR2_CONFIG or SUDERRA_VARIANT' "${POST_BUILD}"
grep -q 'SUDERRA_VARIANT must be dev or prod' "${POST_BUILD}"

grep -q 'SUDERRA_SIGNING_MODE' "${SIGN_BUNDLE}"
grep -q 'SUDERRA_RELEASE_TIER' "${SIGN_BUNDLE}"
grep -q 'PROD_MODE' "${SIGN_BUNDLE}"
grep -q 'warn_or_fail' "${SIGN_BUNDLE}"
grep -q 'SUDERRA_RAUC_PKCS11_URI' "${SIGN_BUNDLE}"
grep -q 'SUDERRA_HSM_SIGNING_EVIDENCE' "${SIGN_BUNDLE}"
grep -q 'validate-hsm-signing-evidence.py' "${SIGN_BUNDLE}"
grep -q 'production signing rejects file-backed private keys' "${SIGN_BUNDLE}"
grep -q 'RAUC bundle HSM/PKCS#11' "${SIGN_BUNDLE}"
if grep -q 'PKCS#11 RAUC signing provider is not implemented' "${SIGN_BUNDLE}"; then
    echo "ERROR: production signing must have a real PKCS#11 provider path, not a placeholder hard-fail" >&2
    exit 1
fi

grep -q 'SUDERRA_RAUC_PKCS11_URI' "${CREATE_RAUC_BUNDLE}"
grep -q 'SUDERRA_HSM_SIGNING_EVIDENCE' "${CREATE_RAUC_BUNDLE}"
grep -q 'validate-hsm-signing-evidence.py' "${CREATE_RAUC_BUNDLE}"
grep -q 'production RAUC signing rejects file-backed private keys' "${CREATE_RAUC_BUNDLE}"
if grep -q 'PKCS#11 RAUC signing provider is not implemented' "${CREATE_RAUC_BUNDLE}"; then
    echo "ERROR: RAUC bundle creation must support production PKCS#11 signing without file fallback" >&2
    exit 1
fi

python3 -m py_compile "${HSM_EVIDENCE}"
grep -q 'hsm_signing_session' "${HSM_EVIDENCE}"
grep -q 'suderra.hsm-signing-session.v2' "${EVIDENCE_CONTRACT}"
grep -q 'hardware_backed' "${HSM_EVIDENCE}"
grep -q 'certificate_sha256' "${HSM_EVIDENCE}"
grep -q 'challenge' "${HSM_EVIDENCE}"
grep -q 'SoftHSM' "${HSM_EVIDENCE}"

python3 - "${TMPDIR}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
cert = root / "rauc-signing.crt"
cert.write_text("contract certificate\n", encoding="utf-8")
payload = {
    "schema_version": "suderra.hsm-signing-session.v2",
    "mode": "production",
    "provider": "contract-hsm",
    "hardware_backed": True,
    "hsm_serial": "contract-serial",
    "pkcs11_uri": "pkcs11:token=Suderra;object=rauc-prod;type=private",
    "key_label": "rauc-prod",
    "key_id": "01",
    "certificate_sha256": hashlib.sha256(cert.read_bytes()).hexdigest(),
    "ceremony_id": "CER-2026-0001",
    "operator": "release-operator",
    "issuer": "security-compliance",
    "started_at": "2026-05-21T00:00:00Z",
    "signed_at": "2026-05-21T00:00:01Z",
    "expires_at": "2099-01-01T00:00:00Z",
    "audit": {
        "log_sha256": "a" * 64,
        "transcript_sha256": "b" * 64,
    },
    "token": {
        "label": "Suderra Production Token",
        "manufacturer": "contract-hsm-vendor",
        "model": "contract-hsm-model",
        "serial": "contract-serial",
        "module_sha256": "c" * 64,
    },
    "key": {
        "uri": "pkcs11:token=Suderra;object=rauc-prod;type=private",
        "label": "rauc-prod",
        "id": "01",
        "type": "private",
        "private": True,
        "extractable": False,
        "usages": ["sign"],
    },
    "challenge": {
        "nonce": "contract-nonce",
        "request_sha256": "d" * 64,
        "signature_sha256": "e" * 64,
        "transcript_sha256": "f" * 64,
        "algorithm": "pkcs11-signature-challenge-v1",
    },
    "artifacts": [
        {
            "role": "rauc-bundle",
            "name": "contract.raucb",
            "sha256": "1" * 64,
            "bytes": 1024,
        }
    ],
}
(root / "hsm-evidence.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "${HSM_EVIDENCE}" validate \
    "${TMPDIR}/hsm-evidence.json" \
    --pkcs11-uri 'pkcs11:token=Suderra;object=rauc-prod;type=private' \
    --certificate "${TMPDIR}/rauc-signing.crt" \
    --artifact-role rauc-bundle \
    --artifact-sha256 "$(printf '1%.0s' {1..64})" \
    --require-production \
    >/dev/null
if python3 "${HSM_EVIDENCE}" validate \
    "${TMPDIR}/hsm-evidence.json" \
    --pkcs11-uri 'pkcs11:token=Suderra;object=wrong;type=private' \
    --certificate "${TMPDIR}/rauc-signing.crt" \
    --require-production \
    2>"${TMPDIR}/hsm-uri.err"; then
    echo "ERROR: HSM signing evidence validator accepted the wrong PKCS#11 URI" >&2
    exit 1
fi
grep -q "pkcs11_uri" "${TMPDIR}/hsm-uri.err"

python3 - "${TMPDIR}/hsm-evidence.json" "${TMPDIR}/hsm-key-id-mismatch.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["key"]["id"] = "02"
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${HSM_EVIDENCE}" validate \
    "${TMPDIR}/hsm-key-id-mismatch.json" \
    --pkcs11-uri 'pkcs11:token=Suderra;object=rauc-prod;type=private' \
    --certificate "${TMPDIR}/rauc-signing.crt" \
    --artifact-role rauc-bundle \
    --require-production \
    2>"${TMPDIR}/hsm-key-id.err"; then
    echo "ERROR: HSM signing evidence validator accepted key.id/key_id mismatch" >&2
    exit 1
fi
grep -q "key.id" "${TMPDIR}/hsm-key-id.err"

python3 - "${TMPDIR}/hsm-evidence.json" "${TMPDIR}/hsm-split-artifact.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["artifacts"] = [
    {"role": "rauc-bundle", "name": "contract.raucb", "sha256": "2" * 64, "bytes": 1024},
    {"role": "sbom", "name": "contract.sbom", "sha256": "1" * 64, "bytes": 1024},
]
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${HSM_EVIDENCE}" validate \
    "${TMPDIR}/hsm-split-artifact.json" \
    --pkcs11-uri 'pkcs11:token=Suderra;object=rauc-prod;type=private' \
    --certificate "${TMPDIR}/rauc-signing.crt" \
    --artifact-role rauc-bundle \
    --artifact-sha256 "$(printf '1%.0s' {1..64})" \
    --require-production \
    2>"${TMPDIR}/hsm-split.err"; then
    echo "ERROR: HSM validator accepted role/SHA split across artifacts" >&2
    exit 1
fi
grep -q "same record" "${TMPDIR}/hsm-split.err"

python3 - "${TMPDIR}/hsm-evidence.json" "${TMPDIR}/hsm-zero-digest.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["audit"]["log_sha256"] = "0" * 64
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${HSM_EVIDENCE}" validate \
    "${TMPDIR}/hsm-zero-digest.json" \
    --pkcs11-uri 'pkcs11:token=Suderra;object=rauc-prod;type=private' \
    --certificate "${TMPDIR}/rauc-signing.crt" \
    --require-production \
    2>"${TMPDIR}/hsm-zero.err"; then
    echo "ERROR: HSM validator accepted all-zero audit digest" >&2
    exit 1
fi
grep -q "audit.log_sha256" "${TMPDIR}/hsm-zero.err"

python3 - "${TMPDIR}/hsm-evidence.json" "${TMPDIR}/hsm-soft-token.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["token"]["manufacturer"] = "SoftHSM project"
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${HSM_EVIDENCE}" validate \
    "${TMPDIR}/hsm-soft-token.json" \
    --pkcs11-uri 'pkcs11:token=Suderra;object=rauc-prod;type=private' \
    --certificate "${TMPDIR}/rauc-signing.crt" \
    --require-production \
    2>"${TMPDIR}/hsm-soft.err"; then
    echo "ERROR: HSM validator accepted SoftHSM token metadata" >&2
    exit 1
fi
grep -q "SoftHSM" "${TMPDIR}/hsm-soft.err"

python3 - "${PROJECT_ROOT}" "${TMPDIR}/hsm-evidence.json" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
session = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location(
    "validate_release_inputs",
    root / "scripts" / "evidence" / "validate-release-inputs.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
payload = json.loads(session.read_text(encoding="utf-8"))
failures = []
module.validate_hsm_session_replay(
    session,
    payload,
    failures,
    expected_artifact_sha256s={"2" * 64},
)
if not failures or not any("does not bind a release artifact digest" in item for item in failures):
    raise SystemExit("release input HSM replay accepted an unrelated artifact digest")
PY

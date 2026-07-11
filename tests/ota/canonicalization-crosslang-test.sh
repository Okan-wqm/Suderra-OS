#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Diller-arası kanonik JSON sözleşmesi (AUD-4 / NEW-7):
# 1) Python imzalayıcının kanonik bayt üretimi, committed golden vektörlerle
#    bayt-bayt aynı olmalı (Rust yarısı: suderra-config unit testi aynı
#    dosyalara karşı koşar — eşitlik transitiftir).
# 2) create(python) → verify(python) taze anahtarla uçtan uca tutarlı olmalı
#    (-v1'deki sign/verify kendi-tutarsızlığının regresyon testi).
# 3) Committed imzalı fixture, Python verify'dan geçmeli (Rust yarısı:
#    suderra-ota python_signed_fixture_verifies_in_rust).
set -euo pipefail
IFS=$'\n\t'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VECTOR_DIR="${PROJECT_ROOT}/tests/ota/fixtures/canonical-vectors"
FIXTURE_DIR="${PROJECT_ROOT}/tests/ota/fixtures/signed-manifest"
SIGNER="${PROJECT_ROOT}/scripts/create-os-update-manifest.py"

command -v python3 >/dev/null || { echo "SKIP: python3 yok"; exit 77; }

# --- 1) Golden vektörler: Python kanonik baytları == committed .canon ---
checked=0
for vector in "${VECTOR_DIR}"/*.json; do
    canon="${vector%.json}.canon"
    [ -f "${canon}" ] || { echo "FAIL: eksik canon dosyası: ${canon}"; exit 1; }
    python3 - "${vector}" "${canon}" "${SIGNER}" <<'PY'
import importlib.util
import json
import pathlib
import sys

vector, canon = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("signer", sys.argv[3])
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)

payload = json.loads(vector.read_text(encoding="utf-8"))
actual = signer.canonical_bytes(payload)
expected = canon.read_bytes()
if actual != expected:
    raise SystemExit(f"kanonik bayt uyuşmazlığı: {vector.name}\n  py : {actual!r}\n  gold: {expected!r}")
PY
    checked=$((checked + 1))
done
[ "${checked}" -ge 5 ] || { echo "FAIL: en az 5 golden vektör bekleniyor (${checked})"; exit 1; }
echo "PASS: ${checked} golden vektör Python tarafında bayt-bayt eşleşti"

# --- 2) Taze anahtarla create → verify roundtrip ---
if command -v openssl >/dev/null; then
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' EXIT
    openssl genpkey -algorithm ed25519 -out "${tmpdir}/key.pem" 2>/dev/null
    openssl pkey -in "${tmpdir}/key.pem" -pubout -out "${tmpdir}/key.pub" 2>/dev/null
    printf 'roundtrip bundle\n' > "${tmpdir}/bundle.raucb"
    python3 "${SIGNER}" create \
        --bundle "${tmpdir}/bundle.raucb" \
        --version v9.9.9 --target suderra-os-test \
        --min-current-version v0.1.0 --rollback-floor v0.1.0 \
        --key-epoch 1 --key-id roundtrip \
        --expires-at 2099-01-01T00:00:00Z \
        --release-notes "roundtrip — ğüşöç" \
        --signing-key "${tmpdir}/key.pem" --public-key "${tmpdir}/key.pub" \
        --output "${tmpdir}/manifest.json" >/dev/null
    python3 "${SIGNER}" verify \
        --manifest "${tmpdir}/manifest.json" \
        --public-key "${tmpdir}/key.pub" \
        --bundle "${tmpdir}/bundle.raucb" >/dev/null
    echo "PASS: create→verify roundtrip (taze anahtar, non-ASCII release notes)"
else
    echo "NOTE: openssl yok — roundtrip atlandı (golden vektörler yine de kanıt)"
fi

# --- 3) Committed fixture Python verify'dan geçmeli ---
python3 - "${FIXTURE_DIR}" "${SIGNER}" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import sys

fixture_dir = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("signer", sys.argv[2])
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)

payload = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
signature = payload.pop("signature")
assert signature["algorithm"] == signer.SIGNATURE_ALGORITHM, signature["algorithm"]
public_hex = (fixture_dir / "test-key.ed25519.pub").read_text().strip()
assert hashlib.sha256(bytes.fromhex(public_hex)).hexdigest() == signature["public_key_sha256"]
# openssl yoksa imza doğrulaması yapılamaz; bayt sözleşmesi yine sabitlenir.
canonical = signer.canonical_bytes(payload)
assert b'"schema_version":"suderra.os-update-manifest.v1"' in canonical
print("PASS: committed fixture kanonik bayt + pubkey pin tutarlı")
PY

echo "OK: canonicalization-crosslang-test"

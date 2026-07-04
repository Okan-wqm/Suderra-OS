#!/usr/bin/env bash
#
# ARM production build lane sözleşmesi (PR-A9, ADR-0007).
#
# Ayrı prod_ab defconfig + gated signing workflow deseninin bütünlüğünü korur:
# prod defconfig'ler kilitli (dropbear/getty yok, VARIANT_PROD), standart Image
# Build'den hariç, GPT/verity-signed-fit, uboot-rauc OTA, HSM-signed gated
# workflow. Dev rpi4/revpi4 DOKUNULMAZ (her-PR build yeşil kalır).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# 1. Prod defconfig'ler: VARIANT_PROD + kilitli (dropbear/getty yok).
for b in rpi4 revpi4; do
    dc="${ROOT}/configs/suderra_aarch64_${b}_prod_ab_defconfig"
    [ -f "${dc}" ] || { echo "ERROR: ${b} prod_ab defconfig yok" >&2; exit 1; }
    grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${dc}" || { echo "ERROR: ${b} prod_ab VARIANT_PROD değil" >&2; exit 1; }
    grep -q '^# BR2_PACKAGE_DROPBEAR is not set' "${dc}" || { echo "ERROR: ${b} prod_ab dropbear kapalı değil" >&2; exit 1; }
    grep -q '^# BR2_TARGET_GENERIC_GETTY is not set' "${dc}" || { echo "ERROR: ${b} prod_ab getty kapalı değil" >&2; exit 1; }
    if grep -qE '^BR2_PACKAGE_DROPBEAR=y|^BR2_TARGET_GENERIC_GETTY=y' "${dc}"; then
        echo "ERROR: ${b} prod_ab hâlâ dropbear/getty açık" >&2; exit 1; fi
    grep -q "^BR2_ROOTFS_POST_SCRIPT_ARGS=\"suderra_aarch64_${b}_prod_ab\"" "${dc}" || {
        echo "ERROR: ${b} prod_ab post-script arg yanlış" >&2; exit 1; }
    # Dev defconfig kilitlenMEMELİ (her-PR build).
    grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_DEV=y' "${ROOT}/configs/suderra_aarch64_${b}_defconfig" || {
        echo "ERROR: dev ${b} VARIANT_DEV kalmalı" >&2; exit 1; }
done

# 2. build-matrix + evidence-contract: validator geçmeli (join tutarlı).
python3 "${ROOT}/scripts/ci/validate-build-matrix.py" validate >/dev/null

# 3. build-matrix prod_ab: gpt + verity-signed-fit + genimage-prod + standart build'den hariç.
python3 - "${ROOT}" <<'PY'
import yaml, sys
root = sys.argv[1]
m = yaml.safe_load(open(f"{root}/ci/build-matrix.yml"))
byname = {t["name"]: t for t in m["defconfigs"]}
for dc, tgt, gi in (
    ("suderra_aarch64_rpi4_prod_ab_defconfig", "rpi4-prod-ab", "board/suderra/aarch64-rpi4/genimage-prod.cfg"),
    ("suderra_aarch64_revpi4_prod_ab_defconfig", "revpi4-prod-ab", "board/suderra/aarch64-revpi4/genimage-prod.cfg"),
):
    e = byname.get(dc)
    assert e, f"{dc} build-matrix'te yok"
    assert e["target"] == tgt, f"{dc} target {tgt} değil"
    assert e["partition_table"] == "gpt", f"{dc} gpt değil"
    assert e["root_identity"] == "verity-signed-fit", f"{dc} root_identity verity-signed-fit değil"
    assert e["genimage"] == gi, f"{dc} genimage {gi} değil"
    assert e["image_build"] is False, f"{dc} standart Image Build'den hariç olmalı (image_build:false)"
    assert e["fast_required"] is False and e["ci_build"] is False, f"{dc} standart CI'dan hariç olmalı"
    assert e["production_required"] is True and e["production_ready"] is False, f"{dc} prod-gated + not-ready olmalı"
print("build-matrix prod_ab OK")
PY

# 4. evidence-contract prod_ab OTA: uboot-rauc + ota_capable.
python3 - "${ROOT}" <<'PY'
import json, sys
root = sys.argv[1]
c = json.load(open(f"{root}/ci/evidence-contract.yml"))
for t in ("rpi4-prod-ab", "revpi4-prod-ab"):
    assert c["targets"][t]["ota_capable"] is True, f"{t} targets ota_capable değil"
    o = c["ota"]["targets"][t]
    assert o["backend"] == "uboot-rauc", f"{t} backend uboot-rauc değil"
    assert o["ota_capable"] is True and o["bundle_artifacts"], f"{t} ota bundle_artifacts boş"
    assert o["rollback_storage"] != "not-applicable", f"{t} rollback_storage tanımlı olmalı"
print("evidence-contract prod_ab OK")
PY

# 5. post-image: prod_ab RAUC bundle + arm-pre-genimage wiring.
PI="${ROOT}/board/suderra/common/post-image.sh"
grep -q 'suderra_aarch64_rpi4_prod_ab) ota_target="rpi4-prod-ab"' "${PI}" || {
    echo "ERROR: post-image rpi4-prod-ab RAUC bundle ota_target yok" >&2; exit 1; }
grep -q 'suderra_aarch64_revpi4_prod_ab) ota_target="revpi4-prod-ab"' "${PI}" || {
    echo "ERROR: post-image revpi4-prod-ab ota_target yok" >&2; exit 1; }
grep -qF 'suderra_aarch64_rpi4_prod_ab|suderra_aarch64_revpi4|suderra_aarch64_revpi4_prod_ab' "${PI}" || {
    echo "ERROR: post-image arm-pre-genimage prod_ab case içermiyor" >&2; exit 1; }

# 6. Gated workflow: workflow_dispatch + production-runtime environment + prod signing.
WF="${ROOT}/.github/workflows/arm-production-build.yml"
[ -f "${WF}" ] || { echo "ERROR: arm-production-build.yml yok" >&2; exit 1; }
python3 - "${WF}" <<'PY'
import yaml, sys
w = yaml.safe_load(open(sys.argv[1]))
assert "workflow_dispatch" in (w.get("on") or w.get(True) or {}), "workflow_dispatch yok"
job = w["jobs"]["arm-production-build"]
assert job["environment"]["name"] == "production-runtime", "gated environment değil"
body = open(sys.argv[1]).read()
for tok in ("SUDERRA_VARIANT: prod", "SUDERRA_SIGNING_MODE: prod", "SUDERRA_FIT_SIGNING_KEY", "suderra-A.fit"):
    assert tok in body, f"workflow eksik: {tok}"
print("gated workflow OK")
PY

echo "ARM production build lane contract passed"

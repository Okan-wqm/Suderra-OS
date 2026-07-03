#!/usr/bin/env bash
#
# OTA bundle subcommand dispatch sözleşmesi (PR-A9-prep).
#
# produce-ota-artifacts.py'nin create-rauc-bundle subcommand'ını OTA target'ın
# backend'inden (SSOT) türettiğini korur: grub-rauc→x86, uboot-rauc→arm. Önceden
# "x86" hardcoded'dı → ARM bundle'ı yanlış (UKI) imzalayıcıya giderdi. x86
# davranışı DEĞİŞMEZ.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${ROOT}" <<'PY'
import importlib.util, sys
root = sys.argv[1]
sys.path.insert(0, f"{root}/scripts/evidence")
spec = importlib.util.spec_from_file_location("poa", f"{root}/scripts/evidence/produce-ota-artifacts.py")
m = importlib.util.module_from_spec(spec); sys.modules["poa"] = m; spec.loader.exec_module(m)

assert m.bundle_subcommand_for("x86_64", {"backend": "grub-rauc"}) == "x86"
assert m.bundle_subcommand_for("qemu-x86_64-prod-ab", {"backend": "grub-rauc"}) == "x86"
assert m.bundle_subcommand_for("rpi4", {"backend": "uboot-rauc"}) == "arm"
assert m.bundle_subcommand_for("revpi4", {"backend": "uboot-rauc"}) == "arm"
for bad in ({"backend": "none"}, {"backend": None}, {}):
    try:
        m.bundle_subcommand_for("t", bad)
        raise SystemExit(f"FAIL: unknown backend {bad} must raise")
    except ValueError:
        pass

# x86 davranışı gerçek SSOT'ta korunmalı.
import evidence_contract as ec
c = ec.load_contract()
assert m.bundle_subcommand_for("x86_64", ec.ota_target_policy("x86_64", c)) == "x86", \
    "x86_64 must still dispatch to the x86 bundle subcommand"

print("OTA bundle subcommand dispatch contract passed")
PY

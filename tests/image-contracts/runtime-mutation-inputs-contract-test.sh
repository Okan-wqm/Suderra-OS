#!/usr/bin/env bash
#
# Production-runtime mutation-inputs plumbing sözleşmesi (PR-B4, hermetik).
#
# runtime-plan'ın mutation_inputs'u güvenli birleştirmesini (yalnız governed
# senaryolar) ve derive-mutation-inputs'un partition offset'lerini gerçek
# araçlarla doğru çıkarmasını kanıtlar. Tam boot-time suite manuel workflow.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
EVID="${ROOT}/scripts/evidence/evidence_contract.py"
DERIVE="${ROOT}/scripts/qemu/derive-mutation-inputs.py"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

python3 -m py_compile "${EVID}" "${DERIVE}"

SHA64="$(printf 'a%.0s' $(seq 1 64))"
common_args=(
    runtime-plan --version v9.9.9 --target qemu-x86_64-prod-ab
    --source-sha 0123456789abcdef0123456789abcdef01234567
    --source-run-id 1 --source-run-attempt 1
    --defconfig suderra_qemu_x86_64_prod_ab_defconfig --image disk.img
    --release-artifact a.img.xz --raw-image-sha256 "${SHA64}"
    --compressed-artifact-sha256 "${SHA64}" --ovmf-code c --ovmf-vars v
    --swtpm-state s --ovmf-enrollment-mode secure-boot-enrolled
    --ovmf-enrolled-vars-sha256 "${SHA64}" --secure-boot-db-sha256 "${SHA64}"
)

# 1) governed scenario merges into plan.mutation_inputs
printf '%s' '{"anti-rollback-downgrade-rejection":{"downgrade_version":"1.0.0"}}' > "${WORK}/mi.json"
python3 "${EVID}" "${common_args[@]}" --mutation-inputs-file "${WORK}/mi.json" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "anti-rollback-downgrade-rejection" in d["mutation_inputs"], "merge failed"'

# 2) ungoverned scenario rejected (fail-closed)
printf '%s' '{"bogus-scenario":{"x":1}}' > "${WORK}/bad.json"
if python3 "${EVID}" "${common_args[@]}" --mutation-inputs-file "${WORK}/bad.json" >/dev/null 2>&1; then
    echo "ERROR: runtime-plan accepted an ungoverned mutation scenario" >&2
    exit 1
fi

# 3) derive extracts real ESP/rootfs offsets from a synthetic GPT image.
command -v sfdisk >/dev/null 2>&1 && command -v parted >/dev/null 2>&1 || { echo "SKIP: sfdisk/parted yok"; exit 0; }
img="${WORK}/disk.img"
dd if=/dev/zero of="${img}" bs=1M count=80 status=none
parted -s "${img}" mklabel gpt mkpart efi fat32 1MiB 33MiB mkpart rootfs-a ext4 33MiB 75MiB >/dev/null 2>&1
mkdir -p "${WORK}/bin" "${WORK}/keys" "${WORK}/swtpm"
for f in suderra-A.efi linuxx64.efi.stub bzImage suderra-A.initrd os-release; do printf 'x' > "${WORK}/bin/${f}"; done
printf 'root=/dev/mapper/suderra-root suderra.verity.root_hash=abc ro\n' > "${WORK}/bin/suderra-A.cmdline"
for f in uefi-db.key uefi-db.crt os-update-manifest.key; do printf 'k' > "${WORK}/keys/${f}"; done
python3 "${DERIVE}" --image "${img}" --binaries-dir "${WORK}/bin" --keys-dir "${WORK}/keys" \
    --swtpm-state "${WORK}/swtpm" --rollback-floor 2.0.0 --downgrade-version 1.0.0 \
    --output "${WORK}/out.json" >/dev/null
python3 - "${WORK}/out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
esp = d["unsigned-boot-rejection"]["esp_offset"]
assert esp == 1048576, f"esp_offset {esp} != 1MiB"
assert d["dm-verity-rootfs-tamper-rejection"]["offset"] > esp, "rootfs offset must be past ESP"
assert set(d) >= {
    "unsigned-boot-rejection", "cmdline-tamper-rejection",
    "dm-verity-rootfs-tamper-rejection", "anti-rollback-downgrade-rejection",
    "data-luks-swtpm", "rauc-good-update", "rauc-bad-signature-rejection",
    "rauc-health-rollback",
}, "derive missing scenarios"
PY
echo "runtime mutation-inputs plumbing contract passed"

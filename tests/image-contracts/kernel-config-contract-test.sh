#!/usr/bin/env bash
#
# Kernel config contract of every Suderra OS image (ADR-048 DEC-8.10).
#
# scripts/ci/check-kernel-config.py derives each image's required kernel
# symbols from what the image runs (nftables rulesets, LUKS2 /data, the agent
# unit sandbox, the board's TPM and field I/O, the production verity
# initramfs) and from boards.json. This test runs its static mode over every
# defconfig on every PR, and proves on a scratch copy of the tree that it
# fails for each class of defect it exists to catch: a dropped required
# symbol, a trailing comment, a nonexistent symbol (CONFIG_SPIDEV, EI-065),
# a line the resolved .config does not honour, and a stale tracked override.
# post-build.sh runs the resolved mode on the real kernel tree of every image.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/scripts/ci/check-kernel-config.py"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECK}" ] || fail "missing ${CHECK}"

# 1. The repository itself.
python3 -I "${CHECK}" --root "${ROOT}" static

# post-build enforces the resolved mode on every image it builds, with the
# argument shape this test runs below (--root is a global option, before the
# subcommand; after it, argparse refuses the call and every image build fails).
grep -qF 'check-kernel-config.py" --root "${SUDERRA_EXTERNAL_DIR}" resolved' \
    "${ROOT}/board/suderra/common/post-build.sh" ||
    fail "post-build.sh must run check-kernel-config.py --root <external> resolved on the image's kernel tree"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fresh_copy() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree/contracts/suderra-edge/v1" "${WORK}/tree/configs"
    cp "${ROOT}"/configs/*_defconfig "${WORK}/tree/configs/"
    cp "${ROOT}/contracts/suderra-edge/v1/boards.json" "${WORK}/tree/contracts/suderra-edge/v1/"
    (cd "${ROOT}" && find board -name '*.config' -exec cp --parents {} "${WORK}/tree" \;)
}

expect_fail() {
    local label="$1" pattern="$2"
    shift 2
    local out
    if out="$("$@" 2>&1)"; then
        fail "${label}: the checker accepted it"
    fi
    grep -q -- "${pattern}" <<<"${out}" || {
        echo "${out}" >&2
        fail "${label}: the checker failed without naming ${pattern}"
    }
    echo "  rejects: ${label}"
}

QEMU_FRAG="board/suderra/x86_64/linux-qemu.config"
RPI_FRAG="board/suderra/aarch64-rpi4/linux-rpi4.config"
REVPI_FRAG="board/suderra/aarch64-revpi-connect4/linux-revpi-suderra.config"
REVPI_PROD_FRAG="board/suderra/aarch64-revpi-connect4/linux-revpi-suderra-prod.config"

# 2. Static mode rejects each defect class.
fresh_copy
sed -i '/^CONFIG_NFT_CT=y$/d' "${WORK}/tree/${QEMU_FRAG}"
expect_fail "dev QEMU kernel without NFT_CT" "suderra_qemu_x86_64_defconfig: CONFIG_NFT_CT must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i 's/^CONFIG_DM_CRYPT=y$/# CONFIG_DM_CRYPT is not set/' "${WORK}/tree/board/suderra/x86_64/linux-x86_64.config"
expect_fail "x86 prod kernel with DM_CRYPT off" "suderra_x86_64_defconfig: CONFIG_DM_CRYPT must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i 's/^CONFIG_BLK_DEV_INITRD=y$/CONFIG_BLK_DEV_INITRD=m/' "${WORK}/tree/board/suderra/x86_64/linux-x86_64.config"
expect_fail "x86 prod kernel with initramfs support as a module" "CONFIG_BLK_DEV_INITRD must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i 's/^CONFIG_SPI_SPIDEV=y$/CONFIG_SPIDEV=y/' "${WORK}/tree/${RPI_FRAG}"
expect_fail "rpi4 fragment with the nonexistent CONFIG_SPIDEV (EI-065)" \
    "suderra_aarch64_rpi4_defconfig: CONFIG_SPI_SPIDEV must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i 's/^CONFIG_NFT_LIMIT=y$/CONFIG_NFT_LIMIT=y   # rate limits/' "${WORK}/tree/${QEMU_FRAG}"
expect_fail "trailing comment on a config line" "no trailing" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

# The SPI TPM driver is declared by the RevPi board fragment and by the shared
# arm64 hardening fragment: both must lose it for the requirement to be unmet.
fresh_copy
sed -i '/^CONFIG_TCG_TIS_SPI=y$/d' \
    "${WORK}/tree/board/suderra/aarch64-rpi4/linux-rpi4-hardening.config" \
    "${WORK}/tree/${REVPI_FRAG}"
expect_fail "RevPi kernel without its SPI TPM driver" "suderra_aarch64_revpi4_defconfig: CONFIG_TCG_TIS_SPI must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i '/^CONFIG_RTC_DRV_PCF2127=y$/d' "${WORK}/tree/${REVPI_FRAG}"
expect_fail "RevPi kernel without its PCF2129 RTC driver" "suderra_aarch64_revpi4_defconfig: CONFIG_RTC_DRV_PCF2127 must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i '/^CONFIG_SERIAL_DEV_MUX_PIBRIDGE=y$/d' "${WORK}/tree/${REVPI_FRAG}"
expect_fail "RevPi kernel without the PiBridge serdev master" "suderra_aarch64_revpi4_defconfig: CONFIG_SERIAL_DEV_MUX_PIBRIDGE must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i '/^CONFIG_PREEMPT_RT=y$/d' "${WORK}/tree/${REVPI_FRAG}"
expect_fail "RevPi kernel that is no longer the real-time kernel" "CONFIG_PREEMPT_RT must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

# Module signing is a production requirement of the RevPi (EI-048): losing the
# forced signature check, or the forced lockdown, from the prod-only fragment
# fails the production image and no other.
fresh_copy
sed -i '/^CONFIG_MODULE_SIG_FORCE=y$/d' "${WORK}/tree/${REVPI_PROD_FRAG}"
expect_fail "RevPi production kernel that accepts unsigned modules" \
    "suderra_aarch64_revpi4_prod_ab_defconfig: CONFIG_MODULE_SIG_FORCE must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
sed -i 's/^CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y$/# CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY is not set/' "${WORK}/tree/${REVPI_PROD_FRAG}"
expect_fail "RevPi production kernel that is not locked down at build time" \
    "suderra_aarch64_revpi4_prod_ab_defconfig: CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY must be =y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" static

fresh_copy
python3 -I "${CHECK}" --root "${WORK}/tree" list >"${WORK}/list.txt"
grep -q '^suderra_aarch64_revpi4_prod_ab_defconfig	.*module-signing' "${WORK}/list.txt" ||
    fail "the RevPi production image does not require module signing"
if grep -q '^suderra_aarch64_revpi4_defconfig	.*module-signing' "${WORK}/list.txt"; then
    fail "the RevPi dev image must not require module signing (a developer loads their own modules)"
fi
echo "  requires module signing on the RevPi production image only"

# 3. Resolved mode on a synthetic kernel tree for the dev QEMU defconfig:
#    a Kconfig defining every symbol its fragment names, and a .config that
#    honours every line.
fresh_copy
KTREE="${WORK}/ktree"
mkdir -p "${KTREE}"
grep -oE '^(# )?CONFIG_[A-Za-z0-9_]+' "${WORK}/tree/${QEMU_FRAG}" | sed 's/^# //; s/^CONFIG_//' | sort -u |
    sed 's/^/config /' > "${KTREE}/Kconfig"
grep -E '^CONFIG_[A-Za-z0-9_]+=' "${WORK}/tree/${QEMU_FRAG}" > "${KTREE}/.config"
python3 -I "${CHECK}" --root "${WORK}/tree" resolved \
    --defconfig suderra_qemu_x86_64_defconfig --kernel-tree "${KTREE}" >/dev/null ||
    fail "resolved mode rejected a synthetic tree that honours every line"

sed -i 's/^CONFIG_CGROUP_BPF=y$/# CONFIG_CGROUP_BPF is not set/' "${KTREE}/.config"
expect_fail "resolved kernel without CGROUP_BPF" "resolved CONFIG_CGROUP_BPF=n, must be y" \
    python3 -I "${CHECK}" --root "${WORK}/tree" resolved \
    --defconfig suderra_qemu_x86_64_defconfig --kernel-tree "${KTREE}"
expect_fail "fragment line the resolved .config drops" "CONFIG_CGROUP_BPF=y is not honoured" \
    python3 -I "${CHECK}" --root "${WORK}/tree" resolved \
    --defconfig suderra_qemu_x86_64_defconfig --kernel-tree "${KTREE}"
sed -i 's/^# CONFIG_CGROUP_BPF is not set$/CONFIG_CGROUP_BPF=y/' "${KTREE}/.config"

echo 'CONFIG_GPIO_SYSFS_TYPO=y' >> "${WORK}/tree/${QEMU_FRAG}"
echo 'CONFIG_GPIO_SYSFS_TYPO=y' >> "${KTREE}/.config"
expect_fail "fragment symbol the kernel does not define" "CONFIG_GPIO_SYSFS_TYPO does not exist in this kernel" \
    python3 -I "${CHECK}" --root "${WORK}/tree" resolved \
    --defconfig suderra_qemu_x86_64_defconfig --kernel-tree "${KTREE}"

# 4. A tracked override that no longer happens is stale and fails, so
#    KNOWN_OVERRIDES cannot outlive the defect it names (EI-056).
fresh_copy
X86_FRAGS=("board/suderra/x86_64/linux-x86_64.config" "board/suderra/common/kernel-fragment.config")
rm -rf "${KTREE}" && mkdir -p "${KTREE}"
for f in "${X86_FRAGS[@]}"; do
    grep -oE '^(# )?CONFIG_[A-Za-z0-9_]+' "${WORK}/tree/${f}" | sed 's/^# //; s/^CONFIG_//'
done | sort -u | sed 's/^/config /' > "${KTREE}/Kconfig"
python3 -I - "${WORK}/tree" "${KTREE}/.config" "${X86_FRAGS[@]}" <<'PY'
import re, sys
root, out, files = sys.argv[1], sys.argv[2], sys.argv[3:]
eff = {}
for f in files:
    for line in open(f"{root}/{f}", encoding="utf-8"):
        m = re.match(r"^CONFIG_(\w+)=(.*)$", line.strip())
        if m:
            eff[m.group(1)] = m.group(2)
        m = re.match(r"^# CONFIG_(\w+) is not set$", line.strip())
        if m:
            eff[m.group(1)] = "n"
with open(out, "w", encoding="utf-8") as fh:
    for sym, val in sorted(eff.items()):
        fh.write(f"# CONFIG_{sym} is not set\n" if val == "n" else f"CONFIG_{sym}={val}\n")
PY
expect_fail "tracked override that is honoured again" "no longer happens; remove it from KNOWN_OVERRIDES" \
    python3 -I "${CHECK}" --root "${WORK}/tree" resolved \
    --defconfig suderra_x86_64_defconfig --kernel-tree "${KTREE}"

echo "kernel config contract passed"

#!/usr/bin/env bash
#
# U-Boot contract of the production images (ADR-048 DEC-18; EI-013, EI-034,
# EI-035, EI-036).
#
# scripts/ci/check-uboot-config.py holds the policy: which symbols a production
# U-Boot must set and unset, what its default environment (the whole of it,
# bootcmd included) may contain, and that the stored environment may write only
# the RAUC boot counters. This test runs its static mode on every PR and proves,
# on a scratch copy of the tree, that it fails for each class of defect it
# exists to catch. Its resolved mode (post-build.sh runs it on the U-Boot that
# Buildroot built; tests/qemu/arm-fit-signature-boot.sh runs it on the one it
# boots) is exercised here on a synthetic tree, so a checker that stopped
# looking at the resolved .config would fail this test, not pass a build.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/scripts/ci/check-uboot-config.py"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECK}" ] || fail "missing ${CHECK}"

# 1. The repository itself.
python3 -I "${CHECK}" --root "${ROOT}" static

# post-build runs the resolved mode on every image that builds U-Boot, with the
# argument shape this test uses below (--root is global, before the subcommand).
grep -qF 'check-uboot-config.py" --root "${SUDERRA_EXTERNAL_DIR}" resolved' \
    "${ROOT}/board/suderra/common/post-build.sh" ||
    fail "post-build.sh must run check-uboot-config.py --root <external> resolved on the image's U-Boot tree"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fresh_copy() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree"
    (cd "${ROOT}" && cp -a --parents configs board/suderra/uboot board/suderra/aarch64-rpi4/uboot-fragment.config \
        "${WORK}/tree")
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

static() { python3 -I "${CHECK}" --root "${WORK}/tree" static; }

HARDENING="${WORK}/tree/board/suderra/uboot/hardening.config"
ENVFILE="${WORK}/tree/board/suderra/uboot/suderra.env"
RPI_FRAG="${WORK}/tree/board/suderra/aarch64-rpi4/uboot-fragment.config"
PATCH="${WORK}/tree/board/suderra/uboot/patches/0001-env-flag-the-rauc-boot-counters-as-the-writeable-variables.patch"

echo "static mode: configuration"
fresh_copy
sed -i '/^CONFIG_ENV_WRITEABLE_LIST=y$/d' "${HARDENING}"
expect_fail "no writeable list: the stored environment could set bootcmd" \
    "CONFIG_ENV_WRITEABLE_LIST must be y" static

fresh_copy
sed -i '/^# CONFIG_LEGACY_IMAGE_FORMAT is not set$/d' "${HARDENING}"
expect_fail "legacy images left to the base defconfig (EI-036)" \
    "CONFIG_LEGACY_IMAGE_FORMAT must be explicitly unset" static

fresh_copy
sed -i 's/^CONFIG_BOOTDELAY=-2$/CONFIG_BOOTDELAY=-1/' "${HARDENING}"
expect_fail "bootdelay -1 stops at the prompt" "CONFIG_BOOTDELAY must be -2" static

fresh_copy
sed -i 's/^# CONFIG_CMD_BOOTEFI is not set$/CONFIG_CMD_BOOTEFI=y/' "${HARDENING}"
expect_fail "bootefi back in (EI-035)" "CONFIG_CMD_BOOTEFI must be explicitly unset" static

fresh_copy
sed -i 's/^# CONFIG_USB is not set$/CONFIG_USB=y/' "${HARDENING}"
expect_fail "USB boot back in (EI-035)" "CONFIG_USB must be explicitly unset" static

fresh_copy
sed -i 's/^CONFIG_OF_BOARD=y$/# CONFIG_OF_BOARD is not set/' "${HARDENING}"
expect_fail "OF_BOARD dropped: the keyed firmware device trees would no longer be the control FDT" \
    "CONFIG_OF_BOARD must be y" static

fresh_copy
sed -i 's/^CONFIG_ENV_IS_IN_MMC=y$/CONFIG_ENV_IS_IN_FAT=y/' "${RPI_FRAG}"
expect_fail "environment back in a FAT file (EI-034)" "CONFIG_ENV_IS_IN_MMC must be y" static

fresh_copy
sed -i 's/^CONFIG_FIT_SIGNATURE=y$/CONFIG_FIT_SIGNATURE=y   # enforce/' "${HARDENING}"
expect_fail "trailing comment on a config line" "no trailing" static

fresh_copy
sed -i 's/^CONFIG_SYS_REDUNDAND_ENVIRONMENT=y$/CONFIG_ENV_REDUNDANT=y/' "${HARDENING}"
expect_fail "the ADR text's ENV_REDUNDANT instead of SYS_REDUNDAND_ENVIRONMENT" \
    "CONFIG_SYS_REDUNDAND_ENVIRONMENT must be y" static

fresh_copy
sed -i '/BR2_TARGET_UBOOT_DEFAULT_ENV_FILE=/d' "${WORK}/tree/configs/suderra_aarch64_rpi4_prod_ab_defconfig"
expect_fail "a production defconfig without the default environment file" \
    "suderra_aarch64_rpi4_prod_ab_defconfig: BR2_TARGET_UBOOT_DEFAULT_ENV_FILE must name one existing file" static

fresh_copy
sed -i 's#\$(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra/uboot/hardening.config ##' \
    "${WORK}/tree/configs/suderra_aarch64_revpi4_prod_ab_defconfig"
expect_fail "a production defconfig that does not merge the hardening fragment" \
    "suderra_aarch64_revpi4_prod_ab_defconfig: CONFIG_FIT_SIGNATURE must be y" static

echo "static mode: default environment"
fresh_copy
sed -i '/^stdin=nulldev$/d' "${ENVFILE}"
expect_fail "console input left to the board's default" "stdin must be nulldev" static

fresh_copy
sed -i 's/^bootdelay=-2$/bootdelay=-1/' "${ENVFILE}"
expect_fail "environment bootdelay -1" "bootdelay must be -2" static

fresh_copy
printf 'bootargs=console=ttyAMA0 root=/dev/mmcblk0p2\n' >> "${ENVFILE}"
expect_fail "a bootargs variable beside the signed FIT's own" "defines bootargs" static

fresh_copy
printf 'preboot=usb start\n' >> "${ENVFILE}"
expect_fail "a preboot step" "defines preboot" static

fresh_copy
printf 'fdt_addr=0x2eff8f00\n' >> "${ENVFILE}"
expect_fail "fdt_addr fixed in the environment instead of set from the firmware pointer" \
    "defines fdt_addr" static

fresh_copy
printf 'fdtcontroladdr=0x2eff8f00\n' >> "${ENVFILE}"
expect_fail "the control FDT address named by the environment" "defines fdtcontroladdr" static

fresh_copy
sed -i 's/^fdt addr \${fdtcontroladdr}; \\$/fdt addr ${fdt_addr}; \\/' "${ENVFILE}"
expect_fail "a guard that reads the firmware's blob, not the control FDT" \
    "suderra_guard must read the control FDT" static

fresh_copy
python3 -I - "${ENVFILE}" <<'EOF'
import re, sys
p = sys.argv[1]
s = open(p).read()
s2 = re.sub(r"; \\\nreset\n$", "\n", s)
assert s2 != s
open(p, "w").write(s2)
EOF
expect_fail "bootcmd that can return to the prompt" "bootcmd must end in 'reset'" static

fresh_copy
sed -i 's/^load \${suderra_bootdev} \${fitaddr} suderra-\${suderra_slot}.fit && bootm \${fitaddr}$/load ${suderra_bootdev} ${fitaddr} suderra-${suderra_slot}.fit \&\& booti ${fitaddr}/' "${ENVFILE}"
expect_fail "bootcmd that boots the raw image (EI-035)" "runs 'booti'" static

fresh_copy
sed -i 's/^echo Suderra: booting slot \${suderra_slot}; \\$/usb start; \\/' "${ENVFILE}"
expect_fail "a USB step in the boot" "runs 'usb'" static

fresh_copy
sed -i 's/^test "\${suderra_required}" = conf$/test -n "${suderra_required}"/' "${ENVFILE}"
expect_fail "a guard that accepts a key node without required = conf" "must end by requiring required = conf" static

fresh_copy
sed -i 's#^if run suderra_guard; then \\$#if true; then \\#' "${ENVFILE}"
expect_fail "bootcmd without the key guard first" "bootcmd must start with 'if run suderra_guard; then'" static

fresh_copy
python3 -I - "${ENVFILE}" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
s2 = s.replace("    run suderra_fail; \\\n", "")
assert s2 != s
open(p, "w").write(s2)
EOF
expect_fail "a slot whose FIT does not verify is not spent (it would boot-loop)" "does not run suderra_fail" static

fresh_copy
sed -i 's/^bootdelay=-2$/bootdelay=-2\nstdout=serial/' "${ENVFILE}"
expect_fail "an environment that defines a variable twice" "defined twice" static

fresh_copy
sed -i 's/^BOOT_B_LEFT=0$/BOOT_B_LEFT=3/' "${ENVFILE}"
expect_fail "factory slot B counted as bootable" "BOOT_B_LEFT must start at 0" static

fresh_copy
sed -i 's/^BOOT_A_LEFT=3$/BOOT_A_LEFT=2/' "${ENVFILE}"
expect_fail "factory slot A not confirmed" "BOOT_A_LEFT must start at suderra_good_attempts" static

fresh_copy
sed -i 's/BOOT_B_LEFT:dw"/BOOT_B_LEFT:dw,bootcmd:sw"/' "${PATCH}"
expect_fail "bootcmd in the writeable list" "the writeable variables are" static

fresh_copy
sed -i 's/BOOT_ORDER:sw,//' "${PATCH}"
expect_fail "BOOT_ORDER dropped from the writeable list" "the writeable variables are" static

fresh_copy
sed -i 's/^suderra_good_attempts=3$/suderra_good_attempts=12/' "${ENVFILE}"
expect_fail "a good-attempts value setexpr cannot count down" "one digit" static

# 3. Resolved mode, on a synthetic tree: a Kconfig that defines every symbol the
# fragments name, and a .config that honours them. The checker must accept it
# and must reject a .config that kept LEGACY_IMAGE_FORMAT from the base
# defconfig, a fragment line for a symbol this U-Boot does not define, and a
# build that used another environment file.
echo "resolved mode"
fresh_copy
SYN="${WORK}/syn"
mkdir -p "${SYN}/tree"
python3 -I - "${WORK}/tree" "${SYN}" <<'EOF'
import re, sys
from pathlib import Path
root, syn = Path(sys.argv[1]), Path(sys.argv[2])
frags = [root / "board/suderra/uboot/hardening.config",
         root / "board/suderra/aarch64-rpi4/uboot-fragment.config"]
cfg, syms = [], []
for f in frags:
    for line in f.read_text().splitlines():
        m = re.match(r"CONFIG_(\w+)=(.*)", line)
        if m:
            cfg.append(line); syms.append(m.group(1))
        m = re.match(r"# CONFIG_(\w+) is not set", line)
        if m:
            syms.append(m.group(1))
cfg += ['CONFIG_USE_DEFAULT_ENV_FILE=y',
        f'CONFIG_DEFAULT_ENV_FILE="{root}/board/suderra/uboot/suderra.env"']
syms += ["USE_DEFAULT_ENV_FILE", "DEFAULT_ENV_FILE"]
(syn / "tree" / "Kconfig").write_text("".join(f"config {s}\n\tbool\n" for s in sorted(set(syms))))
(syn / "dotconfig").write_text("\n".join(cfg) + "\n")
EOF
resolved() {
    python3 -I "${CHECK}" --root "${WORK}/tree" resolved --defconfig suderra_aarch64_rpi4_prod_ab \
        --uboot-tree "${SYN}/tree" --dotconfig "$1"
}
resolved "${SYN}/dotconfig" >/dev/null || fail "the checker rejected a resolved .config that honours the fragments"
echo "  accepts: a .config that honours every line"

cp "${SYN}/dotconfig" "${SYN}/legacy"
echo 'CONFIG_LEGACY_IMAGE_FORMAT=y' >> "${SYN}/legacy"
expect_fail "base defconfig value kept: LEGACY_IMAGE_FORMAT=y" \
    "resolved CONFIG_LEGACY_IMAGE_FORMAT=y, must be unset" resolved "${SYN}/legacy"

sed 's/^CONFIG_ENV_WRITEABLE_LIST=y$/# CONFIG_ENV_WRITEABLE_LIST is not set/' "${SYN}/dotconfig" > "${SYN}/dropped"
expect_fail "a line Kconfig dropped (ENV_WRITEABLE_LIST)" \
    "CONFIG_ENV_WRITEABLE_LIST=y is not honoured" resolved "${SYN}/dropped"

sed 's/^CONFIG_BOOTDELAY=-2$/CONFIG_BOOTDELAY=2/' "${SYN}/dotconfig" > "${SYN}/delay"
expect_fail "resolved bootdelay 2" "resolved CONFIG_BOOTDELAY=2, must be -2" resolved "${SYN}/delay"

sed -i 's/^config SYS_REDUNDAND_ENVIRONMENT$/config SYS_REDUNDANT_ENVIRONMENT/' "${SYN}/tree/Kconfig"
expect_fail "a symbol this U-Boot does not define" \
    "CONFIG_SYS_REDUNDAND_ENVIRONMENT does not exist in this U-Boot" resolved "${SYN}/dotconfig"
sed -i 's/^config SYS_REDUNDANT_ENVIRONMENT$/config SYS_REDUNDAND_ENVIRONMENT/' "${SYN}/tree/Kconfig"

printf 'bootcmd=run evil; reset\n' > "${SYN}/other.env"
sed "s#^CONFIG_DEFAULT_ENV_FILE=.*#CONFIG_DEFAULT_ENV_FILE=\"${SYN}/other.env\"#" "${SYN}/dotconfig" > "${SYN}/otherenv"
expect_fail "a build that used another default environment" "differs from board/suderra/uboot/suderra.env" \
    resolved "${SYN}/otherenv"

sed '/^CONFIG_USE_DEFAULT_ENV_FILE=y$/d' "${SYN}/dotconfig" > "${SYN}/boardenv"
expect_fail "a build that kept the board's own environment" "CONFIG_USE_DEFAULT_ENV_FILE is not y" \
    resolved "${SYN}/boardenv"

echo "U-Boot config contract test OK"

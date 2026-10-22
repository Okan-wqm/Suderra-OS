#!/usr/bin/env bash
#
# Revolution Pi Connect 4 board contract (ADR-048 DEC-8; EI-032, EI-029, EI-024).
#
# The RevPi images are the KUNBUS kernel with the piControl driver and the
# revpi-connect4 device tree, not a generic CM4 image. This test holds what
# makes them that, in two parts.
#
# 1. The pins and wiring in the repository: the kernel pin, its hash and its
#    header series; the piControl pairing; the firmware configs, which may not
#    carry a dtoverlay=/dtparam= (the production kernel gets the FIT's device
#    tree, so such a line would reach only the dev kernel); the dev image's root
#    name; the board's data files.
# 2. The device-tree and FIT mechanism, run with the real tools
#    (fdtoverlay, fdtget, mkimage, dumpimage, veritysetup) on stand-in device
#    trees that have the nodes of the real ones, and the same mechanism proven to
#    reject every defect class it exists to catch: a merged tree without the TPM
#    node, with a disabled node, without the RS485 flag, built without symbols,
#    without the board's root compatible; a FIT whose tree lacks a required node
#    or differs from the merged tree; a kernel too large for the FIT's load
#    window; a malformed board description.
#
# The real KUNBUS tree is not in this test (it is a 247 MB tarball): the
# resolved kernel config and the real merged device tree are checked on every
# image build, by post-build.sh (check-kernel-config.py resolved) and by
# arm-pre-genimage's gate. The tools come from the CI build container
# (ci/Dockerfile) and from the contract-test jobs of build.yml and lint.yml; a
# missing one fails this test rather than skipping it, because a skipped test
# here is a gate nobody runs.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BOARD="${ROOT}/board/suderra/aarch64-revpi-connect4"
PA="${ROOT}/scripts/production-artifacts.sh"
DEV="${ROOT}/configs/suderra_aarch64_revpi4_defconfig"
PROD="${ROOT}/configs/suderra_aarch64_revpi4_prod_ab_defconfig"
HASHES="${ROOT}/board/suderra/buildroot-hashes/linux/linux.hash"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for tool in dtc fdtoverlay fdtget mkimage dumpimage veritysetup mkfs.ext4 openssl cpio gzip awk; do
    command -v "${tool}" >/dev/null 2>&1 ||
        fail "${tool} is missing (ci/Dockerfile and the contract-test jobs of build.yml and lint.yml install u-boot-tools, device-tree-compiler and cryptsetup-bin)"
done
[ -d "${BOARD}" ] || fail "missing ${BOARD}"
# fit_check_sign is U-Boot's own FIT verifier, which the producer's boot gate runs:
# Buildroot's host-uboot-tools installs it, a distribution package does not, so it
# is built from the pinned sources (scripts/ci/uboot-build.sh) when it is missing.
if ! command -v fit_check_sign >/dev/null 2>&1; then
    UBOOT_TOOLS="${SUDERRA_UBOOT_BUILD:-$(mktemp -d)}"
    bash "${ROOT}/scripts/ci/uboot-build.sh" tools "${UBOOT_TOOLS}" >/dev/null ||
        { echo "SKIP: fit_check_sign is missing and the U-Boot tools could not be built" >&2; exit 77; }
    export PATH="${UBOOT_TOOLS}/bin:${PATH}"
fi

# ---------------------------------------------------------------------------
# 1. Pins and wiring
# ---------------------------------------------------------------------------
echo "pins and wiring"

cfg() { # <defconfig> <symbol>: the value of BR2_<symbol>, quotes stripped
    local v
    v="$(sed -n "s/^BR2_$2=\(.*\)$/\1/p" "$1" | head -1)"
    v="${v#\"}"
    printf '%s' "${v%\"}"
}

# The old directory is gone and nothing refers to it.
[ ! -e "${ROOT}/board/suderra/aarch64-revpi4" ] || fail "board/suderra/aarch64-revpi4 still exists: the board directory is aarch64-revpi-connect4"

location_dev="$(cfg "${DEV}" LINUX_KERNEL_CUSTOM_TARBALL_LOCATION)"
location_prod="$(cfg "${PROD}" LINUX_KERNEL_CUSTOM_TARBALL_LOCATION)"
[ "${location_dev}" = "${location_prod}" ] || fail "the dev and production RevPi images pin different kernels"
# shellcheck disable=SC2016
sha="$(sed -n 's#^\$(call gitlab,revolutionpi,linux,\([0-9a-f]\{40\}\))/linux-\([0-9a-f]\{40\}\)\.tar\.gz$#\1 \2#p' <<<"${location_dev}")"
if [ -z "${sha}" ] || [ "${sha%% *}" != "${sha##* }" ]; then
    fail "the RevPi kernel must be the KUNBUS RevolutionPi/linux archive of one 40-hex commit (\$(call gitlab,revolutionpi,linux,<sha>)/linux-<sha>.tar.gz): ${location_dev}"
fi
sha="${sha%% *}"
grep -Eq "^sha256[[:space:]]+[0-9a-f]{64}[[:space:]]+linux-${sha}\.tar\.gz$" "${HASHES}" ||
    fail "${HASHES} has no sha256 entry for linux-${sha}.tar.gz"
if grep -Eq "^sha256[[:space:]]+0{64}[[:space:]]" "${HASHES}"; then fail "${HASHES} holds a placeholder digest"; fi
# The pin records which KUNBUS release it is (a tag of the revpi-6.12 line); that
# tag's series is the headers series of the toolchain (DEC-8.12: one 6.12 line).
tag="$(grep -E "commit ${sha}, which tag v6\.12\.[0-9]+-revpi[0-9]+" "${HASHES}" | sed -n 's/.*tag \(v6\.12\.[0-9]*-revpi[0-9]*\).*/\1/p' | head -1)"
[ -n "${tag}" ] || fail "${HASHES} must say which v6.12.<n>-revpi<m> tag of the revpi-6.12 line commit ${sha} is"
for c in "${DEV}" "${PROD}"; do
    grep -qx 'BR2_KERNEL_HEADERS_6_12=y' "${c}" || fail "${c}: the kernel is ${tag}, the toolchain headers must be 6.12 (BR2_KERNEL_HEADERS_6_12=y)"
    grep -qx 'BR2_DOWNLOAD_FORCE_CHECK_HASHES=y' "${c}" || fail "${c}: kernel hash checking must be forced"
    [ "$(cfg "${c}" LINUX_KERNEL_DEFCONFIG)" = "revpi-v8" ] || fail "${c}: the base config is KUNBUS's revpi-v8_defconfig"
    [ "$(cfg "${c}" LINUX_KERNEL_INTREE_DTS_NAME)" = "broadcom/bcm2711-rpi-cm4" ] ||
        fail "${c}: the stock tree is broadcom/bcm2711-rpi-cm4 only (the CM4 IO board's tree is not a RevPi)"
    [ "$(cfg "${c}" LINUX_KERNEL_INTREE_DTSO_NAMES)" = "overlays/revpi-connect4" ] ||
        fail "${c}: the kernel must build KUNBUS's overlays/revpi-connect4"
    for sym in LINUX_KERNEL_DTB_OVERLAY_SUPPORT PACKAGE_HOST_DTC PACKAGE_XZ PACKAGE_REVPI_PICONTROL; do
        grep -qx "BR2_${sym}=y" "${c}" || fail "${c}: BR2_${sym}=y is missing"
    done
    grep -q 'raspberrypi,linux' "${c}" && fail "${c} still pins the raspberrypi kernel"
    grep -qF 'aarch64-revpi-connect4/config.txt' "${c}" || fail "${c} does not use the RevPi firmware config"
    grep -qF 'aarch64-revpi-connect4/cmdline.txt' "${c}" || fail "${c} does not use the RevPi cmdline"
    grep -qF 'aarch64-rpi4/config.txt' "${c}" && fail "${c} uses the Raspberry Pi firmware config"
done

# piControl: the release KUNBUS builds for this kernel, a signed module.
mk="${ROOT}/package/revpi-picontrol/revpi-picontrol.mk"
pic="$(sed -n 's/^REVPI_PICONTROL_VERSION = \([0-9a-f]\{40\}\)$/\1/p' "${mk}")"
[ -n "${pic}" ] || fail "${mk}: REVPI_PICONTROL_VERSION must be one 40-hex commit"
grep -Eq "^sha256[[:space:]]+[0-9a-f]{64}[[:space:]]+piControl-${pic}\.tar\.gz$" "${ROOT}/package/revpi-picontrol/revpi-picontrol.hash" ||
    fail "revpi-picontrol.hash has no entry for piControl-${pic}.tar.gz"
for lic in GPL-2.0-only LGPL-2.1-only MIT; do
    grep -Eq "^sha256[[:space:]]+[0-9a-f]{64}[[:space:]]+LICENSES/${lic}\.txt$" "${ROOT}/package/revpi-picontrol/revpi-picontrol.hash" ||
        fail "revpi-picontrol.hash has no hash for LICENSES/${lic}.txt"
done
grep -q 'gitlab,revolutionpi,piControl' "${mk}" || fail "${mk}: piControl comes from gitlab.com/revolutionpi/piControl"
# shellcheck disable=SC2016
grep -q 'eval \$(kernel-module)' "${mk}" || fail "${mk}: piControl is built by the kernel-module infrastructure (so modules_install signs it)"
grep -q 'KCONFIG_ENABLE_OPT,CONFIG_SERIAL_DEV_MUX_PIBRIDGE' "${mk}" || fail "${mk}: the kernel fixups must keep the PiBridge serdev master piControl links against"
grep -qx 'piControl' "${ROOT}/package/revpi-picontrol/revpi-picontrol.conf" || fail "revpi-picontrol.conf must name the module systemd-modules-load loads"
grep -q 'revpi-picontrol/Config.in' "${ROOT}/Config.in" || fail "Config.in does not source package/revpi-picontrol/Config.in"
# The pairing rationale the .mk header states is the reason for the pin: the
# release newer than this kernel needs symbols this kernel does not export.
grep -q 'pibridge_req_io_tmt' "${mk}" || fail "${mk} must keep the record of why a newer piControl does not fit this kernel"

# Firmware configs: no overlay or dtparam line reaches the kernel of production,
# so none may exist for the dev kernel either; both name the right kernel.
for f in config.txt config-uboot.txt; do
    if grep -Eq '^[[:space:]]*(dtoverlay|dtparam)=' "${BOARD}/${f}"; then
        fail "${BOARD#"${ROOT}/"}/${f}: a dtoverlay=/dtparam= line never reaches the production kernel (EI-024): put the node in the overlay"
    fi
done
grep -qx 'kernel=Image' "${BOARD}/config.txt" || fail "config.txt (dev) must load kernel=Image"
grep -qx 'kernel=u-boot.bin' "${BOARD}/config-uboot.txt" || fail "config-uboot.txt (prod) must chain-load kernel=u-boot.bin"
grep -qx 'arm_64bit=1' "${BOARD}/config.txt" || fail "config.txt must be 64-bit"
grep -qx 'arm_64bit=1' "${BOARD}/config-uboot.txt" || fail "config-uboot.txt must be 64-bit"

# board-boot.conf: the names the firmware, genimage and the FIT agree on.
conf_get() { sed -n "s/^$1=\\(.*\\)$/\\1/p" "${BOARD}/board-boot.conf" | head -1 | sed 's/^"//; s/"$//'; }
final="$(conf_get BOARD_FINAL_DTB)"
compat="$(conf_get BOARD_COMPATIBLE)"
[ "${compat}" = "kunbus,revpi-connect4" ] || fail "BOARD_COMPATIBLE must be kunbus,revpi-connect4 (boards.json identity_cross_check)"
grep -qx "device_tree=${final}" "${BOARD}/config.txt" || fail "config.txt must load device_tree=${final}"
grep -qF "\"${final}\"" "${BOARD}/genimage.cfg" || fail "genimage.cfg (dev) must carry ${final}"
# The firmware loads the stock tree: the copy with the FIT key in it, U-Boot's control FDT.
grep -qF "image = \"firmware-dtb/$(conf_get BOARD_BASE_DTB)\"" "${BOARD}/genimage-prod.cfg" || fail "genimage-prod.cfg must carry the keyed stock tree for the firmware (firmware-dtb/)"
grep -qE "^[[:space:]]*\"$(conf_get BOARD_BASE_DTB)\"" "${BOARD}/genimage-prod.cfg" && fail "genimage-prod.cfg must not carry the unkeyed stock tree"
grep -qF "\"${final}\"" "${BOARD}/genimage-prod.cfg" && fail "genimage-prod.cfg must not carry ${final}: it lives in the signed FIT only"
for g in genimage.cfg genimage-prod.cfg; do
    code="$(grep -vE '^[[:space:]]*#' "${BOARD}/${g}")"
    if grep -q 'cm4-io' <<<"${code}"; then fail "${g}: the CM4 IO board's tree is not a RevPi tree"; fi
    if grep -q 'overlays' <<<"${code}"; then fail "${g}: no firmware overlays directory is shipped (the overlay is merged at build time)"; fi
done
[ -f "${BOARD}/$(conf_get BOARD_FIT_ITS)" ] || fail "BOARD_FIT_ITS names a missing file"
[ -f "${BOARD}/$(conf_get BOARD_DT_REQUIRED)" ] || fail "BOARD_DT_REQUIRED names a missing file"
boards_json="${ROOT}/contracts/suderra-edge/v1/boards.json"
python3 -I - "${boards_json}" "${compat}" <<'PY' || fail "boards.json identity_cross_check of revpi-connect4 is not ${compat}"
import json, sys
board = next(b for b in json.load(open(sys.argv[1]))["boards"] if b["board_profile"] == "revpi-connect4")
assert sys.argv[2] in board["identity_cross_check"]["values"]
PY

# The dev image resolves its root without an initramfs: root=PARTUUID=<disk
# signature>-02, and the disk signature is what genimage writes (EI-022).
cmdline="$(cat "${BOARD}/cmdline.txt")"
case "${cmdline}" in
    *root=LABEL=* | *root=UUID=*) fail "cmdline.txt (dev) names its root by LABEL=/UUID=: the kernel cannot resolve that without an initramfs" ;;
esac
partuuid="$(sed -n 's/.*root=PARTUUID=\([0-9a-f]\{8\}\)-02\( .*\)\?$/\1/p' <<<"${cmdline}")"
[ -n "${partuuid}" ] || fail "cmdline.txt (dev) must name root=PARTUUID=<8 hex>-02 (rootfs is partition 2)"
grep -qx "    disk-signature = 0x${partuuid}" "${BOARD}/genimage.cfg" || fail "genimage.cfg disk-signature must be 0x${partuuid}"
awk '/^  partition /{n++; if ($2 == "rootfs") {print n; exit}}' "${BOARD}/genimage.cfg" | grep -qx 2 || fail "rootfs must be partition 2 of genimage.cfg"

# The FIT template and the required-node list.
its="${BOARD}/$(conf_get BOARD_FIT_ITS)"
grep -qF "compatible = \"${compat}\"" "${its}" || fail "the FIT template's configuration compatible must start with ${compat}"
grep -qF 'required = "conf"' "${its}" || fail "the FIT configuration signature must be required"
[ "$(grep -c '^        conf-' "${its}")" = 1 ] || fail "the board FIT has exactly one configuration"
leftover="$(grep -o '@[A-Z]*@' "${its}" | sort -u | tr '\n' ' ')"
[ "${leftover}" = "@FDT@ @INITRD@ @KERNEL@ @SLOT@ " ] || fail "the FIT template's placeholders are '${leftover}'"
# U-Boot reads no bootargs property of a FIT configuration: the command line is in the signed device tree.
if grep -vE '^[[:space:]]*(/?\*|#)' "${its}" | grep -Eq '^[[:space:]]*bootargs[[:space:]]*='; then
    fail "the FIT template has a configuration bootargs property, which U-Boot never reads"; fi
req="${BOARD}/$(conf_get BOARD_DT_REQUIRED)"
for want in 'label:tpm *compatible *infineon,slb9670' 'label:i2c1/rtc@51 *compatible *nxp,pcf2129' \
    'path:/pibridge *compatible *kunbus,pibridge' 'label:uart5 *linux,rs485-enabled-at-boot-time'; do
    grep -Eq "^${want}" "${req}" || fail "$(basename "${req}") lacks '${want}' (the nodes DEC-8.7 names: TPM, RTC, PiBridge, RS485)"
done

# post-image builds the board's tree for the dev image and hands the board to the
# production producer.
PI="${ROOT}/board/suderra/common/post-image.sh"
# shellcheck disable=SC2016
for token in \
    '"${PRODUCTION_ARTIFACTS}" arm-board-dtb "${BINARIES_DIR}" "${ARM_BOARD_DIR}"' \
    '"${PRODUCTION_ARTIFACTS}" arm-pre-genimage "${BINARIES_DIR}" "${TARGET_DIR:?TARGET_DIR not set}" \' \
    '${ARM_BOARD_DIR:+"${ARM_BOARD_DIR}"}' \
    'fw_config="${ARM_BOARD_DIR}/config-uboot.txt"'
do
    grep -qF -e "${token}" "${PI}" || fail "post-image.sh does not wire: ${token}"
done

# Device access of the agent: the drop-in and the udev rule that match it.
dropin="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service.d/10-board-revpi-connect4.conf"
grep -qx 'DeviceAllow=/dev/piControl0 rw' "${dropin}" || fail "the agent drop-in must allow /dev/piControl0"
grep -q 'KERNEL=="piControl0", GROUP="suderra-io"' "${ROOT}/board/suderra/common/rootfs-overlay/usr/lib/udev/rules.d/60-suderra-devices.rules" ||
    fail "udev must give /dev/piControl0 to suderra-io"

# ---------------------------------------------------------------------------
# 2. Device-tree and FIT mechanism on stand-in trees
# ---------------------------------------------------------------------------
echo "device-tree and FIT mechanism"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# A stand-in for the stock CM4 tree: the labels and nodes the overlay targets.
cat > "${WORK}/base.dts" <<'EOF'
/dts-v1/;
/ {
	compatible = "raspberrypi,4-compute-module", "brcm,bcm2711";
	model = "Raspberry Pi Compute Module 4";
	#address-cells = <1>;
	#size-cells = <1>;
	aliases { serial0 = &uart1; serial5 = &uart5; };
	soc {
		#address-cells = <1>;
		#size-cells = <1>;
		gpio: gpio@7e200000 { compatible = "brcm,bcm2711-gpio"; reg = <0x7e200000 0x100>; gpio-controller; #gpio-cells = <2>; };
		i2c1: i2c@7e804000 { compatible = "brcm,bcm2835-i2c"; reg = <0x7e804000 0x100>; #address-cells = <1>; #size-cells = <0>; status = "disabled"; };
		spi1: spi@7e215080 { compatible = "brcm,bcm2835-aux-spi"; reg = <0x7e215080 0x100>; #address-cells = <1>; #size-cells = <0>; status = "disabled"; };
		uart1: serial@7e215040 { compatible = "brcm,bcm2835-aux-uart"; reg = <0x7e215040 0x100>; };
		uart3: serial@7e201600 { compatible = "arm,pl011"; reg = <0x7e201600 0x100>; status = "disabled"; };
		uart5: serial@7e201a00 { compatible = "arm,pl011"; reg = <0x7e201a00 0x100>; status = "disabled"; };
	};
};
EOF
dtc -@ -I dts -O dtb -o "${WORK}/base-sym.dtb" "${WORK}/base.dts" 2>/dev/null
dtc -I dts -O dtb -o "${WORK}/base-nosym.dtb" "${WORK}/base.dts" 2>/dev/null

# A stand-in for the revpi-connect4 overlay, assembled from the parts the gate
# checks; a variant leaves one out or breaks one.
overlay_root='	fragment@0 { target-path = "/"; __overlay__ {
		compatible = "kunbus,revpi-connect4", "brcm,bcm2711";
		pibridge { compatible = "kunbus,pibridge"; connect-gpios = <&gpio 6 0>, <&gpio 16 0>; };
		leds {
			power_red { label = "power:1:fault"; };
			a1_green { label = "a1:green:status"; };
			a5_blue { label = "a5:blue:status"; };
		};
	}; };'
overlay_i2c='	fragment@1 { target = <&i2c1>; __overlay__ {
		status = "okay";
		gpio@21 { compatible = "nxp,pcal6416"; reg = <0x21>; };
		gpio@22 { compatible = "nxp,pcal6524"; reg = <0x22>; };
		rtc@51 { compatible = "nxp,pcf2129"; reg = <0x51>; status = "okay"; reset-source; };
	}; };'
overlay_spi='	fragment@2 { target = <&spi1>; __overlay__ {
		status = "okay";
		tpm: tpm@0 { compatible = "infineon,slb9670"; reg = <0>; status = "okay"; };
	}; };'
overlay_uart5='	fragment@3 { target = <&uart5>; __overlay__ { status = "okay"; linux,rs485-enabled-at-boot-time; }; };'
overlay_uart3='	fragment@4 { target = <&uart3>; __overlay__ { status = "okay"; pi_bridge { compatible = "kunbus,pi-bridge"; }; }; };'

write_overlay() { # <out.dtbo> <part>...
    local out="$1"
    shift
    {
        printf '/dts-v1/;\n/plugin/;\n/ {\n\tcompatible = "brcm,bcm2711";\n'
        printf '%s\n' "$@"
        printf '};\n'
    } > "${WORK}/ov.dts"
    dtc -@ -I dts -O dtb -o "${out}" "${WORK}/ov.dts" 2>/dev/null
}

new_bin() { # <name> <base.dtb> [overlay.dtbo]: a BINARIES_DIR of the board
    local d="${WORK}/$1"
    rm -rf "${d}"
    mkdir -p "${d}"
    cp "$2" "${d}/$(conf_get BOARD_BASE_DTB)"
    if [ -n "${3:-}" ]; then cp "$3" "${d}/$(conf_get BOARD_DT_OVERLAYS)"; fi
    printf '%s' "${d}"
}

expect_dtb_fail() { # <label> <pattern> <bindir> [board_dir]
    local out
    if out="$(bash "${PA}" arm-board-dtb "$3" "${4:-${BOARD}}" 2>&1)"; then
        fail "$1: the device-tree gate accepted it"
    fi
    grep -qF -- "$2" <<<"${out}" || {
        echo "${out}" >&2
        fail "$1: the gate failed without saying '$2'"
    }
    echo "  rejects: $1"
}

write_overlay "${WORK}/full.dtbo" "${overlay_root}" "${overlay_i2c}" "${overlay_spi}" "${overlay_uart5}" "${overlay_uart3}"
bin_ok="$(new_bin ok "${WORK}/base-sym.dtb" "${WORK}/full.dtbo")"
bash "${PA}" arm-board-dtb "${bin_ok}" "${BOARD}" >/dev/null || fail "the complete stand-in overlay was rejected"
[ "$(fdtget -t s "${bin_ok}/${final}" / compatible)" = "kunbus,revpi-connect4 brcm,bcm2711" ] || fail "the merged tree does not carry the board's compatible"
[ "$(fdtget -t s "${bin_ok}/${final}" "$(fdtget -t s "${bin_ok}/${final}" /__symbols__ tpm)" compatible)" = "infineon,slb9670" ] || fail "the merged tree has no TPM"
echo "  merges the overlay into the stock tree and enables the board's nodes"

overlay_spi_no_tpm='	fragment@2 { target = <&spi1>; __overlay__ { status = "okay"; }; };'
write_overlay "${WORK}/no-tpm.dtbo" "${overlay_root}" "${overlay_i2c}" "${overlay_spi_no_tpm}" "${overlay_uart5}" "${overlay_uart3}"
expect_dtb_fail "a merged tree without the SPI TPM node" "label tpm" "$(new_bin no-tpm "${WORK}/base-sym.dtb" "${WORK}/no-tpm.dtbo")"

write_overlay "${WORK}/tpm-off.dtbo" "${overlay_root}" "${overlay_i2c}" "${overlay_spi/tpm@0 \{ compatible = \"infineon,slb9670\"; reg = <0>; status = \"okay\";/tpm@0 \{ compatible = \"infineon,slb9670\"; reg = <0>; status = \"disabled\";}" "${overlay_uart5}" "${overlay_uart3}"
expect_dtb_fail "a TPM node that is disabled" "status is 'disabled', must be 'okay'" "$(new_bin tpm-off "${WORK}/base-sym.dtb" "${WORK}/tpm-off.dtbo")"

write_overlay "${WORK}/no-rs485.dtbo" "${overlay_root}" "${overlay_i2c}" "${overlay_spi}" "${overlay_uart5/linux,rs485-enabled-at-boot-time;/}" "${overlay_uart3}"
expect_dtb_fail "a UART5 without the RS485 flag" "has no property linux,rs485-enabled-at-boot-time" "$(new_bin no-rs485 "${WORK}/base-sym.dtb" "${WORK}/no-rs485.dtbo")"

write_overlay "${WORK}/no-reset.dtbo" "${overlay_root}" "${overlay_i2c/ reset-source;/}" "${overlay_spi}" "${overlay_uart5}" "${overlay_uart3}"
expect_dtb_fail "an RTC that is not a reset source" "has no property reset-source" "$(new_bin no-reset "${WORK}/base-sym.dtb" "${WORK}/no-reset.dtbo")"

write_overlay "${WORK}/no-pibridge.dtbo" "${overlay_root/pibridge \{ compatible = \"kunbus,pibridge\"; connect-gpios = <&gpio 6 0>, <&gpio 16 0>; \};/}" "${overlay_i2c}" "${overlay_spi}" "${overlay_uart5}" "${overlay_uart3}"
expect_dtb_fail "a tree without the PiBridge node" "/pibridge" "$(new_bin no-pibridge "${WORK}/base-sym.dtb" "${WORK}/no-pibridge.dtbo")"

write_overlay "${WORK}/no-compat.dtbo" "${overlay_root/compatible = \"kunbus,revpi-connect4\", \"brcm,bcm2711\";/}" "${overlay_i2c}" "${overlay_spi}" "${overlay_uart5}" "${overlay_uart3}"
expect_dtb_fail "a merged tree that is not identified as the Connect 4" "root compatible is 'raspberrypi,4-compute-module" "$(new_bin no-compat "${WORK}/base-sym.dtb" "${WORK}/no-compat.dtbo")"

expect_dtb_fail "a stock tree built without symbols (dtc -@)" "__symbols__" "$(new_bin nosym "${WORK}/base-nosym.dtb" "${WORK}/full.dtbo")"

bin_noov="$(new_bin missing-overlay "${WORK}/base-sym.dtb")"
expect_dtb_fail "a build that has no overlay to merge" "required file missing" "${bin_noov}"

# board-boot.conf is parsed strictly.
cp -r "${BOARD}" "${WORK}/board-bad"
printf 'BOARD_SURPRISE=1\n' >> "${WORK}/board-bad/board-boot.conf"
expect_dtb_fail "a board description with an unknown key" "unknown key BOARD_SURPRISE" "${bin_ok}" "${WORK}/board-bad"
cp "${BOARD}/board-boot.conf" "${WORK}/board-bad/board-boot.conf"
sed -i '/^BOARD_CONSOLE=/d' "${WORK}/board-bad/board-boot.conf"
expect_dtb_fail "a board description missing a key" "BOARD_CONSOLE is required" "${bin_ok}" "${WORK}/board-bad"
cp "${BOARD}/board-boot.conf" "${WORK}/board-bad/board-boot.conf"
sed -i 's/^BOARD_CONSOLE=.*/BOARD_CONSOLE=ttyS0;rm/' "${WORK}/board-bad/board-boot.conf"
expect_dtb_fail "a board description with a shell metacharacter" "outside [A-Za-z0-9._,:@+/ -]" "${bin_ok}" "${WORK}/board-bad"
rm "${WORK}/board-bad/board-boot.conf"
expect_dtb_fail "a board directory without board-boot.conf" "has no board-boot.conf" "${bin_ok}" "${WORK}/board-bad"

# --- the signed FIT ---------------------------------------------------------
KEYS="${WORK}/keys"
mkdir -p "${KEYS}"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEYS}/fit-signing.key" 2>/dev/null
openssl req -batch -new -x509 -key "${KEYS}/fit-signing.key" -days 30 \
    -out "${KEYS}/fit-signing.crt" -subj "/CN=Suderra CI FIT" 2>/dev/null

TGT="${WORK}/target"
mkdir -p "${TGT}/bin" "${TGT}/sbin" "${TGT}/lib"
for f in bin/busybox bin/mount bin/sleep sbin/blkid sbin/dmsetup sbin/switch_root; do
    printf 'x' > "${TGT}/${f}"
    chmod 0755 "${TGT}/${f}"
done
printf 'lib' > "${TGT}/lib/placeholder"

stage_fit_inputs() { # <bindir> <image bytes>
    head -c "$2" /dev/zero | tr '\0' 'K' > "$1/Image"
    dd if=/dev/zero of="$1/rootfs.ext4" bs=1M count=8 status=none
    mkfs.ext4 -q -F "$1/rootfs.ext4" 2>/dev/null
}

fit_args() { # <fit>: /chosen/bootargs of its (one) flat_dt image
    local fit="$1" idx=0 n
    for n in $(fdtget -l "${fit}" /images); do
        if [ "$(fdtget -t s "${fit}" "/images/${n}" type)" = flat_dt ]; then
            dumpimage -T flat_dt -p "${idx}" -o "${WORK}/args.dtb" "${fit}" >/dev/null
            fdtget -t s "${WORK}/args.dtb" /chosen bootargs
            return 0
        fi
        idx=$((idx + 1))
    done
    return 1
}

run_fit() { # <bindir> <board_dir>
    SUDERRA_FIT_KEYS_DIR="${KEYS}" SUDERRA_KEYS_DIR="${KEYS}" \
        bash "${PA}" arm-pre-genimage "$1" "${TGT}" "$2"
}

stage_fit_inputs "${bin_ok}" 65536
run_fit "${bin_ok}" "${BOARD}" >"${WORK}/fit.log" 2>&1 || { cat "${WORK}/fit.log" >&2; fail "the board FIT build failed"; }
for slot in A B; do
    fit="${bin_ok}/suderra-${slot}.fit"
    [ -s "${fit}" ] || fail "no suderra-${slot}.fit"
    [ "$(fdtget -l "${fit}" /configurations | wc -l)" = 1 ] || fail "slot ${slot}: the board FIT must have one configuration"
    [ "$(fdtget -t s "${fit}" /configurations default)" = "conf-revpi-connect4" ] || fail "slot ${slot}: default configuration"
    [ "$(fdtget -t s "${fit}" /configurations/conf-revpi-connect4 compatible)" = "kunbus,revpi-connect4 brcm,bcm2711" ] || fail "slot ${slot}: configuration compatible"
    listing="$(mkimage -l "${fit}" 2>/dev/null)"
    grep -qF 'Sign algo:    sha256,rsa2048:fit-signing (required)' <<<"${listing}" || fail "slot ${slot}: the configuration signature is not required"
    grep -qE 'FDT: +fdt-revpi-connect4' <<<"${listing}" || fail "slot ${slot}: the configuration does not boot the board's tree"
    if grep -qi 'cm4' <<<"$(fdtget -l "${fit}" /images)"; then fail "slot ${slot}: a raw CM4 tree is an image of the RevPi FIT"; fi
    # The command line is the /chosen/bootargs of the signed device tree: U-Boot
    # reads no bootargs property of a FIT configuration.
    if fdtget -p "${fit}" /configurations/conf-revpi-connect4 | grep -Fxq bootargs; then
        fail "slot ${slot}: the configuration has a bootargs property, which nothing reads"; fi
    args="$(fit_args "${fit}")"
    grep -qF 'console=ttyS0,115200' <<<"${args}" || fail "slot ${slot}: the console is the mini-UART (ttyS0)"
    grep -qF 'console=ttyAMA0' <<<"${args}" && fail "slot ${slot}: ttyAMA0 is not the Connect 4's console"
    grep -qF "rauc.slot=${slot}" <<<"${args}" || fail "slot ${slot}: bootargs lack rauc.slot"
    grep -qF 'suderra.verity.root_hash=' <<<"${args}" || fail "slot ${slot}: bootargs lack the verity root hash"
    if [ ! -s "${fit}.sig" ] || [ ! -s "${fit}.cert" ]; then fail "slot ${slot}: missing detached sidecars"; fi
done
for slot in A B; do
    grep -q "device tree of suderra-${slot}.fit: [0-9]* required nodes present" "${WORK}/fit.log" ||
        fail "the FIT build did not gate the device tree it put into suderra-${slot}.fit"
done
echo "  builds a signed one-configuration FIT around the merged tree"

# U-Boot's control FDT on this board is the stock tree the firmware loads: the
# keyed copy is there, the FIT verifies against it, the merged tree stays unkeyed.
base="$(conf_get BOARD_BASE_DTB)"
keyed="${bin_ok}/firmware-dtb/${base}"
[ -s "${keyed}" ] || fail "no keyed copy of ${base}"
[ "$(fdtget -t s "${keyed}" /signature/key-fit-signing required)" = conf ] || fail "the keyed ${base} does not require the FIT key"
for slot in A B; do
    fit_check_sign -f "${bin_ok}/suderra-${slot}.fit" -k "${keyed}" >/dev/null 2>&1 ||
        fail "slot ${slot} does not verify against the key in ${base}"
done
fdtget -l "${bin_ok}/${final}" / | grep -Fxq signature && fail "the merged tree ${final} carries the verification key"
echo "  keys the stock tree the firmware loads and verifies both slots against it"

bash "${PA}" arm-fit-gate "${bin_ok}/suderra-A.fit" "${bin_ok}" "${BOARD}" >/dev/null || fail "arm-fit-gate rejected the FIT it built"

# The FIT gate judges what the FIT carries.
cp -r "${BOARD}" "${WORK}/board-strict"
printf 'label:i2c1/rtc@99 compatible nxp,pcf2129\n' >> "${WORK}/board-strict/dt-required.txt"
if out="$(bash "${PA}" arm-fit-gate "${bin_ok}/suderra-A.fit" "${bin_ok}" "${WORK}/board-strict" 2>&1)"; then
    fail "the FIT gate accepted a FIT whose tree lacks a required node"
fi
grep -qF 'rtc@99' <<<"${out}" || fail "the FIT gate failed without naming the missing node"
echo "  rejects: a FIT whose tree lacks a required node"

cp "${bin_ok}/${final}" "${WORK}/final.good"
cp "${WORK}/base-sym.dtb" "${bin_ok}/${final}"
if out="$(bash "${PA}" arm-fit-gate "${bin_ok}/suderra-A.fit" "${bin_ok}" "${BOARD}" 2>&1)"; then
    fail "the FIT gate accepted a FIT whose tree is not the merged tree"
fi
grep -qF 'is not' <<<"${out}" || fail "the FIT gate failed without saying the tree differs"
cp "${WORK}/final.good" "${bin_ok}/${final}"
echo "  rejects: a FIT whose tree is not the merged tree"

# A FIT with a second configuration is not the board's FIT.
cp "${bin_ok}/suderra-A.fit" "${WORK}/two.fit"
printf '/dts-v1/; / { };' > "${WORK}/x.dts"
python3 -I - "${bin_ok}/suderra-A.its" "${WORK}/two.its" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
extra = '''        conf-extra {
            description = "extra"; compatible = "kunbus,revpi-connect4";
            kernel = "kernel"; fdt = "fdt-revpi-connect4"; ramdisk = "ramdisk-1";
        };
'''
t = t.replace("    };\n};\n", extra + "    };\n};\n") if "conf-extra" not in t else t
open(sys.argv[2], "w").write(t)
PY
mkimage -f "${WORK}/two.its" "${WORK}/two.fit" >/dev/null 2>&1 || fail "could not build the two-configuration FIT of the test"
if out="$(bash "${PA}" arm-fit-gate "${WORK}/two.fit" "${bin_ok}" "${BOARD}" 2>&1)"; then
    fail "the FIT gate accepted a FIT with two configurations"
fi
grep -qF 'has 2 configurations' <<<"${out}" || fail "the FIT gate failed without counting the configurations"
echo "  rejects: a FIT with a second configuration"

# U-Boot copies the kernel out of the FIT's own load area: a kernel larger than
# the gap between fitaddr (board/suderra/uboot/suderra.env) and its load address
# overwrites the FIT.
bin_big="$(new_bin big "${WORK}/base-sym.dtb" "${WORK}/full.dtbo")"
stage_fit_inputs "${bin_big}" 34000000
if out="$(run_fit "${bin_big}" "${BOARD}" 2>&1)"; then
    fail "a kernel larger than the FIT's load window was accepted"
fi
grep -qF 'fit between fitaddr' <<<"${out}" || { echo "${out}" >&2; fail "the oversized kernel failed without the window message"; }
echo "  rejects: a kernel larger than the window between fitaddr and its load address"

# A board without a board-boot.conf keeps the generic producer: one signed
# configuration per stock tree (the rpi4 images).
bin_gen="${WORK}/generic"
mkdir -p "${bin_gen}"
cp "${WORK}/base-sym.dtb" "${bin_gen}/bcm2711-rpi-cm4.dtb"
stage_fit_inputs "${bin_gen}" 4096
SUDERRA_FIT_KEYS_DIR="${KEYS}" SUDERRA_KEYS_DIR="${KEYS}" \
    bash "${PA}" arm-pre-genimage "${bin_gen}" "${TGT}" "${ROOT}/board/suderra/aarch64-rpi4" >/dev/null 2>&1 ||
    fail "the generic ARM FIT producer broke for a board without board-boot.conf"
[ "$(fdtget -t s "${bin_gen}/suderra-A.fit" /configurations default)" = "conf-bcm2711-rpi-cm4" ] || fail "the generic producer's configuration naming changed"
echo "  leaves the generic ARM producer untouched"

echo "revpi board contract passed"

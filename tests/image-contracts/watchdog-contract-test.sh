#!/usr/bin/env bash
#
# The hardware watchdog of every Suderra OS image (ADR-048 DEC-6.6, EI-033).
#
# systemd PID1 is the only owner of the hardware watchdog: the image's
# system.conf.d drop-in names /dev/suderra-watchdog and the timeouts, and its udev
# rule links that name to the board's own timer by the identity the driver
# reports in sysfs. Nothing else may open the device, and a production kernel
# cannot be told to let go of it.
#
# scripts/ci/board-watchdog.py holds every key (board profile or pending
# board family) and every image to that statement. This test runs it over the
# repository, parses every rule with udev's own parser (udevadm verify: a rule
# the daemon would drop leaves the board without a watchdog and without a
# message), executes the installer post-build.sh calls for every defconfig, and
# proves on a scratch copy of the tree that the checker fails for each class of
# defect it exists to catch. What a rule file cannot show is what a real board's
# drivers report and when they probe: that is the hardware check
# (docs/operations/watchdog.md), not this test.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/scripts/ci/board-watchdog.py"
DIR="board/suderra/watchdog"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECK}" ] || fail "missing ${CHECK}"
command -v udevadm >/dev/null 2>&1 || {
    echo "SKIP: udevadm is missing (apt: udev)" >&2
    exit 77
}

# 1. The repository itself.
python3 -I "${CHECK}" --root "${ROOT}" check

# 2. udev parses every rule, and rejects a rule that is not one.
for rules in "${ROOT}/${DIR}"/*/60-suderra-watchdog.rules; do
    out="$(udevadm verify "${rules}" 2>&1)" || {
        echo "${out}" >&2
        fail "udevadm verify rejects ${rules#"${ROOT}"/}"
    }
done
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
printf 'SUBSYSTEM=="watchdog", ATTR{identity}="x" SYMLINK+="suderra-watchdog"\n' >"${WORK}/bad.rules"
if udevadm verify "${WORK}/bad.rules" >/dev/null 2>&1; then
    fail "udevadm verify accepted a malformed rule: it cannot stand for udev's parser"
fi
echo "  udev parses every rule of every board"

# 3. post-build.sh installs the image's own pair, through the call it makes.
grep -qF 'board-watchdog.py" \
    --root "${SUDERRA_EXTERNAL_DIR}" install \
    --defconfig "${DEFCONFIG_NAME}_defconfig" --target "${TARGET_DIR}"' \
    "${ROOT}/board/suderra/common/post-build.sh" ||
    fail "post-build.sh must run board-watchdog.py --root <external> install --defconfig <name>_defconfig --target <rootfs>"
for defconfig in "${ROOT}"/configs/*_defconfig; do
    name="$(basename "${defconfig}")"
    target="${WORK}/target-${name}"
    mkdir -p "${target}"
    key="$(python3 -I "${CHECK}" --root "${ROOT}" install --defconfig "${name}" --target "${target}")"
    if [ "${key}" = "-" ]; then
        [ ! -e "${target}/etc/systemd/system.conf.d" ] && [ ! -e "${target}/usr/lib/udev/rules.d" ] ||
            fail "${name} has no watchdog key and still got files"
        case "${name}" in
            suderra_aarch64_rpi4_usb_installer_defconfig | suderra_aarch64_defconfig) ;;
            *) fail "${name} runs systemd on a board and has no watchdog key" ;;
        esac
        continue
    fi
    cmp -s "${ROOT}/${DIR}/${key}/10-suderra-watchdog.conf" "${target}/etc/systemd/system.conf.d/10-suderra-watchdog.conf" ||
        fail "${name}: the drop-in of ${key} was not installed byte for byte"
    cmp -s "${ROOT}/${DIR}/${key}/60-suderra-watchdog.rules" "${target}/usr/lib/udev/rules.d/60-suderra-watchdog.rules" ||
        fail "${name}: the rule of ${key} was not installed byte for byte"
    [ "$(find "${target}" -type f | wc -l)" -eq 2 ] || fail "${name}: the install wrote more than the pair"
    # post-build reruns on a filled target: the second run changes nothing.
    python3 -I "${CHECK}" --root "${ROOT}" install --defconfig "${name}" --target "${target}" >/dev/null
    [ "$(find "${target}" -type f | wc -l)" -eq 2 ] || fail "${name}: a rerun of the install duplicated files"
done
# A stale pair on an image that has no key is removed.
stale="${WORK}/stale"
mkdir -p "${stale}/etc/systemd/system.conf.d" "${stale}/usr/lib/udev/rules.d"
: >"${stale}/etc/systemd/system.conf.d/10-suderra-watchdog.conf"
: >"${stale}/usr/lib/udev/rules.d/60-suderra-watchdog.rules"
python3 -I "${CHECK}" --root "${ROOT}" install --defconfig suderra_aarch64_rpi4_usb_installer_defconfig \
    --target "${stale}" >/dev/null
[ "$(find "${stale}" -type f | wc -l)" -eq 0 ] || fail "a stale watchdog pair stayed on an image that has no key"
if python3 -I "${CHECK}" --root "${ROOT}" install --defconfig suderra_no_such_defconfig --target "${WORK}/none" 2>/dev/null; then
    fail "an unclassified defconfig was given a watchdog"
fi
echo "  post-build installs each image's own pair, once, and none where there is no board"

# 4. The checker rejects each defect class on a scratch copy of the tree.
fresh_copy() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree/contracts/suderra-edge/v1" "${WORK}/tree/configs" "${WORK}/tree/userspace" \
        "${WORK}/tree/scripts/ci" "${WORK}/tree/package"
    cp "${ROOT}"/configs/*_defconfig "${WORK}/tree/configs/"
    cp "${ROOT}/contracts/suderra-edge/v1/boards.json" "${WORK}/tree/contracts/suderra-edge/v1/"
    cp "${ROOT}/userspace/Cargo.toml" "${WORK}/tree/userspace/"
    cp "${ROOT}/scripts/ci/check-kernel-config.py" "${WORK}/tree/scripts/ci/"
    mkdir -p "${WORK}/tree/board/suderra/buildroot-hashes/linux"
    cp "${ROOT}/board/suderra/buildroot-hashes/linux/linux.hash" "${WORK}/tree/board/suderra/buildroot-hashes/linux/"
    (cd "${ROOT}" && find board -name '*.config' -exec cp --parents {} "${WORK}/tree" \;)
    cp -r "${ROOT}/${DIR}" "${WORK}/tree/${DIR}"
    mkdir -p "${WORK}/tree/board/suderra/common"
    cp "${ROOT}/board/suderra/common/post-build.sh" "${WORK}/tree/board/suderra/common/"
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
check_tree() { python3 -I "${CHECK}" --root "${WORK}/tree" check; }

fresh_copy
check_tree >/dev/null || fail "the scratch copy of the tree does not pass before mutation"

fresh_copy
sed -i 's#^WatchdogDevice=/dev/suderra-watchdog$#WatchdogDevice=/dev/watchdog0#' "${WORK}/tree/${DIR}/rpi4-cm4/10-suderra-watchdog.conf"
expect_fail "a drop-in that opens /dev/watchdog0, whichever driver probed first" "WatchdogDevice=/dev/watchdog0, must be /dev/suderra-watchdog" check_tree

fresh_copy
sed -i 's#^RuntimeWatchdogSec=10s$#RuntimeWatchdogSec=30s#' "${WORK}/tree/${DIR}/revpi-connect4/10-suderra-watchdog.conf"
expect_fail "a runtime timeout above the BCM2835's 15.999 s" "RuntimeWatchdogSec=30s must be at least 5s and below the hardware maximum 15.999s" check_tree

fresh_copy
sed -i 's#^RuntimeWatchdogSec=10s$#RuntimeWatchdogSec=1s#' "${WORK}/tree/${DIR}/rpi4-cm4/10-suderra-watchdog.conf"
expect_fail "a runtime timeout a loaded PID1 cannot feed" "RuntimeWatchdogSec=1s must be at least 5s" check_tree

fresh_copy
sed -i 's#^RuntimeWatchdogSec=30s$#RuntimeWatchdogSec=40s#' "${WORK}/tree/${DIR}/x86-ipc/10-suderra-watchdog.conf"
expect_fail "an x86 runtime timeout above the oldest iTCO's 37.8 s" "RuntimeWatchdogSec=40s must be at least 5s and below the hardware maximum 37.8s" check_tree

fresh_copy
sed -i '/^RebootWatchdogSec=/d' "${WORK}/tree/${DIR}/qemu-x86_64/10-suderra-watchdog.conf"
expect_fail "a drop-in without a reboot timeout" "sets \['RuntimeWatchdogSec', 'WatchdogDevice'\], must set" check_tree

fresh_copy
sed -i 's#^RebootWatchdogSec=2min$#RebootWatchdogSec=20min#' "${WORK}/tree/${DIR}/x86-ipc/10-suderra-watchdog.conf"
expect_fail "a reboot timeout of 20 minutes, beyond systemd's own default" "RebootWatchdogSec=1200s must exceed RuntimeWatchdogSec and not exceed" check_tree

fresh_copy
sed -i 's#^RebootWatchdogSec=2min$#RebootWatchdogSec=20s#' "${WORK}/tree/${DIR}/x86-ipc/10-suderra-watchdog.conf"
expect_fail "a reboot timeout shorter than the runtime one" "RebootWatchdogSec=20s must exceed RuntimeWatchdogSec" check_tree

fresh_copy
sed -i 's#^RebootWatchdogSec=2min$#RebootWatchdogSec=1h#' "${WORK}/tree/${DIR}/x86-ipc/10-suderra-watchdog.conf"
expect_fail "a time the checker does not read" "'1h' is not <n>s or <n>min" check_tree

fresh_copy
printf 'KExecWatchdogSec=30s\n' >>"${WORK}/tree/${DIR}/x86-ipc/10-suderra-watchdog.conf"
expect_fail "a drop-in that arms the watchdog for kexec, which no image has" "is not one of" check_tree

fresh_copy
sed -i 's#ATTR{identity}=="iTCO_wdt"#ATTR{identity}=="Software Watchdog"#' "${WORK}/tree/${DIR}/x86-ipc/60-suderra-watchdog.rules"
expect_fail "a rule that links the software watchdog" "links \['Software Watchdog'\], the board's watchdogs are \['iTCO_wdt'\]" check_tree

fresh_copy
sed -i 's#ATTR{identity}=="Broadcom BCM2835 Watchdog timer"#ATTR{identity}=="NXP PCF2127/PCF2129 Watchdog"#' "${WORK}/tree/${DIR}/revpi-connect4/60-suderra-watchdog.rules"
expect_fail "a RevPi rule for the PCF2129's watchdog nobody decided on" "links \['NXP PCF2127/PCF2129 Watchdog'\]" check_tree

fresh_copy
sed -i 's#SYMLINK+="suderra-watchdog"#SYMLINK+="watchdog"#' "${WORK}/tree/${DIR}/rpi4-cm4/60-suderra-watchdog.rules"
expect_fail "a rule that makes another link than the one PID1 opens" "not exactly: SUBSYSTEM" check_tree

fresh_copy
sed -i 's#^SUBSYSTEM=="watchdog", #SUBSYSTEM=="misc", #' "${WORK}/tree/${DIR}/rpi4-cm4/60-suderra-watchdog.rules"
expect_fail "a rule on the wrong subsystem" "not exactly: SUBSYSTEM" check_tree

fresh_copy
rm "${WORK}/tree/${DIR}/qemu-x86_64/60-suderra-watchdog.rules"
expect_fail "a key without its rule" "holds \['10-suderra-watchdog.conf'\], must hold exactly" check_tree

fresh_copy
rm -r "${WORK}/tree/${DIR}/revpi-connect4"
expect_fail "a board without a watchdog key" "board/suderra/watchdog holds" check_tree

fresh_copy
mkdir "${WORK}/tree/${DIR}/revpi-compact"
expect_fail "a key no image has" "board/suderra/watchdog holds" check_tree

fresh_copy
sed -i 's/"suderra-telemetry",/"suderra-telemetry",\n    "suderra-watchdog",/' "${WORK}/tree/userspace/Cargo.toml"
expect_fail "the second owner's crate back in the workspace" "userspace/suderra-watchdog exists" check_tree

fresh_copy
mkdir -p "${WORK}/tree/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service.d"
printf '[Service]\nDeviceAllow=/dev/watchdog rw\n' >"${WORK}/tree/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service.d/10-board-rpi4-cm4.conf"
expect_fail "a unit that may open the hardware watchdog" "a unit that may open the hardware watchdog" check_tree

fresh_copy
sed -i '/board-watchdog.py/d' "${WORK}/tree/board/suderra/common/post-build.sh"
expect_fail "post-build.sh that no longer installs the pair" "does not install the watchdog pair" check_tree

# An identity whose driver no kernel of the board builds in.
fresh_copy
sed -i 's/"watchdog-bcm2835",//' "${WORK}/tree/scripts/ci/check-kernel-config.py"
expect_fail "a board whose kernel does not build the driver its rule names" "lacks 'watchdog-bcm2835'" check_tree
echo "  rejects each class of watchdog defect"

echo "watchdog contract passed"

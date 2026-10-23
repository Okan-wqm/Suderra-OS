#!/usr/bin/env bash
#
# One board's bundle does not install on another board, with the real RAUC
# (ADR-048 DEC-8.3, EI-045).
#
# rauc-compatible-contract-test.sh holds the strings: one RAUC compatible per
# board, from boards.json, in the device's system.conf and in the bundle tool's
# argument. This test holds what RAUC does with them, end to end:
#
# 1. The bundle tool (scripts/create-rauc-bundle.sh) builds a signed bundle for
#    the compatible of every OTA-capable target of ci/evidence-contract.yml, and
#    `rauc info` reads that compatible back from the signed manifest. (RAUC 1.14,
#    the Buildroot pin, refuses an input manifest that names an image's size or
#    sha256, and the tool's EXIT trap used to make every successful build exit 1:
#    the tool had never run against the RAUC the images ship.)
# 2. RAUC, started with the device configuration post-build.sh renders for
#    every OTA-capable image (package/suderra-rauc-config/system.conf[.arm] with
#    the compatible scripts/ci/rauc-compatible.py takes from the OTA target
#    contract), reports exactly that compatible.
# 3. As root, `rauc install` of every board's bundle on every board's device
#    refuses the other boards' bundles with "Compatible mismatch" and gets past
#    the check for its own, where it then stops at the slot device that only a
#    real board has. The matrix asserts both directions, so a RAUC that always
#    refuses or always accepts fails it; a system.conf that carries a literal
#    compatible instead of the rendered one (the shared suderra-os-aarch64 of
#    EI-045) fails the rendering step.
#
# Part 3 installs plain-format bundles built here (not the tool's verity
# bundles): the compatible comparison is the same for both formats, and a verity
# bundle is mounted through device-mapper before RAUC reads its manifest, which
# a contract-test lane may not have. The device configuration is the real one
# with `bundle-formats=plain` and a test keyring and status file. The tool's
# verity bundles are covered by part 1 (the signature and the compatible).
#
# RAUC runs on a private D-Bus session bus (DBUS_STARTER_BUS_TYPE=session), as
# its own tests do. Part 3 needs root (loop mounts): the test elevates itself
# with `sudo -n` when it can and otherwise ends SKIPPED after parts 1 and 2.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

find_rauc() {
    if [ -n "${SUDERRA_RAUC:-}" ]; then
        printf '%s\n' "${SUDERRA_RAUC}"
    elif [ -n "${HOST_DIR:-}" ] && [ -x "${HOST_DIR}/bin/rauc" ]; then
        printf '%s\n' "${HOST_DIR}/bin/rauc"
    elif command -v rauc >/dev/null 2>&1; then
        command -v rauc
    fi
}

RAUC="$(find_rauc)"
if [ -z "${RAUC}" ] || [ ! -x "${RAUC}" ]; then
    echo "SKIP: rauc is missing (apt: rauc, or SUDERRA_RAUC=<path>)" >&2
    exit 77
fi
for tool in openssl python3 dbus-daemon; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "SKIP: ${tool} is missing" >&2
        exit 77
    }
done

ELEVATED=0
if [ "$(id -u)" -eq 0 ]; then
    ELEVATED=1
elif [ -z "${SUDERRA_RAUC_REFUSAL_NO_SUDO:-}" ] && sudo -n true 2>/dev/null; then
    exec sudo -n -E env "PATH=${PATH}" SUDERRA_RAUC="${RAUC}" bash "${BASH_SOURCE[0]}" "$@"
fi

WORK="$(mktemp -d)"
SERVICE_PID=""
BUS_PID=""
stop_service() {
    if [ -n "${SERVICE_PID}" ]; then
        kill "${SERVICE_PID}" 2>/dev/null || true
        wait "${SERVICE_PID}" 2>/dev/null || true
        SERVICE_PID=""
    fi
}
cleanup() {
    stop_service
    if [ -n "${BUS_PID}" ]; then
        kill "${BUS_PID}" 2>/dev/null || true
        wait "${BUS_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

# The OTA-capable targets: build target, defconfig, backend, compatible. The
# compatible is the one the image's own system.conf gets (rauc-compatible.py,
# which post-build.sh calls) and must equal the target contract's.
python3 -I - "${ROOT}" >"${WORK}/targets.tsv" <<'PY'
import json, subprocess, sys
root = sys.argv[1]
boards = json.load(open(f"{root}/contracts/suderra-edge/v1/boards.json", encoding="utf-8"))
contract = json.load(open(f"{root}/ci/evidence-contract.yml", encoding="utf-8"))
defconfigs = {}
for b in boards["boards"]:
    for i in b["os_images"]:
        defconfigs[i["build_target"]] = i["defconfig"]
for f in boards["pending_board_families"]:
    for i in f["os_images"]:
        defconfigs[i["build_target"]] = i["defconfig"]
rows = []
for target, t in sorted(contract["ota"]["targets"].items()):
    if not t["ota_capable"]:
        continue
    if t["backend"] not in ("grub-rauc", "uboot-rauc"):
        sys.exit(f"{target}: backend {t['backend']} is neither grub-rauc nor uboot-rauc")
    defconfig = defconfigs.get(target)
    if defconfig is None:
        sys.exit(f"{target}: boards.json has no image for it")
    rendered = subprocess.run(
        [sys.executable, "-I", f"{root}/scripts/ci/rauc-compatible.py", "--root", root, "image", defconfig],
        capture_output=True, text=True, check=True).stdout.strip()
    if rendered != t["compatible"]:
        sys.exit(f"{target}: post-build renders {rendered}, the target contract says {t['compatible']}")
    rows.append((target, defconfig, t["backend"], rendered))
print("\n".join("\t".join(r) for r in rows))
PY
mapfile -t TARGETS <"${WORK}/targets.tsv"
[ "${#TARGETS[@]}" -ge 4 ] || fail "only ${#TARGETS[@]} OTA-capable targets found, expected at least 4 (x86_64, qemu-x86_64-prod-ab, rpi4-prod-ab, revpi4-prod-ab)"
compat_of() { cut -f4 <<<"$1"; }
target_of() { cut -f1 <<<"$1"; }
backend_of() { cut -f3 <<<"$1"; }
[ "$(for row in "${TARGETS[@]}"; do compat_of "${row}"; done | sort -u | wc -l)" -eq "${#TARGETS[@]}" ] ||
    fail "two OTA targets share a RAUC compatible"

# A throwaway signer: the keyring of every device below is its certificate.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${WORK}/key.pem" -out "${WORK}/cert.pem" \
    -days 2 -subj "/O=Suderra OS test/CN=rauc test signer" 2>/dev/null
ART="${WORK}/artifacts"
mkdir -p "${ART}"
head -c 65536 /dev/urandom >"${ART}/rootfs.ext4"
head -c 16384 /dev/urandom >"${ART}/rootfs.verity"
for slot in A B; do
    echo "efi ${slot}" >"${ART}/suderra-${slot}.efi"
    echo "fit ${slot}" >"${ART}/suderra-${slot}.fit"
done

# 1. The tool's bundle of every target, read back by RAUC.
export SUDERRA_RAUC="${RAUC}" SUDERRA_RAUC_SIGNING_KEY="${WORK}/key.pem"
export SUDERRA_RAUC_SIGNING_CERT="${WORK}/cert.pem" SUDERRA_RAUC_KEYRING="${WORK}/cert.pem"
for row in "${TARGETS[@]}"; do
    target="$(target_of "${row}")"
    compat="$(compat_of "${row}")"
    flavour=x86
    [ "$(backend_of "${row}")" = uboot-rauc ] && flavour=arm
    bundle="${WORK}/${target}.raucb"
    # The tool's own stage directory lives in a TMPDIR of its own, which it
    # must leave empty (its EXIT trap used to find the variable gone).
    rm -rf "${WORK}/tool-tmp"
    mkdir "${WORK}/tool-tmp"
    TMPDIR="${WORK}/tool-tmp" "${ROOT}/scripts/create-rauc-bundle.sh" "${flavour}" "${ART}" 1.0.0 "${bundle}" "${compat}" >"${WORK}/bundle.log" 2>&1 ||
        { cat "${WORK}/bundle.log" >&2; fail "${target}: create-rauc-bundle.sh ${flavour} failed or exited non-zero after building"; }
    [ -z "$(ls -A "${WORK}/tool-tmp")" ] || fail "${target}: the bundle tool left its stage directory behind"
    info="$("${RAUC}" info --keyring="${WORK}/cert.pem" "${bundle}" 2>&1)" || { echo "${info}" >&2; fail "${target}: rauc info refused the bundle"; }
    grep -Eq "^Compatible: +'${compat}'\$" <<<"${info}" || { echo "${info}" >&2; fail "${target}: the signed manifest does not carry ${compat}"; }
    grep -Eq '^Bundle Format: +verity' <<<"${info}" || fail "${target}: the tool must build verity bundles"
done
echo "  the bundle tool builds a signed verity bundle for each of ${#TARGETS[@]} targets, with the target's compatible"

# A private D-Bus session bus; RAUC's service and client both use it.
dbus-daemon --session --nofork --address="unix:path=${WORK}/bus.sock" >"${WORK}/bus.log" 2>&1 &
BUS_PID=$!
export DBUS_SESSION_BUS_ADDRESS="unix:path=${WORK}/bus.sock" DBUS_STARTER_BUS_TYPE=session
for _ in $(seq 1 50); do
    [ -S "${WORK}/bus.sock" ] && break
    sleep 0.1
done
[ -S "${WORK}/bus.sock" ] || fail "the private D-Bus session bus did not come up"

# device_conf <target> <compatible> <bundle-formats> <out>: the image's system.conf as
# post-build.sh renders it, with the test's keyring and status file.
device_conf() {
    local flavour="$1" compat="$2" formats="$3" out="$4" source
    source="${ROOT}/package/suderra-rauc-config/system.conf"
    [ "${flavour}" = uboot-rauc ] && source="${ROOT}/package/suderra-rauc-config/system.conf.arm"
    sed -e "s#^compatible=@SUDERRA_RAUC_COMPATIBLE@\$#compatible=${compat}#" \
        -e "s#^bundle-formats=.*#bundle-formats=${formats}#" \
        -e "s#^statusfile=.*#statusfile=${WORK}/status.ini#" \
        -e "s#^path=/etc/rauc/keyring.pem\$#path=${WORK}/cert.pem#" "${source}" >"${out}"
    grep -qx "compatible=${compat}" "${out}" || fail "the rendered ${flavour} configuration lost its compatible"
}

# start_service <conf> <compatible>: the service reports the compatible of its
# configuration. It owns its bus name a moment before its properties are set,
# so a status read right then says "(null)": wait for the value, and a service
# that never reports the expected one fails here with what it did report.
start_service() {
    stop_service
    "${RAUC}" --conf="$1" --override-boot-slot=A service >"${WORK}/service.log" 2>&1 &
    SERVICE_PID=$!
    local tries=0
    until "${RAUC}" --conf="$1" status >"${WORK}/status.txt" 2>&1 &&
        grep -Eq "^Compatible: +$2\$" "${WORK}/status.txt"; do
        tries=$((tries + 1))
        if [ "${tries}" -ge 50 ]; then
            cat "${WORK}/service.log" "${WORK}/status.txt" >&2
            fail "RAUC does not report the compatible $2 for $1"
        fi
        sleep 0.2
    done
}

# 2. The device side: RAUC reports the compatible post-build renders.
for row in "${TARGETS[@]}"; do
    target="$(target_of "${row}")"
    compat="$(compat_of "${row}")"
    device_conf "$(backend_of "${row}")" "${compat}" verity "${WORK}/device-${target}.conf"
    start_service "${WORK}/device-${target}.conf" "${compat}"
done
stop_service
echo "  RAUC reports each image's rendered compatible"

if [ "${ELEVATED}" -ne 1 ]; then
    echo "SKIP: the install matrix needs root (sudo -n is not available): parts 1 and 2 passed" >&2
    exit 77
fi
losetup -f >/dev/null 2>&1 || {
    echo "SKIP: the install matrix needs a loop device: parts 1 and 2 passed" >&2
    exit 77
}

# 3. The install matrix, with plain bundles (see the header).
plain_bundle() {
    local compat="$1" out="$2" dir
    dir="$(mktemp -d "${WORK}/plain.XXXXXX")"
    cp "${ART}/rootfs.ext4" "${dir}/rootfs.img"
    printf '[update]\ncompatible=%s\nversion=1.0.0\n\n[bundle]\nformat=plain\n\n[image.rootfs]\nfilename=rootfs.img\n' "${compat}" >"${dir}/manifest.raucm"
    "${RAUC}" bundle --cert="${WORK}/cert.pem" --key="${WORK}/key.pem" "${dir}" "${out}" >/dev/null 2>&1 ||
        fail "rauc could not build the plain bundle for ${compat}"
}

# try_install <conf> <bundle>: RAUC's last error, in ${WORK}/install.txt.
try_install() {
    "${RAUC}" --conf="$1" install "$2" >"${WORK}/install.txt" 2>&1 && fail "installing $2 on $1 succeeded without a board"
    return 0
}

for row in "${TARGETS[@]}"; do
    plain_bundle "$(compat_of "${row}")" "${WORK}/plain-$(target_of "${row}").raucb"
done
refused=0
accepted=0
for device in "${TARGETS[@]}"; do
    dtarget="$(target_of "${device}")"
    dcompat="$(compat_of "${device}")"
    device_conf "$(backend_of "${device}")" "${dcompat}" plain "${WORK}/plain-device-${dtarget}.conf"
    start_service "${WORK}/plain-device-${dtarget}.conf" "${dcompat}"
    for bundle in "${TARGETS[@]}"; do
        btarget="$(target_of "${bundle}")"
        bcompat="$(compat_of "${bundle}")"
        try_install "${WORK}/plain-device-${dtarget}.conf" "${WORK}/plain-${btarget}.raucb"
        if [ "${bcompat}" = "${dcompat}" ]; then
            if grep -q 'Compatible mismatch' "${WORK}/install.txt"; then
                cat "${WORK}/install.txt" >&2
                fail "${dtarget} refused its own bundle for compatible ${dcompat}"
            fi
            # Past the check, it stops at what only a real board has.
            grep -q "Destination device '/run/suderra-os/disk/rootfs-[ab]' for slot 'rootfs.[01]' not found" "${WORK}/install.txt" || {
                cat "${WORK}/install.txt" >&2
                fail "${dtarget}: installing its own bundle stopped somewhere unexpected"
            }
            accepted=$((accepted + 1))
        else
            grep -q "Compatible mismatch: Expected '${dcompat}' but bundle manifest has '${bcompat}'" "${WORK}/install.txt" || {
                cat "${WORK}/install.txt" >&2
                fail "${dtarget} did not refuse the bundle of ${btarget} (${bcompat}) with a compatible mismatch"
            }
            refused=$((refused + 1))
        fi
    done
done
stop_service
echo "  on every device RAUC refuses the other ${refused} board bundles and passes its own ${accepted} the compatible check"

if losetup -a 2>/dev/null | grep -qF "${WORK}"; then
    fail "the install matrix left a loop device on its bundles"
fi
echo "rauc compatible refusal passed"

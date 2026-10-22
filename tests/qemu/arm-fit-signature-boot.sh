#!/usr/bin/env bash
#
# The production U-Boot boot chain, executed (ADR-048 DEC-18; EI-013, EI-034,
# EI-035, EI-036).
#
# A real U-Boot, built from the sources Buildroot pins with the fragment every
# production U-Boot merges (board/suderra/uboot/hardening.config) and the
# production default environment (board/suderra/uboot/suderra.env: the A/B slot
# choice, the key guard, the reset), boots on qemu-system-aarch64 -M virt. QEMU's
# -dtb plays the part of the Raspberry Pi firmware: it hands U-Boot a device tree,
# which is U-Boot's control FDT (OF_BOARD), and the build's key goes into it the
# way the image build puts it into the trees the firmware loads. The FIT, its
# keyed device tree, its verity-carrying kernel command line and the stub "kernel"
# are the production producer's output (scripts/production-artifacts.sh
# arm-pre-genimage), signed by a throw-away key.
#
# What it proves, one boot each:
#   - the signed FIT of the chosen slot boots, and the kernel receives the command
#     line that is in the signed device tree (verity root hash, lockdown), not the
#     one in the firmware's tree or in a stored environment;
#   - a control FDT without the FIT key (T88: U-Boot would accept ANY FIT) boots
#     nothing; the control run shows that the same U-Boot, built without the guard,
#     boots an unsigned FIT in exactly that case;
#   - a FIT with one flipped kernel byte, one flipped byte of the signed command
#     line, a signature by another key, no signature, or a legacy image format is
#     refused;
#   - every boot of a slot spends one try and saves it before the kernel starts:
#     a FIT that does not verify or does not load costs that one try, never the
#     slot (a factory board has no other slot), a slot that boots but never
#     reaches RAUC's mark-good (a kernel panic, a dm-verity restart) falls back
#     to the other slot after its tries, and a board with no try left is armed
#     again instead of staying down;
#   - a stored environment that sets bootcmd, bootargs, stdin or preboot changes
#     none of them, while BOOT_ORDER and the boot counters it carries apply, and
#     what U-Boot writes back holds the compiled-in values;
#   - a console full of keystrokes (Ctrl-C included) reaches no prompt, on a good
#     boot and on every refusal.
#
# What it cannot prove (hardware only): that the Pi firmware loads the keyed
# trees from the boot partition, that U-Boot's raw environment on the eMMC/SD
# survives a power cut, and the integrity of the boot partition itself, which
# is the board's secure boot (Raspberry Pi OTP), an operator action.
#
# Needs: qemu-system-aarch64, aarch64-linux-gnu-gcc, the U-Boot build tools
# (bison flex swig libssl-dev), dtc, mkfs.vfat + mtools, veritysetup, mke2fs,
# openssl, python3, network access for the U-Boot tarball (cached). Exits 77
# when a tool is missing, so a CI run fails instead of passing without a boot.
#
# Environment: SUDERRA_UBOOT_BUILD (reuse a build directory), SUDERRA_QEMU_WORK
# (keep the scratch directory).
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
UBOOT_BUILD_SH="${ROOT}/scripts/ci/uboot-build.sh"
PRODUCER="${ROOT}/scripts/production-artifacts.sh"
STUB_DIR="${ROOT}/tests/qemu/uboot"
PROD_ENV="${ROOT}/board/suderra/uboot/suderra.env"

# The two values of the production environment that are facts of the Pi (where
# the FIT is loaded in RAM, which device it is read from) and of the QEMU virt
# machine instead: its RAM starts at 0x40000000, its disk is a virtio device.
QEMU_FITADDR=0x44000000
QEMU_BOOTDEV="virtio 0:1"
KERNEL_LOAD=0x40080000
ENV_SIZE=0x4000    # CONFIG_ENV_SIZE of the QEMU build (and of the Pi's raw environment)
ENV_SECOND=0x20000 # CONFIG_ENV_ADDR_REDUND - CONFIG_ENV_ADDR: the second copy, one flash sector further

skip() {
    echo "SKIP: $*" >&2
    exit 77
}
fail() {
    echo "ERROR: $*" >&2
    exit 1
}
step() { echo "==> $*"; }
ok() { echo "  ok: $*"; }

for tool in qemu-system-aarch64 aarch64-linux-gnu-gcc aarch64-linux-gnu-objcopy dtc fdtget fdtput \
    mkfs.vfat mcopy veritysetup mke2fs openssl python3 bison flex swig patch curl make gcc; do
    command -v "${tool}" >/dev/null 2>&1 || skip "${tool} is not installed"
done

WORK="${SUDERRA_QEMU_WORK:-$(mktemp -d)}"
mkdir -p "${WORK}"
if [ -z "${SUDERRA_QEMU_WORK:-}" ]; then
    trap 'rm -rf "${WORK}"' EXIT
fi
BUILD="${SUDERRA_UBOOT_BUILD:-${WORK}/uboot}"
# U-Boot writes the machine's flash one word at a time (see qemu-arm64.config) and
# QEMU writes each word through to the backing file, so the flash images live
# in RAM when the host has a tmpfs: a saveenv takes seconds there and minutes on a
# slow disk.
FAST="${WORK}"
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    FAST="$(mktemp -d /dev/shm/suderra-qemu.XXXXXX)"
    trap 'rm -rf "${FAST}"; if [ -z "${SUDERRA_QEMU_WORK:-}" ]; then rm -rf "${WORK}"; fi' EXIT
fi

# ---------------------------------------------------------------------------
# Build: U-Boot (tools, QEMU U-Boot, control U-Boot), the stub kernel, the FIT
# ---------------------------------------------------------------------------
step "U-Boot host tools and QEMU U-Boot from the pinned sources"
bash "${UBOOT_BUILD_SH}" tools "${BUILD}" >/dev/null
export PATH="${BUILD}/bin:${PATH}"
command -v fit_check_sign >/dev/null || fail "no fit_check_sign after the tools build"

QENV="${WORK}/qemu.env"
sed -e "s/^fitaddr=.*/fitaddr=${QEMU_FITADDR}/" -e "s/^suderra_bootdev=.*/suderra_bootdev=${QEMU_BOOTDEV}/" \
    "${PROD_ENV}" > "${QENV}"
# The QEMU environment is the production file with those two values replaced and
# nothing else.
[ "$(diff <(cat "${PROD_ENV}") <(cat "${QENV}") | grep -c '^[<>]')" -eq 4 ] ||
    fail "the QEMU environment differs from ${PROD_ENV} in more than fitaddr and suderra_bootdev"
bash "${UBOOT_BUILD_SH}" qemu "${BUILD}" "${QENV}" >/dev/null
UBOOT="${BUILD}/qemu/u-boot.bin"

# The control U-Boot: the same build with the key guard replaced by "true".
CENV="${WORK}/control.env"
python3 -I - "${QENV}" "${CENV}" <<'EOF'
import re, sys
src = open(sys.argv[1]).read()
out = re.sub(r"suderra_guard=\\\n(?:[^\n]*\\\n)*[^\n]*\n", "suderra_guard=true\n", src, count=1)
assert out != src
open(sys.argv[2], "w").write(out)
EOF
bash "${UBOOT_BUILD_SH}" qemu "${BUILD}" "${CENV}" control >/dev/null
CONTROL_UBOOT="${BUILD}/qemu-control/u-boot.bin"
ok "U-Boot built with the production fragments; its resolved .config passes check-uboot-config.py"

step "stub kernel"
aarch64-linux-gnu-gcc -O2 -Wall -Wextra -ffreestanding -fno-pic -fno-stack-protector \
    -fno-asynchronous-unwind-tables -nostdlib -static -mgeneral-regs-only \
    -Wl,--build-id=none -Wl,--no-warn-rwx-segments -Wl,-T,"${STUB_DIR}/stub-kernel.lds" \
    -o "${WORK}/stub.elf" "${STUB_DIR}/stub-head.S" "${STUB_DIR}/stub-kernel.c"
aarch64-linux-gnu-objcopy -O binary "${WORK}/stub.elf" "${WORK}/Image"

QEMU_COMMON=(-M virt -cpu cortex-a72 -m 512 -display none -monitor none -serial stdio -no-reboot)
QEMU_DEVICES=(-device "virtio-blk-device,drive=d0")

step "the machine's device tree (U-Boot's control FDT, as the firmware would pass it)"
truncate -s 64M "${WORK}/dump-env.img"
truncate -s 1M "${WORK}/dump-disk.img"
qemu-system-aarch64 "${QEMU_COMMON[@]}" -machine virt,dumpdtb="${WORK}/virt-raw.dtb" \
    -drive if=pflash,format=raw,index=1,file="${WORK}/dump-env.img" \
    -drive file="${WORK}/dump-disk.img",if=none,id=d0,format=raw "${QEMU_DEVICES[@]}" >/dev/null 2>&1
dtc -I dtb -O dtb -o "${WORK}/virt.dtb" "${WORK}/virt-raw.dtb" 2>/dev/null
[ "$(fdtget -t s "${WORK}/virt.dtb" / compatible)" = linux,dummy-virt ] || fail "unexpected QEMU device tree"

# ---------------------------------------------------------------------------
# The production producer on synthetic inputs: FIT per slot, keyed device tree
# ---------------------------------------------------------------------------
make_inputs() { # <bin-dir> <target-dir>
    local bin="$1" tgt="$2" f
    rm -rf "${bin}" "${tgt}"
    mkdir -p "${bin}" "${tgt}/bin" "${tgt}/sbin" "${tgt}/lib"
    cp "${WORK}/Image" "${bin}/Image"
    cp "${WORK}/virt.dtb" "${bin}/virt.dtb"
    dd if=/dev/zero of="${bin}/rootfs.ext4" bs=1M count=8 status=none
    mke2fs -q -F -t ext4 "${bin}/rootfs.ext4"
    for f in bin/busybox bin/mount bin/sleep sbin/blkid sbin/dmsetup sbin/switch_root; do
        printf 'x' > "${tgt}/${f}"
        chmod 0755 "${tgt}/${f}"
    done
    printf 'lib' > "${tgt}/lib/placeholder"
}

make_keys() { # <dir>
    mkdir -p "$1"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1/fit-signing.key" 2>/dev/null
    openssl req -batch -new -x509 -key "$1/fit-signing.key" -days 30 -out "$1/fit-signing.crt" \
        -subj "/CN=Suderra QEMU test FIT" 2>/dev/null
}

produce() { # <bin-dir> <target-dir> <keys-dir>
    SUDERRA_FIT_KEYS_DIR="$3" SUDERRA_KEYS_DIR="$3" SUDERRA_FIT_KERNEL_LOAD="${KERNEL_LOAD}" \
        bash "${PRODUCER}" arm-pre-genimage "$1" "$2" >/dev/null
}

step "production producer: signed FITs, command line in the signed device tree, keyed firmware device tree"
BIN="${WORK}/bin"
make_keys "${WORK}/keys"
make_inputs "${BIN}" "${WORK}/target"
produce "${BIN}" "${WORK}/target" "${WORK}/keys"
KEYED_DTB="${BIN}/firmware-dtb/virt.dtb"
FIT_A="${BIN}/suderra-A.fit"
FIT_B="${BIN}/suderra-B.fit"
for f in "${KEYED_DTB}" "${FIT_A}" "${FIT_B}"; do [ -s "${f}" ] || fail "the producer left no ${f}"; done
CMDLINE_A="$(cat "${BIN}/suderra-A.cmdline")"
CMDLINE_B="$(cat "${BIN}/suderra-B.cmdline")"
[ "${CMDLINE_A}" != "${CMDLINE_B}" ] || fail "slot A and B have the same command line"
ok "slot commands: $(printf '%s' "${CMDLINE_A}" | grep -o 'suderra.verity.root_hash=[0-9a-f]\{8\}')... lockdown=confidentiality"

# Unkeyed control FDT, and one whose key is not required.
UNKEYED_DTB="${WORK}/unkeyed.dtb"
cp "${WORK}/virt.dtb" "${UNKEYED_DTB}"
OPTIONAL_DTB="${WORK}/optional-key.dtb"
cp "${KEYED_DTB}" "${OPTIONAL_DTB}"
fdtput -d "${OPTIONAL_DTB}" /signature/key-fit-signing required
# The firmware's own /chosen/bootargs, which U-Boot must never hand the kernel.
FIRMWARE_ARGS_DTB="${WORK}/keyed-firmware-bootargs.dtb"
cp "${KEYED_DTB}" "${FIRMWARE_ARGS_DTB}"
fdtput -c "${FIRMWARE_ARGS_DTB}" /chosen 2>/dev/null || true
fdtput -t s "${FIRMWARE_ARGS_DTB}" /chosen bootargs "firmware.evil=1 root=/dev/sda1 init=/bin/sh"

# ---------------------------------------------------------------------------
# The FITs an attacker could offer
# ---------------------------------------------------------------------------
flip() { # <in> <out> <needle-file-or-string> <offset-into-needle>
    python3 -I - "$@" <<'EOF'
import sys
src, dst, needle, off = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
data = bytearray(open(src, "rb").read())
n = open(needle, "rb").read(48) if needle.startswith("/") else needle.encode()
i = data.find(n)
assert i >= 0, "needle not in the FIT"
data[i + off] ^= 0x01
open(dst, "wb").write(data)
EOF
}

TAMPER_KERNEL="${WORK}/tamper-kernel.fit"
flip "${FIT_A}" "${TAMPER_KERNEL}" "${WORK}/Image" 100
TAMPER_ARGS="${WORK}/tamper-bootargs.fit"
flip "${FIT_A}" "${TAMPER_ARGS}" "suderra.verity.root_hash=" 28

step "a second producer run with another signing key"
make_keys "${WORK}/attacker-keys"
make_inputs "${WORK}/bin-attacker" "${WORK}/target-attacker"
produce "${WORK}/bin-attacker" "${WORK}/target-attacker" "${WORK}/attacker-keys"
RESIGNED="${WORK}/bin-attacker/suderra-A.fit"
cmp -s "${BIN}/firmware-dtb/virt.dtb" "${WORK}/bin-attacker/firmware-dtb/virt.dtb" &&
    fail "two different signing keys produced the same keyed device tree"

UNSIGNED="${WORK}/unsigned.fit"
python3 -I - "${BIN}/suderra-A.its" "${WORK}/unsigned.its" <<'EOF'
import re, sys
src = open(sys.argv[1]).read()
out = re.sub(r"\n\s*signature-1 \{[^}]*\};", "", src)
assert out != src and "signature-1" not in out
open(sys.argv[2], "w").write(out)
EOF
mkimage -f "${WORK}/unsigned.its" "${UNSIGNED}" >/dev/null
LEGACY="${WORK}/legacy.uimage"
mkimage -A arm64 -O linux -T kernel -C none -a "${KERNEL_LOAD}" -e "${KERNEL_LOAD}" -n legacy \
    -d "${WORK}/Image" "${LEGACY}" >/dev/null

# ---------------------------------------------------------------------------
# Boot helpers
# ---------------------------------------------------------------------------
make_disk() { # <out> <fit-A|-> <fit-B|->: "-" leaves that FIT off the boot partition
    local out="$1" fat="${WORK}/fat.$$.img"
    rm -f "${fat}"
    truncate -s 20M "${fat}"
    mkfs.vfat -F 16 "${fat}" >/dev/null
    [ "$2" = - ] || mcopy -i "${fat}" "$2" ::suderra-A.fit
    [ "$3" = - ] || mcopy -i "${fat}" "$3" ::suderra-B.fit
    python3 -I "${STUB_DIR}/mbr-disk.py" "${out}" "${fat}"
    rm -f "${fat}"
}

blank_env() { rm -f "$1"; truncate -s 64M "$1"; }

keys() { # keystrokes, Ctrl-C and Enter among them, as long as the machine runs
    while :; do
        printf '\r\003 q\r'
        sleep 0.05
    done
}

# run_qemu <label> <u-boot.bin> <control-dtb> <disk> <env-image>: boots, returns
# the log path in LOG. A run that does not stop on its own is a failure.
run_qemu() {
    local label="$1" uboot="$2" dtb="$3" disk="$4" envimg="$5" rc
    LOG="${WORK}/${label}.log"
    set +e
    timeout 240 qemu-system-aarch64 "${QEMU_COMMON[@]}" -bios "${uboot}" -dtb "${dtb}" \
        -drive if=pflash,format=raw,index=1,file="${envimg}" \
        -drive file="${disk}",if=none,id=d0,format=raw "${QEMU_DEVICES[@]}" \
        < <(keys) > "${LOG}" 2>&1
    rc=$?
    set -e
    [ "${rc}" -ne 124 ] || {
        tail -30 "${LOG}" >&2
        fail "${label}: QEMU did not stop within 240 s"
    }
    # No prompt on any run: nothing in the log is a console waiting for input.
    if grep -qE '^=> |Hit any key|autoboot' "${LOG}"; then
        tail -30 "${LOG}" >&2
        fail "${label}: U-Boot showed a prompt or an autoboot message"
    fi
}

log_has() { grep -qF -- "$1" "${LOG}"; }
expect_log() { log_has "$1" || { tail -40 "${LOG}" >&2; fail "${CURRENT}: the log lacks: $1"; }; }
refuse_log() { ! log_has "$1" || { tail -40 "${LOG}" >&2; fail "${CURRENT}: the log has: $1"; }; }
kernel_args() { sed -n 's/^SUDERRA-STUB: bootargs=\[\(.*\)\]\r\?$/\1/p' "${LOG}" | tr -d '\r'; }

expect_booted() { # <slot> <cmdline>
    expect_log "Suderra: booting slot $1"
    expect_log "SUDERRA-STUB: kernel started"
    [ "$(kernel_args)" = "$2" ] || {
        tail -40 "${LOG}" >&2
        fail "${CURRENT}: the kernel received [$(kernel_args)], not the signed [$2]"
    }
}
expect_refused() {
    refuse_log "SUDERRA-STUB: kernel started"
    refuse_log "Starting kernel"
    expect_log "resetting"
}

env_dump() { python3 -I "${STUB_DIR}/envimage.py" dump "$1" "${ENV_SIZE}" "${ENV_SECOND}"; }
# The value U-Boot compiles in for a variable: the file's lines joined the way
# U-Boot's Makefile joins them (comments dropped, a trailing backslash continues).
default_value() { # <env-file> <name>
    python3 -I - "$1" "$2" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
kept = [l for l in text.split("\n") if not l.startswith("#") and l != ""]
joined = re.sub(r"\\\n\s*", "", "\n".join(kept))
for entry in joined.split("\n"):
    name, _, value = entry.partition("=")
    if name == sys.argv[2]:
        print(value)
        break
else:
    raise SystemExit(f"{sys.argv[2]} is not in {sys.argv[1]}")
EOF
}
env_make() { # <out> NAME=VALUE...
    local out="$1"
    shift
    python3 -I "${STUB_DIR}/envimage.py" make "${out}" "${ENV_SIZE}" "${ENV_SECOND}" "$@"
}

DISK="${WORK}/disk.img"
ENVIMG="${FAST}/env.img"
CURRENT=""
SCENARIOS=0
scenario() { CURRENT="$1"; SCENARIOS=$((SCENARIOS + 1)); step "$1"; }

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
scenario "S1 the signed FIT of slot A boots; the kernel gets the signed command line; the boot spent one try and saved it"
make_disk "${DISK}" "${FIT_A}" "${FIT_B}"
blank_env "${ENVIMG}"
run_qemu s1 "${UBOOT}" "${FIRMWARE_ARGS_DTB}" "${DISK}" "${ENVIMG}"
expect_booted A "${CMDLINE_A}"
refuse_log "firmware.evil"
case "$(kernel_args)" in
    *suderra.verity.root_hash=*lockdown=confidentiality*) ok "the kernel command line carries the verity root hash and lockdown" ;;
    *) fail "the signed command line lacks the verity root hash or lockdown" ;;
esac
ok "the command line of the firmware's own /chosen/bootargs never reaches the kernel"
saved="$(env_dump "${ENVIMG}")"
grep -qx 'BOOT_A_LEFT=2' <<<"${saved}" || fail "the boot did not spend and save a try of slot A: $(grep BOOT_ <<<"${saved}")"
grep -qx 'BOOT_B_LEFT=0' <<<"${saved}" || fail "slot B (not in the factory image) has tries: $(grep BOOT_ <<<"${saved}")"
ok "the factory counters (A 3, B 0) became A 2 before the kernel started: a boot that never returns has counted"

scenario "S2 a control FDT without the FIT key boots nothing (T88)"
run_qemu s2 "${UBOOT}" "${UNKEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_log "Suderra: the control FDT carries no required FIT key"
expect_refused
ok "no key in the control FDT: refused, reset, no prompt"
run_qemu s2b "${UBOOT}" "${OPTIONAL_DTB}" "${DISK}" "${ENVIMG}"
expect_log "Suderra: the control FDT carries no required FIT key"
expect_refused
ok "a key that is not required = \"conf\": refused"

scenario "S3 the control run: without the guard, that same control FDT accepts an unsigned FIT"
make_disk "${WORK}/unsigned-disk.img" "${UNSIGNED}" "${UNSIGNED}"
run_qemu s3 "${CONTROL_UBOOT}" "${UNKEYED_DTB}" "${WORK}/unsigned-disk.img" "${ENVIMG}"
expect_log "SUDERRA-STUB: kernel started"
ok "control: U-Boot with no /signature node in its control FDT booted an unsigned FIT (the T88 hole is real)"
run_qemu s3b "${CONTROL_UBOOT}" "${KEYED_DTB}" "${WORK}/unsigned-disk.img" "${ENVIMG}"
refuse_log "SUDERRA-STUB: kernel started"
ok "control: with the key in the control FDT the same U-Boot refuses it (what the keyed trees are for)"

reject_fit() { # <label> <fit> <why>
    local label="$1" fit="$2" why="$3"
    make_disk "${WORK}/bad.img" "${fit}" "${FIT_B}"
    blank_env "${ENVIMG}"
    run_qemu "${label}" "${UBOOT}" "${KEYED_DTB}" "${WORK}/bad.img" "${ENVIMG}"
    expect_log "Suderra: booting slot A"
    expect_log "Suderra: slot A did not boot"
    expect_refused
    grep -qx 'BOOT_A_LEFT=2' <<<"$(env_dump "${ENVIMG}")" ||
        fail "${label}: the refused boot did not cost exactly one try of slot A: $(env_dump "${ENVIMG}" | grep BOOT_)"
    ok "${why}"
}

scenario "S4 FITs that must not boot"
reject_fit s4a "${TAMPER_KERNEL}" "one flipped kernel byte: refused"
reject_fit s4b "${TAMPER_ARGS}" "one flipped byte of the signed command line (the verity root hash): refused"
reject_fit s4c "${RESIGNED}" "a FIT signed by another key under the same key name: refused"
reject_fit s4d "${UNSIGNED}" "a FIT with no signature (required = \"conf\"): refused"
reject_fit s4e "${LEGACY}" "a legacy uImage in the FIT's place (no legacy image format in this U-Boot): refused"

scenario "S5 a FIT that does not verify costs one try per boot; when its tries are gone the other slot boots"
make_disk "${DISK}" "${FIT_A}" "${TAMPER_KERNEL}"
env_make "${ENVIMG}" "BOOT_ORDER=B A" "BOOT_A_LEFT=3" "BOOT_B_LEFT=2"
run_qemu s5a "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_log "Suderra: booting slot B"
expect_log "Suderra: slot B did not boot"
expect_refused
saved="$(env_dump "${ENVIMG}")"
grep -qx 'BOOT_B_LEFT=1' <<<"${saved}" || fail "the failed boot of slot B did not cost exactly one try: $(grep BOOT_ <<<"${saved}")"
grep -qx 'BOOT_A_LEFT=3' <<<"${saved}" || fail "the failed boot of slot B touched slot A: $(grep BOOT_ <<<"${saved}")"
grep -qx 'BOOT_ORDER=B A' <<<"${saved}" || fail "BOOT_ORDER changed"
ok "slot B (2 tries) did not verify: it has 1 left, slot A is untouched"
run_qemu s5b "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_log "Suderra: booting slot B"
expect_refused
grep -qx 'BOOT_B_LEFT=0' <<<"$(env_dump "${ENVIMG}")" || fail "the second failed boot of slot B left tries: $(env_dump "${ENVIMG}" | grep BOOT_)"
ok "the next boot tried slot B again (its last try) and refused it again"
run_qemu s5c "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_booted A "${CMDLINE_A}"
grep -qx 'BOOT_A_LEFT=2' <<<"$(env_dump "${ENVIMG}")" || fail "the fallback boot of slot A did not spend a try: $(env_dump "${ENVIMG}" | grep BOOT_)"
ok "with slot B out of tries the next boot took slot A and booted it"

scenario "S6 the factory counters: one failed boot of the only slot is followed by a good boot (a transient load failure must not end the board)"
make_disk "${DISK}" - "${FIT_B}"
blank_env "${ENVIMG}"
run_qemu s6a "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_log "Suderra: booting slot A"
expect_log "Suderra: slot A did not boot"
expect_refused
saved="$(env_dump "${ENVIMG}")"
grep -qx 'BOOT_A_LEFT=2' <<<"${saved}" || fail "the unloadable FIT did not cost exactly one try: $(grep BOOT_ <<<"${saved}")"
ok "boot 1: the FIT of slot A could not be loaded; slot A kept 2 of its 3 tries (the board was not ended)"
make_disk "${DISK}" "${FIT_A}" "${FIT_B}"
run_qemu s6b "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
refuse_log "no slot with tries left"
expect_booted A "${CMDLINE_A}"
ok "boot 2, healthy disk: slot A booted (the review's reproduction: it used to be 'no slot with tries left' for ever)"

scenario "S7 a slot that boots but never reaches mark-good (a panic, a dm-verity restart) falls back after its tries"
make_disk "${DISK}" "${FIT_A}" "${FIT_B}"
env_make "${ENVIMG}" "BOOT_ORDER=A B" "BOOT_A_LEFT=3" "BOOT_B_LEFT=3"
for n in 1 2 3; do
    run_qemu "s7a${n}" "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
    expect_booted A "${CMDLINE_A}"
    grep -qx "BOOT_A_LEFT=$((3 - n))" <<<"$(env_dump "${ENVIMG}")" ||
        fail "boot ${n} of slot A did not leave $((3 - n)) tries: $(env_dump "${ENVIMG}" | grep BOOT_)"
done
ok "slot A, confirmed (3 tries), booted three times without mark-good: its tries are 0"
run_qemu s7b "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_booted B "${CMDLINE_B}"
grep -qx 'BOOT_B_LEFT=2' <<<"$(env_dump "${ENVIMG}")" || fail "the fallback boot of slot B did not spend a try: $(env_dump "${ENVIMG}" | grep BOOT_)"
ok "the fourth boot took slot B: a confirmed slot that keeps restarting no longer loops for ever"

scenario "S8 a stored environment cannot set bootcmd, bootargs, stdin or preboot; the boot counters it carries apply"
make_disk "${DISK}" "${FIT_A}" "${FIT_B}"
env_make "${ENVIMG}" \
    "bootcmd=echo ENV-BOOTCMD-RAN; setenv stdin serial; sleep 1; reset" \
    "bootargs=stored.evil=1 init=/bin/sh" "stdin=serial" "preboot=echo ENV-PREBOOT-RAN" \
    "bootdelay=5" "altbootcmd=echo ENV-ALT" "BOOT_ORDER=B A" "BOOT_A_LEFT=3" "BOOT_B_LEFT=2"
run_qemu s6 "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
refuse_log "ENV-BOOTCMD-RAN"
refuse_log "ENV-PREBOOT-RAN"
refuse_log "ENV-ALT"
refuse_log "stored.evil"
expect_booted B "${CMDLINE_B}"
ok "stored bootcmd, preboot, altbootcmd, bootargs, stdin and bootdelay were ignored; BOOT_ORDER=B A took effect"
saved="$(env_dump "${ENVIMG}")"
grep -qx 'BOOT_B_LEFT=1' <<<"${saved}" || fail "a trial boot of slot B did not spend a try: $(grep BOOT_ <<<"${saved}")"
ok "the trial boot of slot B spent one try and saved it (BOOT_B_LEFT=2 -> 1)"
[ "$(sed -n 's/^bootcmd=//p' <<<"${saved}")" = "$(default_value "${QENV}" bootcmd)" ] ||
    fail "the saved environment's bootcmd is not the compiled-in one"
for name in bootargs preboot altbootcmd; do
    ! grep -q "^${name}=" <<<"${saved}" || fail "the saved environment carries ${name}"
done
grep -qx 'stdin=nulldev' <<<"${saved}" || fail "the saved environment's stdin is not the null device"
grep -qx 'bootdelay=-2' <<<"${saved}" || fail "the saved environment's bootdelay is not the compiled-in -2"
ok "what U-Boot wrote back holds the compiled-in bootcmd and none of the stored attacker variables"

scenario "S9 no slot has a try left: both are armed again and the board resets, never a prompt, never down for good"
env_make "${ENVIMG}" "BOOT_ORDER=A B" "BOOT_A_LEFT=0" "BOOT_B_LEFT=0"
run_qemu s9a "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_log "Suderra: no slot with tries left in BOOT_ORDER"
expect_refused
saved="$(env_dump "${ENVIMG}")"
grep -qx 'BOOT_A_LEFT=3' <<<"${saved}" || fail "slot A was not armed again: $(grep BOOT_ <<<"${saved}")"
grep -qx 'BOOT_B_LEFT=3' <<<"${saved}" || fail "slot B was not armed again: $(grep BOOT_ <<<"${saved}")"
grep -qx 'BOOT_ORDER=A B' <<<"${saved}" || fail "BOOT_ORDER changed"
ok "no slot with tries left: both armed with 3, saved, reset, no prompt"
run_qemu s9b "${UBOOT}" "${KEYED_DTB}" "${DISK}" "${ENVIMG}"
expect_booted A "${CMDLINE_A}"
ok "the next boot took slot A"

echo "ARM boot-chain test passed (${SCENARIOS} scenarios; set SUDERRA_QEMU_WORK to keep the QEMU logs)"

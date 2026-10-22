#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Hardware checks of a Revolution Pi Connect 4 running a Suderra OS revpi4 image
# (docs/hardware/revpi-connect4.md section 6). Run it on the device as root; it
# only reads the kernel's views of the hardware (and, with --try-unsigned-insmod,
# tries one module load that must be refused). For every check it writes an
# evidence file and a record of the shape scripts/evidence/suderra-lab.py takes
# (devices[].checks.<name>: path, status, command, expected, observed), so an
# operator copies the results into the lab input instead of retyping them.
#
#   revpi-connect4-board-checks.sh --out DIR [--variant prod|dev]
#       [--try-unsigned-insmod] [--root DIR] [--insmod PROGRAM]
#
# --root runs the same checks on a directory laid out like the device's /proc,
# /sys, /dev and /etc, which is how tests/image-contracts/
# revpi-board-checks-contract-test.sh runs them without hardware. Outside a
# --root, /dev/piControl0 must be a character device; inside one it only has to
# exist (a test directory cannot mknod).
#
# Not covered here, because they need wiring or a person at the board: the RS485
# loopback, the LEDs' look, the board reset by each watchdog, which Ethernet driver
# eth1 needs, U-Boot rejecting a tampered FIT (docs/hardware/revpi-connect4.md
# section 6).
#
# Output: DIR/<check>.txt per check and DIR/checks.json. Exit status 0 when every
# check passed, 1 otherwise, 2 for a usage error. POSIX sh: the image has busybox.

set -eu

usage() {
    echo "usage: $0 --out DIR [--variant prod|dev] [--try-unsigned-insmod] [--root DIR] [--insmod PROGRAM]" >&2
}

ROOT=""
OUT=""
VARIANT="prod"
TRY_INSMOD=0
INSMOD="insmod"

while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT="${2:?--root needs a directory}"; shift 2 ;;
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        --variant) VARIANT="${2:?--variant needs prod or dev}"; shift 2 ;;
        --try-unsigned-insmod) TRY_INSMOD=1; shift ;;
        --insmod) INSMOD="${2:?--insmod needs a program}"; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
[ -n "${OUT}" ] || { usage; exit 2; }
case "${VARIANT}" in prod | dev) ;; *) usage; exit 2 ;; esac

mkdir -p "${OUT}"
JSON=""
FAILED=0

# jesc: a JSON string body (backslash, quote, newlines and tabs flattened).
jesc() {
    printf '%s' "$1" | tr '\n\t' '  ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# record <check> <status> <command> <expected> <observed>
record() {
    printf 'check:    %s\nstatus:   %s\ncommand:  %s\nexpected: %s\nobserved: %s\n' \
        "$1" "$2" "$3" "$4" "$5" > "${OUT}/$1.txt"
    entry="\"$1\": {\"path\": \"$1.txt\", \"status\": \"$2\", \"command\": \"$(jesc "$3")\", \"expected\": \"$(jesc "$4")\", \"observed\": \"$(jesc "$5")\"}"
    if [ -n "${JSON}" ]; then JSON="${JSON}, ${entry}"; else JSON="${entry}"; fi
    if [ "$2" = passed ]; then
        echo "PASS $1"
    else
        echo "FAIL $1: $5"
        FAILED=1
    fi
}

read_first() { # <file>: the first line, or nothing
    if [ -r "$1" ]; then head -n 1 "$1" 2>/dev/null || true; fi
}

# char_device <path>: a character device on the device, an existing node in a --root.
char_device() {
    if [ -n "${ROOT}" ]; then [ -e "$1" ]; else [ -c "$1" ]; fi
}

# strip_module_signature <module.ko> <out.ko>: the module without its appended
# signature, i.e. the same module as an unsigned build would have produced. The
# appended layout is  module | signature | struct module_signature (12 bytes, the
# big-endian signature length in its last four) | "~Module signature appended~\n"
# (28 bytes); a PKCS#7 signature has no signer name or key id (both lengths 0).
strip_module_signature() {
    marker='~Module signature appended~'
    size="$(wc -c < "$1")"
    [ "${size}" -gt 40 ] || return 1
    [ "$(tail -c 28 "$1" | head -c 27)" = "${marker}" ] || return 1
    # struct module_signature: algo hash id_type signer_len key_id_len pad[3] sig_len
    # becomes $3..$14 (the positions above 9 need braces).
    # shellcheck disable=SC2046
    set -- "$1" "$2" $(od -An -tu1 -j "$((size - 28 - 12))" -N 12 "$1")
    [ "$6" = 0 ] && [ "$7" = 0 ] || return 1
    sig_len=$((${11} * 16777216 + ${12} * 65536 + ${13} * 256 + ${14}))
    body=$((size - 28 - 12 - sig_len))
    [ "${body}" -gt 0 ] || return 1
    head -c "${body}" "$1" > "$2"
}

# --- board-identity: the signed image's board, and the device tree agrees --------
check_board_identity() {
    profile="$(sed -n 's/^BOARD_PROFILE=//p' "${ROOT}/etc/suderra/board" 2>/dev/null | head -n 1)"
    compat="$(tr '\0' ' ' < "${ROOT}/proc/device-tree/compatible" 2>/dev/null || true)"
    status=failed
    case " ${compat}" in
        *" kunbus,revpi-connect4 "*) [ "${profile}" = revpi-connect4 ] && status=passed ;;
    esac
    record board-identity "${status}" \
        "sed /etc/suderra/board; tr '\\0' ' ' < /proc/device-tree/compatible" \
        "BOARD_PROFILE=revpi-connect4 and device-tree compatible kunbus,revpi-connect4" \
        "BOARD_PROFILE=${profile:-none}; compatible=${compat:-none}"
}

# --- kernel: the pinned 6.12 line, real-time ---------------------------------
check_kernel() {
    rel="$(read_first "${ROOT}/proc/sys/kernel/osrelease")"
    ver="$(read_first "${ROOT}/proc/version")"
    status=failed
    case "${rel}" in
        6.12.*-v8) case "${ver}" in *PREEMPT_RT*) status=passed ;; esac ;;
    esac
    record kernel "${status}" "cat /proc/sys/kernel/osrelease /proc/version" \
        "a 6.12.<n>-v8 PREEMPT_RT kernel (KUNBUS revpi-6.12)" \
        "osrelease=${rel:-none}; version=${ver:-none}"
}

# --- revpi-io: piControl is loaded and /dev/piControl0 exists ----------------
check_revpi_io() {
    status=failed
    detail="no /dev/piControl0"
    if char_device "${ROOT}/dev/piControl0"; then
        detail="/dev/piControl0 present"
        if [ -d "${ROOT}/sys/module/piControl" ]; then
            status=passed
            detail="${detail}, module piControl loaded"
        else
            detail="${detail}, module piControl not loaded"
        fi
    fi
    record revpi-io "${status}" "test -c /dev/piControl0; test -d /sys/module/piControl" \
        "/dev/piControl0 exists and the piControl module is loaded" "${detail}"
}

# --- tpm: the SLB9670 probed ----------------------------------------------
check_tpm() {
    major="$(read_first "${ROOT}/sys/class/tpm/tpm0/tpm_version_major")"
    status=failed
    if [ -e "${ROOT}/dev/tpmrm0" ] && [ "${major}" = 2 ]; then status=passed; fi
    record tpm "${status}" "test -e /dev/tpmrm0; cat /sys/class/tpm/tpm0/tpm_version_major" \
        "/dev/tpmrm0 exists and tpm0 is a TPM 2.0" \
        "tpmrm0=$([ -e "${ROOT}/dev/tpmrm0" ] && echo yes || echo no); tpm_version_major=${major:-none}"
}

# --- rtc: the PCF2129 is the system's RTC ----------------------------------
check_rtc() {
    name="$(read_first "${ROOT}/sys/class/rtc/rtc0/name")"
    status=failed
    case "${name}" in *pcf2127*) [ -e "${ROOT}/dev/rtc0" ] && status=passed ;; esac
    record rtc "${status}" "cat /sys/class/rtc/rtc0/name; test -e /dev/rtc0" \
        "rtc0 is the PCF2127/PCF2129 driver" "rtc0 name=${name:-none}"
}

# --- rs485: UART5 is there; the loopback itself needs wiring -----------------
check_rs485() {
    status=failed
    if [ -e "${ROOT}/dev/ttyAMA5" ] && [ -e "${ROOT}/sys/class/tty/ttyAMA5" ]; then status=passed; fi
    record rs485 "${status}" "test -e /dev/ttyAMA5; test -e /sys/class/tty/ttyAMA5" \
        "/dev/ttyAMA5 (UART5, the RS485 port) exists" \
        "ttyAMA5 node=$([ -e "${ROOT}/dev/ttyAMA5" ] && echo yes || echo no)"
}

# --- leds: the 15 RGB status LEDs and the power LED ----------------------------
check_leds() {
    found=0
    missing=""
    for a in a1 a2 a3 a4 a5; do
        for c in red green blue; do
            if [ -e "${ROOT}/sys/class/leds/${a}:${c}:status" ]; then
                found=$((found + 1))
            else
                missing="${missing} ${a}:${c}:status"
            fi
        done
    done
    power=no
    if [ -e "${ROOT}/sys/class/leds/power:1:fault" ]; then power=yes; fi
    status=failed
    if [ "${found}" = 15 ] && [ "${power}" = yes ]; then status=passed; fi
    record leds "${status}" "ls /sys/class/leds" \
        "15 RGB status LEDs a1..a5 and power:1:fault" \
        "status LEDs found=${found}; power=${power}; missing=${missing:-none}"
}

# --- watchdog: a hardware watchdog is registered ----------------------------
check_watchdog() {
    idents=""
    bcm=no
    for w in "${ROOT}"/sys/class/watchdog/watchdog*; do
        [ -e "${w}" ] || continue
        id="$(read_first "${w}/identity")"
        idents="${idents}${idents:+; }$(basename "${w}")=${id:-unknown}"
        case "${id}" in *[Bb][Cc][Mm]2835*) bcm=yes ;; esac
    done
    status=failed
    if [ "${bcm}" = yes ]; then status=passed; fi
    record watchdog "${status}" "cat /sys/class/watchdog/watchdog*/identity" \
        "the BCM2835 watchdog is registered (the PCF2129's may be too)" "${idents:-none}"
}

# --- module-signing: production refuses unsigned modules and is locked down ---
check_module_signing() {
    enforce="$(read_first "${ROOT}/sys/module/module/parameters/sig_enforce")"
    lockdown="$(read_first "${ROOT}/sys/kernel/security/lockdown")"
    status=failed
    if [ "${VARIANT}" = prod ]; then
        case "${lockdown}" in
            *"[integrity]"* | *"[confidentiality]"*) [ "${enforce}" = Y ] && status=passed ;;
        esac
        expected="sig_enforce=Y and lockdown integrity or confidentiality (production kernel)"
    else
        [ -n "${enforce}" ] && [ -n "${lockdown}" ] && status=passed
        expected="the dev image reports its module and lockdown state (it does not force either)"
    fi
    record module-signing "${status}" \
        "cat /sys/module/module/parameters/sig_enforce /sys/kernel/security/lockdown" \
        "${expected}" "sig_enforce=${enforce:-none}; lockdown=${lockdown:-none}"
}

# --- boot-chain: the FIT's command line (prod) or the dev root (dev) ---------
check_boot_chain() {
    cmdline="$(read_first "${ROOT}/proc/cmdline")"
    status=failed
    if [ "${VARIANT}" = prod ]; then
        case "${cmdline}" in
            *suderra.verity.root_hash=*) case "${cmdline}" in *console=ttyS0,115200*) status=passed ;; esac ;;
        esac
        expected="the signed FIT's bootargs: suderra.verity.root_hash= and console=ttyS0,115200"
    else
        case "${cmdline}" in *root=PARTUUID=5d3e0a11-02*) status=passed ;; esac
        expected="the dev root named root=PARTUUID=5d3e0a11-02"
    fi
    record boot-chain "${status}" "cat /proc/cmdline" "${expected}" "cmdline=${cmdline:-none}"
}

# --- unsigned-module-rejected: a module without its signature must not load ---
check_unsigned_module() {
    work="${OUT}/unsigned-module.work"
    mkdir -p "${work}"
    smallest=""
    smallest_size=0
    for m in "${ROOT}"/lib/modules/*/kernel/*/*.ko "${ROOT}"/lib/modules/*/kernel/*/*/*.ko \
        "${ROOT}"/lib/modules/*/kernel/*/*/*/*.ko "${ROOT}"/lib/modules/*/extra/*.ko; do
        [ -f "${m}" ] || continue
        s="$(wc -c < "${m}")"
        if [ -z "${smallest}" ] || [ "${s}" -lt "${smallest_size}" ]; then
            smallest="${m}"
            smallest_size="${s}"
        fi
    done
    status=failed
    observed="no signed module found under /lib/modules"
    if [ -n "${smallest}" ]; then
        if strip_module_signature "${smallest}" "${work}/unsigned.ko"; then
            if out="$("${INSMOD}" "${work}/unsigned.ko" 2>&1)"; then
                observed="the kernel loaded ${smallest##*/} without its signature"
                "${RMMOD:-rmmod}" unsigned >/dev/null 2>&1 || true
            else
                case "${out}" in
                    *"Key was rejected by service"*) status=passed; observed="refused: ${out}" ;;
                    *) observed="insmod failed, but not for the signature: ${out}" ;;
                esac
            fi
        else
            observed="${smallest##*/} has no module signature to strip: it was not signed"
        fi
    fi
    rm -rf "${work}"
    record unsigned-module-rejected "${status}" \
        "strip the signature of the smallest module; insmod it" \
        "insmod fails with EKEYREJECTED (Key was rejected by service)" "${observed}"
}

check_board_identity
check_kernel
check_revpi_io
check_tpm
check_rtc
check_rs485
check_leds
check_watchdog
check_module_signing
check_boot_chain
if [ "${TRY_INSMOD}" = 1 ]; then
    check_unsigned_module
fi

printf '{%s}\n' "${JSON}" > "${OUT}/checks.json"
if [ "${FAILED}" = 0 ]; then
    echo "revpi-connect4 board checks passed (${VARIANT}); records in ${OUT}/checks.json"
    exit 0
fi
echo "revpi-connect4 board checks FAILED (${VARIANT}); see ${OUT}" >&2
exit 1

#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Hardware checks of a Revolution Pi Connect 4 running a Suderra OS revpi4 image
# (docs/hardware/revpi-connect4.md section 6). Run it on the device as root; it
# reads the kernel's views of the hardware and does two things to the board: the
# tpm-seal check seals a throw-away secret under the TPM's null hierarchy and
# extends the debug PCR 16 (never PCR 7: the /data seal binds it; PCR 16 is reset
# afterwards), and --try-unsigned-insmod tries one module load that must be
# refused. For every check it writes an evidence file and a record of the shape
# scripts/evidence/suderra-lab.py takes (devices[].checks.<name>: path, status,
# command, expected, observed), so an operator copies the results into the lab
# input instead of retyping them.
#
#   revpi-connect4-board-checks.sh --out DIR [--variant prod|dev]
#       [--try-unsigned-insmod] [--root DIR] [--insmod PROGRAM] [--tcti TCTI]
#
# --root runs the same checks on a directory laid out like the device's /proc,
# /sys, /dev and /etc, which is how tests/image-contracts/
# revpi-board-checks-contract-test.sh runs them without hardware. Outside a
# --root, /dev/piControl0 must be a character device; inside one it only has to
# exist (a test directory cannot mknod). --tcti names the TPM the tpm-seal check
# talks to (default device:/dev/tpmrm0, the kernel's resource manager); the test
# points it at a software TPM.
#
# Not covered here, because they need wiring or a person at the board: the RS485
# loopback, the LEDs' look, the board reset by each watchdog, which Ethernet driver
# eth1 needs, U-Boot rejecting a tampered FIT, and which board a watchdog reset
# resets (docs/hardware/revpi-connect4.md section 6).
#
# Output: DIR/<check>.txt per check and DIR/checks.json. Exit status 0 when every
# check passed, 1 otherwise, 2 for a usage error. POSIX sh: the image has busybox.

set -eu

usage() {
    echo "usage: $0 --out DIR [--variant prod|dev] [--try-unsigned-insmod] [--root DIR] [--insmod PROGRAM] [--tcti TCTI]" >&2
}

ROOT=""
OUT=""
VARIANT="prod"
TRY_INSMOD=0
INSMOD="insmod"
TCTI="device:/dev/tpmrm0"

while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT="${2:?--root needs a directory}"; shift 2 ;;
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        --variant) VARIANT="${2:?--variant needs prod or dev}"; shift 2 ;;
        --try-unsigned-insmod) TRY_INSMOD=1; shift ;;
        --insmod) INSMOD="${2:?--insmod needs a program}"; shift 2 ;;
        --tcti) TCTI="${2:?--tcti needs a TCTI string}"; shift 2 ;;
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

# --- tpm-seal: the TPM seals a secret to PCR 7 and releases it only to that state
# The /data key is sealed to PCR 7 (suderra-data-unlock: systemd-cryptenroll
# --tpm2-pcrs=7). This runs that primitive with a throw-away secret under the
# null hierarchy (it needs no owner or endorsement authorisation, sets none, and
# is gone at the next TPM reset): seal to PCR 7 and PCR 16, unseal and compare,
# then extend PCR 16 - the debug PCR; PCR 7 is never touched, the real /data seal
# binds it - and require the policy to refuse the unseal, then reset PCR 16.
# tpm2-tools only. The transient objects and sessions are flushed between steps:
# a raw TCTI (the test's software TPM) has no resource manager to do it, and on
# /dev/tpmrm0 it is harmless.
TPM_DETAIL=""
TPM_WORK=""
TPM_PCR16_EXTENDED=0

tpm_flush() {
    tpm2_flushcontext -T "${TCTI}" -t >/dev/null 2>&1 || true
    tpm2_flushcontext -T "${TCTI}" -l >/dev/null 2>&1 || true
}

# tpm_error: the ERROR lines of the last tool run, on one line.
tpm_error() {
    grep -h 'ERROR' "${TPM_WORK}/step.err" 2>/dev/null | head -n 3 | tr '\n' ' '
}

# tpm_step <label> <command...>: run it; on failure TPM_DETAIL names the step and its error.
tpm_step() {
    label="$1"
    shift
    if "$@" > "${TPM_WORK}/step.out" 2> "${TPM_WORK}/step.err"; then
        return 0
    fi
    TPM_DETAIL="${label} failed: $(tpm_error)"
    return 1
}

# tpm_seal_roundtrip <workdir>: 0 when the secret survives seal and unseal and
# a changed PCR 16 blocks the release; TPM_DETAIL says what happened.
tpm_seal_roundtrip() {
    w="$1"
    TPM_WORK="${w}"
    for t in tpm2_createprimary tpm2_pcrread tpm2_createpolicy tpm2_create tpm2_load \
        tpm2_unseal tpm2_pcrextend tpm2_pcrreset tpm2_flushcontext; do
        if ! command -v "${t}" >/dev/null 2>&1; then
            TPM_DETAIL="${t} is not installed (tpm2-tools)"
            return 1
        fi
    done
    if ! head -c 32 /dev/urandom > "${w}/secret.bin" 2>/dev/null; then
        TPM_DETAIL="no random bytes to seal"
        return 1
    fi
    tpm_flush
    tpm_step "tpm2_createprimary (null hierarchy)" \
        tpm2_createprimary -T "${TCTI}" -C n -G ecc -c "${w}/primary.ctx" || return 1
    tpm_flush
    tpm_step "tpm2_pcrread sha256:7,16" \
        tpm2_pcrread -T "${TCTI}" -o "${w}/pcrs.bin" sha256:7,16 || return 1
    tpm_step "tpm2_createpolicy (PCR 7,16)" \
        tpm2_createpolicy -T "${TCTI}" --policy-pcr -l sha256:7,16 -f "${w}/pcrs.bin" -L "${w}/policy.digest" || return 1
    tpm_step "tpm2_create (seal)" \
        tpm2_create -T "${TCTI}" -C "${w}/primary.ctx" -i "${w}/secret.bin" -L "${w}/policy.digest" \
        -u "${w}/seal.pub" -r "${w}/seal.priv" || return 1
    tpm_flush
    tpm_step "tpm2_load" \
        tpm2_load -T "${TCTI}" -C "${w}/primary.ctx" -u "${w}/seal.pub" -r "${w}/seal.priv" -c "${w}/seal.ctx" || return 1
    tpm_flush
    tpm_step "tpm2_unseal" \
        tpm2_unseal -T "${TCTI}" -c "${w}/seal.ctx" -p pcr:sha256:7,16 -o "${w}/unsealed.bin" || return 1
    tpm_flush
    if ! cmp -s "${w}/secret.bin" "${w}/unsealed.bin"; then
        TPM_DETAIL="the unsealed bytes differ from the sealed secret"
        return 1
    fi
    # The state the secret was sealed to changes: the policy must refuse the release.
    tpm_step "tpm2_pcrextend 16" \
        tpm2_pcrextend -T "${TCTI}" "16:sha256=0000000000000000000000000000000000000000000000000000000000000001" || return 1
    TPM_PCR16_EXTENDED=1
    if tpm2_unseal -T "${TCTI}" -c "${w}/seal.ctx" -p pcr:sha256:7,16 -o "${w}/unsealed-2.bin" \
        > "${w}/step.out" 2> "${w}/step.err"; then
        TPM_DETAIL="unseal succeeded after PCR 16 changed: the PCR policy is not enforced"
        return 1
    fi
    case "$(cat "${w}/step.err")" in
        *"policy check failed"*) ;;
        *)
            TPM_DETAIL="unseal was refused after PCR 16 changed, but not by the policy: $(tpm_error)"
            return 1
            ;;
    esac
    TPM_DETAIL="sealed 32 bytes to PCR 7 and 16 under the null hierarchy; the unseal returned them; after a PCR 16 extend the policy refused the unseal"
    return 0
}

check_tpm_seal() {
    work="${OUT}/tpm-seal.work"
    mkdir -p "${work}"
    status=failed
    TPM_PCR16_EXTENDED=0
    if tpm_seal_roundtrip "${work}"; then status=passed; fi
    if [ "${TPM_PCR16_EXTENDED}" = 1 ]; then
        if tpm2_pcrreset -T "${TCTI}" 16 >/dev/null 2>&1; then
            TPM_DETAIL="${TPM_DETAIL}; PCR 16 reset"
        else
            TPM_DETAIL="${TPM_DETAIL}; PCR 16 could not be reset and holds the check's extend value until the next boot"
        fi
    fi
    tpm_flush
    rm -rf "${work}"
    record tpm-seal "${status}" \
        "tpm2_createprimary -C n; tpm2_createpolicy --policy-pcr -l sha256:7,16; tpm2_create; tpm2_load; tpm2_unseal; tpm2_pcrextend 16; tpm2_unseal" \
        "a secret sealed to PCR 7 and 16 is released to that state and refused after PCR 16 changes" \
        "${TPM_DETAIL}"
}

# --- rtc: the PCF2129 is the system's RTC ----------------------------------
check_rtc() {
    name="$(read_first "${ROOT}/sys/class/rtc/rtc0/name")"
    status=failed
    case "${name}" in *pcf2127*) [ -e "${ROOT}/dev/rtc0" ] && status=passed ;; esac
    record rtc "${status}" "cat /sys/class/rtc/rtc0/name; test -e /dev/rtc0" \
        "rtc0 is the PCF2127/PCF2129 driver" "rtc0 name=${name:-none}"
}

# --- rtc-hctosys: the kernel set the system clock from the RTC at boot -----
# hctosys is 1 only on the RTC the kernel used for CONFIG_RTC_HCTOSYS_DEVICE
# (rtc0) and only when it read a valid time from it: 0 means the PCF2129 lost
# its CR2032 or was never set, or another RTC is rtc0.
check_rtc_hctosys() {
    hctosys="$(read_first "${ROOT}/sys/class/rtc/rtc0/hctosys")"
    since="$(read_first "${ROOT}/sys/class/rtc/rtc0/since_epoch")"
    status=failed
    if [ "${hctosys}" = 1 ]; then status=passed; fi
    record rtc-hctosys "${status}" "cat /sys/class/rtc/rtc0/hctosys /sys/class/rtc/rtc0/since_epoch" \
        "rtc0 set the system clock at boot (hctosys=1): the RTC held a valid time" \
        "hctosys=${hctosys:-none}; since_epoch=${since:-none}"
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

# --- watchdog: systemd PID1 holds the board's watchdog armed ------------------
# ADR-048 DEC-6.6: the image's udev rule links /dev/suderra-watchdog to the
# BCM2711 PM watchdog by its sysfs identity, and PID1 opens that link with the
# RuntimeWatchdogSec of /etc/systemd/system.conf.d/10-suderra-watchdog.conf.
# Passed when the link names a watchdogN of that identity, its state is active,
# PID1 has it open, the kernel's programmed timeout is the drop-in's, and (on a
# production kernel) nowayout is 1.
check_watchdog() {
    idents=""
    for w in "${ROOT}"/sys/class/watchdog/watchdog*; do
        [ -e "${w}" ] || continue
        idents="${idents}${idents:+; }$(basename "${w}")=$(read_first "${w}/identity")"
    done
    target=""
    if [ -L "${ROOT}/dev/suderra-watchdog" ]; then target="$(readlink "${ROOT}/dev/suderra-watchdog")"; fi
    name="${target##*/}"
    case "${name}" in
        watchdog | watchdog*[!0-9]*) name="" ;;
        watchdog[0-9]*) ;;
        *) name="" ;;
    esac
    ident=""
    state=""
    nowayout=""
    timeout=""
    held=no
    if [ -n "${name}" ]; then
        class="${ROOT}/sys/class/watchdog/${name}"
        ident="$(read_first "${class}/identity")"
        state="$(read_first "${class}/state")"
        nowayout="$(read_first "${class}/nowayout")"
        timeout="$(read_first "${class}/timeout")"
        for fd in "${ROOT}"/proc/1/fd/*; do
            [ -L "${fd}" ] || continue
            case "$(readlink "${fd}")" in */"${name}") held=yes ;; esac
        done
    fi
    configured="$(sed -n 's/^RuntimeWatchdogSec=\([0-9][0-9]*\)s$/\1/p' \
        "${ROOT}/etc/systemd/system.conf.d/10-suderra-watchdog.conf" 2>/dev/null | head -n 1)"
    status=failed
    if [ "${ident}" = "Broadcom BCM2835 Watchdog timer" ] && [ "${state}" = active ] &&
        [ "${held}" = yes ] && [ -n "${configured}" ] && [ "${timeout}" = "${configured}" ]; then
        status=passed
        if [ "${VARIANT}" = prod ] && [ "${nowayout}" != 1 ]; then status=failed; fi
    fi
    record watchdog "${status}" "ls -l /dev/suderra-watchdog /proc/1/fd; cat /sys/class/watchdog/watchdog*/{identity,state,nowayout,timeout}" \
        "/dev/suderra-watchdog is the BCM2711 watchdog, active, open in PID1, programmed to RuntimeWatchdogSec, nowayout 1 on production" \
        "link=${target:-none}; identity=${ident:-none}; state=${state:-none}; nowayout=${nowayout:-none}; timeout=${timeout:-none}; configured=${configured:-none}; pid1-holds=${held}; all: ${idents:-none}"
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
check_tpm_seal
check_rtc
check_rtc_hctosys
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

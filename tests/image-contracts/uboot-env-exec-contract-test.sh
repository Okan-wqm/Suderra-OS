#!/usr/bin/env bash
#
# The production U-Boot environment, executed (ADR-048 DEC-18; EI-013, EI-035,
# EI-036).
#
# board/suderra/uboot/suderra.env is code: the key guard that refuses to boot
# unless the control FDT demands a signed FIT (T88), and the A/B slot choice
# whose counters decide which slot a board boots. scripts/ci/check-uboot-config.py
# reads it statically and cannot tell a guard from text that looks like one: a
# line that sets suderra_required before the final test survives every regular
# expression. This test runs it. U-Boot's sandbox (a U-Boot that is a host
# process, scripts/ci/uboot-build.sh sandbox) is built from the pinned sources
# with suderra.env as its compiled-in default environment, and U-Boot itself
# executes
#   - suderra_guard against fixture control FDTs (keyed, unkeyed, key not
#     required, key under another name, ...),
#   - suderra_pick and suderra_rearm against a table of counters, and the whole
#     cycle of a board whose slot never reaches mark-good (the factory counters
#     included): a failed boot costs one try, never the slot, and a board that
#     ran out of tries is armed again instead of staying down,
# and then runs the same checks against mutated copies of the file (imported at
# run time, so no rebuild) to show that each defect class fails them.
#
# What this does not run: the bootcmd end to end (reset restarts the sandbox)
# or a kernel. tests/qemu/arm-fit-signature-boot.sh boots the production chain
# on QEMU for that. Needs: gcc make bison flex swig libssl-dev patch curl dtc
# (the U-Boot tarball is cached). Exits 77 when a tool is missing, so a CI run
# fails instead of passing without having executed anything.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ENVFILE="${ROOT}/board/suderra/uboot/suderra.env"
BUILD_SH="${ROOT}/scripts/ci/uboot-build.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for tool in gcc make bison flex swig patch curl python3 dtc fdtput; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "SKIP: ${tool} is not installed" >&2
        exit 77
    }
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "U-Boot sandbox with the production default environment"
bash "${BUILD_SH}" sandbox "${WORK}/uboot" "${ENVFILE}" >/dev/null
UBOOT="${WORK}/uboot/sandbox/u-boot"
BASE_DTB="${WORK}/uboot/sandbox/arch/sandbox/dts/sandbox.dtb"

# ---------------------------------------------------------------------------
# Fixture control FDTs: what the firmware hands U-Boot
# ---------------------------------------------------------------------------
FX="${WORK}/fx"
mkdir -p "${FX}"
keyed() { # <out> <key-node-name>
    cp "${BASE_DTB}" "$1"
    fdtput -c "$1" /signature
    fdtput -c "$1" "/signature/$2"
    fdtput -t s "$1" "/signature/$2" algo "sha256,rsa2048"
}
cp "${BASE_DTB}" "${FX}/unkeyed.dtb"
keyed "${FX}/keyed.dtb" key-fit-signing
fdtput -t s "${FX}/keyed.dtb" /signature/key-fit-signing required conf
keyed "${FX}/key-not-required.dtb" key-fit-signing
fdtput -t s "${FX}/key-not-required.dtb" /signature/key-fit-signing required image
keyed "${FX}/key-without-required.dtb" key-fit-signing
keyed "${FX}/key-other-name.dtb" key-other
fdtput -t s "${FX}/key-other-name.dtb" /signature/key-other required conf
keyed "${FX}/key-required-empty.dtb" key-fit-signing
fdtput -t s "${FX}/key-required-empty.dtb" /signature/key-fit-signing required ""
GUARD_CASES=(keyed:pass unkeyed:fail key-not-required:fail key-without-required:fail key-other-name:fail key-required-empty:fail)

# ---------------------------------------------------------------------------
# Running U-Boot
# ---------------------------------------------------------------------------
# ub <control-dtb> <import-file|-> <command>: the command runs in the sandbox
# (after the import of a joined environment file, when one is given); its
# console output, without terminal escapes, is in UB_OUT.
UB_OUT=""
ub() {
    local dtb="$1" imp="$2" cmd="$3" pre="" log="${WORK}/ub.log" rc
    if [ "${imp}" != - ]; then
        pre="host load hostfs - 0x1000000 ${imp}; env import -t 0x1000000 \${filesize}; "
    fi
    set +e
    timeout 60 "${UBOOT}" -d "${dtb}" -c "${pre}${cmd}" < /dev/null > "${log}" 2>&1
    rc=$?
    set -e
    [ "${rc}" -ne 124 ] || fail "the sandbox U-Boot did not stop within 60 s: ${cmd}"
    UB_OUT="$(sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' "${log}" | tr -d '\r')"
}

# The failures of the guard table against the environment <import-file|->.
guard_failures() {
    local imp="$1" n=0 item name want got
    for item in "${GUARD_CASES[@]}"; do
        name="${item%%:*}"
        want="${item##*:}"
        ub "${FX}/${name}.dtb" "${imp}" 'if run suderra_guard; then echo GUARD=pass; else echo GUARD=fail; fi'
        got="$(sed -n 's/^GUARD=//p' <<<"${UB_OUT}" | head -n 1)"
        if [ "${got}" != "${want}" ]; then
            [ "${QUIET:-0}" = 1 ] || echo "  guard on ${name}: wanted ${want}, got [${got}]" >&2
            n=$((n + 1))
        fi
    done
    echo "${n}"
}

# pick <import> <order> <a> <b>: runs suderra_pick, sets PICK to "slot|a|b".
pick() {
    ub "${FX}/keyed.dtb" "$1" "setenv BOOT_ORDER '$2'; setenv BOOT_A_LEFT $3; setenv BOOT_B_LEFT $4; run suderra_pick; echo RESULT slot=[\${suderra_slot}] a=\${BOOT_A_LEFT} b=\${BOOT_B_LEFT}"
    PICK="$(sed -n 's/^RESULT slot=\[\(.*\)\] a=\(.*\) b=\(.*\)$/\1|\2|\3/p' <<<"${UB_OUT}" | head -n 1)"
}

# order|a|b|slot|a after|b after: the slot that boots (empty when none has tries
# left) and the counters after it spent its try.
PICK_TABLE=(
    "A B|3|0|A|2|0"
    "A B|2|0|A|1|0"
    "A B|1|0|A|0|0"
    "A B|0|0||0|0"
    "A B|0|3|B|0|2"
    "A B|1|3|A|0|3"
    "B A|3|2|B|3|1"
    "B A|0|2|B|0|1"
    "A|3|3|A|2|3"
    "B|3|0||3|0"
    "B A|0|0||0|0"
)

pick_failures() {
    local imp="$1" n=0 row order a b want_slot want_a want_b
    for row in "${PICK_TABLE[@]}"; do
        IFS='|' read -r order a b want_slot want_a want_b <<<"${row}"
        pick "${imp}" "${order}" "${a}" "${b}"
        if [ "${PICK}" != "${want_slot}|${want_a}|${want_b}" ]; then
            [ "${QUIET:-0}" = 1 ] || echo "  pick '${order}' ${a} ${b}: wanted [${want_slot}|${want_a}|${want_b}], got [${PICK}]" >&2
            n=$((n + 1))
        fi
    done
    echo "${n}"
}

# The cycle of a board whose slot never reaches mark-good, from the counters in
# <a> <b> (order "A B"): 15 boots, a boot with nothing left arms both again.
cycle_of() { # <import> <a> <b>
    ub "${FX}/keyed.dtb" "$1" "setenv BOOT_ORDER 'A B'; setenv BOOT_A_LEFT $2; setenv BOOT_B_LEFT $3; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do run suderra_pick; if test -n \"\${suderra_slot}\"; then echo SEQ \${suderra_slot}; else echo SEQ none; run suderra_rearm; fi; done"
    sed -n 's/^SEQ //p' <<<"${UB_OUT}" | tr '\n' ' ' | sed 's/ $//'
}
# The factory counters: slot A confirmed, no slot B. A boot that never reaches
# mark-good spends A's three tries, the next one arms both again, A has its
# three again, then B (which has no FIT here, so costs its three as well).
FACTORY_CYCLE="A A A none A A A B B B none A A A B"

# A board that confirms every boot (RAUC mark-good) boots slot A for ever and
# never reaches the re-arm.
confirmed_cycle() { # <import>
    ub "${FX}/keyed.dtb" "$1" "setenv BOOT_ORDER 'A B'; setenv BOOT_A_LEFT 3; setenv BOOT_B_LEFT 0; for i in 1 2 3 4 5 6 7 8; do run suderra_pick; echo SEQ \${suderra_slot}; setenv BOOT_A_LEFT 3; done"
    sed -n 's/^SEQ //p' <<<"${UB_OUT}" | tr '\n' ' ' | sed 's/ $//'
}

# rearm <import>: counters and BOOT_ORDER after suderra_rearm from (0, 0).
rearm_state() {
    ub "${FX}/keyed.dtb" "$1" "setenv BOOT_ORDER 'B A'; setenv BOOT_A_LEFT 0; setenv BOOT_B_LEFT 0; run suderra_rearm; echo RESULT order=[\${BOOT_ORDER}] a=\${BOOT_A_LEFT} b=\${BOOT_B_LEFT}"
    sed -n 's/^RESULT //p' <<<"${UB_OUT}" | head -n 1
}

all_failures() { # <import> -> number of failed checks
    local imp="$1" n=0 got
    n=$(($(guard_failures "${imp}") + $(pick_failures "${imp}")))
    got="$(cycle_of "${imp}" 3 0)"
    [ "${got}" = "${FACTORY_CYCLE}" ] || {
        [ "${QUIET:-0}" = 1 ] || echo "  the factory cycle was [${got}], must be [${FACTORY_CYCLE}]" >&2
        n=$((n + 1))
    }
    got="$(confirmed_cycle "${imp}")"
    [ "${got}" = "A A A A A A A A" ] || {
        [ "${QUIET:-0}" = 1 ] || echo "  a board that confirms every boot booted [${got}], not slot A every time" >&2
        n=$((n + 1))
    }
    got="$(rearm_state "${imp}")"
    [ "${got}" = "order=[B A] a=3 b=3" ] || {
        [ "${QUIET:-0}" = 1 ] || echo "  suderra_rearm left [${got}], must arm both slots with 3 and keep BOOT_ORDER" >&2
        n=$((n + 1))
    }
    echo "${n}"
}

# ---------------------------------------------------------------------------
# 1. The production environment, as compiled in
# ---------------------------------------------------------------------------
echo "guard against fixture control FDTs"
[ "$(guard_failures -)" = 0 ] || fail "suderra_guard does not refuse every control FDT that does not demand a signed FIT"
echo "  the guard boots only with /signature/key-fit-signing required = \"conf\" (${#GUARD_CASES[@]} fixtures)"

echo "slot choice against the counter table"
[ "$(pick_failures -)" = 0 ] || fail "suderra_pick does not choose and count as the table says"
echo "  ${#PICK_TABLE[@]} rows: first slot of BOOT_ORDER with tries left, one try spent, nothing else touched"

echo "the cycle of a slot that never reaches mark-good"
got="$(cycle_of - 3 0)"
[ "${got}" = "${FACTORY_CYCLE}" ] || fail "the factory counters cycle [${got}], must be [${FACTORY_CYCLE}]"
echo "  factory counters: ${FACTORY_CYCLE} ... (a failed boot costs one try; no counter ends the boots for good)"
got="$(cycle_of - 3 3)"
[ "${got}" = "A A A B B B none A A A B B B none A" ] || fail "two armed slots cycle [${got}]"
echo "  two armed slots: A A A B B B none ... (a slot that never confirms falls back, then both are armed again)"
got="$(confirmed_cycle -)"
[ "${got}" = "A A A A A A A A" ] || fail "a board that confirms every boot booted [${got}]"
echo "  mark-good between boots: slot A every time"
got="$(rearm_state -)"
[ "${got}" = "order=[B A] a=3 b=3" ] || fail "suderra_rearm left [${got}]"
echo "  suderra_rearm: both slots armed with suderra_attempts, BOOT_ORDER kept"

# ---------------------------------------------------------------------------
# 2. Mutated environments: each defect class must fail one of the checks above
# ---------------------------------------------------------------------------
joined() { # <mutated env file> <out>: the file as U-Boot's Makefile joins it
    python3 -I - "$1" "$2" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
kept = [l for l in text.split("\n") if not l.startswith("#") and l != ""]
open(sys.argv[2], "w").write(re.sub(r"\\\n\s*", "", "\n".join(kept)) + "\n")
EOF
}

mutate() { # <label> <old> <new>: the file with one text replaced must fail a check
    local label="$1" old="$2" new="$3" src="${WORK}/mut.env" imp="${WORK}/mut.joined" n
    python3 -I - "${ENVFILE}" "${src}" "${old}" "${new}" <<'EOF'
import sys
text = open(sys.argv[1]).read()
out = text.replace(sys.argv[3], sys.argv[4], 1)
assert out != text, "the text to mutate is not in the file: " + sys.argv[3]
open(sys.argv[2], "w").write(out)
EOF
    joined "${src}" "${imp}"
    n="$(QUIET=1 all_failures "${imp}")"
    [ "${n}" -gt 0 ] || fail "mutation survived: ${label}"
    echo "  rejects: ${label} (${n} checks fail)"
}

echo "mutated environments"
# The unmutated file, imported the same way, passes: the harness itself is sound.
joined "${ENVFILE}" "${WORK}/clean.joined"
[ "$(QUIET=1 all_failures "${WORK}/clean.joined")" = 0 ] ||
    fail "the production environment fails its own checks when imported at run time"
mutate "a guard that sets the required value itself before the final test (fail-open)" \
    'test "${suderra_required}" = conf' 'setenv suderra_required conf; test "${suderra_required}" = conf'
mutate "a guard that only needs the property to exist" \
    'test "${suderra_required}" = conf' 'test -n "${suderra_required}"'
mutate "a guard that reads another key node" \
    '/signature/key-fit-signing required' '/signature/key-other required'
mutate "a guard that is always true" \
    'fdt addr ${fdtcontroladdr}; \' 'true; \'
mutate "a slot choice that does not spend a try" \
    'setexpr BOOT_A_LEFT ${BOOT_A_LEFT} - 1; \' 'setenv suderra_dummy 1; \'
mutate "a slot choice that spends the whole slot (one failed load would end it)" \
    'setexpr BOOT_B_LEFT ${BOOT_B_LEFT} - 1; \' 'setenv BOOT_B_LEFT 0; \'
mutate "a slot choice that takes slot B first" \
    'for suderra_s in ${BOOT_ORDER}; do' 'for suderra_s in B A; do'
mutate "a slot with no tries left that boots anyway" \
    'if test ${BOOT_A_LEFT} -gt 0; then' 'if test ${BOOT_A_LEFT} -ge 0; then'
mutate "a re-arm that zeroes the counters (a board that stays down)" \
    'setenv BOOT_A_LEFT ${suderra_attempts}; \' 'setenv BOOT_A_LEFT 0; \'
mutate "a re-arm that arms one slot only" \
    'setenv BOOT_B_LEFT ${suderra_attempts}; \' 'setenv suderra_dummy 1; \'

echo "U-Boot env execution test passed"

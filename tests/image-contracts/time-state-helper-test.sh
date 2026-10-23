#!/usr/bin/env bash
#
# The clock trust helper (ADR-048 DEC-7; EI-046, EDGE-MEDIUM-077):
# suderra-time-state turns chronyd's reports and the time floor into
# /run/suderra/time-state, the document the agent and root's installer take as
# the clock's trust.
#
# The test runs the real script, under the host's /bin/sh and under BusyBox
# ash (the image's shell; BusyBox's own awk and date formatting), against a
# fake root (--root), a fake chronyc that answers with chronyc -c reports, and
# a fake clock. The reports are the real thing: the NTS, plain and unsynced
# captures below are the output of chrony 4.6.1 (the version Buildroot builds)
# against a loopback NTS server and an unreachable one; the others change one
# field of them. The fakes are shell functions, not files in PATH, because
# BusyBox ash prefers its own applets to PATH. The clock is never set for
# real: `date -s` is a function that writes a file.
#
# What it holds: the state each report decides (boundaries of every limit, the
# authentication of the sources in use), the document's schema and mode, the
# floor (build time, persisted time, raising the clock, never trusting a wall
# clock that may be a reset RTC, lowering only for an authenticated clock,
# hourly and shutdown saves), the bounded wait and its once-per-boot results,
# and the command line.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
SCRIPT="${OVERLAY}/usr/sbin/suderra-time-state"
CONTRACT="${ROOT}/contracts/suderra-edge/v1"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -x "${SCRIPT}" ] || fail "suderra-time-state is missing or not executable"
command -v python3 > /dev/null 2>&1 || fail "python3 is required"

shells=("sh")
if command -v busybox > /dev/null 2>&1; then
    shells+=("busybox sh")
elif [ "${SUDERRA_FAIL_ON_SKIP:-0}" = "1" ] || [ "${CI:-}" = "true" ]; then
    fail "busybox is required in CI (package busybox-static): the image's shell is BusyBox ash"
fi

# --- the fakes ---------------------------------------------------------------------------------
mkdir -p "${WORK}/bin"
cat > "${WORK}/bin/chronyc" << 'EOF'
#!/bin/sh
# A chronyc that answers `-c tracking`, `-c -n sources -a` and `-c -n authdata`
# from FAKE_DIR. tracking.<n>.csv answers the n-th tracking request when it
# exists (a clock that synchronizes while the wait runs).
[ ! -e "${FAKE_DIR}/chronyd-down" ] || exit 1
command=""
for word in "$@"; do
    case "${word}" in
        tracking | sources | authdata) command="${word}" ;;
    esac
done
echo "chronyc $*" >> "${FAKE_DIR}/chronyc.log"
file="${FAKE_DIR}/${command}.csv"
if [ "${command}" = tracking ]; then
    n=0
    [ ! -e "${FAKE_DIR}/n" ] || n="$(cat "${FAKE_DIR}/n")"
    n=$((n + 1))
    echo "${n}" > "${FAKE_DIR}/n"
    [ ! -e "${FAKE_DIR}/tracking.${n}.csv" ] || file="${FAKE_DIR}/tracking.${n}.csv"
    [ -r "${file}" ] || exit 1
fi
if [ -r "${file}" ]; then cat "${file}"; fi
exit 0
EOF
cat > "${WORK}/bin/suderra-installer" << 'EOF'
#!/bin/sh
echo "$*" >> "${FAKE_DIR}/installer.log"
[ ! -e "${FAKE_DIR}/installer-fails" ] || exit 1
exit 0
EOF
chmod 0755 "${WORK}/bin/chronyc" "${WORK}/bin/suderra-installer"
# BusyBox ash prefers its applets to PATH, so the applets the script runs that
# the test must control are functions.
cat > "${WORK}/prelude.sh" << 'EOF'
date() {
    case "$1" in
        +%s) cat "${FAKE_DIR}/clock" ;;
        -s)
            echo "$2" >> "${FAKE_DIR}/date-set.log"
            if [ -e "${FAKE_DIR}/date-set-fails" ]; then return 1; fi
            echo "${2#@}" > "${FAKE_DIR}/clock"
            ;;
        *) command date "$@" ;;
    esac
}
sleep() { echo "$1" >> "${FAKE_DIR}/sleep.log"; }
chgrp() { echo "$*" >> "${FAKE_DIR}/chgrp.log"; }
EOF

# --- scenario helpers --------------------------------------------------------------------------
NOW=1792714600
BUILD=1760000000
n_scenario=0

scenario() {
    # scenario <name>: a fresh root R and fake directory F
    n_scenario=$((n_scenario + 1))
    R="${WORK}/s${n_scenario}-$1"
    F="${R}.fake"
    mkdir -p "${R}/run/suderra" "${R}/run/suderra-os" "${R}/data/suderra/os" "${R}/usr/lib/suderra" "${R}/proc" "${F}"
    printf '%s\n' "${BUILD}" > "${R}/usr/lib/suderra/build-epoch"
    set_clock "${NOW}"
    set_uptime 100
    : > "${F}/installer.log"
}

set_clock() { printf '%s\n' "$1" > "${F}/clock"; }
set_uptime() { printf '%s.00 %s.00\n' "$1" "$1" > "${R}/proc/uptime"; }
set_floor() { mkdir -p "${R}/data/suderra/os/time"; printf '%s\n' "$1" > "${R}/data/suderra/os/time/floor"; }
floor_file() { cat "${R}/data/suderra/os/time/floor" 2> /dev/null || echo none; }
installer_log() { cat "${F}/installer.log"; }

# fixture <tracking> [sources...]: a source line per argument; authdata from AUTH.
fixture() {
    printf '%s\n' "$1" > "${F}/tracking.csv"
    shift
    : > "${F}/sources.csv"
    local row
    for row in "$@"; do printf '%s\n' "${row}" >> "${F}/sources.csv"; done
    printf '%s\n' "${AUTH}" > "${F}/authdata.csv"
}

# track <refid> <reference> <stratum> <ref time> <system time> <last offset> <root delay> <root dispersion> <leap>
track() {
    printf '%s,%s,%s,%s,%s,%s,0.000003529,0.010,0.003,0.147,%s,%s,1.0,%s' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}

# Captures of chrony 4.6.1 (chronyc -c ...) against a loopback NTS server, a
# loopback plain NTP server and an NTS server nothing answers.
NTS_TRACKING='7F000001,127.0.0.1,4,1792714555.638954447,-0.000005079,-0.000003523,0.000003529,0.010,0.003,0.147,0.000018241,0.000002948,1.0,Normal'
NTS_SOURCE='^,*,127.0.0.1,3,0,377,2,0.000002702,-0.000000821,0.000009183'
NTS_AUTH='127.0.0.1,NTS,1,30,128,11,0,0,8,64'
PLAIN_TRACKING='7F000001,127.0.0.1,4,1792714624.538273085,-0.000001252,0.000000116,0.000000537,-0.026,0.003,0.351,0.000005144,0.000005501,1.0,Normal'
PLAIN_AUTH='127.0.0.1,-,0,0,0,4294967295,0,0,0,0'
UNSYNCED_TRACKING='00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised'
UNSYNCED_SOURCE='^,?,192.53.103.108,0,6,0,4294967295,0.000000000,0.000000000,0.000000000'
UNSYNCED_AUTH='192.53.103.108,NTS,0,0,0,4294967295,1,0,0,0'
AUTH="${NTS_AUTH}"

run() {
    # run <shell> <args...>: the script under the shell, against R and F
    local shell="$1"
    shift
    local cmd
    IFS=' ' read -r -a cmd <<< "${shell}"
    set +e
    (
        export FAKE_DIR="${F}"
        export PATH="${WORK}/bin:${PATH}"
        cd "${R}"
        # shellcheck disable=SC2016 # the program is the inner shell's
        "${cmd[@]}" -c '. "$1"; shift; SCRIPT="$1"; shift; set -- "$@"; . "${SCRIPT}"' _ "${WORK}/prelude.sh" "${SCRIPT}" --root "${R}" "$@"
    ) > "${R}.out" 2> "${R}.err"
    RC=$?
    set -e
}

must_run() {
    run "$@"
    [ "${RC}" -eq 0 ] || { cat "${R}.err" >&2; fail "suderra-time-state ${*:2} failed with ${RC} under $1"; }
}

doc() { cat "${R}/run/suderra/time-state"; }

# check <description> <python expression over d (the document) and R (the root)>
check() {
    python3 -I - "$1" "$2" "${R}/run/suderra/time-state" "${CONTRACT}" << 'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

description, expression, path, contract = sys.argv[1:]
try:
    text = Path(path).read_text(encoding="utf-8")
    d = json.loads(text)
except (OSError, ValueError) as error:
    sys.exit(f"ERROR: {description}: no document ({error})")

# The contract's schema: every field, the enum, the timestamp pattern, null
# exactly where the schema says.
common = json.loads(Path(contract, "schemas/common.schema.json").read_text(encoding="utf-8"))
timestamp = re.compile(common["$defs"]["timestamp"]["pattern"])
schema = json.loads(Path(contract, "schemas/time-state.schema.json").read_text(encoding="utf-8"))
problems = []
if set(d) != set(schema["required"]):
    problems.append(f"fields {sorted(d)} != {sorted(schema['required'])}")
if d.get("_type") != "suderra.time-state.v1":
    problems.append("_type")
if d.get("state") not in schema["properties"]["state"]["enum"]:
    problems.append("state")
for field in ("floor_at", "updated_at"):
    if not isinstance(d.get(field), str) or not timestamp.match(d[field]):
        problems.append(field)
if d.get("last_sync_at") is not None and not (isinstance(d["last_sync_at"], str) and timestamp.match(d["last_sync_at"])):
    problems.append("last_sync_at")
if d.get("state") == "unsynced":
    if d.get("offset_ms") is not None:
        problems.append("offset_ms must be null while unsynced")
else:
    if type(d.get("offset_ms")) is not int:
        problems.append("offset_ms must be an integer once synced")
    if not isinstance(d.get("last_sync_at"), str):
        problems.append("last_sync_at must be a timestamp once synced")
try:
    import jsonschema
    import referencing
    import referencing.jsonschema

    registry = referencing.Registry()
    for schema_file in Path(contract, "schemas").glob("*.schema.json"):
        loaded = json.loads(schema_file.read_text(encoding="utf-8"))
        registry = registry.with_resource(
            loaded["$id"], referencing.Resource.from_contents(loaded, default_specification=referencing.jsonschema.DRAFT202012)
        )
    validator = jsonschema.Draft202012Validator(schema, registry=registry)
    for error in validator.iter_errors(d):
        problems.append(f"schema: {error.message}")
except ImportError:
    pass
if problems:
    sys.exit(f"ERROR: {description}: the document breaks the contract: {problems}: {text}")


def ts(epoch):
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


root = Path(path).parent.parent.parent
if not eval(expression, {"d": d, "ts": ts, "R": root, "Path": Path}):
    sys.exit(f"ERROR: {description}: expected {expression}, got {text}")
PY
}

# --- the states ---------------------------------------------------------------------------------
for shell in "${shells[@]}"; do
    echo "== ${shell}"

    scenario nts
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" tick
    check "real NTS capture" \
        'd["state"] == "synced-nts" and d["offset_ms"] == 0 and d["last_sync_at"] == ts(1792714555) and d["floor_at"] == ts(1760000000) and d["updated_at"] == ts(1792714600)'
    [ ! -s "${R}.err" ] || fail "a healthy first tick must be silent: $(cat "${R}.err")"
    [ "$(stat -c '%a' "${R}/run/suderra/time-state")" = 640 ] || fail "the document must be mode 640"
    grep -qx 'suderra .*time-state.new.*' "${F}/chgrp.log" || fail "the document must be group suderra: $(cat "${F}/chgrp.log" 2> /dev/null)"
    # shellcheck disable=SC2144
    if compgen -G "${R}/run/suderra/*.new.*" > /dev/null; then fail "the temporary document was left behind"; fi
    grep -q -- '-h /run/chrony/chronyd.sock -c tracking' "${F}/chronyc.log" || fail "chronyc must talk to the chrony socket: $(cat "${F}/chronyc.log")"
    grep -q -- '-c -n sources -a' "${F}/chronyc.log" || fail "the sources must be read by address (-n), unresolved ones included (-a)"

    scenario plain
    AUTH="${PLAIN_AUTH}"
    fixture "${PLAIN_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" tick
    check "real plain NTP capture" \
        'd["state"] == "synced-unauthenticated" and d["offset_ms"] == 0 and d["last_sync_at"] == ts(1792714624)'

    scenario unsynced
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    must_run "${shell}" tick
    check "real unsynced capture" 'd["state"] == "unsynced" and d["offset_ms"] is None and d["last_sync_at"] is None'

    scenario down
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    : > "${F}/chronyd-down"
    must_run "${shell}" tick
    check "chronyd is not running" 'd["state"] == "unsynced" and d["last_sync_at"] is None'

    scenario notracking
    rm -f "${F}/tracking.csv"
    must_run "${shell}" tick
    check "chronyc answers nothing for tracking" 'd["state"] == "unsynced"'

    scenario garbage
    AUTH="${NTS_AUTH}"
    fixture 'not,a,tracking,report' "${NTS_SOURCE}"
    must_run "${shell}" tick
    check "a garbled tracking line" 'd["state"] == "unsynced"'

    # --- authentication of the sources in use -------------------------------------------------
    AUTH=$'10.0.0.1,NTS,1,30,128,11,0,0,8,64\n10.0.0.2,NTS,1,30,128,11,0,0,8,64\n10.0.0.3,-,0,0,0,4294967295,0,0,0,0'
    T="$(track 0A000001 10.0.0.1 2 1792714590.5 0.000001 0.000002 0.01 0.002 Normal)"

    scenario two-nts
    fixture "${T}" '^,*,10.0.0.1,2,6,377,5,0.000001,0.000001,0.00001' '^,+,10.0.0.2,2,6,377,5,0.000001,0.000001,0.00001'
    must_run "${shell}" tick
    check "two combined NTS sources" 'd["state"] == "synced-nts"'

    scenario nts-and-plain-combined
    fixture "${T}" '^,*,10.0.0.1,2,6,377,5,0.000001,0.000001,0.00001' '^,+,10.0.0.3,2,6,377,5,0.000001,0.000001,0.00001'
    must_run "${shell}" tick
    check "a combined source without NTS makes the clock unauthenticated" 'd["state"] == "synced-unauthenticated"'

    scenario plain-not-combined
    fixture "${T}" '^,*,10.0.0.1,2,6,377,5,0.000001,0.000001,0.00001' '^,-,10.0.0.3,2,6,377,5,0.000001,0.000001,0.00001' '^,x,10.0.0.3,2,6,377,5,0.5,0.5,0.1'
    must_run "${shell}" tick
    check "a plain source that is not combined does not matter" 'd["state"] == "synced-nts"'

    scenario reference-not-nts
    T3="$(track 0A000003 10.0.0.3 2 1792714590.5 0.000001 0.000002 0.01 0.002 Normal)"
    fixture "${T3}" '^,*,10.0.0.1,2,6,377,5,0.000001,0.000001,0.00001'
    must_run "${shell}" tick
    check "the reference itself is plain" 'd["state"] == "synced-unauthenticated"'

    scenario holdover-nts
    fixture "${T}"
    must_run "${shell}" tick
    check "no source selectable, the reference is NTS" 'd["state"] == "synced-nts"'

    scenario holdover-no-authdata
    : > "${F}/authdata.csv"
    printf '%s\n' "${T}" > "${F}/tracking.csv"
    : > "${F}/sources.csv"
    must_run "${shell}" tick
    check "no authentication data at all" 'd["state"] == "synced-unauthenticated"'

    scenario refclock
    T4="$(track 47505300 GPS 1 1792714590.5 0.000001 0.000002 0.01 0.002 Normal)"
    fixture "${T4}" '#,*,GPS,0,4,377,5,0.000001,0.000001,0.00001'
    must_run "${shell}" tick
    check "a reference clock is not NTS" 'd["state"] == "synced-unauthenticated"'

    AUTH="${NTS_AUTH}"
    # --- the limits -----------------------------------------------------------------------------
    S1="${NTS_SOURCE}"
    limit() {
        # limit <name> <expected state> <track args...>
        local name="$1" expected="$2"
        shift 2
        scenario "limit-${name}"
        fixture "$(track 7F000001 127.0.0.1 4 1792714555.6 "$@")" "${S1}"
        must_run "${shell}" tick
        check "limit ${name}" "d[\"state\"] == \"${expected}\""
    }
    # <system time> <last offset> <root delay> <root dispersion> <leap>
    limit distance-at-bound synced-nts 0.0 0.0 4.0 1.0 Normal
    limit distance-above unsynced 0.0 0.0 4.0 1.001 Normal
    limit distance-by-dispersion unsynced 0.0 0.0 0.0 3.001 Normal
    limit error-at-bound synced-nts 1.0 0.0 0.01 0.01 Normal
    limit error-above unsynced 1.001 0.0 0.01 0.01 Normal
    limit error-negative unsynced -1.5 0.0 0.01 0.01 Normal
    limit leap-insert synced-nts 0.0 0.0 0.01 0.01 "Insert second"
    limit leap-delete synced-nts 0.0 0.0 0.01 0.01 "Delete second"
    limit leap-unsynchronised unsynced 0.0 0.0 0.01 0.01 "Not synchronised"
    limit leap-invalid unsynced 0.0 0.0 0.01 0.01 "Invalid"

    scenario limit-local-refid
    fixture "$(track 7F7F0101 127.127.1.1 10 1792714555.6 0 0 0.01 0.01 Normal)" "${S1}"
    must_run "${shell}" tick
    check "chrony's LOCAL reference is not a source" 'd["state"] == "unsynced"'

    scenario limit-refid-zero
    fixture "$(track 00000000 '' 4 1792714555.6 0 0 0.01 0.01 Normal)" "${S1}"
    must_run "${shell}" tick
    check "no reference id" 'd["state"] == "unsynced"'

    scenario limit-stratum-zero
    fixture "$(track 7F000001 127.0.0.1 0 1792714555.6 0 0 0.01 0.01 Normal)" "${S1}"
    must_run "${shell}" tick
    check "stratum 0" 'd["state"] == "unsynced"'

    scenario limit-no-reftime
    fixture "$(track 7F000001 127.0.0.1 4 0.000000000 0 0 0.01 0.01 Normal)" "${S1}"
    must_run "${shell}" tick
    check "no reference time" 'd["state"] == "unsynced" and d["last_sync_at"] is None'

    scenario limit-source-offset
    fixture "$(track 7F000001 127.0.0.1 4 1792714555.6 0 0 0.01 0.01 Normal)" '^,*,127.0.0.1,3,0,377,2,2.5,2.5,0.00001'
    must_run "${shell}" tick
    check "the selected source disagrees by 2.5 s (maxchange refused to correct it)" \
        'd["state"] == "unsynced" and d["offset_ms"] is None and d["last_sync_at"] == ts(1792714555)'

    scenario limit-source-offset-bound
    fixture "$(track 7F000001 127.0.0.1 4 1792714555.6 0 0 0.01 0.01 Normal)" '^,*,127.0.0.1,3,0,377,2,-1.0,-1.0,0.00001'
    must_run "${shell}" tick
    check "the selected source disagrees by exactly 1 s" 'd["state"] == "synced-nts"'

    # offset_ms: chrony's last offset in ms, rounded half away from zero, signed.
    offset() {
        scenario "offset-$1"
        fixture "$(track 7F000001 127.0.0.1 4 1792714555.6 0 "$1" 0.01 0.01 Normal)" "${S1}"
        must_run "${shell}" tick
        check "offset $1" "d[\"offset_ms\"] == $2"
    }
    offset 0.0123 12
    offset 0.0125 13
    offset -0.0123 -12
    offset -0.0125 -13
    offset -0.000004 0
    offset 0.9 900

    # --- the floor ------------------------------------------------------------------------------
    AUTH="${NTS_AUTH}"

    scenario apply-build
    set_clock 500
    must_run "${shell}" floor-apply
    [ "$(cat "${F}/date-set.log")" = "@${BUILD}" ] || fail "the clock must be raised to the build time: $(cat "${F}/date-set.log" 2> /dev/null)"
    [ "$(cat "${F}/clock")" = "${BUILD}" ] || fail "the fake clock was not set"
    check "floor-apply: only the build time" 'd["state"] == "unsynced" and d["floor_at"] == ts(1760000000)'
    [ "$(cat "${R}/run/suderra-os/time/applied")" = "${BUILD} 100" ] || fail "the applied floor and uptime must be recorded: $(cat "${R}/run/suderra-os/time/applied")"
    [ ! -s "${F}/installer.log" ] || fail "no RTC: a clock below the floor is normal and records nothing: $(installer_log)"

    scenario apply-persisted
    set_floor 1790000000
    set_clock 1780000000
    must_run "${shell}" floor-apply
    [ "$(cat "${F}/date-set.log")" = "@1790000000" ] || fail "the clock must be raised to the persisted floor: $(cat "${F}/date-set.log")"
    check "floor-apply: persisted above build" 'd["floor_at"] == ts(1790000000)'

    scenario apply-persisted-below-build
    set_floor 1750000000
    set_clock 1755000000
    must_run "${shell}" floor-apply
    [ "$(cat "${F}/date-set.log")" = "@${BUILD}" ] || fail "the build time wins over an older persisted floor"

    scenario apply-clock-ahead
    set_floor 1780000000
    set_clock 1790000000
    must_run "${shell}" floor-apply
    [ ! -e "${F}/date-set.log" ] || fail "a clock above the floor is left alone"
    check "the floor in force stays the floor" 'd["floor_at"] == ts(1780000000)'

    for bad in abc 0123 99999999999999 '' '1.5' '-5'; do
        scenario "apply-bad-floor"
        mkdir -p "${R}/data/suderra/os/time"
        printf '%s\n' "${bad}" > "${R}/data/suderra/os/time/floor"
        set_clock 500
        must_run "${shell}" floor-apply
        [ "$(cat "${F}/date-set.log")" = "@${BUILD}" ] || fail "a persisted floor of '${bad}' must be ignored"
        grep -q 'does not hold a time' "${R}.err" || [ -z "${bad}" ] || fail "an unusable persisted floor '${bad}' must be reported"
    done

    scenario apply-floor-is-a-directory
    mkdir -p "${R}/data/suderra/os/time/floor"
    set_clock 500
    must_run "${shell}" floor-apply
    [ "$(cat "${F}/date-set.log")" = "@${BUILD}" ] || fail "a floor that is not a file is ignored"
    if grep -v 'does not hold a time\|below the time floor\|raised to the time floor' "${R}.err"; then
        fail "the shell's own read error must not reach the journal"
    fi

    scenario no-proc-uptime
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    rm -f "${R}/proc/uptime"
    must_run "${shell}" tick
    [ ! -s "${R}.err" ] || fail "a missing /proc/uptime must not make noise: $(cat "${R}.err")"
    check "the document is written without /proc/uptime" 'd["state"] == "synced-nts"'

    scenario apply-no-newline
    mkdir -p "${R}/data/suderra/os/time"
    printf '1790000000' > "${R}/data/suderra/os/time/floor"
    printf '1760000000' > "${R}/usr/lib/suderra/build-epoch"
    set_clock 500
    must_run "${shell}" floor-apply
    [ "$(cat "${F}/date-set.log")" = "@1790000000" ] || fail "a floor file without a trailing newline must be read"

    scenario apply-no-build-epoch
    rm -f "${R}/usr/lib/suderra/build-epoch"
    set_floor 1790000000
    set_clock 500
    must_run "${shell}" floor-apply
    grep -q 'build-epoch' "${R}.err" || fail "a missing build time must be reported at boot"
    [ "$(cat "${F}/date-set.log")" = "@1790000000" ] || fail "the persisted floor still applies without a build time"

    scenario apply-set-fails
    set_clock 500
    : > "${F}/date-set-fails"
    must_run "${shell}" floor-apply
    grep -q 'could not be set' "${R}.err" || fail "a clock that cannot be set must be reported"
    check "the document is written anyway" 'd["state"] == "unsynced"'

    scenario apply-rtc-reset
    mkdir -p "${R}/sys/class/rtc/rtc0"
    set_clock 946684800
    must_run "${shell}" floor-apply
    grep -q -- '--kind time-state --outcome alarm --reason clock-below-floor' "${F}/installer.log" || fail "a reset RTC must record clock-below-floor: $(installer_log)"
    [ "$(wc -l < "${F}/installer.log")" -eq 1 ] || fail "one alarm per boot"
    set_clock 946684800
    must_run "${shell}" floor-apply
    [ "$(wc -l < "${F}/installer.log")" -eq 1 ] || fail "the alarm is once per boot"

    scenario apply-rtc-slightly-behind
    mkdir -p "${R}/sys/class/rtc/rtc0"
    set_floor 1790000000
    set_clock 1789999100
    must_run "${shell}" floor-apply
    [ ! -s "${F}/installer.log" ] || fail "an RTC 900 s behind is within the kernel's 11-minute copy: $(installer_log)"
    [ "$(cat "${F}/date-set.log")" = "@1790000000" ] || fail "the clock is still raised"
    scenario apply-rtc-behind-more
    mkdir -p "${R}/sys/class/rtc/rtc0"
    set_floor 1790000000
    set_clock 1789999099
    must_run "${shell}" floor-apply
    grep -q 'clock-below-floor' "${F}/installer.log" || fail "an RTC 901 s behind the floor lost its time"

    scenario apply-no-installer
    mkdir -p "${R}/sys/class/rtc/rtc0"
    set_clock 946684800
    # An image without the installer has none in PATH at all.
    mv "${WORK}/bin/suderra-installer" "${WORK}/suderra-installer.away"
    must_run "${shell}" floor-apply
    mv "${WORK}/suderra-installer.away" "${WORK}/bin/suderra-installer"
    check "no installer: the alarm is skipped, the document is written" 'd["state"] == "unsynced"'

    scenario apply-installer-fails
    mkdir -p "${R}/sys/class/rtc/rtc0"
    set_clock 946684800
    : > "${F}/installer-fails"
    must_run "${shell}" floor-apply
    grep -q 'result could not be recorded' "${R}.err" || fail "a result that cannot be recorded must be reported"

    # tick: the floor is enforced for an unsynchronized clock, and lowered for an authenticated one.
    scenario tick-raise
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    set_floor 1790000000
    set_clock 1700000000
    must_run "${shell}" tick
    [ "$(cat "${F}/date-set.log")" = "@1790000000" ] || fail "an unsynchronized clock below the floor is raised again by the tick"

    scenario tick-synced-below-floor
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    set_floor 1800000000
    must_run "${shell}" tick
    [ ! -e "${F}/date-set.log" ] || fail "the authenticated clock is never set to the floor"
    [ "$(floor_file)" = "${NOW}" ] || fail "an authenticated clock below the floor lowers the persisted floor (got $(floor_file))"
    grep -q 'clock-below-floor' "${F}/installer.log" || fail "an authenticated clock below the floor is an alarm"
    check "the document says what is" 'd["state"] == "synced-nts" and d["floor_at"] == ts(1792714600)'

    scenario tick-synced-below-build
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    printf '%s\n' 1800000000 > "${R}/usr/lib/suderra/build-epoch"
    must_run "${shell}" tick
    [ ! -e "${F}/date-set.log" ] || fail "the authenticated clock is never set to the build time"
    grep -q 'clock-below-floor' "${F}/installer.log" || fail "an authenticated clock below the image's build time is an alarm"
    check "the build time stays the floor" 'd["floor_at"] == ts(1800000000)'

    # persistence
    scenario save-first-sync
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" tick
    [ "$(floor_file)" = "${NOW}" ] || fail "the pass that first sees the clock synchronized saves it as the floor (got $(floor_file))"
    [ "$(stat -c '%a' "${R}/data/suderra/os/time/floor")" = 600 ] || fail "the floor file is root-only"
    [ "$(stat -c '%a' "${R}/data/suderra/os/time")" = 700 ] || fail "the floor directory is root-only"
    # shellcheck disable=SC2144
    if compgen -G "${R}/data/suderra/os/time/*.new.*" > /dev/null; then fail "a temporary floor was left behind"; fi
    set_clock $((NOW + 100))
    set_uptime 200
    must_run "${shell}" tick
    [ "$(floor_file)" = "${NOW}" ] || fail "later passes do not write /data (a pass 100 s later saved $(floor_file))"
    set_clock $((NOW + 3600))
    set_uptime 3700
    must_run "${shell}" floor-save
    [ "$(floor_file)" = "$((NOW + 3600))" ] || fail "floor-save (the hourly timer) saves the synchronized clock (got $(floor_file))"

    scenario tick-unsynced-saves-nothing
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    must_run "${shell}" tick
    must_run "${shell}" tick
    [ ! -e "${R}/data/suderra/os/time/floor" ] || fail "an unsynchronized pass must not write /data every 15 s (got $(floor_file))"

    scenario save-unsynced-extrapolates
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    set_floor 1790000000
    set_clock 1790000000
    set_uptime 50
    must_run "${shell}" floor-apply
    # The wall clock is now a reset RTC's lie; the floor advances by uptime only.
    set_clock 4000000000
    set_uptime 650
    must_run "${shell}" floor-save
    [ ! -s "${R}.err" ] || fail "a save without evidence of a synchronized clock must be silent: $(cat "${R}.err")"
    [ "$(floor_file)" = "1790000600" ] || fail "an unsynchronized clock saves the applied floor plus the uptime since, never the wall clock (got $(floor_file))"

    scenario save-never-lowers
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    set_floor 1790000000
    set_clock 1790000000
    set_uptime 50
    must_run "${shell}" floor-apply
    set_floor 1790005000
    set_clock 1790005100
    set_uptime 650
    must_run "${shell}" floor-save
    [ "$(floor_file)" = "1790005000" ] || fail "a save never lowers the floor: the extrapolated 1790000600 replaced 1790005000 (got $(floor_file))"

    scenario save-implausible
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    set_clock 4200000000
    must_run "${shell}" tick
    [ ! -e "${R}/data/suderra/os/time/floor" ] || fail "a time beyond 2100 is not saved as the floor"
    grep -q 'not a plausible time' "${R}.err" || fail "an implausible floor must be reported"

    scenario save-no-data
    rmdir "${R}/data/suderra/os"
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" tick
    grep -q 'cannot be saved' "${R}.err" || fail "an unmounted /data must be reported"
    check "the document is written without /data" 'd["state"] == "synced-nts"'

    scenario shutdown-fresh-evidence
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    set_uptime 1000
    must_run "${shell}" tick
    : > "${F}/chronyd-down"
    set_clock $((NOW + 60))
    set_uptime 1060
    must_run "${shell}" floor-save
    [ "$(floor_file)" = "$((NOW + 60))" ] || fail "at shutdown, after a synchronized tick a minute ago, the clock is the floor (got $(floor_file))"

    scenario shutdown-stale-evidence
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    set_uptime 1000
    must_run "${shell}" tick
    : > "${F}/chronyd-down"
    set_clock $((NOW + 5000))
    set_uptime 6000
    must_run "${shell}" floor-save
    [ ! -s "${R}.err" ] || fail "a save at shutdown must be silent: $(cat "${R}.err")"
    [ "$(floor_file)" = "${NOW}" ] || fail "stale evidence does not make the clock trusted (got $(floor_file))"

    scenario shutdown-unsynced
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    set_floor 1790000000
    set_clock 1790000000
    set_uptime 10
    must_run "${shell}" floor-apply
    set_uptime 400
    set_clock 1790000390
    must_run "${shell}" floor-save
    [ "$(floor_file)" = "1790000390" ] || fail "an unsynchronized clock saves the floor plus uptime at shutdown (got $(floor_file))"

    # --- the bounded wait -----------------------------------------------------------------------
    scenario wait-synced
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" wait --tries 30 --interval 2
    [ ! -e "${F}/sleep.log" ] || fail "a synchronized clock needs no wait"
    [ ! -s "${F}/installer.log" ] || fail "no result for a clock that was synchronized: $(installer_log)"
    check "wait ends with a document" 'd["state"] == "synced-nts"'

    scenario wait-becomes-synced
    AUTH="${NTS_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    cp "${F}/tracking.csv" "${F}/tracking.1.csv"
    cp "${F}/tracking.csv" "${F}/tracking.2.csv"
    printf '%s\n' "${NTS_TRACKING}" > "${F}/tracking.csv"
    printf '%s\n' "${NTS_SOURCE}" > "${F}/sources.csv"
    must_run "${shell}" wait --tries 30 --interval 2
    [ "$(wc -l < "${F}/sleep.log")" -eq 2 ] || fail "two unsynchronized checks, two sleeps: $(cat "${F}/sleep.log")"
    [ "$(head -n 1 "${F}/sleep.log")" = 2 ] || fail "the sleep is the interval"
    check "synchronized on the third check" 'd["state"] == "synced-nts"'
    [ ! -s "${F}/installer.log" ] || fail "no alarm for a clock that synchronized within the wait: $(installer_log)"

    scenario wait-never
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    must_run "${shell}" wait --tries 4 --interval 3
    [ "${RC}" -eq 0 ] || fail "the wait never fails the boot"
    [ "$(wc -l < "${F}/sleep.log")" -eq 3 ] || fail "four tries sleep three times: $(cat "${F}/sleep.log")"
    grep -q -- '--kind time-state --outcome alarm --reason clock-unsynced' "${F}/installer.log" || fail "an unsynchronized wait records clock-unsynced: $(installer_log)"
    grep -q 'chronyd reports it is not synchronised' "${F}/installer.log" || fail "the alarm says why"
    check "wait ends with a document" 'd["state"] == "unsynced"'
    must_run "${shell}" wait --tries 2 --interval 1
    [ "$(wc -l < "${F}/installer.log")" -eq 1 ] || fail "the alarm is once per boot: $(installer_log)"
    # The clock synchronizes later: one ok, once.
    printf '%s\n' "${NTS_TRACKING}" > "${F}/tracking.csv"
    printf '%s\n' "${NTS_SOURCE}" > "${F}/sources.csv"
    must_run "${shell}" tick
    grep -q -- '--kind time-state --outcome ok' "${F}/installer.log" || fail "a clock that synchronizes after the alarm records ok: $(installer_log)"
    [ "$(wc -l < "${F}/installer.log")" -eq 2 ] || fail "the ok is recorded once"
    must_run "${shell}" tick
    [ "$(wc -l < "${F}/installer.log")" -eq 2 ] || fail "no more results while synchronized: $(installer_log)"

    scenario wait-defaults
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    must_run "${shell}" wait
    [ "$(wc -l < "${F}/sleep.log")" -eq 29 ] || fail "without options the wait makes 30 checks (29 sleeps), got $(wc -l < "${F}/sleep.log")"
    [ "$(sort -u "${F}/sleep.log")" = 2 ] || fail "without options the wait sleeps 2 s between checks"

    scenario wait-zero-interval
    AUTH="${UNSYNCED_AUTH}"
    fixture "${UNSYNCED_TRACKING}" "${UNSYNCED_SOURCE}"
    must_run "${shell}" wait --tries 1 --interval 0
    [ ! -e "${F}/sleep.log" ] || fail "one try never sleeps"

    # --- the service loop -----------------------------------------------------------------------
    scenario run-passes
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" run --tries 3 --interval 15
    [ "$(cat "${F}/n")" = 3 ] || fail "three passes read tracking three times, got $(cat "${F}/n")"
    [ "$(wc -l < "${F}/sleep.log")" -eq 2 ] || fail "two sleeps between three passes: $(cat "${F}/sleep.log")"
    [ "$(sort -u "${F}/sleep.log")" = 15 ] || fail "the sleep is the interval"
    check "the loop leaves a document" 'd["state"] == "synced-nts"'

    scenario run-default-interval
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    must_run "${shell}" run --tries 2
    [ "$(cat "${F}/sleep.log")" = 15 ] || fail "without --interval the service passes every 15 s, got $(cat "${F}/sleep.log")"

    scenario run-survives-a-failed-pass
    AUTH="${NTS_AUTH}"
    fixture "${NTS_TRACKING}" "${NTS_SOURCE}"
    rmdir "${R}/run/suderra"
    run "${shell}" run --tries 2 --interval 0
    [ "${RC}" -eq 0 ] || fail "a failed pass must not end the loop (exit ${RC})"
    [ "$(grep -c 'could not be refreshed' "${R}.err")" -eq 2 ] || fail "each failed pass is reported: $(cat "${R}.err")"
    mkdir "${R}/run/suderra"
    must_run "${shell}" run --tries 1 --interval 0
    check "the next pass repairs the document" 'd["state"] == "synced-nts"'

    # --- the command line -----------------------------------------------------------------------
    scenario cli
    for args in "" "bogus" "--tries" "--tries x tick" "--interval -1 tick" "--root" "--nope tick" "tick tick"; do
        IFS=' ' read -r -a argv <<< "${args}"
        run "${shell}" "${argv[@]}"
        [ "${RC}" -eq 2 ] || fail "arguments '${args}' must exit 2, got ${RC}"
        grep -q 'Usage:\|needs a number' "${R}.err" || fail "arguments '${args}' must print the usage: $(cat "${R}.err")"
    done
    scenario no-run-dir
    rmdir "${R}/run/suderra"
    run "${shell}" tick
    [ "${RC}" -eq 1 ] || fail "without /run/suderra the helper fails loudly (got ${RC})"
done

echo "time state helper contract passed: ${n_scenario} scenarios under ${#shells[@]} shell(s)"

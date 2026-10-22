#!/usr/bin/env bash
#
# eMMC wear telemetry (ADR-048 DEC-24): suderra-emmc-wear turns the kernel's
# life_time and pre_eol_info attributes of each eMMC into
# /run/suderra-os/emmc-wear.json. The test runs the real script against fake
# sysfs trees (the registers' meaning is JEDEC JESD84-B51's, the attributes'
# format is Linux drivers/mmc/core/mmc.c's) and checks the document, its
# states, its mode and that the units run it.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
SCRIPT="${OVERLAY}/usr/sbin/suderra-emmc-wear"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -x "${SCRIPT}" ] || fail "suderra-emmc-wear is missing or not executable"

# Shells the script must run under: the host's /bin/sh and, where present,
# BusyBox ash, which the image's /bin/sh is.
shells=("/bin/sh")
if command -v busybox > /dev/null 2>&1; then
    shells+=("busybox sh")
elif [ "${SUDERRA_FAIL_ON_SKIP:-0}" = "1" ] || [ "${CI:-}" = "true" ]; then
    fail "busybox is required in CI (package busybox-static): the image's shell is BusyBox ash"
fi

card() {
    # card <tree> <host> <name> <life_time> <pre_eol_info>
    local dir="$1/$2/$3"
    mkdir -p "${dir}"
    [ -z "$4" ] || printf '%s\n' "$4" > "${dir}/life_time"
    [ -z "$5" ] || printf '%s\n' "$5" > "${dir}/pre_eol_info"
}

run() {
    # run <shell> <tree> -> prints the document
    local out="$2.json" cmd
    IFS=' ' read -r -a cmd <<< "$1"
    (umask 022 && "${cmd[@]}" "${SCRIPT}" "$2" "${out}" > "$2.log" 2>&1) || {
        cat "$2.log" >&2
        fail "suderra-emmc-wear failed under $1"
    }
    [ ! -e "${out}.new" ] || fail "the temporary file was left behind"
    [ "$(stat -c '%a' "${out}")" = 600 ] || fail "the document must be root-only (mode 600)"
    cat "${out}"
}

check() {
    # check <description> <document> <python expression over d>
    python3 -I - "$1" "$2" "$3" << 'PY'
import json, sys
description, text, expression = sys.argv[1:]
try:
    d = json.loads(text)
except ValueError as error:
    sys.exit(f"ERROR: {description}: not JSON ({error}): {text}")
if d.get("_type") != "suderra.emmc-wear.v1":
    sys.exit(f"ERROR: {description}: wrong _type: {text}")
if not eval(expression, {"d": d}):
    sys.exit(f"ERROR: {description}: expected {expression}, got {text}")
PY
}

n=0
for shell in "${shells[@]}"; do
    n=$((n + 1))
    tree() { echo "${WORK}/t${n}-$1"; }

    t="$(tree none)"; mkdir -p "${t}"
    check "no eMMC at all" "$(run "${shell}" "${t}")" \
        'd["supported"] is False and d["devices"] == [] and d["worst_state"] == "unknown"'

    t="$(tree missing-dir)"
    check "no mmc_host directory" "$(run "${shell}" "${t}")" 'd["devices"] == [] and d["supported"] is False'

    t="$(tree sd)"; mkdir -p "${t}/mmc0/mmc0:aaaa"
    check "an SD card has no wear attributes" "$(run "${shell}" "${t}")" 'd["devices"] == []'

    t="$(tree normal)"; card "${t}" mmc0 mmc0:0001 "0x01 0x01" "0x01"
    check "a new eMMC" "$(run "${shell}" "${t}")" \
        'd["supported"] is True and d["worst_state"] == "normal" and d["devices"][0]["device"] == "mmc0:0001" and d["devices"][0]["life_used_percent_upper_bound"] == 10 and d["devices"][0]["life_time_est_typ_a"] == 1 and d["devices"][0]["pre_eol_info"] == 1'

    t="$(tree mid)"; card "${t}" mmc0 mmc0:0001 "0x05 0x02" "0x01"
    check "50 % used is normal and reports the worse type" "$(run "${shell}" "${t}")" \
        'd["worst_state"] == "normal" and d["devices"][0]["life_used_percent_upper_bound"] == 50'

    t="$(tree warn-life)"; card "${t}" mmc0 mmc0:0001 "0x02 0x09" "0x01"
    check "80-90 % used warns" "$(run "${shell}" "${t}")" \
        'd["worst_state"] == "warning" and d["devices"][0]["life_used_percent_upper_bound"] == 90'

    t="$(tree warn-eol)"; card "${t}" mmc0 mmc0:0001 "0x01 0x01" "0x02"
    check "pre-EOL warning" "$(run "${shell}" "${t}")" 'd["worst_state"] == "warning"'

    t="$(tree urgent-eol)"; card "${t}" mmc0 mmc0:0001 "0x01 0x01" "0x03"
    check "pre-EOL urgent" "$(run "${shell}" "${t}")" 'd["worst_state"] == "urgent"'

    t="$(tree exceeded)"; card "${t}" mmc0 mmc0:0001 "0x0a 0x0b" "0x01"
    check "exceeded life" "$(run "${shell}" "${t}")" \
        'd["worst_state"] == "urgent" and d["devices"][0]["life_used_percent_upper_bound"] == 100'

    t="$(tree undefined)"; card "${t}" mmc0 mmc0:0001 "0x00 0x00" "0x00"
    check "a card that defines nothing" "$(run "${shell}" "${t}")" \
        'd["supported"] is True and d["worst_state"] == "unknown" and d["devices"][0]["state"] == "unknown" and d["devices"][0]["life_used_percent_upper_bound"] is None'

    t="$(tree garbage)"; card "${t}" mmc0 mmc0:0001 "garbage here" "zz"
    check "garbage attributes do not crash" "$(run "${shell}" "${t}")" \
        'd["devices"][0]["state"] == "unknown" and d["devices"][0]["life_time_est_typ_a"] is None'

    t="$(tree two)"; card "${t}" mmc0 mmc0:0001 "0x01 0x01" "0x01"; card "${t}" mmc1 mmc1:0001 "0x0b 0x01" "0x01"
    check "the worst card decides" "$(run "${shell}" "${t}")" \
        'd["worst_state"] == "urgent" and [x["state"] for x in d["devices"]] == ["normal", "urgent"]'

    t="$(tree rerun)"; card "${t}" mmc0 mmc0:0001 "0x01 0x01" "0x01"
    run "${shell}" "${t}" > /dev/null
    printf '%s\n' "0x0b 0x0b" > "${t}/mmc0/mmc0:0001/life_time"
    check "a second run replaces the document" "$(run "${shell}" "${t}")" 'd["worst_state"] == "urgent"'
done

# A warning is logged for the journal, a normal card is not.
t="${WORK}/log"; card "${t}" mmc0 mmc0:0001 "0x09 0x01" "0x01"
run /bin/sh "${t}" > /dev/null
grep -q 'WARNING: eMMC mmc0:0001 wear is warning' "${t}.log" || fail "a worn eMMC must be logged for the journal"
t="${WORK}/quiet"; card "${t}" mmc0 mmc0:0001 "0x01 0x01" "0x01"
run /bin/sh "${t}" > /dev/null
if grep -q WARNING "${t}.log"; then fail "a healthy eMMC must not warn"; fi

# The units run the script, daily, in a sandbox that can write only the document's tree.
UNITS="${OVERLAY}/etc/systemd/system"
grep -qx 'ExecStart=/usr/sbin/suderra-emmc-wear' "${UNITS}/suderra-emmc-wear.service" ||
    fail "suderra-emmc-wear.service must run /usr/sbin/suderra-emmc-wear"
grep -qx 'ReadWritePaths=/run/suderra-os' "${UNITS}/suderra-emmc-wear.service" ||
    fail "suderra-emmc-wear.service may write /run/suderra-os alone"
grep -qx 'ProtectSystem=strict' "${UNITS}/suderra-emmc-wear.service" || fail "suderra-emmc-wear.service must be sandboxed"
grep -qx 'OnUnitActiveSec=1d' "${UNITS}/suderra-emmc-wear.timer" || fail "the wear is recorded daily"
grep -qx 'OnBootSec=3min' "${UNITS}/suderra-emmc-wear.timer" || fail "the wear is recorded after boot"

echo "emmc wear contract passed"

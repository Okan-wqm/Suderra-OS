#!/usr/bin/env bash
#
# The clock trust helper against a real chronyd doing real NTS (ADR-048 DEC-7;
# EI-046): time-state-helper-test.sh runs suderra-time-state against captured
# chronyc reports, this test runs it against the daemon itself.
#
# One chronyd is an NTS server on the loopback (a self-signed certificate for
# `localhost`, NTS-KE on a TCP port, NTP on a UDP port, its own clock as the
# reference), a second is the client, configured like etc/chrony.conf (nts,
# authselectmode require, makestep 1.0 1, maxchange 1000 1 -1, maxdistance 3.0).
# Neither controls the system clock (-x), and `date -s` is a function that only
# records, so nothing here can move this host's clock. The helper's chronyc is
# a shim that points the real chronyc at the test's command socket.
#
#   1. a client with `nts` that has done NTS-KE and synchronized: synced-nts,
#      and the wait returns at once without an alarm;
#   2. the same server reached as plain NTP (authselectmode ignore, as a signed
#      site policy would need): synced-unauthenticated;
#   3. a client that reaches no server: unsynced, the bounded wait ends and
#      records its clock-unsynced alarm;
#   4. no chronyd at all: unsynced.
#
# Skipped (exit 77, a failure in CI) where chronyd with NTS, chronyc or openssl
# are missing.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-time-state"
CONTRACT="${ROOT}/contracts/suderra-edge/v1"
WORK="$(mktemp -d)"
PIDS=()

cleanup() {
    local pid
    for pid in "${PIDS[@]}"; do
        kill "${pid}" 2> /dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        wait "${pid}" 2> /dev/null || true
    done
    rm -rf "${WORK}"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

skip() {
    if [ "${SUDERRA_FAIL_ON_SKIP:-0}" = "1" ] || [ "${CI:-}" = "true" ]; then
        fail "$1 is required in CI"
    fi
    echo "SKIP: $1" >&2
    exit 77
}

CHRONYD=""
for candidate in "$(command -v chronyd 2> /dev/null || true)" /usr/sbin/chronyd; do
    if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
        CHRONYD="${candidate}"
        break
    fi
done
[ -n "${CHRONYD}" ] || skip "chronyd (package chrony)"
"${CHRONYD}" --version 2> /dev/null | grep -q '+NTS' || skip "a chronyd built with NTS"
CHRONYC="$(command -v chronyc 2> /dev/null || true)"
[ -n "${CHRONYC}" ] || skip "chronyc (package chrony)"
command -v openssl > /dev/null 2>&1 || skip "openssl"
command -v python3 > /dev/null 2>&1 || skip "python3"
[ -x "${SCRIPT}" ] || fail "suderra-time-state is missing or not executable"

shells=("sh")
if command -v busybox > /dev/null 2>&1; then
    shells+=("busybox sh")
fi

# Two ports free for TCP and UDP both.
IFS=" " read -r NTP_PORT NTSKE_PORT < <(python3 -I - << 'PY'
import socket

ports = []
while len(ports) < 2:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        tcp.bind(("127.0.0.1", 0))
        port = tcp.getsockname()[1]
        udp.bind(("127.0.0.1", port))
        ports.append(port)
    except OSError:
        pass
    finally:
        tcp.close()
        udp.close()
print(*ports)
PY
)

USER_NAME="$(id -un)"
# --- the server -----------------------------------------------------------------------------------------
mkdir -p "${WORK}/server/sock" "${WORK}/server/state"
chmod 0750 "${WORK}/server/sock"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "${WORK}/server/key.pem" -out "${WORK}/server/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" > /dev/null 2>&1 || fail "openssl could not make a certificate"
cat > "${WORK}/server/chrony.conf" << EOF
local stratum 3
allow 127.0.0.1
bindaddress 127.0.0.1
port ${NTP_PORT}
ntsport ${NTSKE_PORT}
ntsservercert ${WORK}/server/cert.pem
ntsserverkey ${WORK}/server/key.pem
ntsdumpdir ${WORK}/server/state
cmdport 0
bindcmdaddress ${WORK}/server/sock/chronyd.sock
pidfile ${WORK}/server/sock/chronyd.pid
EOF

# --- the clients -----------------------------------------------------------------------------------------
client_conf() {
    # client_conf <name> <source line> <authselectmode>
    local dir="${WORK}/$1"
    mkdir -p "${dir}/sock" "${dir}/state"
    chmod 0750 "${dir}/sock"
    cat > "${dir}/chrony.conf" << EOF
$2
nosystemcert
ntstrustedcerts ${WORK}/server/cert.pem
authselectmode $3
makestep 1.0 1
maxchange 1000 1 -1
maxdistance 3.0
rtcsync
port 0
cmdport 0
ntsdumpdir ${dir}/state
driftfile ${dir}/state/drift
bindcmdaddress ${dir}/sock/chronyd.sock
pidfile ${dir}/sock/chronyd.pid
EOF
}
client_conf nts "server localhost port ${NTP_PORT} ntsport ${NTSKE_PORT} iburst nts minpoll 0 maxpoll 0" require
client_conf plain "server localhost port ${NTP_PORT} iburst minpoll 0 maxpoll 0" ignore
# A client whose server nothing answers (a port nothing listens on).
client_conf dead "server localhost port 9 ntsport 9 iburst nts minpoll 0 maxpoll 0" require
for conf in "${WORK}/server/chrony.conf" "${WORK}/nts/chrony.conf" "${WORK}/plain/chrony.conf" "${WORK}/dead/chrony.conf"; do
    "${CHRONYD}" -p -f "${conf}" > /dev/null 2> "${WORK}/parse.err" || fail "chronyd -p refuses ${conf}: $(cat "${WORK}/parse.err")"
done

start() {
    # start <name>: chronyd -x (never the system clock) as this user
    "${CHRONYD}" -n -x -U -4 -u "${USER_NAME}" -f "${WORK}/$1/chrony.conf" > "${WORK}/$1/log" 2>&1 &
    PIDS+=("$!")
    LAST_PID="$!"
}

stop() {
    # stop <pid>
    kill "$1" 2> /dev/null || true
    wait "$1" 2> /dev/null || true
}

real_chronyc() {
    "${CHRONYC}" -h "${WORK}/$1/sock/chronyd.sock" "${@:2}"
}

wait_synchronized() {
    # wait_synchronized <client>: chronyd's own word, up to 60 s
    for _ in $(seq 1 120); do
        if real_chronyc "$1" -c tracking 2> /dev/null | grep -q ',Normal$'; then
            return 0
        fi
        sleep 0.5
    done
    cat "${WORK}/$1/log" >&2
    real_chronyc "$1" -c tracking >&2 || true
    return 1
}

# --- the helper's side -----------------------------------------------------------------------------------
mkdir -p "${WORK}/bin"
cat > "${WORK}/bin/chronyc" << 'EOF'
#!/bin/sh
# The helper names chrony's socket in /run/chrony; this test's daemons have their own.
args=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h) shift 2 ;;
        *) args="${args} $1"; shift ;;
    esac
done
# shellcheck disable=SC2086
exec "${REAL_CHRONYC}" -h "${CLIENT_SOCKET}" ${args}
EOF
cat > "${WORK}/bin/suderra-installer" << 'EOF'
#!/bin/sh
echo "$*" >> "${INSTALLER_LOG}"
EOF
chmod 0755 "${WORK}/bin/chronyc" "${WORK}/bin/suderra-installer"
cat > "${WORK}/prelude.sh" << 'EOF'
date() {
    case "$1" in
        -s) echo "date $*" >> "${INSTALLER_LOG}.clock"; return 1 ;;
        *) command date "$@" ;;
    esac
}
chgrp() { :; }
EOF

new_root() {
    HROOT="${WORK}/root-$1"
    mkdir -p "${HROOT}/run/suderra" "${HROOT}/run/suderra-os" "${HROOT}/data/suderra/os" "${HROOT}/usr/lib/suderra" "${HROOT}/proc"
    printf '1700000000\n' > "${HROOT}/usr/lib/suderra/build-epoch"
    cp /proc/uptime "${HROOT}/proc/uptime" 2> /dev/null || printf '1000.00 1000.00\n' > "${HROOT}/proc/uptime"
}

helper() {
    # helper <shell> <args...>: against HROOT, CLIENT_SOCKET and INSTALLER_LOG
    local shell="$1" cmd
    shift
    IFS=' ' read -r -a cmd <<< "${shell}"
    (
        export REAL_CHRONYC="${CHRONYC}" CLIENT_SOCKET INSTALLER_LOG
        export PATH="${WORK}/bin:${PATH}"
        # shellcheck disable=SC2016 # the program is the inner shell's
        "${cmd[@]}" -c '. "$1"; shift; SCRIPT="$1"; shift; set -- "$@"; . "${SCRIPT}"' _ "${WORK}/prelude.sh" "${SCRIPT}" --root "${HROOT}" "$@"
    ) > "${HROOT}.out" 2> "${HROOT}.err" || {
        cat "${HROOT}.err" >&2
        fail "suderra-time-state $* failed under ${shell}"
    }
}

check() {
    # check <description> <python expression over d>
    python3 -I - "$1" "$2" "${HROOT}/run/suderra/time-state" "${CONTRACT}" << 'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

description, expression, path, contract = sys.argv[1:]
text = Path(path).read_text(encoding="utf-8")
d = json.loads(text)
common = json.loads(Path(contract, "schemas/common.schema.json").read_text(encoding="utf-8"))
timestamp = re.compile(common["$defs"]["timestamp"]["pattern"])
schema = json.loads(Path(contract, "schemas/time-state.schema.json").read_text(encoding="utf-8"))
problems = []
if set(d) != set(schema["required"]) or d["_type"] != "suderra.time-state.v1":
    problems.append("members")
for field in ("floor_at", "updated_at"):
    if not timestamp.match(d[field]):
        problems.append(field)
if d["state"] == "unsynced":
    if d["offset_ms"] is not None:
        problems.append("offset_ms")
elif type(d["offset_ms"]) is not int or not timestamp.match(d["last_sync_at"] or ""):
    problems.append("synchronized members")
if problems:
    sys.exit(f"ERROR: {description}: {problems}: {text}")


def epoch(stamp):
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


now = datetime.now(timezone.utc).timestamp()
if not eval(expression, {"d": d, "epoch": epoch, "now": now}):
    sys.exit(f"ERROR: {description}: expected {expression}, got {text}")
PY
}

# 1. NTS ---------------------------------------------------------------------------------------------------
start server
SERVER_PID="${LAST_PID}"
sleep 1
start nts
NTS_PID="${LAST_PID}"
CLIENT_SOCKET="${WORK}/nts/sock/chronyd.sock"
wait_synchronized nts || fail "the NTS client never synchronized to the NTS server"
real_chronyc nts -c -n authdata | grep -q '^127.0.0.1,NTS,' || fail "chronyc does not report the source as NTS: $(real_chronyc nts -c -n authdata)"
INSTALLER_LOG="${WORK}/installer-nts.log"
: > "${INSTALLER_LOG}"
for shell in "${shells[@]}"; do
    new_root "nts-${shell// /-}"
    helper "${shell}" tick
    check "NTS under ${shell}" \
        'd["state"] == "synced-nts" and abs(d["offset_ms"]) < 100 and abs(epoch(d["last_sync_at"]) - now) < 90 and abs(epoch(d["updated_at"]) - now) < 30'
    start_s="$(date +%s)"
    helper "${shell}" wait --tries 5 --interval 1
    [ $(($(date +%s) - start_s)) -le 3 ] || fail "a synchronized clock must not be waited for"
    [ ! -s "${INSTALLER_LOG}" ] || fail "no alarm for a clock that is synchronized: $(cat "${INSTALLER_LOG}")"
    [ ! -e "${INSTALLER_LOG}.clock" ] || fail "the helper tried to set the clock: $(cat "${INSTALLER_LOG}.clock")"
done
stop "${NTS_PID}"

# 2. plain NTP ----------------------------------------------------------------------------------------------
start plain
PLAIN_PID="${LAST_PID}"
CLIENT_SOCKET="${WORK}/plain/sock/chronyd.sock"
wait_synchronized plain || fail "the plain client never synchronized"
for shell in "${shells[@]}"; do
    new_root "plain-${shell// /-}"
    helper "${shell}" tick
    check "plain NTP under ${shell}" 'd["state"] == "synced-unauthenticated" and abs(d["offset_ms"]) < 100'
done
stop "${PLAIN_PID}"
stop "${SERVER_PID}"

# 3. a client that reaches nothing --------------------------------------------------------------------------
start dead
DEAD_PID="${LAST_PID}"
CLIENT_SOCKET="${WORK}/dead/sock/chronyd.sock"
sleep 2
for shell in "${shells[@]}"; do
    new_root "dead-${shell// /-}"
    INSTALLER_LOG="${WORK}/installer-dead-${shell// /-}.log"
    : > "${INSTALLER_LOG}"
    helper "${shell}" wait --tries 3 --interval 1
    check "no server under ${shell}" 'd["state"] == "unsynced" and d["offset_ms"] is None'
    grep -q -- '--kind time-state --outcome alarm --reason clock-unsynced' "${INSTALLER_LOG}" ||
        fail "the bounded wait of a clock that never synchronizes records clock-unsynced under ${shell}: $(cat "${INSTALLER_LOG}")"
done
stop "${DEAD_PID}"

# 4. no chronyd ---------------------------------------------------------------------------------------------
sleep 1
for shell in "${shells[@]}"; do
    new_root "down-${shell// /-}"
    INSTALLER_LOG="${WORK}/installer-down.log"
    helper "${shell}" tick
    check "no daemon under ${shell}" 'd["state"] == "unsynced" and d["last_sync_at"] is None'
done

echo "time NTS loopback contract passed ($("${CHRONYD}" --version | head -n 1))"

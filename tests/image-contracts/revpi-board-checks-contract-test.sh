#!/usr/bin/env bash
#
# Mock-backed run of the Revolution Pi Connect 4 hardware checks
# (scripts/evidence/revpi-connect4-board-checks.sh).
#
# The collector reads the kernel's views of the hardware on a real board; the
# hardware checklist of docs/hardware/revpi-connect4.md section 6 cannot run in
# CI. What can run is the collector itself, on a directory laid out like the
# device's /proc, /sys, /dev and /etc: this test builds one that a correct
# Connect 4 image would show, proves every check passes on it, and proves that
# damaging each thing a check looks at fails that check and no other. The
# signature-stripping of the unsigned-module check is run on a synthetic module
# in the documented appended-signature format. The tpm-seal check runs its real
# tpm2-tools sequence against a software TPM (swtpm) that the collector's --tcti
# option points at, as it points at /dev/tpmrm0 on the board; the TPM's failure
# modes are tpm2-tools wrappers that break one step. The collector runs under
# dash, the strict POSIX shell standing in for the image's busybox sh.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKS="${ROOT}/scripts/evidence/revpi-connect4-board-checks.sh"
SH="$(command -v dash || command -v sh)"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECKS}" ] || fail "missing ${CHECKS}"
command -v python3 >/dev/null 2>&1 || fail "python3 is missing"
for tool in swtpm swtpm_setup tpm2_createprimary tpm2_pcrread tpm2_createpolicy tpm2_create tpm2_load \
    tpm2_unseal tpm2_pcrextend tpm2_pcrreset tpm2_flushcontext; do
    command -v "${tool}" >/dev/null 2>&1 ||
        fail "${tool} is missing (swtpm, swtpm-tools, tpm2-tools and libtss2-tcti-swtpm0: ci/Dockerfile and the contract-test jobs of build.yml and lint.yml install them)"
done

WORK="$(mktemp -d)"
# The software TPM's sockets live under a short path: a unix socket path is
# limited to about 100 characters and TMPDIR may be longer than that.
TPMDIR="$(mktemp -d /tmp/revpi-swtpm.XXXXXX)"
cleanup() {
    if [ -f "${TPMDIR}/swtpm.pid" ]; then kill "$(cat "${TPMDIR}/swtpm.pid")" 2>/dev/null || true; fi
    rm -rf "${WORK}" "${TPMDIR}"
}
trap cleanup EXIT

# A software TPM 2.0 with the SHA-256 PCR bank the SLB9670 runs, started clean.
mkdir -p "${TPMDIR}/state"
swtpm_setup --tpm2 --tpmstate "${TPMDIR}/state" --pcr-banks sha256 --overwrite >"${TPMDIR}/setup.log" 2>&1 ||
    { cat "${TPMDIR}/setup.log" >&2; fail "swtpm_setup failed"; }
swtpm socket --tpm2 --tpmstate "dir=${TPMDIR}/state" \
    --server "type=unixio,path=${TPMDIR}/tpm.sock" --ctrl "type=unixio,path=${TPMDIR}/tpm.sock.ctrl" \
    --flags startup-clear,not-need-init --daemon --pid "file=${TPMDIR}/swtpm.pid" ||
    fail "swtpm did not start"
TCTI="swtpm:path=${TPMDIR}/tpm.sock"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    tpm2_pcrread -T "${TCTI}" sha256:16 >/dev/null 2>&1 && break
    sleep 0.5
done
tpm2_pcrread -T "${TCTI}" sha256:16 >/dev/null 2>&1 || fail "the software TPM does not answer"

# A directory a correct Connect 4 image would show.
mkroot() { # <dir> <variant>
    local d="$1" variant="$2" a c
    rm -rf "${d}"
    mkdir -p "${d}/etc/suderra" "${d}/proc/device-tree" "${d}/proc/sys/kernel" "${d}/dev" \
        "${d}/sys/module/piControl" "${d}/sys/module/module/parameters" "${d}/sys/class/tpm/tpm0" \
        "${d}/sys/class/rtc/rtc0" "${d}/sys/class/tty/ttyAMA5" "${d}/sys/class/leds" \
        "${d}/sys/class/watchdog/watchdog0" "${d}/sys/kernel/security"
    printf 'BOARD_PROFILE=revpi-connect4\nARCH=aarch64\n' > "${d}/etc/suderra/board"
    printf 'kunbus,revpi-connect4\0brcm,bcm2711\0' > "${d}/proc/device-tree/compatible"
    printf '6.12.91-v8\n' > "${d}/proc/sys/kernel/osrelease"
    printf 'Linux version 6.12.91-v8 (build@ci) (gcc 13.4.0) #1 SMP PREEMPT_RT Sun May 24 2026\n' > "${d}/proc/version"
    : > "${d}/dev/piControl0"
    : > "${d}/dev/tpmrm0"
    : > "${d}/dev/rtc0"
    : > "${d}/dev/ttyAMA5"
    printf '2\n' > "${d}/sys/class/tpm/tpm0/tpm_version_major"
    printf 'rtc-pcf2127 1-0051\n' > "${d}/sys/class/rtc/rtc0/name"
    printf '1\n' > "${d}/sys/class/rtc/rtc0/hctosys"
    printf '1790000000\n' > "${d}/sys/class/rtc/rtc0/since_epoch"
    for a in a1 a2 a3 a4 a5; do
        for c in red green blue; do mkdir -p "${d}/sys/class/leds/${a}:${c}:status"; done
    done
    mkdir -p "${d}/sys/class/leds/power:1:fault"
    printf 'Broadcom BCM2835 Watchdog timer\n' > "${d}/sys/class/watchdog/watchdog0/identity"
    if [ "${variant}" = prod ]; then
        printf 'Y\n' > "${d}/sys/module/module/parameters/sig_enforce"
        printf 'none [integrity] confidentiality\n' > "${d}/sys/kernel/security/lockdown"
        printf 'console=ttyS0,115200 console=tty1 root=/dev/mapper/suderra-root ro rootwait rauc.slot=A suderra.verity.root_hash=00ff lockdown=confidentiality\n' > "${d}/proc/cmdline"
    else
        printf 'N\n' > "${d}/sys/module/module/parameters/sig_enforce"
        printf '[none] integrity confidentiality\n' > "${d}/sys/kernel/security/lockdown"
        printf 'console=serial0,115200 console=tty1 root=PARTUUID=5d3e0a11-02 rootfstype=ext4 rootwait ro\n' > "${d}/proc/cmdline"
    fi
}

# COLLECTOR_PATH, when set, is the PATH of the collector alone.
run_checks() { # <root> <out> <args...>: the collector's exit status; output in <out>.log
    local r="$1" o="$2"
    shift 2
    rm -rf "${o}"
    PATH="${COLLECTOR_PATH:-${PATH}}" "${SH}" "${CHECKS}" --root "${r}" --out "${o}" --tcti "${TCTI}" "$@" >"${o}.log" 2>&1 || return $?
}

status_of() { # <out> <check>
    python3 -I -c '
import json, sys
print(json.load(open(sys.argv[1] + "/checks.json"))[sys.argv[2]]["status"])' "$1" "$2"
}

expect_pass() { # <label> <root> <out> <args...>
    local label="$1" r="$2" o="$3"
    shift 3
    run_checks "${r}" "${o}" "$@" || { cat "${o}.log" >&2; fail "${label}: the checks failed on a correct board"; }
    echo "  passes: ${label}"
}

# expect_fail <label> <check> <root> <out> <args...>: exit 1, that check failed,
# and every other check still passed (the damage is attributed to what it hit).
expect_fail() {
    local label="$1" check="$2" r="$3" o="$4" rc=0 other
    shift 4
    run_checks "${r}" "${o}" "$@" || rc=$?
    [ "${rc}" = 1 ] || { cat "${o}.log" >&2; fail "${label}: expected exit 1, got ${rc}"; }
    [ "$(status_of "${o}" "${check}")" = failed ] || fail "${label}: ${check} did not fail"
    other="$(python3 -I -c '
import json, sys
c = json.load(open(sys.argv[1] + "/checks.json"))
print(" ".join(sorted(k for k, v in c.items() if v["status"] != "passed" and k != sys.argv[2])))' "${o}" "${check}")"
    [ -z "${other}" ] || fail "${label}: also failed: ${other}"
    echo "  rejects: ${label}"
}

# --- the collector's own contract -------------------------------------------
echo "collector"
"${SH}" "${CHECKS}" >/dev/null 2>&1 && fail "a run without --out was accepted"
"${SH}" "${CHECKS}" --out "${WORK}/x" --variant staging >/dev/null 2>&1 && fail "an unknown variant was accepted"
"${SH}" "${CHECKS}" --bogus >/dev/null 2>&1 && fail "an unknown option was accepted"
echo "  refuses a bad command line"

# --- a correct production board --------------------------------------------
echo "production board"
mkroot "${WORK}/prod" prod
expect_pass "a correct production Connect 4" "${WORK}/prod" "${WORK}/out-prod" --variant prod

python3 -I - "${WORK}/out-prod" <<'PY' || fail "checks.json is not the record shape suderra-lab.py takes"
import json, os, sys
out = sys.argv[1]
checks = json.load(open(out + "/checks.json"))
want = {"board-identity", "kernel", "revpi-io", "tpm", "tpm-seal", "rtc", "rtc-hctosys", "rs485",
        "leds", "watchdog", "module-signing", "boot-chain"}
assert set(checks) == want, sorted(set(checks) ^ want)
for name, rec in checks.items():
    assert set(rec) == {"path", "status", "command", "expected", "observed"}, name
    assert rec["status"] == "passed", name
    assert os.path.isfile(os.path.join(out, rec["path"])), name
    assert open(os.path.join(out, rec["path"])).read().count("status:   passed") == 1, name
PY
echo "  writes the record shape suderra-lab.py takes (board-identity, watchdog and revpi-io among them)"

# Each thing a check looks at, damaged on its own.
damage() { # <label> <check> <variant> <mutation shell snippet run in the root> [args...]
    local label="$1" check="$2" variant="$3" snippet="$4"
    shift 4
    mkroot "${WORK}/m" "${variant}"
    (cd "${WORK}/m" && eval "${snippet}")
    expect_fail "${label}" "${check}" "${WORK}/m" "${WORK}/out-m" --variant "${variant}" "$@"
}
damage "a board profile that is not the Connect 4" board-identity prod 'printf "BOARD_PROFILE=rpi4-cm4\n" > etc/suderra/board'
damage "a device tree that is not the Connect 4's" board-identity prod "printf 'raspberrypi,4-compute-module\\0brcm,bcm2711\\0' > proc/device-tree/compatible"
damage "the old raspberrypi kernel" kernel prod 'printf "6.6.28-v8\n" > proc/sys/kernel/osrelease'
damage "a kernel that is not real-time" kernel prod 'printf "Linux version 6.12.91-v8 #1 SMP PREEMPT\n" > proc/version'
damage "no /dev/piControl0" revpi-io prod 'rm dev/piControl0'
damage "piControl not loaded" revpi-io prod 'rmdir sys/module/piControl'
damage "no TPM resource-manager node" tpm prod 'rm dev/tpmrm0'
damage "a TPM 1.2" tpm prod 'printf "1\n" > sys/class/tpm/tpm0/tpm_version_major'
damage "the DS1307 as RTC" rtc prod 'printf "rtc-ds1307 1-0068\n" > sys/class/rtc/rtc0/name'
damage "an RTC the kernel could not read at boot (hctosys 0)" rtc-hctosys prod 'printf "0\n" > sys/class/rtc/rtc0/hctosys'
damage "a kernel without CONFIG_RTC_HCTOSYS" rtc-hctosys prod 'rm sys/class/rtc/rtc0/hctosys'
damage "no RS485 UART" rs485 prod 'rm dev/ttyAMA5'
damage "a missing status LED" leds prod 'rmdir sys/class/leds/a3:blue:status'
damage "a missing power LED" leds prod 'rmdir sys/class/leds/power:1:fault'
damage "no hardware watchdog" watchdog prod 'rm -r sys/class/watchdog/watchdog0'
damage "a watchdog that is not the BCM2835's" watchdog prod 'printf "Some Other Watchdog\n" > sys/class/watchdog/watchdog0/identity'
damage "a production kernel that accepts unsigned modules" module-signing prod 'printf "N\n" > sys/module/module/parameters/sig_enforce'
damage "a production kernel that is not locked down" module-signing prod 'printf "[none] integrity confidentiality\n" > sys/kernel/security/lockdown'
damage "a production command line without the verity root hash" boot-chain prod 'printf "console=ttyS0,115200 ro\n" > proc/cmdline'
damage "a production console on the PL011" boot-chain prod 'printf "console=ttyAMA0,115200 suderra.verity.root_hash=00ff\n" > proc/cmdline'

# --- the tpm-seal check against the software TPM -------------------------------
echo "tpm seal"
ZERO="0x0000000000000000000000000000000000000000000000000000000000000000"
pcr_value() { # <index>: the PCR's value in the software TPM
    tpm2_pcrread -T "${TCTI}" "sha256:$1" 2>/dev/null | sed -n "s/^ *$1 *: *\\(0x[0-9a-f]*\\)\$/\\1/p"
}
[ "$(pcr_value 16)" = "${ZERO}" ] || fail "PCR 16 is not zero after the runs above: the check leaves it extended"
[ "$(pcr_value 7)" = "${ZERO}" ] || fail "PCR 7 is not zero: a check extended the PCR the /data seal binds"
grep -q 'sealed 32 bytes to PCR 7 and 16 under the null hierarchy' "${WORK}/out-prod/tpm-seal.txt" ||
    fail "the evidence does not say what was sealed"
grep -q 'PCR 16 reset' "${WORK}/out-prod/tpm-seal.txt" || fail "the evidence does not say PCR 16 was reset"
[ ! -e "${WORK}/out-prod/tpm-seal.work" ] || fail "the check left its work directory, and the secret it sealed, behind"
echo "  seals, unseals, is refused after a PCR 16 change, and leaves every PCR as it found it"

# Wrappers of single tpm2-tools programs: a directory searched first by the collector.
SHIMS="${WORK}/shims"
new_shims() { rm -rf "${SHIMS}"; mkdir -p "${SHIMS}"; rm -f "${WORK}/unseal-count" "${WORK}/tool-calls"; }
add_shim() { # <tool>, the wrapper's body on stdin; REAL is the real program
    local real
    real="$(command -v "$1")"
    { printf '#!/bin/sh\nREAL=%s\n' "${real}"; cat; } > "${SHIMS}/$1"
    chmod +x "${SHIMS}/$1"
}
shimmed() { PATH="${SHIMS}:${PATH}" "$@"; }

# What the collector asks the TPM for: a null-hierarchy primary (never the owner's), a
# policy over PCR 7 (the PCR the /data seal binds) and PCR 16, the unseal under that
# policy twice, and the only PCR writes: one extend and one reset, both of PCR 16.
new_shims
for tool in tpm2_createprimary tpm2_createpolicy tpm2_unseal tpm2_pcrextend tpm2_pcrreset; do
    add_shim "${tool}" <<EOF
echo "${tool} \$@" >> "${WORK}/tool-calls"
exec "\${REAL}" "\$@"
EOF
done
shimmed expect_pass "a correct board with the TPM calls recorded" "${WORK}/prod" "${WORK}/out-pcr" --variant prod
calls() { grep -Ec -- "$1" "${WORK}/tool-calls" || true; }
[ "$(calls '^tpm2_createprimary -T [^ ]+ -C n -G ecc -c ')" = 1 ] || fail "the primary is not made under the null hierarchy: $(grep '^tpm2_createprimary' "${WORK}/tool-calls")"
[ "$(calls '^tpm2_createpolicy ')" = 1 ] && [ "$(calls '^tpm2_createpolicy -T [^ ]+ --policy-pcr -l sha256:7,16 ')" = 1 ] ||
    fail "the policy is not over PCR 7 and 16: $(grep '^tpm2_createpolicy' "${WORK}/tool-calls")"
[ "$(calls '^tpm2_unseal ')" = 2 ] && [ "$(calls '^tpm2_unseal -T [^ ]+ -c [^ ]+ -p pcr:sha256:7,16 -o ')" = 2 ] ||
    fail "the unseals do not present PCR 7 and 16: $(grep '^tpm2_unseal' "${WORK}/tool-calls")"
[ "$(calls '^tpm2_pcrextend ')" = 1 ] && [ "$(calls '^tpm2_pcrextend -T [^ ]+ 16:sha256=[0-9a-f]{64}$')" = 1 ] ||
    fail "the PCR extend is not one extend of PCR 16: $(grep '^tpm2_pcrextend' "${WORK}/tool-calls")"
[ "$(calls '^tpm2_pcrreset ')" = 1 ] && [ "$(calls '^tpm2_pcrreset -T [^ ]+ 16$')" = 1 ] ||
    fail "the PCR reset is not one reset of PCR 16: $(grep '^tpm2_pcrreset' "${WORK}/tool-calls")"
[ "$(pcr_value 7)" = "${ZERO}" ] || fail "PCR 7 changed"
echo "  asks for a null-hierarchy seal to PCR 7 and 16 and writes PCR 16 only"

new_shims
add_shim tpm2_unseal <<'EOF'
out=""
while [ $# -gt 0 ]; do
    [ "$1" = -o ] && out="$2"
    shift
done
printf 'not the secret' > "${out}"
EOF
shimmed expect_fail "a TPM whose unseal returns other bytes" tpm-seal "${WORK}/prod" "${WORK}/out-t" --variant prod
grep -q 'differ from the sealed secret' "${WORK}/out-t/tpm-seal.txt" || fail "the failure does not say the bytes differ"

new_shims
add_shim tpm2_pcrextend <<'EOF'
exit 0
EOF
shimmed expect_fail "a TPM that releases the secret after the PCR changed" tpm-seal "${WORK}/prod" "${WORK}/out-t" --variant prod
grep -q 'policy is not enforced' "${WORK}/out-t/tpm-seal.txt" || fail "the failure does not say the policy is not enforced"

new_shims
add_shim tpm2_unseal <<EOF
n=\$(cat "${WORK}/unseal-count" 2>/dev/null || echo 0)
echo \$((n + 1)) > "${WORK}/unseal-count"
if [ "\${n}" -ge 1 ]; then
    echo "ERROR: Esys_Unseal(0x902) - tpm:warn(2.0): out of memory for object contexts" >&2
    exit 1
fi
exec "\${REAL}" "\$@"
EOF
shimmed expect_fail "a refusal after the PCR change that is not the policy's" tpm-seal "${WORK}/prod" "${WORK}/out-t" --variant prod
grep -q 'not by the policy' "${WORK}/out-t/tpm-seal.txt" || fail "the failure does not say the refusal was not the policy's"

for step in tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_pcrread tpm2_createpolicy tpm2_pcrextend; do
    new_shims
    add_shim "${step}" <<'EOF'
echo "ERROR: simulated failure" >&2
exit 1
EOF
    shimmed expect_fail "a TPM whose ${step} fails" tpm-seal "${WORK}/prod" "${WORK}/out-t" --variant prod
    grep -q "${step}.* failed: ERROR: simulated failure" "${WORK}/out-t/tpm-seal.txt" ||
        fail "the failure of ${step} is not named in the evidence"
done
[ "$(pcr_value 16)" = "${ZERO}" ] || fail "PCR 16 is not zero after a failure that followed the extend"

new_shims
add_shim tpm2_pcrreset <<'EOF'
echo "ERROR: simulated failure" >&2
exit 1
EOF
shimmed expect_pass "a TPM that refuses to reset PCR 16 (the debug PCR; noted, not a seal failure)" "${WORK}/prod" "${WORK}/out-t" --variant prod
grep -q 'PCR 16 could not be reset' "${WORK}/out-t/tpm-seal.txt" || fail "the evidence does not say PCR 16 stayed extended"
tpm2_pcrreset -T "${TCTI}" 16 >/dev/null 2>&1 || fail "could not reset PCR 16 of the software TPM"

expect_fail "no TPM behind the TCTI" tpm-seal "${WORK}/prod" "${WORK}/out-t" --variant prod --tcti "swtpm:path=${WORK}/nothing-listens"

# tpm2-tools without one program: a PATH holding the collector's tools and all but that one.
for missing in tpm2_pcrread tpm2_unseal tpm2_pcrreset; do
    rm -rf "${WORK:?}/bin"
    mkdir -p "${WORK}/bin"
    for t in head tail tr sed wc od cat cmp grep mkdir rm basename \
        tpm2_createprimary tpm2_pcrread tpm2_createpolicy tpm2_create tpm2_load tpm2_unseal \
        tpm2_pcrextend tpm2_pcrreset tpm2_flushcontext; do
        [ "${t}" = "${missing}" ] || ln -s "$(command -v "${t}")" "${WORK}/bin/${t}"
    done
    COLLECTOR_PATH="${WORK}/bin" expect_fail "tpm2-tools without ${missing}" tpm-seal "${WORK}/prod" "${WORK}/out-t" --variant prod
    grep -q "${missing} is not installed" "${WORK}/out-t/tpm-seal.txt" || fail "the failure does not name ${missing}"
done

# --- the dev board ------------------------------------------------------------
echo "dev board"
mkroot "${WORK}/dev" dev
expect_pass "a correct dev Connect 4 (no forced signatures)" "${WORK}/dev" "${WORK}/out-dev" --variant dev
mkroot "${WORK}/prod-as-dev" dev
rc=0
run_checks "${WORK}/prod-as-dev" "${WORK}/out-pad" --variant prod || rc=$?
[ "${rc}" = 1 ] || fail "a dev board passed the production checks"
[ "$(status_of "${WORK}/out-pad" module-signing)" = failed ] || fail "module-signing passed on a dev kernel judged as production"
[ "$(status_of "${WORK}/out-pad" boot-chain)" = failed ] || fail "boot-chain passed on a dev command line judged as production"
echo "  rejects: a dev board judged as production"

# --- the unsigned-module check -------------------------------------------------
echo "unsigned module"
python3 -I - "${WORK}" <<'PY'
import struct, sys
work = sys.argv[1]
payload = bytes(range(256)) * 3 + b"module body"
def build(sig_len, signer_len=0, key_id_len=0, marker=True):
    sig = b"S" * sig_len
    body = payload + b"N" * (signer_len + key_id_len) + sig
    body += struct.pack(">BBBBB3xI", 0, 2, 2, signer_len, key_id_len, sig_len)
    if marker:
        body += b"~Module signature appended~\n"
    return body
open(work + "/payload.ko", "wb").write(payload)
open(work + "/signed-258.ko", "wb").write(build(258))          # sig_len 0x00000102: two length bytes
open(work + "/signed-65537.ko", "wb").write(build(65537))      # 0x00010001: three
open(work + "/signed-signer.ko", "wb").write(build(100, signer_len=8))
# sig_len 0x01000001 uses all four length bytes; the signature bytes are a hole
# in a sparse file (no disk), the head and the tail are the real format.
sig_len = 0x01000001
with open(work + "/signed-16777217.ko", "wb") as f:
    f.write(payload)
    f.seek(len(payload) + sig_len)
    f.write(struct.pack(">BBBBB3xI", 0, 2, 2, 0, 0, sig_len))
    f.write(b"~Module signature appended~\n")
open(work + "/unsigned-build.ko", "wb").write(payload)
PY
cat > "${WORK}/insmod-kernel" <<'EOF'
#!/bin/sh
# A kernel that enforces module signatures: it keeps a copy of what it was asked to load.
cp "$1" "${CAPTURE}"
if tail -c 28 "$1" | grep -q 'Module signature appended'; then
    exit 0
fi
echo "insmod: ERROR: could not insert module $1: Key was rejected by service" >&2
exit 1
EOF
cat > "${WORK}/insmod-lax" <<'EOF'
#!/bin/sh
# A kernel that loads anything.
exit 0
EOF
cat > "${WORK}/insmod-other" <<'EOF'
#!/bin/sh
echo "insmod: ERROR: could not insert module $1: Invalid module format" >&2
exit 1
EOF
chmod +x "${WORK}/insmod-kernel" "${WORK}/insmod-lax" "${WORK}/insmod-other"

with_module() { # <signed fixture name>: the smallest module of the fixture root
    mkroot "${WORK}/mod" prod
    mkdir -p "${WORK}/mod/lib/modules/6.12.91-v8/extra"
    cp "${WORK}/$1" "${WORK}/mod/lib/modules/6.12.91-v8/extra/piControl.ko"
}
for fx in signed-258 signed-65537 signed-16777217; do
    with_module "${fx}.ko"
    rm -f "${WORK}/capture.ko"
    CAPTURE="${WORK}/capture.ko" run_checks "${WORK}/mod" "${WORK}/out-mod" --variant prod \
        --try-unsigned-insmod --insmod "${WORK}/insmod-kernel" ||
        { cat "${WORK}/out-mod.log" >&2; fail "${fx}: the unsigned-module check failed against a kernel that refuses it"; }
    cmp -s "${WORK}/capture.ko" "${WORK}/payload.ko" ||
        fail "${fx}: the module the kernel was asked to load is not the module body without its signature"
    [ "$(status_of "${WORK}/out-mod" unsigned-module-rejected)" = passed ] || fail "${fx}: not recorded as passed"
done
echo "  strips the appended signature exactly (two-, three- and four-byte lengths) and passes when the kernel refuses it"

with_module signed-258.ko
CAPTURE="${WORK}/capture.ko" expect_fail "a kernel that loads an unsigned module" unsigned-module-rejected \
    "${WORK}/mod" "${WORK}/out-mod" --variant prod --try-unsigned-insmod --insmod "${WORK}/insmod-lax"
grep -q 'loaded' "${WORK}/out-mod/unsigned-module-rejected.txt" || fail "the failure does not say the module loaded"
CAPTURE="${WORK}/capture.ko" expect_fail "a refusal that is not about the signature" unsigned-module-rejected \
    "${WORK}/mod" "${WORK}/out-mod" --variant prod --try-unsigned-insmod --insmod "${WORK}/insmod-other"
with_module unsigned-build.ko
CAPTURE="${WORK}/capture.ko" expect_fail "a module that was never signed" unsigned-module-rejected \
    "${WORK}/mod" "${WORK}/out-mod" --variant prod --try-unsigned-insmod --insmod "${WORK}/insmod-kernel"
with_module signed-signer.ko
CAPTURE="${WORK}/capture.ko" expect_fail "a signature with a signer name (not PKCS#7)" unsigned-module-rejected \
    "${WORK}/mod" "${WORK}/out-mod" --variant prod --try-unsigned-insmod --insmod "${WORK}/insmod-kernel"
mkroot "${WORK}/nomod" prod
CAPTURE="${WORK}/capture.ko" expect_fail "no module under /lib/modules" unsigned-module-rejected \
    "${WORK}/nomod" "${WORK}/out-mod" --variant prod --try-unsigned-insmod --insmod "${WORK}/insmod-kernel"

# The same collector run by bash must agree (the device runs busybox sh, a
# developer's host may run bash).
BASH_OUT="${WORK}/out-bash"
bash "${CHECKS}" --root "${WORK}/prod" --out "${BASH_OUT}" --tcti "${TCTI}" --variant prod >/dev/null 2>&1 || fail "the collector fails under bash"
cmp -s "${WORK}/out-prod/checks.json" "${BASH_OUT}/checks.json" || fail "bash and dash disagree on checks.json"
echo "  agrees under bash and dash"

echo "revpi board checks contract passed"

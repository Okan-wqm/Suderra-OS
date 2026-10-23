#!/usr/bin/env bash
#
# Authenticated time of the image (ADR-048 DEC-7; EI-046, EI-052).
#
# The image's time identity is NTS-authenticated chrony, and it is made of
# parts that each fail silently on their own: chrony builds NTS only when gnutls
# is present and drops it without an error otherwise, the configuration is
# only as good as the daemon that reads it, and a unit that is not ordered or
# not enabled does nothing. This test holds the parts to each other:
#
# 1. The chronyd feature gate (scripts/ci/check-chrony-features.py) accepts a
#    chronyd that reports +NTS and refuses one without it, one that carries no
#    feature string and a missing one, and post-build.sh runs it.
# 2. Config.in selects chrony and gnutls (and with it nettle, whose AES-SIV
#    chrony uses) for every defconfig, by an option nobody can switch off: the
#    Buildroot-resolved .config of every defconfig has them, and the same
#    resolution of a tree without the select does not.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for tool in python3 make gcc; do
    command -v "${tool}" > /dev/null 2>&1 || fail "${tool} is required"
done
[ -f "${ROOT}/buildroot/Config.in" ] || fail "the buildroot submodule is not checked out"

CHECKER="${ROOT}/scripts/ci/check-chrony-features.py"
python3 -B -m py_compile "${CHECKER}"

# --- 1. the chronyd feature gate ---------------------------------------------------------------
python3 -I - "${CHECKER}" "${WORK}" << 'PY'
import subprocess
import sys
from pathlib import Path

checker, work = sys.argv[1], Path(sys.argv[2])
GOOD = b"+CMDMON +NTP +REFCLOCK +RTC +PRIVDROP -SCFILTER -SIGND +ASYNCDNS +NTS +SECHASH +IPV6 -DEBUG"
NO_NTS = GOOD.replace(b"+NTS +SECHASH", b"-NTS -SECHASH")
NO_PRIVDROP = GOOD.replace(b"+PRIVDROP", b"-PRIVDROP")
NO_RTC = GOOD.replace(b"+RTC", b"-RTC")
failures = []


def target(name: str, chronyd: bytes | None) -> Path:
    root = work / name
    (root / "usr/sbin").mkdir(parents=True)
    if chronyd is not None:
        (root / "usr/sbin/chronyd").write_bytes(chronyd)
    return root


def blob(*strings: bytes) -> bytes:
    """A stand-in binary: noise, the strings as NUL-terminated literals, noise."""
    return b"\x7fELF\x00\x01" + b"".join(b"\x00junk\x00" + s + b"\x00" for s in strings) + b"\x00tail\x00"


def run(root: Path):
    return subprocess.run([sys.executable, "-I", "-B", checker, str(root)], capture_output=True, text=True, check=False)


def expect(name: str, root: Path, ok: bool, needle: str = "") -> None:
    result = run(root)
    if ok and result.returncode != 0:
        failures.append(f"{name}: expected success, got {result.returncode}: {result.stderr}")
    if not ok:
        if result.returncode != 1:
            failures.append(f"{name}: expected exit 1, got {result.returncode}: {result.stderr}")
        if needle not in result.stderr:
            failures.append(f"{name}: the error must mention {needle!r}: {result.stderr}")


expect("good", target("good", blob(GOOD)), True)
expect("the real build before the fix", target("no-nts", blob(NO_NTS)), False, "lacks +NTS")
expect("the gnutls hint", target("no-nts-hint", blob(NO_NTS)), False, "BR2_PACKAGE_GNUTLS")
expect("no privilege drop", target("no-privdrop", blob(NO_PRIVDROP)), False, "lacks +PRIVDROP")
expect("no RTC support", target("no-rtc", blob(NO_RTC)), False, "lacks +RTC")
expect("no chronyd at all", target("missing", None), False, "is not in the target")
expect("no feature string", target("bare", blob(b"nothing of interest")), False, "no chrony feature string")
expect(
    "two different strings",
    target("two", blob(GOOD, NO_NTS)),
    False,
    "different feature strings",
)
# A line of prose that starts like a feature string is not one.
expect(
    "prose is not a feature string",
    target("prose", blob(b"+CMDMON is documented in chrony.conf(5)")),
    False,
    "no chrony feature string",
)
expect("one string twice is one string", target("twice", blob(GOOD, GOOD)), True)
# A feature present only as a longer token must not satisfy the check: "+NTSX".
expect(
    "a token that merely starts with the feature",
    target("prefix", blob(GOOD.replace(b"+NTS ", b"+NTSX "))),
    False,
    "lacks +NTS",
)

if failures:
    print("\n".join(f"ERROR: {line}" for line in failures), file=sys.stderr)
    sys.exit(1)
print("chronyd feature gate: synthetic targets ok")
PY

grep -q 'check-chrony-features.py' "${ROOT}/board/suderra/common/post-build.sh" ||
    fail "post-build.sh does not run check-chrony-features.py"
python3 -I - "${ROOT}/board/suderra/common/post-build.sh" << 'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
gate = text.index("check-chrony-features.py")
# After the units are kept or removed and before the command gate: the binary
# it checks is in the target tree already, and a failure stops the build.
if gate < text.index("# 7. Read-only root mutable state") or gate > text.index("check-target-commands.py"):
    sys.exit("ERROR: post-build.sh must run the chrony feature gate after the image is assembled and before the command gate")
PY

# --- 2. Config.in selects chrony and gnutls for every image --------------------------------------
resolve() {
    # resolve <external-tree> <defconfig> <output-dir>
    make -s -C "${ROOT}/buildroot" BR2_EXTERNAL="$1" O="$3" "$2" > "$3.log" 2>&1 ||
        fail "Buildroot could not resolve $2 (see $3.log): $(tail -n 5 "$3.log")"
}

defconfigs=()
for file in "${ROOT}"/configs/*_defconfig; do
    defconfigs+=("$(basename -- "${file}")")
done
[ "${#defconfigs[@]}" -ge 9 ] || fail "expected at least 9 defconfigs, found ${#defconfigs[@]}"
for defconfig in "${defconfigs[@]}"; do
    out="${WORK}/resolved-${defconfig%_defconfig}"
    resolve "${ROOT}" "${defconfig}" "${out}"
    for symbol in BR2_PACKAGE_SUDERRA_TIME_SYNC BR2_PACKAGE_CHRONY BR2_PACKAGE_GNUTLS BR2_PACKAGE_NETTLE; do
        grep -qx "${symbol}=y" "${out}/.config" ||
            fail "${defconfig}: the resolved .config lacks ${symbol}=y (chrony would be built -NTS, EI-052)"
    done
    if grep -q '^BR2_PACKAGE_GNUTLS' "${ROOT}/configs/${defconfig}"; then
        fail "${defconfig}: gnutls must come from Config.in, not from the defconfig"
    fi
done

# The same resolution of an external tree without the select must lack gnutls:
# the check is not vacuous.
mutated="${WORK}/mutated-external"
mkdir -p "${mutated}"
cp -r "${ROOT}/Config.in" "${ROOT}/external.desc" "${ROOT}/external.mk" "${ROOT}/configs" "${ROOT}/package" "${mutated}/"
python3 -I - "${mutated}/Config.in" << 'PY'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
mutated = text.replace("\tselect BR2_PACKAGE_GNUTLS\n", "")
if mutated == text:
    sys.exit("ERROR: Config.in no longer selects BR2_PACKAGE_GNUTLS in the form this test mutates")
open(path, "w", encoding="utf-8").write(mutated)
PY
resolve "${mutated}" suderra_qemu_x86_64_prod_ab_defconfig "${WORK}/resolved-mutated"
if grep -qx 'BR2_PACKAGE_GNUTLS=y' "${WORK}/resolved-mutated/.config"; then
    fail "an external tree without the select still resolves gnutls: something else selects it and this test proves nothing"
fi

echo "time sync contract passed"

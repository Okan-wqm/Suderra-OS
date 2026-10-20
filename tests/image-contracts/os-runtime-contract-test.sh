#!/usr/bin/env bash
#
# The runtime a Suderra OS image offers an agent binary matches boards.json
# os_runtime (ADR-048 DEC-8.5; INFRA-MEDIUM-253).
#
# The release pipeline checks a built binary against os_runtime (ELF NEEDED,
# program interpreter, highest GLIBC symbol version). That is only a gate if
# the table describes the images. This test compares it with what the images
# are built from: the Buildroot toolchain C library of every defconfig, the
# glibc version the pinned Buildroot builds, and the libraries its glibc
# package installs on the target. Each mutation of the table or of the
# build inputs, applied to a scratch copy, is rejected.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

CHECK="$(mktemp)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}" "${CHECK}"' EXIT

cat >"${CHECK}" <<'PY'
import fnmatch
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
errors = []

boards = json.loads((root / "contracts/suderra-edge/v1/boards.json").read_text())
runtime = boards["os_runtime"]
if runtime["libc"] != "glibc":
    errors.append(f"os_runtime.libc is {runtime['libc']!r}; every image builds glibc")

# glibc version the pinned Buildroot builds.
mk = (root / "buildroot/package/glibc/glibc.mk").read_text()
match = re.search(r"^GLIBC_VERSION\s*=\s*(\d+\.\d+)(?:[-.\s]|$)", mk, re.M)
if not match:
    errors.append("buildroot glibc.mk has no GLIBC_VERSION")
elif match.group(1) != runtime["glibc_version"]:
    errors.append(
        f"os_runtime.glibc_version {runtime['glibc_version']} but Buildroot builds glibc {match.group(1)}"
    )

# Libraries glibc.mk installs on the target (patterns), plus libgcc_s which
# the same list names.
block = re.search(r"^GLIBC_LIBS_LIB\s*=\s*((?:.*\\\n)*.*)$", mk, re.M)
patterns = re.findall(r"[A-Za-z0-9_*.]+\.so\.\*", block.group(1)) if block else []
if not patterns:
    errors.append("buildroot glibc.mk has no GLIBC_LIBS_LIB list")

for arch, spec in runtime["shared_libraries"].items():
    interpreter = spec["interpreter"].rsplit("/", 1)[-1]
    if interpreter not in spec["needed"]:
        errors.append(f"{arch}: the interpreter {interpreter} is not in needed")
    for needed in spec["needed"]:
        if not any(fnmatch.fnmatch(needed, pattern) for pattern in patterns):
            errors.append(f"{arch}: {needed} is not installed by Buildroot's glibc package")

# Every image builds the Buildroot glibc toolchain.
configs = sorted((root / "configs").glob("*_defconfig"))
if not configs:
    errors.append("no defconfigs found")
for config in configs:
    text = config.read_text()
    if not re.search(r"^BR2_TOOLCHAIN_BUILDROOT_GLIBC=y$", text, re.M):
        errors.append(f"{config.name} does not build the Buildroot glibc toolchain")
    if not re.search(r'^BR2_TOOLCHAIN_BUILDROOT_LIBC="glibc"$', text, re.M):
        errors.append(f"{config.name} does not name glibc as the toolchain libc")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(
    f"os-runtime: glibc {runtime['glibc_version']} and "
    f"{sum(len(s['needed']) for s in runtime['shared_libraries'].values())} libraries match "
    f"Buildroot and {len(configs)} defconfigs"
)
PY

python3 -I "${CHECK}" "${ROOT}" || fail "os_runtime does not match the images"

# Mutations of the table and of the build inputs, each on a scratch copy.
fresh_copy() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree/contracts/suderra-edge/v1" "${WORK}/tree/buildroot/package/glibc" "${WORK}/tree/configs"
    cp "${ROOT}/contracts/suderra-edge/v1/boards.json" "${WORK}/tree/contracts/suderra-edge/v1/"
    cp "${ROOT}/buildroot/package/glibc/glibc.mk" "${WORK}/tree/buildroot/package/glibc/"
    cp "${ROOT}"/configs/*_defconfig "${WORK}/tree/configs/"
}
expect_rejected() {
    local what="$1"
    if python3 -I "${CHECK}" "${WORK}/tree" >/dev/null 2>&1; then
        fail "${what} was accepted"
    fi
}

fresh_copy
sed -i 's/"glibc_version": "[0-9.]*"/"glibc_version": "2.39"/' "${WORK}/tree/contracts/suderra-edge/v1/boards.json"
expect_rejected "a glibc_version the pinned Buildroot does not build"

fresh_copy
sed -i '0,/"libm.so.6"/s//"libnotinstalled.so.9"/' "${WORK}/tree/contracts/suderra-edge/v1/boards.json"
expect_rejected "a needed library no Buildroot package installs"

fresh_copy
sed -i -E 's/(^|[[:space:]])libm\.so\.\*//' "${WORK}/tree/buildroot/package/glibc/glibc.mk"
expect_rejected "a glibc package that no longer installs a needed library"

fresh_copy
first="$(find "${WORK}/tree/configs" -name '*_defconfig' | sort | head -1)"
sed -i 's/^BR2_TOOLCHAIN_BUILDROOT_GLIBC=y$/BR2_TOOLCHAIN_BUILDROOT_MUSL=y/' "${first}"
expect_rejected "an image that does not build glibc"

fresh_copy
sed -i 's/"libc": "glibc"/"libc": "musl"/' "${WORK}/tree/contracts/suderra-edge/v1/boards.json"
expect_rejected "a table that names another libc"

echo "os-runtime-contract: OK"

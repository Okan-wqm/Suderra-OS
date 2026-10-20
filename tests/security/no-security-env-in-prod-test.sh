#!/usr/bin/env bash
#
# Production mode and security decisions never come from the environment
# (ADR-048 DEC-19, DEC-4.5).
#
# Any unit file or drop-in can change a service's environment, so a security
# decision taken from it would rest on data outside the verity root. This
# test scans the production code paths written in shell and systemd:
#   * the rootfs overlay's runtime helpers (usr/sbin) and every script a
#     package installs into the target (found from the packages' .mk install
#     lines, so a new script is scanned without editing this test) must not
#     read a SUDERRA_* variable;
#   * no Suderra unit or drop-in sets a SUDERRA_* variable through
#     Environment= or reads an EnvironmentFile=.
# The Rust programs carry the same invariant as unit tests
# (suderra-installer variant.rs production_sources_read_no_environment,
# suderra-ota production mode from the image).
#
# ALLOWED is empty. An entry would be "<path>:<VARIABLE> <justification>"
# and needs review; a variable that selects a key, a verifier, a floor, a
# device, a mode or a path is never allowed.
#
# TRACKED holds scripts that still violate the rule, each with its open
# finding (owner and deadline in the finding). The claim of this test is
# therefore: no production script reads security environment except the
# tracked ones. A tracked script that no longer violates fails the test, so
# the entry is removed with the fix.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
ALLOWED=()
# <path> <finding> — see the header.
TRACKED=(
    "package/suderra-os-installer/suderra-os-install docs/assessments/2026-10-19-edge-agent-integration-audit.md#EI-076 (@Okan-wqm, 2026-11-30)"
)

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

scripts=()
for f in "${OVERLAY}"/usr/sbin/*; do
    [ -f "${f}" ] && scripts+=("${f}")
done
# Every package file an install line copies from the package build dir
# ($(@D)/<name>) into the target that is a script (#! first line).
while IFS= read -r f; do
    scripts+=("${f}")
done < <(python3 -I - "${ROOT}" <<'PY'
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
for mk in sorted((root / "package").glob("*/*.mk")):
    text = mk.read_text(encoding="utf-8").replace("\\\n", " ")
    for line in text.splitlines():
        if "$(INSTALL)" not in line or "$(TARGET_DIR)" not in line:
            continue
        for name in re.findall(r"\$\(@D\)/([A-Za-z0-9._-]+)", line):
            src = mk.parent / name
            if src.is_file() and src.read_bytes()[:2] == b"#!":
                print(src)
PY
)
[ "${#scripts[@]}" -gt 0 ] || fail "found no runtime scripts to scan"
for must in package/suderra-rauc-config/suderra-rauc-mark-good \
            package/suderra-rauc-config/suderra-rauc-health-gate \
            package/suderra-os-installer/suderra-os-install; do
    printf '%s\n' "${scripts[@]}" | grep -qx "${ROOT}/${must}" ||
        fail "the package install-line scan missed ${must}"
done

violations=0
for f in "${scripts[@]}"; do
    rel="${f#"${ROOT}/"}"
    tracked=0
    for entry in "${TRACKED[@]}"; do
        [ "${entry%% *}" = "${rel}" ] && tracked=1
    done
    if [ "${tracked}" = "1" ]; then
        if grep -nE '\$\{?SUDERRA_[A-Z0-9_]+' "${f}" | grep -qvE '^[0-9]+:[[:space:]]*#'; then
            echo "tracked: ${rel} still reads SUDERRA_* from the environment (${entry#* })"
        else
            echo "ERROR: ${rel} no longer reads security environment: remove it from TRACKED" >&2
            violations=1
        fi
        continue
    fi
    while IFS= read -r hit; do
        variable="$(printf '%s\n' "${hit}" | grep -oE 'SUDERRA_[A-Z0-9_]+' | head -n 1)"
        allowed=0
        for entry in "${ALLOWED[@]+"${ALLOWED[@]}"}"; do
            [ "${entry%% *}" = "${rel}:${variable}" ] && allowed=1
        done
        if [ "${allowed}" = "0" ]; then
            echo "ERROR: ${rel}: reads ${variable} from the environment: ${hit}" >&2
            violations=1
        fi
    done < <(grep -nE '\$\{?SUDERRA_[A-Z0-9_]+' "${f}" | grep -vE '^[0-9]+:[[:space:]]*#' || true)
done

while IFS= read -r unit; do
    if grep -nE '^[[:space:]]*Environment=.*SUDERRA_' "${unit}"; then
        echo "ERROR: ${unit#"${ROOT}/"} sets a SUDERRA_* variable" >&2
        violations=1
    fi
    if grep -nE '^[[:space:]]*EnvironmentFile=' "${unit}"; then
        case "${unit}" in
            # Buildroot's dropbear.service reads /etc/default/dropbear, a
            # verity-root file holding DROPBEAR_ARGS only.
            */dropbear.service.d/*) ;;
            *)
                echo "ERROR: ${unit#"${ROOT}/"} reads an EnvironmentFile=" >&2
                violations=1
                ;;
        esac
    fi
done < <(find "${OVERLAY}/etc/systemd/system" "${ROOT}/package" -type f \
    \( -name '*.service' -o -name '*.conf' -o -name '*.path' -o -name '*.timer' \) -not -path '*/buildroot/*')

if grep -q 'SUDERRA_' "${OVERLAY}/etc/default/dropbear"; then
    fail "/etc/default/dropbear may hold DROPBEAR_ARGS only"
fi

[ "${violations}" = "0" ] || exit 1
echo "no security environment in production contract passed (${#scripts[@]} scripts, ${#TRACKED[@]} tracked)"

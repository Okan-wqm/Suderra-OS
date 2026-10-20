#!/usr/bin/env bash
#
# Production mode and security decisions never come from the environment
# (ADR-048 DEC-19, DEC-4.5).
#
# Any unit file or drop-in can change a service's environment, so a security
# decision taken from it would rest on data outside the verity root. This
# test scans the production code paths written in shell and systemd:
#   * the rootfs overlay's runtime helpers (usr/sbin) and the runtime scripts
#     packages install into production images (suderra-rauc-config) must not
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
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
ALLOWED=()

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

scripts=()
for f in "${OVERLAY}"/usr/sbin/* \
         "${ROOT}"/package/suderra-rauc-config/suderra-rauc-* \
         "${ROOT}"/package/suderra-rauc-config/*.sh; do
    [ -f "${f}" ] || continue
    case "${f}" in
        *.service|*.mount|*.conf|*.in|*.mk) continue ;;
    esac
    scripts+=("${f}")
done
[ "${#scripts[@]}" -gt 0 ] || fail "found no runtime scripts to scan"

violations=0
for f in "${scripts[@]}"; do
    rel="${f#"${ROOT}/"}"
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
echo "no security environment in production contract passed"

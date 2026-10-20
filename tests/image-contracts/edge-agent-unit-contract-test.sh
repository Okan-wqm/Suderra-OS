#!/usr/bin/env bash
#
# suderra-agent.service contract (ADR-048 DEC-1.1, DEC-1.8, DEC-4.11, DEC-25).
#
# Suderra OS ships exactly one agent unit, the rootfs-overlay
# suderra-agent.service, plus one board drop-in per board_profile under
# suderra-agent.service.d/. Its security-relevant directives are not listed
# here: contracts/suderra-edge/v1/unit-directives.json is their single source,
# shared with the generic-Linux reference unit and the cloud's fleet unit.
# scripts/ci/check-unit-directives.py implements that contract's parsing and
# comparison rules; it must first reproduce the verdict and the violation set
# of every golden unit fixture, then accept the overlay unit with each board's
# drop-in.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACT_DIR="${ROOT}/contracts/suderra-edge/v1"
DIRECTIVES="${CONTRACT_DIR}/unit-directives.json"
CHECKER="${ROOT}/scripts/ci/check-unit-directives.py"
OVERLAY_SYSTEMD="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system"
UNIT="${OVERLAY_SYSTEMD}/suderra-agent.service"
DROPIN_DIR="${OVERLAY_SYSTEMD}/suderra-agent.service.d"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${DIRECTIVES}" ] || fail "missing contract ${DIRECTIVES}"
[ -f "${UNIT}" ] || fail "missing overlay agent unit ${UNIT}"

# The checker agrees with the contract on every golden unit fixture.
python3 -I "${CHECKER}" --contract "${DIRECTIVES}" --fixtures "${CONTRACT_DIR}/fixtures/index.json" ||
    fail "check-unit-directives.py disagrees with the contract's golden unit fixtures"

# The contract names the overlay unit and the drop-in path pattern.
mapfile -t contract_paths < <(python3 -I - "${DIRECTIVES}" <<'PY'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
p = c["profiles"]["suderra-os"]
print(p["unit_path"])
print(p["board_dropins"]["path"])
for board in sorted(p["board_dropins"]["boards"]):
    print(board)
PY
)
[ "${contract_paths[0]}" = "board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service" ] ||
    fail "unit-directives.json names ${contract_paths[0]} as the suderra-os unit, not the overlay unit"
dropin_pattern="${contract_paths[1]}"
boards=("${contract_paths[@]:2}")
[ "${#boards[@]}" -gt 0 ] || fail "unit-directives.json lists no board drop-ins"

for board in "${boards[@]}"; do
    dropin="${ROOT}/${dropin_pattern//\{board_profile\}/${board}}"
    [ -f "${dropin}" ] || fail "missing board drop-in for ${board}: ${dropin}"
    python3 -I "${CHECKER}" --contract "${DIRECTIVES}" --profile suderra-os \
        --unit "${UNIT}" --board "${board}" --dropin "${dropin}" ||
        fail "overlay suderra-agent.service with the ${board} drop-in violates unit-directives.json"
done

# No drop-in for a board the contract does not know.
for dropin in "${DROPIN_DIR}"/*; do
    name="$(basename "${dropin}")"
    known=0
    for board in "${boards[@]}"; do
        [ "${name}" = "10-board-${board}.conf" ] && known=1
    done
    [ "${known}" = "1" ] || fail "unexpected agent drop-in ${name}: the contract lists no such board"
done

# One unit in every image (DEC-1.1): no package or second overlay ships
# another suderra-agent.service, and no defconfig can build the agent in.
while IFS= read -r other; do
    [ "${other}" = "${UNIT}" ] && continue
    fail "second suderra-agent.service in the tree: ${other}"
done < <(find "${ROOT}/board" "${ROOT}/package" -name suderra-agent.service -not -path '*/buildroot/*')
[ ! -e "${ROOT}/package/suderra-edge-agent" ] || fail "package/suderra-edge-agent must not exist (DEC-1.1)"
if grep -R -n 'SUDERRA_EDGE_AGENT' "${ROOT}/configs" "${ROOT}/Config.in"; then
    fail "no defconfig or Kconfig may reference the removed edge-agent package"
fi

# The image carries only its own board's drop-in: post-build.sh keeps the
# drop-in of the board_profile it declares in /etc/suderra/board and removes
# the others.
grep -q 'suderra-agent.service.d' "${POST_BUILD}" ||
    fail "post-build.sh must prune suderra-agent.service.d to the image's board drop-in"

#!/usr/bin/env bash
#
# Provisioning, lifecycle and firewall wiring of Suderra OS (ADR-048 DEC-5,
# DEC-11, DEC-12, DEC-17 flow a).
#
# * The provisioning surface (dropbear, the worker, the password guard) runs
#   only inside suderra-provision-mode's window, and the window opens only
#   while the root-owned lifecycle is PROVISIONING or reprovisioning
#   MAINTENANCE: the mode script's condition is exercised against a stub
#   installer for every lifecycle state.
# * Activation, lifecycle requests and the boot evaluation call the root
#   installer's lifecycle commands; lockdown is keyed on the verified ACTIVE
#   state, never on an agent-writable marker, and writes nothing under /etc.
# * The firewall loads fail-closed: base drop ruleset first (checked), then
#   `suderra-installer policy apply`; networkd requires it; the provisioning
#   ruleset scopes SSH to the default-route interface with a per-source meter
#   and the appliance ruleset opens no inbound service.
#
# The single-quoted patterns below match literal script text on purpose.
# shellcheck disable=SC2016
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
UNITS="${OVERLAY}/etc/systemd/system"
SBIN="${OVERLAY}/usr/sbin"
CLI="${ROOT}/userspace/suderra-installer/src/cli.rs"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

has_line() {
    grep -qxF -- "$2" "$1" || fail "${1#"${ROOT}/"} lacks: $2"
}

# --- The provisioning surface lives inside the window ----------------------
for unit in dropbear.service.d/10-suderra-provisioning.conf suderra-provision-worker.path \
    suderra-provision-worker.service suderra-provision-guard.service; do
    has_line "${UNITS}/${unit}" 'ConditionPathExists=/run/suderra-os/provisioning-open'
    has_line "${UNITS}/${unit}" 'BindsTo=suderra-provision-mode.service'
    grep -qE '^After=.*suderra-provision-mode\.service' "${UNITS}/${unit}" ||
        fail "${unit} must be ordered after suderra-provision-mode.service"
done
MODE_UNIT="${UNITS}/suderra-provision-mode.service"
has_line "${MODE_UNIT}" 'ExecCondition=/usr/sbin/suderra-provision-mode condition'
has_line "${MODE_UNIT}" 'ExecStart=/usr/sbin/suderra-provision-mode open'
has_line "${MODE_UNIT}" 'ExecStopPost=/usr/sbin/suderra-provision-mode close'
has_line "${MODE_UNIT}" 'Wants=dropbear.service suderra-provision-worker.path suderra-provision-guard.service'
# Its binds must reach the whole system: no private mount namespace.
if grep -qE '^(ProtectSystem|ProtectHome|PrivateTmp|ReadWritePaths|ReadOnlyPaths|PrivateDevices|PrivateMounts)=' "${MODE_UNIT}" \
   "${UNITS}/suderra-data.service" "${UNITS}/suderra-provision-guard.service"; then
    fail "units that bind-mount (data, provisioning mode, guard) must not get a private mount namespace"
fi
has_line "${UNITS}/suderra-provision-worker.path" 'PathExists=/var/spool/suderra-provision/inbox/trigger'
# Bound to and ordered after suderra-provision-mode.service (after
# basic.target), so it cannot keep a path unit's default Before=paths.target:
# that is an ordering cycle systemd breaks by dropping paths.target.
has_line "${UNITS}/suderra-provision-worker.path" 'DefaultDependencies=no'
has_line "${UNITS}/suderra-provision-worker.path" 'Conflicts=shutdown.target'
grep -q 'disable dropbear.service' "${POST_BUILD}" || fail "post-build must keep dropbear disabled at boot"
grep -q 'grep -qxF /usr/sbin/suderra-provision "${TARGET_DIR}/etc/shells"' "${POST_BUILD}" ||
    fail "post-build must list the forced provisioning command in /etc/shells (EI-003)"

# The window's condition, exercised for every lifecycle state.
sed -e "s#^INSTALLER=.*#INSTALLER=${WORK}/suderra-installer#" \
    -e "s#^RUN=.*#RUN=${WORK}/run#" \
    "${SBIN}/suderra-provision-mode" > "${WORK}/mode"
mkdir -p "${WORK}/run" "${WORK}/bin"
cat > "${WORK}/suderra-installer" <<'EOF'
#!/bin/sh
[ "$1 $2" = "lifecycle status" ] || exit 64
[ -n "${STUB_STATE}" ] || exit 1
echo "${STUB_STATE}"
EOF
cat > "${WORK}/bin/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >> "${STUB_CALLS}"
EOF
chmod 0755 "${WORK}/suderra-installer" "${WORK}/bin/systemctl"
export STUB_CALLS="${WORK}/calls"
run_mode() {
    set +e
    STUB_STATE="$1" PATH="${WORK}/bin:${PATH}" sh "${WORK}/mode" "$2" >/dev/null 2>&1
    echo $?
    set -e
}
expect_status() {
    local got
    got="$(run_mode "$1" "$2")"
    [ "${got}" = "$3" ] || fail "suderra-provision-mode $2 in ${1:-<unreadable>}: exit ${got}, want $3"
}
for state in PROVISIONING MAINTENANCE; do
    expect_status "${state}" condition 0
    expect_status "${state}" awaiting-activation 0
done
for state in FACTORY ACTIVE LOCKED DECOMMISSIONED RMA; do
    expect_status "${state}" condition 1
    expect_status "${state}" awaiting-activation 1
done
expect_status "" condition 255
expect_status "" awaiting-activation 255
: > "${WORK}/run/provisioning-closed"
expect_status PROVISIONING condition 1
expect_status PROVISIONING awaiting-activation 0
rm -f "${WORK}/run/provisioning-closed"
# reconcile closes an open window when the state no longer allows it, or
# when its time is over, and leaves a valid window alone.
: > "${WORK}/run/provisioning-open"
echo 999999999 > "${WORK}/run/provisioning-expires"
: > "${STUB_CALLS}"
expect_status PROVISIONING reconcile 0
if grep -q 'stop suderra-provision-mode.service' "${STUB_CALLS}"; then
    fail "reconcile closed a valid provisioning window"
fi
expect_status ACTIVE reconcile 0
grep -q 'stop suderra-provision-mode.service' "${STUB_CALLS}" ||
    fail "reconcile must stop provisioning mode once the lifecycle left PROVISIONING"
grep -q 'reload nftables.service' "${STUB_CALLS}" || fail "reconcile must reload the firewall"
[ -e "${WORK}/run/provisioning-closed" ] || fail "reconcile must mark the window closed"
rm -f "${WORK}/run/provisioning-closed"
echo 0 > "${WORK}/run/provisioning-expires"
: > "${STUB_CALLS}"
expect_status PROVISIONING reconcile 0
grep -q 'stop suderra-provision-mode.service' "${STUB_CALLS}" ||
    fail "reconcile must close a provisioning window whose time is over"

# --- Token transport and the root installer --------------------------------
grep -q 'IFS= read -r token' "${SBIN}/suderra-provision" || fail "the forced command must read the token from stdin"
grep -q '"${INSTALLER}" edge provision --device-code "${device_code}"' "${SBIN}/suderra-provision-worker" ||
    fail "the worker must delegate to suderra-installer edge provision"
grep -q -- '--token-file "${WORK}/token"' "${SBIN}/suderra-provision-worker" ||
    fail "the worker must hand the token over as a root-only file, never on argv"
# One token limit: the forced command accepts MAX_TOKEN characters and writes
# them plus a newline; the worker and the installer accept MAX_TOKEN + 1 bytes.
token_max="$(sed -n 's/^MAX_TOKEN=\([0-9]*\)$/\1/p' "${SBIN}/suderra-provision")"
[ -n "${token_max}" ] || fail "suderra-provision must declare MAX_TOKEN"
grep -qx "if ! claim token $((token_max + 1)); then" "${SBIN}/suderra-provision-worker" ||
    fail "the worker must claim exactly MAX_TOKEN + 1 bytes (the token and its newline)"
grep -qx "const MAX_TOKEN: u64 = ${token_max};" "${ROOT}/userspace/suderra-installer/src/cmd/edge.rs" ||
    fail "the installer's MAX_TOKEN must equal suderra-provision's"
grep -q 'read_root_file(path, MAX_TOKEN + 1)' "${ROOT}/userspace/suderra-installer/src/cmd/edge.rs" ||
    fail "the installer must read the token file as MAX_TOKEN + 1 bytes"
for symbol in 'Provision(EdgeProvisionArgs)' 'pub device_code: String' 'pub token_file: std::path::PathBuf' \
    'VerifyCurrent' 'Init,' 'Activate,' 'Request,' 'Factory,' 'Apply,' 'Check,'; do
    grep -qF "${symbol}" "${CLI}" || fail "suderra-installer CLI lacks ${symbol} that the overlay calls"
done

# --- Lifecycle and activation ----------------------------------------------
has_line "${UNITS}/suderra-lifecycle.service" 'ExecStart=/usr/bin/suderra-installer lifecycle init'
has_line "${UNITS}/suderra-lifecycle.service" 'ExecStartPost=/usr/sbin/suderra-provision-mode reconcile'
has_line "${UNITS}/suderra-lifecycle.timer" 'Unit=suderra-lifecycle.service'
has_line "${UNITS}/suderra-lifecycle.path" 'PathChanged=/data/suderra/agent/state/lifecycle-request.dsse'
has_line "${UNITS}/suderra-lifecycle-request.service" 'ExecStart=/usr/bin/suderra-installer lifecycle request'
has_line "${UNITS}/suderra-activation.path" 'PathChanged=/data/suderra/agent/state/activation-receipt.dsse'
has_line "${UNITS}/suderra-activation.service" 'ExecCondition=/usr/sbin/suderra-provision-mode awaiting-activation'
has_line "${UNITS}/suderra-activation.service" 'ExecStart=/usr/bin/suderra-installer lifecycle activate'
has_line "${UNITS}/suderra-activation.service" 'ExecStartPost=/usr/sbin/suderra-lockdown'
for unit in suderra-lifecycle.path suderra-activation.path; do
    grep -qE '^After=.*suderra-data\.service' "${UNITS}/${unit}" ||
        fail "${unit} must start after /data is mounted, or its watch sees only the empty mountpoint"
done
grep -q '"${INSTALLER}" lifecycle factory' "${SBIN}/suderra-data-unlock" ||
    fail "suderra-data-unlock must create the lifecycle store as FACTORY on the boot that formats /data"
grep -q '^DATA_CREATED=/run/suderra-os/data-created$' "${SBIN}/suderra-data-unlock" &&
    grep -q 'printf .*> "${DATA_CREATED}"' "${SBIN}/suderra-data-unlock" ||
    fail "suderra-data-unlock must leave the data-created evidence (DEC-12)"

LOCKDOWN="${SBIN}/suderra-lockdown"
grep -q '\[ "${state}" = ACTIVE \]' "${LOCKDOWN}" || fail "lockdown must require the verified ACTIVE state"
grep -q 'systemctl stop suderra-provision-mode.service' "${LOCKDOWN}" ||
    fail "lockdown must close the provisioning window"
grep -q '\[ "${loaded}" = appliance \]' "${LOCKDOWN}" || fail "lockdown must load the appliance ruleset"
grep -q 'result write --kind lockdown --outcome ok' "${LOCKDOWN}" || fail "lockdown must write its result"
if grep -R -n -E 'appliance-locked|edge/registered|registration\.json' "${OVERLAY}" "${POST_BUILD}"; then
    fail "lock and registration state are root-verified lifecycle state, never marker files"
fi
if grep -n -E '\|\|[[:space:]]*true' "${LOCKDOWN}" "${SBIN}/suderra-provision-mode"; then
    fail "lockdown and provisioning mode must not ignore failures"
fi

# --- Fail-closed firewall --------------------------------------------------
NFT_UNIT="${UNITS}/nftables.service"
has_line "${NFT_UNIT}" 'ExecStartPre=/usr/sbin/nft -c -f /etc/nftables.base.conf'
has_line "${NFT_UNIT}" 'ExecStartPre=/usr/sbin/nft -f /etc/nftables.base.conf'
has_line "${NFT_UNIT}" 'ExecStart=/usr/bin/suderra-installer policy apply'
has_line "${NFT_UNIT}" 'OnFailure=suderra-network-failsafe.target'
has_line "${UNITS}/systemd-networkd.service.d/10-require-firewall.conf" 'Requires=nftables.service'
has_line "${UNITS}/systemd-networkd.service.d/10-require-firewall.conf" 'After=nftables.service'
grep -qE '^Conflicts=.*systemd-networkd\.service' "${UNITS}/suderra-network-failsafe.target" ||
    fail "the network failsafe target must keep systemd-networkd down"
BASE="${OVERLAY}/etc/nftables.base.conf"
APPLIANCE="${OVERLAY}/etc/nftables.conf"
PROVISIONING="${OVERLAY}/etc/nftables.provisioning.conf"
if grep -vE '^[[:space:]]*#' "${BASE}" | grep -qE '\b(ct|limit|meter|set|update)\b'; then
    fail "the base ruleset must load on any nf_tables kernel: no conntrack, limit, meter or set"
fi
grep -qE 'policy drop' "${BASE}" || fail "the base ruleset must drop by default"
if grep -vE '^[[:space:]]*#' "${APPLIANCE}" | grep -qE 'dport 22\b'; then
    fail "the appliance ruleset must not open SSH"
fi
grep -qE '^[[:space:]]*iifname \$provision_iface tcp dport 22 ct state new update @provision_ssh_sources \{ ip saddr limit rate [0-9]+/minute' "${PROVISIONING}" ||
    fail "provisioning SSH must be scoped to \$provision_iface with a per-source meter"
if grep -vE '^[[:space:]]*#' "${PROVISIONING}" | grep -E 'dport 22' | grep -vq 'provision_iface'; then
    fail "every provisioning SSH rule must be scoped to \$provision_iface"
fi
for ruleset in "${APPLIANCE}" "${PROVISIONING}"; do
    grep -q 'udp sport 67 udp dport 68 accept' "${ruleset}" || fail "${ruleset#"${ROOT}/"} must accept DHCP replies"
    grep -q 'udp sport 68 udp dport 67 accept' "${ruleset}" || fail "${ruleset#"${ROOT}/"} must allow DHCP requests"
    grep -q 'tcp dport 4460 accept' "${ruleset}" || fail "${ruleset#"${ROOT}/"} must allow NTS-KE"
done
# The rulesets also parse, when this host may run `nft -c` (it needs
# CAP_NET_ADMIN), against this host's nft and kernel only. Loading them on
# each image's own kernel needs a booted image: that is part of the ADR-048
# P0 exit runtime suite and is not automated yet, so this test makes no claim
# about the target kernels.
if command -v nft >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    nft -c -f "${BASE}" || fail "nft -c rejects the base ruleset"
    nft -c -f "${APPLIANCE}" || fail "nft -c rejects the appliance ruleset"
    printf 'define provision_iface = "eth0"\ninclude "%s"\n' "${PROVISIONING}" > "${WORK}/provisioning.nft"
    nft -c -f "${WORK}/provisioning.nft" || fail "nft -c rejects the provisioning ruleset"
    echo "nft -c: base, appliance and provisioning rulesets parse"
fi

echo "provisioning, lifecycle and firewall contract passed"

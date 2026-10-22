#!/usr/bin/env bash
#
# USB device policy of the production images (ADR-048 DEC-18.2).
#
# A running device has no USB storage, whatever a stick is labelled: usbguard
# blocks it, and allows only hubs, USB-serial adapters (the agent's RS485/RS232
# fieldbus) and HID, each by a narrow rule. This test holds the policy file, the
# daemon configuration, the defconfigs and post-build.sh to that statement, and
# parses every rule with usbguard's own parser (usbguard-rule-parser) so a rule
# the daemon would refuse to load fails here, not on a device that then has no
# policy.
#
# What a rule file cannot show is which descriptors a field adapter really has:
# that is the hardware list (docs/hardware), not this test.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
RULES="${OVERLAY}/etc/usbguard/rules.conf"
CONF="${OVERLAY}/etc/usbguard/usbguard-daemon.conf"
DROPIN="${OVERLAY}/etc/systemd/system/usbguard.service.d/10-suderra.conf"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

command -v usbguard-rule-parser >/dev/null 2>&1 || {
    echo "SKIP: usbguard-rule-parser is missing (apt: usbguard)" >&2
    exit 77
}

# check_rules <rules file>: the policy, as problems on stderr and a status.
check_rules() {
    python3 -I - "$1" <<'EOF'
import re, subprocess, sys

path = sys.argv[1]
problems = []
rules = []
for n, raw in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    rules.append((n, line))

if not rules:
    problems.append("no rule")
for n, line in rules:
    # usbguard's own parser: a rule it refuses is a rule the daemon refuses.
    out = subprocess.run(["usbguard-rule-parser", line], capture_output=True, text=True)
    if "OUTPUT: " not in out.stdout:
        problems.append(f"{path}:{n}: usbguard cannot parse: {line}")
    target = line.split()[0]
    if target not in ("allow", "block", "reject"):
        problems.append(f"{path}:{n}: rule must start with allow, block or reject: {line}")

first = rules[0][1] if rules else ""
if not re.match(r"^(block|reject) with-interface one-of \{[^}]*\b08:\*:\*", first):
    problems.append("the first rule must block mass storage (class 08) wherever it appears in a device")

for n, line in rules:
    if not line.startswith("allow"):
        continue
    # An allow rule names what it allows: no blanket allow, and `equals` only:
    # all-of/one-of accept a device that has the listed interface plus others
    # (a keyboard that also carries a network or storage interface).
    if "with-interface" not in line and " id " not in f" {line} ":
        problems.append(f"{path}:{n}: an allow rule with no interface or id condition: {line}")
    if not re.search(r"with-interface (equals )?\{", line):
        problems.append(f"{path}:{n}: an allow rule must use `with-interface equals {{ ... }}` (or the bare set): {line}")
    if re.search(r"with-interface (all-of|one-of|none-of|equals-ordered)", line):
        problems.append(f"{path}:{n}: an allow rule must not use all-of/one-of/none-of: {line}")
    if re.search(r"\b08:", line):
        problems.append(f"{path}:{n}: an allow rule names mass storage: {line}")
    # A vendor-specific interface (ff) is allowed only for a named chip.
    if re.search(r"\bff:", line) and not re.search(r"\bid [0-9a-f]{4}:[0-9a-f]{4}\b", line):
        problems.append(f"{path}:{n}: vendor-specific interfaces are allowed by vendor/product id only: {line}")

text = "\n".join(l for _, l in rules)
for need, why in (
    (r"allow with-interface equals \{ 09:\*:\* \}", "hubs"),
    (r"allow with-interface equals \{ 02:02:\* 0a:\*:\* \}", "CDC ACM serial"),
    (r"allow with-interface equals \{ 03:\*:\* \}", "HID"),
    (r"allow id 0403:6001 ", "FTDI FT232R"),
    (r"allow id 10c4:ea60 ", "CP210x"),
):
    if not re.search(need, text):
        problems.append(f"no rule for {why}")

for p in problems:
    print(f"ERROR: {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
EOF
}

echo "the policy file"
check_rules "${RULES}" || exit 1

echo "the daemon configuration"
want() { # <key> <value>
    grep -qx "$1=$2" "${CONF}" || fail "usbguard-daemon.conf must set $1=$2"
}
want ImplicitPolicyTarget block
want PresentDevicePolicy apply-policy
want InsertedDevicePolicy apply-policy
want RuleFile /etc/usbguard/rules.conf
want IPCAllowedUsers root
want IPCAllowedGroups ""
want RestoreControllerDeviceState false
grep -q '^RuleFolder=' "${CONF}" && fail "a RuleFolder lets the daemon write rules into the image"
grep -q '^IPCAccessControlFiles=' "${CONF}" && fail "IPC access control files widen who may talk to the daemon"
grep -qx 'RuntimeDirectory=usbguard' "${DROPIN}" || fail "the audit log directory of /run is not created for the daemon"
grep -q "^AuditFilePath=/run/" "${CONF}" || fail "the audit log must live in /run: the root file system is read-only"

echo "the images"
# Every defconfig is resolved by Buildroot, and every one whose resolved .config is
# a production variant must build usbguard: the production kernels build USB mass
# storage in (the provisioning bundle is read from a stick), and the daemon is what
# keeps that class blocked. The list is not written here: a production image added
# later is held to it without anyone remembering to add it (the x86 industrial PC
# image had USB storage and no policy because the first version named three images).
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
production=0
for defconfig in "${ROOT}"/configs/*_defconfig; do
    name="$(basename "${defconfig}" _defconfig)"
    make -s -C "${ROOT}/buildroot" BR2_EXTERNAL="${ROOT}" O="${WORK}/r-${name}" "${name}_defconfig" > "${WORK}/r-${name}.log" 2>&1 ||
        fail "Buildroot could not resolve ${name}_defconfig (see ${WORK}/r-${name}.log)"
    if grep -qx 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${WORK}/r-${name}/.config"; then
        production=$((production + 1))
        grep -qx 'BR2_PACKAGE_USBGUARD=y' "${WORK}/r-${name}/.config" ||
            fail "${name} is a production image and its resolved .config does not build usbguard (Config.in BR2_PACKAGE_SUDERRA_USB_POLICY)"
        echo "  ${name}: production, builds usbguard"
    elif grep -qx 'BR2_PACKAGE_USBGUARD=y' "${WORK}/r-${name}/.config" && ! grep -qx 'BR2_PACKAGE_SUDERRA_VARIANT_DEV=y' "${WORK}/r-${name}/.config"; then
        fail "${name}: neither a production nor a development variant"
    fi
done
[ "${production}" -ge 4 ] || fail "found ${production} production defconfigs, expected at least 4 (rpi4, revpi4, qemu x86 prod_ab, x86 industrial PC)"
grep -qx 'config BR2_PACKAGE_SUDERRA_USB_POLICY' "${ROOT}/Config.in" || fail "Config.in does not define BR2_PACKAGE_SUDERRA_USB_POLICY"
grep -q 'a production image must run usbguard' "${POST_BUILD}" || fail "post-build.sh does not fail a production image without usbguard.service"
grep -q 'enable_unit usbguard.service multi-user.target' "${POST_BUILD}" || fail "post-build.sh does not enable usbguard.service"
grep -q 'preset_enable usbguard.service' "${POST_BUILD}" || fail "post-build.sh does not preset-enable usbguard.service"
grep -q 'chmod 0600 .*etc/usbguard/rules.conf' "${POST_BUILD}" || fail "post-build.sh does not restrict the rule file"

echo "mutations"
mutate() { # <label> <sed expression>
    sed "$2" "${RULES}" > "${WORK}/rules"
    if check_rules "${WORK}/rules" >/dev/null 2>&1; then fail "the policy test accepted: $1"; fi
    echo "  rejects: $1"
}
mutate "storage allowed" 's/^block with-interface one-of { 08:\*:\* }$/allow with-interface equals { 08:*:* }/'
mutate "storage rule no longer first" '1,/^block with-interface/{/^block with-interface/d}'
mutate "a blanket allow" '$a allow'
mutate "all-of for HID (a keyboard that also carries a network interface)" 's/^allow with-interface equals { 03:\*:\* }$/allow with-interface all-of { 03:*:* }/'
mutate "a vendor-specific class with no chip id" '$a allow with-interface equals { ff:*:* }'
mutate "a rule usbguard cannot parse" '$a allow with-interface equals { 09:*:* '
mutate "no hub rule" '/^allow with-interface equals { 09:\*:\* }$/d'
mutate "no HID rule" '/^allow with-interface equals { 03:\*:\* }$/d'

echo "USB policy contract OK"

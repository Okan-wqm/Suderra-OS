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
# 3. etc/chrony.conf says what DEC-7.1 says (NTS servers only, require, one
#    step at most, maxchange that never exits, no server, no pool, no refclock)
#    and, where chronyd is installed, parses with the real chronyd; the
#    constants suderra-time-state compares the clock with are chrony's own.
# 4. The units: chronyd as the chrony user with CAP_SYS_TIME alone, the floor
#    before chronyd and before time-sync.target, the wait bounded, the document
#    refreshed inside the contract's refresh time, no Requires= on
#    time-sync.target anywhere, no ProtectClock= on a unit that sets the clock,
#    the images enable all of it, and the helper's commands are declared.
# 5. The rulesets let NTP and NTS-KE out for the chrony user and nobody else.
# 6. The real chronyd parses the configuration and systemd loads the units
#    (when this host has them; CI does).
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

# --- 3, 4, 5. the configuration, the units and the rulesets ---------------------------------------------
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
python3 -I - "${ROOT}" << 'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
overlay = root / "board/suderra/common/rootfs-overlay"
units = overlay / "etc/systemd/system"
errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def directives(path: Path, section: str | None = None) -> dict[str, list[str]]:
    """The key=value lines of a unit (optionally of one section), comments excluded."""
    result: dict[str, list[str]] = {}
    current = None
    for line in read(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            continue
        if "=" in stripped and (section is None or current == section):
            key, value = stripped.split("=", 1)
            result.setdefault(key, []).append(value)
    return result


helper_text = read(overlay / "usr/sbin/suderra-time-state")


def helper_constant(name: str) -> int:
    match = re.search(rf"^{name}=(\d+)$", helper_text, re.M)
    if not match:
        err(f"suderra-time-state has no constant {name}")
        return -1
    return int(match.group(1))


# -- 3. chrony.conf -------------------------------------------------------------------------------
conf_lines = [
    line.strip()
    for line in read(overlay / "etc/chrony.conf").splitlines()
    if line.strip() and not line.strip().startswith("#")
]
conf: dict[str, list[list[str]]] = {}
for line in conf_lines:
    words = line.split()
    conf.setdefault(words[0], []).append(words[1:])

servers = conf.get("server", [])
if len(servers) < 2:
    err("chrony.conf must pin at least two NTS servers (one operator's outage must not end synchronization)")
hosts = []
for words in servers:
    hosts.append(words[0])
    if "nts" not in words[1:]:
        err(f"chrony.conf: server {words[0]} has no nts option (DEC-7.1: authenticated sources only)")
    for option in words[1:]:
        if option in ("key", "trust", "prefer", "noselect", "ntsport", "port", "minpoll", "maxpoll", "xleave"):
            err(f"chrony.conf: server {words[0]} sets {option}: the firewall opens udp/123 and tcp/4460 and nothing is negotiated away from them")
if len(set(hosts)) != len(hosts) or any(re.fullmatch(r"[0-9.:]+", h) for h in hosts):
    err("chrony.conf: servers are distinct host names (NTS verifies the certificate for the name, an address is no pin)")
for forbidden in ("pool", "peer", "refclock", "local", "allow", "bindaddress", "acquisitionport",
                  "nocerttimecheck", "rtcfile", "hwtimestamp", "minsources", "initstepslew", "sourcedir", "confdir", "include"):
    if forbidden in conf:
        err(f"chrony.conf must not use {forbidden}")
if conf.get("authselectmode") != [["require"]]:
    err("chrony.conf must say `authselectmode require` once")
makestep = conf.get("makestep")
if not makestep or len(makestep) != 1 or len(makestep[0]) != 2 or makestep[0][1] != "1":
    err("chrony.conf: `makestep <threshold> 1`: the clock is stepped by the first update only (DEC-7.1)")
maxchange = conf.get("maxchange")
if not maxchange or len(maxchange) != 1 or len(maxchange[0]) != 3 or int(maxchange[0][1]) < 1 or int(maxchange[0][2]) >= 0:
    err("chrony.conf: `maxchange <offset> <start >= 1> <negative>`: later large offsets are ignored and chronyd never exits "
        "(an exit and restart would make the next update a first update, which steps)")
for directive, value in (("rtcsync", []), ("port", ["0"]), ("cmdport", ["0"]),
                         ("driftfile", ["/var/lib/chrony/drift"]), ("ntsdumpdir", ["/var/lib/chrony"])):
    if conf.get(directive) != [value]:
        err(f"chrony.conf must say `{directive}{' ' + ' '.join(value) if value else ''}` once")
# The helper's constants are chrony's.
maxdistance = conf.get("maxdistance")
if not maxdistance or len(maxdistance) != 1:
    err("chrony.conf must state maxdistance (the helper's root distance limit is the same number)")
else:
    if round(float(maxdistance[0][0]) * 1000) != helper_constant("MAX_ROOT_DISTANCE_MS"):
        err("suderra-time-state MAX_ROOT_DISTANCE_MS must be chrony.conf maxdistance in milliseconds")
if makestep and round(float(makestep[0][0]) * 1000) != helper_constant("MAX_CLOCK_ERROR_MS"):
    err("suderra-time-state MAX_CLOCK_ERROR_MS must be the makestep threshold in milliseconds")
# Every file chrony writes is under the data bind of DEC-4.2.
for directive in ("driftfile", "ntsdumpdir"):
    for words in conf.get(directive, []):
        if not words[0].startswith("/var/lib/chrony"):
            err(f"chrony.conf: {directive} must be under /var/lib/chrony (the /data bind)")
layout = read(overlay / "usr/lib/suderra/data-layout.tmpfiles.conf")
if not re.search(r"^d\s+/data/suderra/os/chrony\s+0750\s+chrony\s+chrony\s", layout, re.M):
    err("data-layout.tmpfiles.conf must create /data/suderra/os/chrony chrony:chrony 0750 (the bind of /var/lib/chrony)")

# -- 4. units ---------------------------------------------------------------------------------------
def unit(name: str) -> dict[str, list[str]]:
    path = units / name
    if not path.is_file():
        err(f"{name} is missing")
        return {}
    return directives(path)


def words(d: dict[str, list[str]], key: str) -> set[str]:
    return {w for value in d.get(key, []) for w in value.split()}


chrony = unit("chrony.service")
if chrony.get("ExecStart") != ["/usr/sbin/chronyd -n -U -4"]:
    err("chrony.service must run `/usr/sbin/chronyd -n -U -4` (not as root, no daemonizing, IPv4)")
for key, value in (("User", "chrony"), ("Group", "chrony"), ("AmbientCapabilities", "CAP_SYS_TIME"),
                   ("CapabilityBoundingSet", "CAP_SYS_TIME"), ("NoNewPrivileges", "true"),
                   ("ProtectSystem", "strict"), ("ReadWritePaths", "/var/lib/chrony"),
                   ("RuntimeDirectory", "chrony"), ("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX")):
    if chrony.get(key) != [value]:
        err(f"chrony.service must set {key}={value}, got {chrony.get(key)}")
if "ProtectClock" in chrony or "PrivateUsers" in chrony:
    err("chrony.service must not set ProtectClock= or PrivateUsers= (both break adjtimex)")
if not {"suderra-timefloor.service", "suderra-data.service"} <= words(chrony, "After"):
    err("chrony.service must start after the time floor is applied and /data is open")
chrony_conf_socket = "/run/chrony/chronyd.sock"
if f"CHRONY_SOCKET={chrony_conf_socket}" not in helper_text:
    err(f"suderra-time-state must talk to {chrony_conf_socket}, the socket in chrony.service's RuntimeDirectory")

floor = unit("suderra-timefloor.service")
if floor.get("ExecStart") != ["/usr/sbin/suderra-time-state floor-apply"] or floor.get("ExecStop") != ["/usr/sbin/suderra-time-state floor-save"]:
    err("suderra-timefloor.service must apply the floor at start and save it at stop")
if floor.get("Type") != ["oneshot"] or floor.get("RemainAfterExit") != ["yes"]:
    err("suderra-timefloor.service must be oneshot with RemainAfterExit=yes (a stopped unit saves at shutdown)")
if not {"chrony.service", "time-sync.target"} <= words(floor, "Before"):
    err("suderra-timefloor.service must run before chronyd and before time-sync.target (DEC-7.2)")
if "suderra-data.service" not in words(floor, "After"):
    err("suderra-timefloor.service must run after /data is open: it is stopped before /data is, so the shutdown save can write")
if "shutdown.target" not in words(floor, "Conflicts"):
    err("suderra-timefloor.service must conflict with shutdown.target, or it is not stopped (and does not save) there")

save = unit("suderra-timefloor-save.service")
if save.get("ExecStart") != ["/usr/sbin/suderra-time-state floor-save"]:
    err("suderra-timefloor-save.service must run floor-save")
timer = directives(units / "suderra-timefloor.timer") if (units / "suderra-timefloor.timer").is_file() else {}
if timer.get("Unit") != ["suderra-timefloor-save.service"] or timer.get("OnUnitActiveSec") != ["1h"]:
    err("suderra-timefloor.timer must start suderra-timefloor-save.service hourly (DEC-7.2)")

contract_time = json.loads(read(root / "contracts/suderra-edge/v1/channels.json"))["time"]
state = unit("suderra-time-state.service")
interval = re.fullmatch(r"/usr/sbin/suderra-time-state run --interval (\d+)", (state.get("ExecStart") or [""])[0])
if not interval:
    err("suderra-time-state.service must run `suderra-time-state run --interval N`")
elif int(interval.group(1)) * 2 > contract_time["refresh_seconds"]:
    err(f"the document must be rewritten at least every {contract_time['refresh_seconds']} s (channels.json time.refresh_seconds); "
        f"a {interval.group(1)} s interval leaves no room for a slow pass")
if state.get("Restart") != ["always"]:
    err("suderra-time-state.service must restart when its loop dies")
if f"DOC=\"${{RUN_DIR}}/time-state\"" not in helper_text or contract_time["document"] != "/run/suderra/time-state":
    err("the document is /run/suderra/time-state (channels.json time.document)")

wait = unit("suderra-chrony-wait.service")
wait_exec = re.fullmatch(r"/usr/sbin/suderra-time-state wait --tries (\d+) --interval (\d+)", (wait.get("ExecStart") or [""])[0])
if not wait_exec:
    err("suderra-chrony-wait.service must run `suderra-time-state wait --tries N --interval S`")
else:
    bound = int(wait_exec.group(1)) * int(wait_exec.group(2))
    timeout = int(re.sub(r"s$", "", (wait.get("TimeoutStartSec") or ["0"])[0]) or 0)
    if bound > 60:
        err(f"the wait is {bound} s: the agent, and with it local control, starts after time-sync.target, so the wait is a delay of every boot without a network")
    if timeout <= bound or timeout > 120:
        err(f"suderra-chrony-wait.service TimeoutStartSec={timeout}s must exceed the {bound} s wait and bound a wedged chronyc (at most 120 s)")
if "time-sync.target" not in words(wait, "Before") or "time-sync.target" not in words(wait, "Wants"):
    err("suderra-chrony-wait.service must be Before= and Wants= time-sync.target (a passive target is reached only if something pulls it in)")
for key in ("Requires", "BindsTo", "PartOf", "Restart", "SuccessExitStatus"):
    if key in wait:
        err(f"suderra-chrony-wait.service must not set {key}=: its failure must not fail anything (DEC-7.3)")
dropin = directives(units / "time-sync.target.d/10-suderra.conf") if (units / "time-sync.target.d/10-suderra.conf").is_file() else {}
if dropin.get("Wants") != ["suderra-chrony-wait.service"]:
    err("time-sync.target.d/10-suderra.conf must pull in suderra-chrony-wait.service")

# Consumers order after time-sync.target and want it; nothing requires it (DEC-7.4).
for name in ("suderra-agent.service", "suderra-provision-worker.service"):
    consumer = unit(name)
    if "time-sync.target" not in words(consumer, "After") or "time-sync.target" not in words(consumer, "Wants"):
        err(f"{name} must be After= and Wants= time-sync.target (DEC-7.4)")
for path in sorted(p for p in (overlay / "etc/systemd").rglob("*") if p.is_file()):
    for key, values in directives(path).items():
        if key in ("Requires", "BindsTo", "Requisite") and any("time-sync.target" in v for v in values):
            err(f"{path.relative_to(overlay)}: {key}= time-sync.target (DEC-7.4: Wants=, never Requires=)")
# Units that set the clock must be allowed to.
for name in ("chrony.service", "suderra-timefloor.service", "suderra-timefloor-save.service",
             "suderra-time-state.service", "suderra-chrony-wait.service"):
    if (units / name).is_file() and "ProtectClock" in directives(units / name):
        err(f"{name} must not set ProtectClock=: it (or the helper it runs) sets the clock")
# The sandbox the helper's units share.
for name in ("suderra-timefloor.service", "suderra-timefloor-save.service", "suderra-time-state.service", "suderra-chrony-wait.service"):
    d = unit(name)
    for key, value in (("NoNewPrivileges", "true"), ("ProtectSystem", "strict"), ("PrivateNetwork", "true")):
        if d.get(key) != [value]:
            err(f"{name} must set {key}={value}")
    for path in words(d, "ReadWritePaths"):
        if path.lstrip("-") not in ("/data/suderra/os", "/run/suderra", "/run/suderra-os"):
            err(f"{name}: ReadWritePaths= {path} is more than the floor, the document and the evidence")

# Every image enables the clock units (post-build.sh) and ships the build time and the helper.
post_build = read(root / "board/suderra/common/post-build.sh")
for unit_name, target in (("suderra-timefloor.service", "sysinit.target"), ("suderra-timefloor.timer", "timers.target"),
                          ("suderra-time-state.service", "multi-user.target"), ("suderra-chrony-wait.service", "multi-user.target"),
                          ("chrony.service", "multi-user.target")):
    if f"enable_unit {unit_name} {target}" not in post_build:
        err(f"post-build.sh must enable {unit_name} in {target}")
preset_units = set()
for match in re.finditer(r'for unit in ((?:[^\n]*\\\n)*[^\n]*)\n\s*do\s*\n\s*preset_enable "\$\{unit\}"', post_build):
    preset_units |= set(match.group(1).replace("\\\n", " ").split())
for unit_name in ("suderra-timefloor.service", "suderra-timefloor.timer", "suderra-time-state.service", "suderra-chrony-wait.service"):
    if unit_name not in preset_units:
        err(f"post-build.sh must put {unit_name} in the preset (a production image disables what the preset does not enable)")
if "enable chrony.service" not in post_build:
    err("post-build.sh must put chrony.service in the preset")
if 'BUILD_EPOCH="${SOURCE_DATE_EPOCH:-}"' not in post_build or \
        'printf \'%s\\n\' "${BUILD_EPOCH}" > "${TARGET_DIR}/usr/lib/suderra/build-epoch"' not in post_build:
    err("post-build.sh must write usr/lib/suderra/build-epoch from SOURCE_DATE_EPOCH")
if not re.search(r"suderra-time-state\s*\n\s*do\s*\n\s*chmod 0755", post_build):
    err("post-build.sh must make suderra-time-state executable")
if "grep -q '^chrony:' \"${TARGET_DIR}/etc/passwd\"" not in post_build:
    err("post-build.sh must fail an image without a chrony user: the rulesets name it and a name nft cannot resolve fails the whole load")
if "BUILD_EPOCH_FILE=\"${ROOT}/usr/lib/suderra/build-epoch\"" not in helper_text:
    err("suderra-time-state must read /usr/lib/suderra/build-epoch")

# The helper's commands are declared for the image (the build-time gate checks them against the target).
spec_path = root / "scripts/ci/check-target-commands.py"
import importlib.util

spec = importlib.util.spec_from_file_location("ctc", spec_path)
ctc = importlib.util.module_from_spec(spec)
sys.modules["ctc"] = ctc
spec.loader.exec_module(ctc)
extraction = ctc.extract(helper_text)
used, dynamic = ctc.external_commands(extraction)
probed = ctc.probed_commands(extraction)
manifest = json.loads(read(root / "board/suderra/common/runtime-commands.json"))["scripts"].get("usr/sbin/suderra-time-state")
if dynamic:
    err(f"suderra-time-state builds command words at run time: {dynamic}")
if manifest is None:
    err("runtime-commands.json has no entry for usr/sbin/suderra-time-state")
else:
    required = {c for g in manifest["groups"] if not g.get("optional") for c in g["commands"]}
    optional = {c for g in manifest["groups"] if g.get("optional") for c in g["commands"]}
    if set(used) | set(probed) != required | optional:
        err(f"runtime-commands.json declares {sorted(required | optional)} for suderra-time-state, the script runs {sorted(set(used) | set(probed))}")
    if "chronyc" not in required or "suderra-installer" not in optional:
        err("chronyc is required by suderra-time-state and the installer is optional (the script probes for it)")

# -- 5. the rulesets ----------------------------------------------------------------------------------
for name in ("nftables.conf", "nftables.provisioning.conf"):
    ruleset = [l.strip() for l in read(overlay / "etc" / name).splitlines() if not l.strip().startswith("#")]
    output = "\n".join(ruleset[next(i for i, l in enumerate(ruleset) if l.startswith("chain output")):])
    for rule in ('meta skuid "chrony" udp dport 123 accept', 'meta skuid "chrony" tcp dport 4460 accept'):
        if rule not in output:
            err(f"{name}: the output chain must have `{rule}` (DEC-7.7, DEC-11.4)")
    for line in output.splitlines():
        if re.search(r"\b(udp dport 123|tcp dport 4460)\b", line) and 'meta skuid "chrony"' not in line:
            err(f"{name}: `{line}` lets NTP or NTS-KE out for every process")

if errors:
    print("\n".join(f"ERROR: {e}" for e in errors), file=sys.stderr)
    sys.exit(1)
print("time configuration, units and rulesets: ok")
PY

# --- the real chronyd parses the configuration ---------------------------------------------------------
# `chronyd -p` reads the file as chronyd would and exits non-zero on a directive it
# does not know, a missing argument or an option the build lacks (a chronyd built
# without NTS refuses `nts`). It does not see conflicts between directives.
need_tool() {
    # need_tool <name>: partial skips fail in CI, where the package is installed
    if [ "${SUDERRA_FAIL_ON_SKIP:-0}" = "1" ] || [ "${CI:-}" = "true" ]; then
        fail "$1 is required in CI: $2"
    fi
    echo "SKIP: $1 is not installed ($2)"
}
chronyd_bin=""
for candidate in "$(command -v chronyd 2> /dev/null || true)" /usr/sbin/chronyd; do
    if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
        chronyd_bin="${candidate}"
        break
    fi
done
if [ -z "${chronyd_bin}" ]; then
    need_tool chronyd "package chrony: the configuration is parsed by the daemon that will read it"
elif ! "${chronyd_bin}" --version 2> /dev/null | grep -q '+NTS'; then
    need_tool "a chronyd with NTS" "package chrony of a distribution that builds it with gnutls"
else
    "${chronyd_bin}" -p -f "${OVERLAY}/etc/chrony.conf" > /dev/null 2> "${WORK}/chronyd-p.err" ||
        fail "the real chronyd refuses etc/chrony.conf: $(cat "${WORK}/chronyd-p.err")"
    # The check is not vacuous: a misspelt directive, a missing argument and an
    # option the daemon does not know each make the same call fail.
    for broken in 'authselectmod require' 'makestep 1.0' 'server a.example nts nosuchoption'; do
        printf '%s\n' "${broken}" > "${WORK}/broken.conf"
        if "${chronyd_bin}" -p -f "${WORK}/broken.conf" > /dev/null 2>&1; then
            fail "chronyd -p accepted '${broken}': it does not validate anything here"
        fi
    done
    echo "chronyd -p: etc/chrony.conf parses ($("${chronyd_bin}" --version | head -n 1))"
fi

# --- the units load in systemd ---------------------------------------------------------------------------
# `systemd-analyze verify` on a root holding the units and stubs for what they run: an unknown
# key (a typo is dropped silently by systemd, and the hardening it meant is gone) or a missing
# executable fails it.
if command -v systemd-analyze > /dev/null 2>&1; then
    vroot="${WORK}/vroot"
    mkdir -p "${vroot}/etc/systemd/system" "${vroot}/usr/sbin" "${vroot}/usr/lib/systemd/system"
    for dir in /usr/lib/systemd/system /lib/systemd/system; do
        if [ -d "${dir}" ] && compgen -G "${dir}/*.target" > /dev/null; then
            cp "${dir}"/*.target "${vroot}/usr/lib/systemd/system/"
            break
        fi
    done
    [ -e "${vroot}/usr/lib/systemd/system/sysinit.target" ] || fail "this host's systemd has no sysinit.target to verify against"
    cp -r "${OVERLAY}/etc/systemd/system/time-sync.target.d" "${vroot}/etc/systemd/system/"
    time_units=(chrony.service suderra-timefloor.service suderra-timefloor-save.service suderra-timefloor.timer
        suderra-time-state.service suderra-chrony-wait.service)
    for unit in "${time_units[@]}"; do cp "${OVERLAY}/etc/systemd/system/${unit}" "${vroot}/etc/systemd/system/"; done
    for binary in chronyd suderra-time-state; do
        printf '#!/bin/sh\n' > "${vroot}/usr/sbin/${binary}"
        chmod 0755 "${vroot}/usr/sbin/${binary}"
    done
    verify() {
        (cd "${vroot}" && systemd-analyze verify --root="${vroot}" --man=no "$@" 2>&1)
    }
    verified=()
    for unit in "${time_units[@]}"; do verified+=("${vroot}/etc/systemd/system/${unit}"); done
    if ! output="$(verify "${verified[@]}")" || [ -n "${output}" ]; then
        fail "systemd-analyze verify finds fault with the time units: ${output}"
    fi
    sed 's/^ProtectSystem=strict/ProtectSytem=strict/' "${OVERLAY}/etc/systemd/system/chrony.service" > "${vroot}/etc/systemd/system/typo.service"
    # An unknown key is a warning for systemd-analyze (status 0, a line of output).
    typo_output="$(verify "${vroot}/etc/systemd/system/typo.service" || true)"
    case "${typo_output}" in
        *"Unknown key name 'ProtectSytem'"*) ;;
        *) fail "systemd-analyze verify did not report a misspelt hardening key: the check proves nothing on this host (${typo_output})" ;;
    esac
    echo "systemd-analyze verify: the ${#time_units[@]} time units load ($(systemd-analyze --version | head -n 1))"
else
    need_tool systemd-analyze "package systemd"
fi

echo "time sync contract passed"

#!/usr/bin/env bash
#
# TPM resource registry (ADR-048 DEC-21): docs/security/tpm-resource-registry.md.
#
# The OS and the agent share one TPM. The registry's JSON block says which
# persistent handles, NV indices, PCRs and devices belong to whom; this test
# holds the code of this repository to it:
#
# * the block is well formed, inside the TPM's handle spaces (tpm2-tss
#   include/tss2/tss2_tpm2_types.h), and no two allocations overlap;
# * the PCRs the /data seal binds (TPM2_SEAL_OPTIONS in suderra-data-unlock)
#   are the registry's;
# * no script of the image runs a command that changes TPM state outside the
#   registry (the forbidden list: ownership changes, NV and persistent
#   objects, dictionary-attack settings, PCR extends);
# * the files that extend or reset a PCR are the registered ones, extend only
#   their registered PCRs, and none of them ships in an image;
# * no unit grants /dev/tpm0, the agent's units grant no TPM device before the
#   phase that allows one, and the OS's units only the registry's.
#
# The validator is also run on mutated registries to prove it rejects an
# overlap, an out-of-range block, a wrong seal PCR and a missing owner.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 -I - "${ROOT}" << 'PY'
import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
errors: list[str] = []

doc = (root / "docs/security/tpm-resource-registry.md").read_text(encoding="utf-8")
match = re.search(r"```json tpm-registry\n(.*?)\n```", doc, re.S)
if not match:
    sys.exit("ERROR: docs/security/tpm-resource-registry.md has no ```json tpm-registry block")
registry = json.loads(match.group(1))

OWNERS = {"os", "agent", "tcg"}
PHASES = {"P0", "P1", "P2", "P3"}


def number(text: str) -> int:
    return int(text, 16)


def validate_registry(reg: dict, luks_pcrs: list[int]) -> list[str]:
    problems: list[str] = []
    if reg.get("registry_version") != 1:
        problems.append("registry_version must be 1")
    limits = reg["limits"]
    owner_low, owner_high = (number(x) for x in limits["persistent_owner"])
    nv_low, nv_high = (number(x) for x in limits["nv"])
    if (owner_low, owner_high) != (0x81000000, 0x817FFFFF):
        problems.append("the owner persistent space is 0x81000000..0x817FFFFF (platform persistent handles start at 0x81800000)")
    if number(limits["persistent_platform"][0]) != 0x81800000 or number(limits["persistent_platform"][1]) != 0x81FFFFFF:
        problems.append("the platform persistent space is 0x81800000..0x81FFFFFF")
    if (nv_low, nv_high) != (0x01000000, 0x01FFFFFF):
        problems.append("NV indices are 0x01000000..0x01FFFFFF")

    def check(kind: str, entries: list[dict], low: int, high: int) -> None:
        spans: list[tuple[int, int, str]] = []
        for entry in entries:
            if "handle" in entry:
                start = end = number(entry["handle"])
            else:
                start, end = (number(x) for x in entry["range"])
            label = entry.get("handle") or "-".join(entry["range"])
            if entry.get("owner") not in OWNERS:
                problems.append(f"{kind} {label}: owner must be one of {sorted(OWNERS)}")
            if not entry.get("purpose"):
                problems.append(f"{kind} {label}: a purpose is required")
            if entry.get("owner") in ("os", "agent") and entry.get("phase") not in PHASES:
                problems.append(f"{kind} {label}: an OS or agent allocation names the phase that creates it")
            if start > end:
                problems.append(f"{kind} {label}: the range is reversed")
            if not (low <= start and end <= high):
                problems.append(f"{kind} {label}: outside the owner's space {hex(low)}..{hex(high)}")
            if entry.get("owner") == "tcg" and entry.get("suderra_creates") is not False:
                problems.append(f"{kind} {label}: a TCG-reserved resource is never created by Suderra (suderra_creates: false)")
            spans.append((start, end, label))
        spans.sort()
        for (a_start, a_end, a_label), (b_start, b_end, b_label) in zip(spans, spans[1:]):
            if b_start <= a_end:
                problems.append(f"{kind} {a_label} and {b_label} overlap")

    check("persistent handle", reg["persistent_handles"], owner_low, owner_high)
    check("NV index", reg["nv_indices"], nv_low, nv_high)

    pcrs = reg["pcrs"]
    if pcrs["luks_seal"]["pcrs"] != luks_pcrs:
        problems.append(f"the /data seal binds PCRs {luks_pcrs} (TPM2_SEAL_OPTIONS), the registry says {pcrs['luks_seal']['pcrs']}")
    if pcrs["agent_extends"]:
        problems.append("the agent never extends a PCR (agent_extends must be empty)")
    for site in pcrs["extend_sites"]:
        if re.match(r"(board|package|userspace)/", site["file"]):
            problems.append(f"{site['file']}: a PCR-extending file must not ship in an image")
        if set(site["pcrs"]) & set(pcrs["debug_only"]) == set() and not site["file"].startswith("tests/"):
            problems.append(f"{site['file']}: outside tests/, a site extends only a debug PCR {pcrs['debug_only']}")
    devices = reg["devices"]
    if "/dev/tpm0" in devices["os"] or any("/dev/tpm0" in v for v in devices["agent"].values()):
        problems.append("/dev/tpm0 is never granted (devices.never)")
    if "/dev/tpm0" not in devices["never"]:
        problems.append("devices.never must name /dev/tpm0")
    return problems


# -- the seal PCRs as the code states them ---------------------------------------------
unlock = (root / "board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock").read_text(encoding="utf-8")
options = re.search(r'^TPM2_SEAL_OPTIONS="([^"]*)"', unlock, re.M)
if not options:
    sys.exit("ERROR: suderra-data-unlock has no TPM2_SEAL_OPTIONS")
pcr_option = re.search(r"--tpm2-pcrs=([0-9+,]+)", options.group(1))
if not pcr_option:
    sys.exit("ERROR: TPM2_SEAL_OPTIONS names no PCRs")
luks_pcrs = sorted(int(x) for x in re.split(r"[+,]", pcr_option.group(1)))
errors += validate_registry(registry, luks_pcrs)

# -- the validator rejects what it must ---------------------------------------------------
def mutate(change):
    candidate = copy.deepcopy(registry)
    change(candidate)
    return candidate


def overlap(reg):
    reg["nv_indices"][1]["range"][0] = reg["nv_indices"][0]["range"][1]


def out_of_range(reg):
    reg["persistent_handles"][3]["range"] = ["0x81800000", "0x818000FF"]


def agent_in_tcg(reg):
    reg["persistent_handles"][0]["suderra_creates"] = True


def wrong_pcr(reg):
    reg["pcrs"]["luks_seal"]["pcrs"] = [0, 2, 4]


def agent_extends(reg):
    reg["pcrs"]["agent_extends"] = [16]


def shipped_extender(reg):
    reg["pcrs"]["extend_sites"].append({"file": "board/suderra/common/rootfs-overlay/usr/sbin/x", "pcrs": [16], "purpose": "x"})


def no_owner(reg):
    del reg["nv_indices"][0]["owner"]


def raw_device(reg):
    reg["devices"]["agent"]["P1"] = ["/dev/tpm0"]


for name, change in [("an overlap", overlap), ("a block outside the owner space", out_of_range),
                     ("a TCG resource Suderra creates", agent_in_tcg), ("a wrong seal PCR set", wrong_pcr),
                     ("an agent that extends", agent_extends), ("a shipped PCR extender", shipped_extender),
                     ("a missing owner", no_owner), ("the raw TPM device", raw_device)]:
    if not validate_registry(mutate(change), luks_pcrs):
        errors.append(f"the validator accepts {name}: the registry check proves nothing")

# -- no script of the image changes TPM state outside the registry ------------------------
spec = importlib.util.spec_from_file_location("ctc", root / "scripts/ci/check-target-commands.py")
ctc = importlib.util.module_from_spec(spec)
sys.modules["ctc"] = ctc
spec.loader.exec_module(ctc)
manifest = json.loads((root / "board/suderra/common/runtime-commands.json").read_text(encoding="utf-8"))
forbidden = set(registry["forbidden_os_commands"])
for script, entry in manifest["scripts"].items():
    declared = {name for group in entry["groups"] for name in group["commands"]}
    used = set(ctc.external_commands(ctc.extract((root / entry["source"]).read_text(encoding="utf-8")))[0])
    for name in sorted((declared | used) & forbidden):
        errors.append(f"{script} runs {name}, which changes TPM state and is not in the registry (DEC-21)")
# The same names anywhere else a script, unit or package file of the image could hide them.
INVOCATION = re.compile(r"\b(" + "|".join(re.escape(x) for x in sorted(forbidden | {"tpm2_pcrextend", "tpm2_pcrreset"})) + r")\b")
scanned: list[Path] = []
for directory in ("board", "package", "userspace"):
    scanned += [p for p in (root / directory).rglob("*") if p.is_file() and "target" not in p.parts
                and p.suffix in ("", ".sh", ".service", ".conf", ".rs", ".mk", ".py", ".json", ".cfg")]
scanned += list((root / "scripts").rglob("*.sh")) + list((root / "tests/qemu").glob("*.sh"))
sites = {site["file"]: site for site in registry["pcrs"]["extend_sites"]}
for path in sorted(set(scanned)):
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if relative == "board/suderra/common/runtime-commands.json":
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or not INVOCATION.search(line):
            continue
        hit = INVOCATION.search(line).group(1)
        if relative in sites and hit in ("tpm2_pcrextend", "tpm2_pcrreset"):
            continue
        errors.append(f"{relative}:{lineno}: {hit} is a TPM state change outside the registry")
for relative, site in sites.items():
    text = (root / relative).read_text(encoding="utf-8")
    extended = {int(n) for n in re.findall(r"\b(\d+):sha(?:1|256)=", text)}
    reset = {int(n) for n in re.findall(r"tpm2_pcrreset[^\n]*?\b(\d+)\b", text)}
    stray = (extended | reset) - set(site["pcrs"])
    if stray:
        errors.append(f"{relative} extends or resets PCR(s) {sorted(stray)}, the registry allows {site['pcrs']}")
    if not (extended | reset):
        errors.append(f"{relative} is a registered PCR site but extends none: remove the entry")

# -- no unit gets a TPM device the registry does not give it ---------------------------------
# /dev/tpm0 is the raw device, without the resource manager: nothing gets it.
# The agent gets no TPM device before the phase that allows one; the OS's units
# only the OS's.
allowed_os = set(registry["devices"]["os"])
allowed_agent = set(registry["devices"]["agent"]["P1"])
unit_files: list[Path] = []
for directory in ("board", "package", "userspace"):
    unit_files += [p for p in (root / directory).rglob("*") if p.is_file() and "target" not in p.parts
                   and (p.suffix == ".service" or (p.suffix == ".conf" and ".service.d" in p.parts[-2]))]
if not any(p.name == "suderra-agent.service" for p in unit_files):
    errors.append("the agent unit was not found: this check would prove nothing")
for path in sorted(set(unit_files)):
    is_agent = path.name == "suderra-agent.service" or path.parent.name == "suderra-agent.service.d"
    allowed = allowed_agent if is_agent else allowed_os
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        for device in re.findall(r"/dev/tpm[a-z0-9]*", line):
            if device == "/dev/tpm0" or device not in allowed:
                who = "the agent unit" if is_agent else "an OS unit"
                errors.append(f"{path.relative_to(root)}:{lineno}: {who} grants {device}, which the registry does not give it (devices)")

if errors:
    print("\n".join(f"ERROR: {line}" for line in errors), file=sys.stderr)
    sys.exit(1)
print("tpm registry: well formed, code within it")
PY

echo "tpm registry contract passed"

#!/usr/bin/env bash
#
# Root's results reach the agent after a reboot (ADR-048 DEC-27).
#
# Root writes every result to /data/suderra/os/results and mirrors it to
# /run/suderra/results, the one directory the agent publishes from. /run is a
# tmpfs: a reboot empties the mirror, and a result the broker had not
# acknowledged before it (a lockdown, a rollback, an alarm) would never be
# published, because the agent keeps only the highest acknowledged sequence
# number. suderra-results-mirror.service restores the mirror from the persistent
# results (`suderra-installer result mirror`, covered by its own unit tests)
# before the agent's first pass over the directory.
#
# This test holds the unit and its wiring to that statement: it runs on /data
# alone and never gates the agent, it is ordered before the agent, it may write
# nothing but the mirror, board images enable it and boardless images do not
# carry it, and systemd loads it. Each rule is shown to fail when broken.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
UNIT="${OVERLAY}/etc/systemd/system/suderra-results-mirror.service"
AGENT="${OVERLAY}/etc/systemd/system/suderra-agent.service"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

for file in "${UNIT}" "${AGENT}" "${POST_BUILD}"; do
    [ -f "${file}" ] || fail "missing ${file#"${ROOT}"/}"
done
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# 1. The unit, the agent unit and post-build.sh, and the same checks on mutated copies.
python3 -I - "${UNIT}" "${AGENT}" "${POST_BUILD}" <<'PY'
import re
import sys
from pathlib import Path

unit, agent, post = (Path(p).read_text(encoding="utf-8") for p in sys.argv[1:4])
UNIT_NAME = "suderra-results-mirror.service"


def parse(text):
    """Directives of a unit by section, in order; a repeated key accumulates."""
    out, section = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.strip("[]")
            out.setdefault(section, {})
            continue
        key, _, value = line.partition("=")
        out[section].setdefault(key, []).append(value)
    return out


def words(values):
    return [w for v in values for w in v.split()]


def post_build_branches(text):
    """The then-branch and the else-branch of the board-profile switch."""
    marker = 'if [ -n "${SUDERRA_BOARD_PROFILE}" ]; then\n    # Identity, lifecycle, provisioning mode, activation and the agent.'
    start = text.index(marker)
    rest = text[start:]
    then_end = rest.index("\nelse\n")
    else_end = rest.index("\nfi\n", then_end)
    return rest[:then_end], rest[then_end:else_end]


def check(unit, agent, post):
    problems = []
    u = parse(unit)
    svc, uni, inst = u.get("Service", {}), u.get("Unit", {}), u.get("Install", {})

    # Runs on /data alone, orders before the agent, gates nothing.
    if "suderra-data.service" not in words(uni.get("After", [])):
        problems.append("the unit does not run after suderra-data.service: /data may not be mounted yet")
    if "suderra-agent.service" not in words(uni.get("Before", [])):
        problems.append("the unit is not ordered before suderra-agent.service: the agent's first pass would miss the restored results")
    for key in ("Requires", "BindsTo", "PartOf", "Wants", "Requisite", "Upholds"):
        if key in uni:
            problems.append(f"the unit declares {key}=: a failed mirror must not stop anything")
    if uni.get("ConditionPathExists") != ["/etc/suderra/board"]:
        problems.append("the unit is not conditional on /etc/suderra/board: a boardless image has no results")
    if uni.get("DefaultDependencies") != ["no"]:
        problems.append("the unit keeps its default dependencies: it would wait for basic.target and the agent could start first")
    ag = parse(agent)
    for section in ag.values():
        for key in ("Requires", "BindsTo", "Requisite"):
            if UNIT_NAME in words(section.get(key, [])):
                problems.append(f"suderra-agent.service has {key}={UNIT_NAME}: the mirror would gate the control loop")

    # What it runs and what it may write.
    if svc.get("ExecStart") != ["/usr/bin/suderra-installer result mirror"]:
        problems.append(f"ExecStart is {svc.get('ExecStart')}, not `suderra-installer result mirror`")
    if svc.get("Type") != ["oneshot"] or svc.get("RemainAfterExit") != ["yes"]:
        problems.append("the unit is not a oneshot that stays active (the agent's ordering needs it finished)")
    if svc.get("ProtectSystem") != ["strict"]:
        problems.append("ProtectSystem=strict is missing")
    if svc.get("NoNewPrivileges") != ["true"] or svc.get("PrivateNetwork") != ["true"]:
        problems.append("NoNewPrivileges=true and PrivateNetwork=true are missing")
    if sorted(words(svc.get("ReadWritePaths", []))) != ["-/data/suderra/os", "/run/suderra"]:
        problems.append(f"ReadWritePaths is {svc.get('ReadWritePaths')}: the mirror writes /run/suderra and takes the results lock under /data/suderra/os, nothing else")
    if inst.get("WantedBy") != ["multi-user.target"]:
        problems.append("the unit is not wanted by multi-user.target")

    # Board images enable it; boardless images do not carry it.
    then, other = post_build_branches(post)
    if not re.search(r"enable_unit " + re.escape(UNIT_NAME) + r" multi-user\.target", then):
        problems.append("post-build.sh does not enable the unit on images with a board")
    if not re.search(r"suderra-agent\.service " + re.escape(UNIT_NAME) + r"\n\s*do\n\s*preset_enable", then):
        problems.append("post-build.sh does not preset-enable the unit on images with a board")
    if UNIT_NAME not in other:
        problems.append("post-build.sh keeps the unit on an image with no board")
    return problems


def must_fail(name, expected, unit=unit, agent=agent, post=post):
    problems = check(unit, agent, post)
    if not any(expected in p for p in problems):
        print(f"ERROR: mutation '{name}' was not rejected for the right reason (wanted {expected!r}): {problems}", file=sys.stderr)
        sys.exit(1)
    print(f"  rejected: {name}")


def mutated(text, old, new):
    if old not in text:
        sys.exit(f"the mutation anchor {old!r} is stale")
    return text.replace(old, new, 1)


problems = check(unit, agent, post)
if problems:
    print("\n".join(f"ERROR: {p}" for p in problems), file=sys.stderr)
    sys.exit(1)
print("  the mirror unit is ordered before the agent, gates nothing, writes only the mirror, and is enabled on board images")

must_fail("not ordered before the agent", "not ordered before suderra-agent.service",
          unit=mutated(unit, "Before=suderra-agent.service\n", ""))
must_fail("not after /data", "does not run after suderra-data.service",
          unit=mutated(unit, "After=suderra-data.service ", "After="))
must_fail("the mirror requires /data", "declares Requires=",
          unit=mutated(unit, "After=suderra-data.service", "Requires=suderra-data.service\nAfter=suderra-data.service"))
must_fail("the agent requires the mirror", "would gate the control loop",
          agent=mutated(agent, "Wants=time-sync.target\n", "Wants=time-sync.target\nRequires=suderra-results-mirror.service\n"))
must_fail("wrong command", "not `suderra-installer result mirror`",
          unit=mutated(unit, "ExecStart=/usr/bin/suderra-installer result mirror", "ExecStart=/usr/bin/suderra-installer result write"))
must_fail("may write more than the mirror", "ReadWritePaths is",
          unit=mutated(unit, "ReadWritePaths=-/data/suderra/os /run/suderra", "ReadWritePaths=-/data /run/suderra"))
must_fail("cannot write the mirror", "ReadWritePaths is",
          unit=mutated(unit, "ReadWritePaths=-/data/suderra/os /run/suderra", "ReadWritePaths=-/data/suderra/os"))
must_fail("not sandboxed", "ProtectSystem=strict is missing",
          unit=mutated(unit, "ProtectSystem=strict\n", ""))
must_fail("not conditional on a board", "not conditional on /etc/suderra/board",
          unit=mutated(unit, "ConditionPathExists=/etc/suderra/board\n", ""))
must_fail("board images do not enable it", "does not enable the unit",
          post=mutated(post, "enable_unit suderra-results-mirror.service multi-user.target\n", ""))
must_fail("board images do not preset it", "does not preset-enable",
          post=mutated(post, "suderra-agent.service suderra-results-mirror.service\n", "suderra-agent.service\n"))
must_fail("boardless images keep it", "keeps the unit on an image with no board",
          post=mutated(post, "suderra-provision-worker.service suderra-results-mirror.service\n",
                       "suderra-provision-worker.service\n"))
PY

# 2. systemd loads the unit: an unknown key (a typo is dropped silently, and the
# hardening it meant is gone) or a missing executable fails `systemd-analyze verify`.
if command -v systemd-analyze >/dev/null 2>&1; then
    vroot="${WORK}/vroot"
    mkdir -p "${vroot}/etc/systemd/system" "${vroot}/usr/bin" "${vroot}/usr/lib/systemd/system"
    for dir in /usr/lib/systemd/system /lib/systemd/system; do
        if [ -d "${dir}" ] && compgen -G "${dir}/*.target" >/dev/null; then
            cp "${dir}"/*.target "${vroot}/usr/lib/systemd/system/"
            break
        fi
    done
    [ -e "${vroot}/usr/lib/systemd/system/sysinit.target" ] ||
        fail "this host's systemd has no sysinit.target to verify against"
    cp "${UNIT}" "${vroot}/etc/systemd/system/"
    printf '#!/bin/sh\n' >"${vroot}/usr/bin/suderra-installer"
    chmod 0755 "${vroot}/usr/bin/suderra-installer"
    verify() {
        (cd "${vroot}" && systemd-analyze verify --root="${vroot}" --man=no "$@" 2>&1)
    }
    if ! output="$(verify "${vroot}/etc/systemd/system/suderra-results-mirror.service")" || [ -n "${output}" ]; then
        fail "systemd-analyze verify finds fault with the unit: ${output}"
    fi
    sed 's/^ProtectSystem=strict/ProtectSytem=strict/' "${UNIT}" >"${vroot}/etc/systemd/system/typo.service"
    typo_output="$(verify "${vroot}/etc/systemd/system/typo.service" || true)"
    case "${typo_output}" in
        *"Unknown key name 'ProtectSytem'"*) ;;
        *) fail "systemd-analyze verify did not report a misspelt hardening key: the check proves nothing on this host (${typo_output})" ;;
    esac
    echo "  systemd-analyze verify: the unit loads ($(systemd-analyze --version | head -n 1))"
else
    echo "SKIP: systemd-analyze is missing (apt: systemd)" >&2
    exit 77
fi

echo "result mirror contract passed"

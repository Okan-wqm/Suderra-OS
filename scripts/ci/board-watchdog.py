#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""The hardware watchdog systemd PID1 owns on each Suderra OS image (ADR-048 DEC-6.6).

Every image that runs on a board has one owner of its hardware watchdog, systemd
PID1, and no other: suderra-watchdog is gone, the agent unit may not name
/dev/watchdog (contracts unit-directives.json), and a production kernel cannot be
told to let go of it (CONFIG_WATCHDOG_NOWAYOUT, scripts/ci/check-kernel-config.py).
What PID1 opens is /dev/suderra-watchdog, a link udev makes to the watchdog whose
sysfs `identity` the board's rule names, so the owner is the board's own timer and
never a software watchdog or whichever driver probed first (a RevPi Connect 4 has
two, and an x86 PC may have several).

board/suderra/watchdog/<key>/ holds the two files of a key:

    10-suderra-watchdog.conf    systemd system.conf.d drop-in: the device and the timeouts
    60-suderra-watchdog.rules   udev rule: the link, by identity

The key is the image's board_profile, or the pending board family of an image that
declares no board (boards.json).

    board-watchdog.py key <defconfig>                          print the image's key, or - for none
    board-watchdog.py install --defconfig <defconfig> --target DIR
                                                               install the image's pair into a rootfs
    board-watchdog.py check                                    check every key and every image
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WATCHDOG_DIR = Path("board/suderra/watchdog")
DROPIN = "10-suderra-watchdog.conf"
RULES = "60-suderra-watchdog.rules"
DROPIN_TARGET = Path("etc/systemd/system.conf.d") / DROPIN
RULES_TARGET = Path("usr/lib/udev/rules.d") / RULES
LINK = "suderra-watchdog"
DEVICE = f"/dev/{LINK}"


@dataclass(frozen=True)
class Identity:
    """A watchdog driver, by the identity it reports in sysfs."""

    capability: str  # check-kernel-config.py capability that builds its driver in
    hw_max_s: float  # the longest timeout its hardware takes, over every variant
    source: str  # where that comes from


# Vendor facts, each from the driver source of Linux 6.12.114
# (https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/<path>?h=v6.12.114).
IDENTITIES: dict[str, Identity] = {
    "Broadcom BCM2835 Watchdog timer": Identity(
        "watchdog-bcm2835",
        15.999,
        "drivers/watchdog/bcm2835_wdt.c: max_hw_heartbeat_ms = 0xfffff ticks of 1/65536 s",
    ),
    "iTCO_wdt": Identity(
        "watchdog-itco",
        37.8,
        "drivers/watchdog/iTCO_wdt.c: TCO version 1 takes at most 0x3f ticks of 0.6 s",
    ),
    "i6300ESB timer": Identity(
        "watchdog-i6300esb",
        2046,
        "drivers/watchdog/i6300esb.c: ESB_HEARTBEAT_MAX",
    ),
}

# The identities each key's rule may match: the watchdogs of that board.
KEYS: dict[str, tuple[str, ...]] = {
    "revpi-connect4": ("Broadcom BCM2835 Watchdog timer",),
    "rpi4-cm4": ("Broadcom BCM2835 Watchdog timer",),
    "qemu-x86_64": ("iTCO_wdt", "i6300ESB timer"),
    "x86-ipc": ("iTCO_wdt",),
}

# [Manager] settings of system.conf (systemd 256.17 src/core/main.c config table): the
# only three a drop-in of this contract sets. KExecWatchdogSec is absent on purpose:
# no image has kexec (CONFIG_KEXEC is not set).
DROPIN_KEYS = ("WatchdogDevice", "RuntimeWatchdogSec", "RebootWatchdogSec")
# systemd's own default of RebootWatchdogSec (man systemd-system.conf).
REBOOT_MAX_S = 600
# Below this a loaded PID1 starves the watchdog.
RUNTIME_MIN_S = 5

RULE = re.compile(
    r'^SUBSYSTEM=="watchdog", KERNEL=="watchdog\[0-9\]\*", '
    r'ATTR\{identity\}=="([^"]+)", SYMLINK\+="' + re.escape(LINK) + r'"$'
)
TIME = re.compile(r"^([0-9]+)(s|min)$")


class ContractError(Exception):
    pass


def load_boards(root: Path) -> dict:
    return json.loads(
        (root / "contracts/suderra-edge/v1/boards.json").read_text(encoding="utf-8")
    )


def images_by_key(boards: dict) -> dict[str, list[str]]:
    """key -> defconfigs, for every image that has a watchdog; excluded images have none."""
    keys: dict[str, list[str]] = {}
    for board in boards["boards"]:
        keys.setdefault(board["board_profile"], []).extend(
            i["defconfig"] for i in board["os_images"]
        )
    for family in boards["pending_board_families"]:
        keys.setdefault(family["family"], []).extend(
            i["defconfig"] for i in family["os_images"]
        )
    return keys


def key_of(root: Path, defconfig: str) -> str | None:
    boards = load_boards(root)
    found = [k for k, images in images_by_key(boards).items() if defconfig in images]
    if len(found) > 1:
        raise ContractError(f"{defconfig} is classified under {found} in boards.json")
    if found:
        return found[0]
    if any(e["defconfig"] == defconfig for e in boards["excluded_os_images"]):
        return None
    raise ContractError(f"{defconfig} is not classified in boards.json")


def parse_seconds(text: str) -> int:
    m = TIME.match(text)
    if not m:
        raise ContractError(f"{text!r} is not <n>s or <n>min")
    return int(m.group(1)) * (60 if m.group(2) == "min" else 1)


def parse_dropin(path: Path) -> dict[str, str]:
    """The [Manager] settings of a drop-in; any other line is an error."""
    section = None
    values: dict[str, str] = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if line != "[Manager]":
                raise ContractError(f"{path}:{n}: section {line} is not [Manager]")
            if section is not None:
                raise ContractError(f"{path}:{n}: [Manager] twice")
            section = line
            continue
        if section is None:
            raise ContractError(f"{path}:{n}: setting outside [Manager]: {line}")
        key, sep, value = line.partition("=")
        if not sep or key not in DROPIN_KEYS:
            raise ContractError(f"{path}:{n}: {line!r} is not one of {DROPIN_KEYS}")
        if key in values:
            raise ContractError(f"{path}:{n}: {key} twice")
        values[key] = value
    return values


def parse_rules(path: Path) -> list[str]:
    """The identities a rules file links, one rule per identity and nothing else."""
    identities: list[str] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = RULE.match(line)
        if not m:
            raise ContractError(
                f'{path}:{n}: not exactly: SUBSYSTEM=="watchdog", KERNEL=="watchdog[0-9]*", '
                f'ATTR{{identity}}=="<identity>", SYMLINK+="{LINK}": {line}'
            )
        identities.append(m.group(1))
    return identities


def check_key(root: Path, key: str, identities: tuple[str, ...], kernel) -> list[str]:
    problems: list[str] = []
    directory = root / WATCHDOG_DIR / key
    names = sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []
    if names != sorted([DROPIN, RULES]):
        return [f"{WATCHDOG_DIR / key}: holds {names}, must hold exactly {[DROPIN, RULES]}"]
    unknown = [i for i in identities if i not in IDENTITIES]
    if unknown:
        return [f"{key}: identities {unknown} are not in IDENTITIES"]
    try:
        linked = parse_rules(directory / RULES)
        values = parse_dropin(directory / DROPIN)
    except ContractError as e:
        return [str(e)]
    if sorted(linked) != sorted(identities):
        problems.append(
            f"{WATCHDOG_DIR / key / RULES}: links {sorted(linked)}, the board's watchdogs "
            f"are {sorted(identities)}"
        )
    if sorted(values) != sorted(DROPIN_KEYS):
        problems.append(
            f"{WATCHDOG_DIR / key / DROPIN}: sets {sorted(values)}, must set {sorted(DROPIN_KEYS)}"
        )
        return problems
    if values["WatchdogDevice"] != DEVICE:
        problems.append(
            f"{WATCHDOG_DIR / key / DROPIN}: WatchdogDevice={values['WatchdogDevice']}, "
            f"must be {DEVICE}, the link the rule makes"
        )
    try:
        runtime = parse_seconds(values["RuntimeWatchdogSec"])
        reboot = parse_seconds(values["RebootWatchdogSec"])
    except ContractError as e:
        return problems + [f"{WATCHDOG_DIR / key / DROPIN}: {e}"]
    hw_max = min(IDENTITIES[i].hw_max_s for i in identities)
    if not RUNTIME_MIN_S <= runtime < hw_max:
        problems.append(
            f"{WATCHDOG_DIR / key / DROPIN}: RuntimeWatchdogSec={runtime}s must be at least "
            f"{RUNTIME_MIN_S}s and below the hardware maximum {hw_max}s of the board's watchdogs"
        )
    if not runtime < reboot <= REBOOT_MAX_S:
        problems.append(
            f"{WATCHDOG_DIR / key / DROPIN}: RebootWatchdogSec={reboot}s must exceed "
            f"RuntimeWatchdogSec and not exceed systemd's default of {REBOOT_MAX_S}s"
        )
    # The kernel checker holds every image of the board to the drivers' symbols
    # and to sysfs identity: the rule above matches nothing without them.
    board_io = kernel.BOARD_IO.get(key)
    if board_io is None:
        problems.append(f"check-kernel-config.py BOARD_IO has no entry for {key}")
    else:
        for identity in identities:
            capability = IDENTITIES[identity].capability
            if capability not in board_io:
                problems.append(
                    f"check-kernel-config.py BOARD_IO[{key!r}] lacks {capability!r}: the rule "
                    f"names {identity!r} and nothing makes the kernel build its driver"
                )
    return problems


def load_kernel_checker(root: Path):
    spec = importlib.util.spec_from_file_location(
        "check_kernel_config", root / "scripts/ci/check-kernel-config.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their annotations through it
    spec.loader.exec_module(module)
    return module


def check(root: Path) -> list[str]:
    problems: list[str] = []
    boards = load_boards(root)
    by_key = images_by_key(boards)
    if sorted(by_key) != sorted(KEYS):
        problems.append(
            f"boards.json has the keys {sorted(by_key)}, board-watchdog.py KEYS has {sorted(KEYS)}"
        )
    directories = sorted(p.name for p in (root / WATCHDOG_DIR).iterdir() if p.is_dir())
    if directories != sorted(KEYS):
        problems.append(f"{WATCHDOG_DIR} holds {directories}, KEYS has {sorted(KEYS)}")
    kernel = load_kernel_checker(root)
    for key, identities in KEYS.items():
        problems += check_key(root, key, identities, kernel)

    # One owner: no second daemon, no unit that may open the device.
    members = (root / "userspace/Cargo.toml").read_text(encoding="utf-8")
    if "suderra-watchdog" in members or (root / "userspace/suderra-watchdog").exists():
        problems.append(
            "userspace/suderra-watchdog exists: the ADR keeps no second owner of "
            "/dev/watchdog (DEC-6.6)"
        )
    for tree in ("board", "package"):
        for path in sorted((root / tree).rglob("*")):
            if not path.is_file() or WATCHDOG_DIR in path.relative_to(root).parents:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if re.search(r"DeviceAllow=\S*/dev/(suderra-)?watchdog|suderra-watchdog\.service", line):
                    problems.append(
                        f"{path.relative_to(root)}:{n}: a unit that may open the hardware "
                        f"watchdog: PID1 is its only owner (DEC-6.6)"
                    )

    post_build = (root / "board/suderra/common/post-build.sh").read_text(encoding="utf-8")
    if "board-watchdog.py" not in post_build:
        problems.append("board/suderra/common/post-build.sh does not install the watchdog pair")
    return problems


def install(root: Path, defconfig: str, target: Path) -> str:
    key = key_of(root, defconfig)
    drop = target / DROPIN_TARGET
    rules = target / RULES_TARGET
    # post-build reruns on a filled target: start from none.
    for stale in (drop, rules):
        stale.unlink(missing_ok=True)
    if key is None:
        return "-"
    if key not in KEYS:
        raise ContractError(f"{defconfig}: key {key} has no watchdog files")
    for name, destination in ((DROPIN, drop), (RULES, rules)):
        source = root / WATCHDOG_DIR / key / name
        if not source.is_file():
            raise ContractError(f"{source} is missing")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
    return key


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    sub = ap.add_subparsers(dest="mode", required=True)
    k = sub.add_parser("key")
    k.add_argument("defconfig")
    i = sub.add_parser("install")
    i.add_argument("--defconfig", required=True)
    i.add_argument("--target", type=Path, required=True)
    sub.add_parser("check")
    args = ap.parse_args()
    root = args.root.resolve()
    try:
        if args.mode == "key":
            print(key_of(root, args.defconfig) or "-")
            return 0
        if args.mode == "install":
            print(install(root, args.defconfig, args.target))
            return 0
        problems = check(root)
    except (ContractError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for p in problems:
        print(f"ERROR: {p}", file=sys.stderr)
    if problems:
        print(f"board watchdog contract: {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print("board watchdog contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

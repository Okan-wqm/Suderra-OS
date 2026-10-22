#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""U-Boot contract of the production images (ADR-048 DEC-18; EI-013, EI-034,
EI-035, EI-036).

U-Boot verifies the FIT signature in bootm and nowhere else, trusts the key in
whatever device tree it runs with, and takes bootcmd, bootargs and every other
variable from a stored environment unless told not to. So the guarantee that
only the signed FIT of the chosen slot boots is made of configuration, and a
configuration line is not a guarantee: Kconfig drops an assignment whose
dependency is gone, and keeps a value the base defconfig expanded before the
fragment was merged (the previous fragment never turned LEGACY_IMAGE_FORMAT
off, and the resolved .config kept it on). The policy below says what must hold
and why; the two modes make it fail when it does not.

static
    Every configs/*_defconfig with BR2_TARGET_UBOOT=y, and the QEMU test build's
    fragment list: the fragment files Buildroot merges (in its order) must
    declare every required symbol with its value and unset every forbidden one
    (an explicit "is not set" line: a symbol the base defconfig enables stays
    enabled otherwise), each line must be a plain CONFIG_<NAME>=<value> or
    "# CONFIG_<NAME> is not set" line, the default environment file the image
    names must satisfy the environment rules below, and the patch directory
    must define the environment flag list those rules are written against.

resolved
    Given the U-Boot tree Buildroot configured (its .config after merge and
    olddefconfig, and its Kconfig files): the same policy on the resolved
    values, every symbol the fragments name exists in this U-Boot (a misspelt
    one, such as the ENV_REDUNDANT of the ADR text, whose real name is
    SYS_REDUNDAND_ENVIRONMENT, is dropped silently), every assignment of the
    fragments is honoured by the .config, and the default environment file the
    .config names is byte for byte the repository's. post-build.sh runs it on
    every image that builds U-Boot, and the QEMU boot-chain test runs it on the
    build it boots.

Environment rules (check_env): the file is the whole default environment, so
bootcmd is the one in it. It starts with the key guard and ends in a reset, it
and everything it runs name no command that boots without the FIT check, the
console input is the null device, bootdelay is -2 (-1 stops at the prompt),
no variable the stored environment could use to redirect the boot exists, and
the variables the stored environment may write (the flag list "w" entries)
are exactly the RAUC boot counters.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = "$(BR2_EXTERNAL_SUDERRA_PATH)"

# --------------------------------------------------------------------------
# Policy: symbol -> value and the reason a production U-Boot needs it.
# --------------------------------------------------------------------------
REQUIRED: dict[str, tuple[str, str]] = {
    "FIT": ("y", "the signed image format"),
    "FIT_SIGNATURE": ("y", "bootm enforces the configuration signature (EI-013)"),
    "RSA": ("y", "the FIT signature algorithm"),
    "SHA256": ("y", "the FIT signature digest"),
    "FIT_BEST_MATCH": ("y", "one FIT boots Pi 4B, CM4 and CM4 IO board by compatible"),
    "OF_CONTROL": ("y", "the key is read from the control FDT"),
    "OF_BOARD": (
        "y",
        "the control FDT is the firmware's device tree, which carries the key "
        "(OF_SEPARATE would run every board on the Pi 4B tree compiled into U-Boot)",
    ),
    "SYS_REDUNDAND_ENVIRONMENT": ("y", "two CRC-checked environment copies (EI-034)"),
    "ENV_WRITEABLE_LIST": ("y", "the stored environment may write only listed variables (EI-034)"),
    "ENV_APPEND": ("y", "the environment is never replaced wholesale"),
    "ENV_ACCESS_IGNORE_FORCE": ("y", "no forced write of a flagged variable"),
    "BOOTDELAY": ("-2", "autoboot at once, no abort check; -1 stops at the prompt (EI-035)"),
    "AUTOBOOT_KEYED": ("y", "Ctrl-C is locked while bootcmd runs"),
    "SYS_DEVICE_NULLDEV": ("y", "stdin is the null device"),
    "CMD_BOOTM": ("y", "the one boot command"),
    "CMD_FDT": ("y", "the key guard reads the control FDT"),
    "CMD_FS_GENERIC": ("y", "bootcmd loads the FIT"),
    "CMD_FAT": ("y", "bootcmd loads the FIT"),
    "FS_FAT": ("y", "the boot partition is FAT"),
    "CMD_SETEXPR": ("y", "the boot counters"),
    "CMD_ECHO": ("y", "bootcmd's messages"),
    "CMD_RUN": ("y", "bootcmd runs its steps"),
    "CMD_SAVEENV": ("y", "a trial boot spends a try"),
}

# Symbols the production U-Boot must not have, explicitly unset in a fragment.
FORBIDDEN: dict[str, str] = {
    "LEGACY_IMAGE_FORMAT": "a legacy uImage or script carries no signature and bootm accepts it (EI-036)",
    "ANDROID_BOOT_IMAGE": "an image format without the FIT signature",
    "EFI_LOADER": "bootefi starts an image bootm never verified (EI-035)",
    "CMD_BOOTEFI": "bootefi starts an image bootm never verified (EI-035)",
    "CMD_BOOTI": "booti starts a raw Image unverified (EI-035)",
    "CMD_BOOTZ": "bootz starts a raw zImage unverified (EI-035)",
    "CMD_SYSBOOT": "sysboot boots an extlinux.conf unverified (EI-035)",
    "CMD_PXE": "PXE boots whatever the network serves (EI-035)",
    "CMD_DHCP": "network boot (EI-035)",
    "CMD_TFTPBOOT": "network boot (EI-035)",
    "NET": "no network boot path (EI-035)",
    "NET_LWIP": "no network boot path (EI-035)",
    "USB": "no boot from a USB device, no USB keyboard (EI-035)",
    "CMD_USB": "no boot from a USB device (EI-035)",
    "BOOTSTD": "distro boot walks every boot method (EI-035)",
    "BOOTSTD_DEFAULTS": "distro boot walks every boot method (EI-035)",
    "BOOTSTD_FULL": "distro boot walks every boot method (EI-035)",
    "CMD_SOURCE": "a script from a file runs unverified (EI-036)",
    "CMD_DFU": "firmware download",
    "DFU": "firmware download",
    "CMD_ELF": "bootelf starts an image unverified",
    "CMD_GO": "go starts code at an address unverified",
    "CMD_LOADB": "code over the serial line",
    "CMD_LOADS": "code over the serial line",
    "USE_PREBOOT": "preboot runs before bootcmd (the base defconfig starts USB there)",
    "ENV_IS_IN_FAT": "a file on a writable FAT is neither redundant nor safe (EI-034)",
    "ENV_IS_IN_EXT4": "a file is not a redundant environment (EI-034)",
    "ENV_IMPORT_FDT": "the control FDT would amend the environment",
    "USE_BOOTARGS": "bootargs come from the signed FIT's device tree only (EI-013)",
    "BOOTARGS_SUBST": "bootargs would be rewritten from the environment",
    "SILENT_CONSOLE": "it creates a bootargs variable of its own (boot/bootm.c)",
    "BOOTCOUNT_LIMIT": "altbootcmd is a second boot command",
    "AUTOBOOT_KEYED_CTRLC": "Ctrl-C would stop bootcmd",
}

# Per image family: the environment storage of the board (a fact of the board,
# so it is not in the shared hardening fragment).
PROFILES: dict[str, dict[str, tuple[str, str]]] = {
    "production": {
        "ENV_IS_IN_MMC": ("y", "the environment is two raw copies on the boot disk (EI-034)"),
    },
    "qemu-test": {
        "ENV_IS_IN_FLASH": ("y", "the test machine's environment is a redundant pair in pflash"),
    },
}

# Commands no bootcmd step may run: a way to start an image the FIT check did
# not see, to reach the network or USB, or to run a script.
FORBIDDEN_COMMANDS = {
    "bootefi", "booti", "bootz", "bootelf", "bootvx", "sysboot", "pxe", "dhcp",
    "tftpboot", "tftp", "nfs", "usb", "source", "go", "loadb", "loads", "loady",
    "bootd", "fatload", "ext4load", "ext2load", "fatsize",
}
# A command word that only introduces another one in the shell of U-Boot.
SHELL_WORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!"}
# Variables whose presence would let the boot be redirected or replaced.
FORBIDDEN_VARIABLES = (
    "bootargs", "altbootcmd", "preboot", "boot_targets", "bootfile", "fdt_addr",
    "fdtcontroladdr",
    "kernel_addr_r", "ramdisk_addr_r", "loadaddr", "dhcpuboot", "scriptaddr",
    "pxefile_addr_r", "menucmd",
)
REQUIRED_VARIABLES = (
    "bootdelay", "stdin", "stdout", "stderr", "fdt_high", "initrd_high",
    "fitaddr", "suderra_bootdev", "suderra_attempts", "BOOT_ORDER",
    "BOOT_A_LEFT", "BOOT_B_LEFT", "suderra_guard", "suderra_pick",
    "suderra_boot", "suderra_rearm", "bootcmd",
)
# The only variables the stored environment may change: the RAUC U-Boot
# backend's (bootchooser: BOOT_ORDER and one BOOT_<slot>_LEFT per bootname).
WRITEABLE = {"BOOT_ORDER", "BOOT_A_LEFT", "BOOT_B_LEFT"}

ASSIGN = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")
NOT_SET = re.compile(r"^# CONFIG_([A-Za-z0-9_]+) is not set$")
VALUE = re.compile(r'^(y|m|-?[0-9]+|0x[0-9a-fA-F]+|"[^"\n]*")$')
KCONFIG_DEF = re.compile(r"^\s*(?:menu)?config\s+([A-Za-z0-9_]+)\s*$")


class ContractError(Exception):
    pass


@dataclass(frozen=True)
class Line:
    path: Path
    lineno: int
    symbol: str
    value: str  # "n" for "is not set"


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------
# Fragment files
# --------------------------------------------------------------------------
def parse_config_file(path: Path) -> list[Line]:
    lines: list[Line] = []
    errors: list[str] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.rstrip()
        if not text:
            continue
        m = NOT_SET.match(text)
        if m:
            lines.append(Line(path, n, m.group(1), "n"))
            continue
        if text.startswith("#"):
            if re.match(r"^#\s*CONFIG_[A-Za-z0-9_]+\s+is not set", text):
                errors.append(f"{path}:{n}: malformed 'is not set' line: {raw!r}")
            continue
        m = ASSIGN.match(text)
        if not m or not VALUE.match(m.group(2)):
            errors.append(
                f"{path}:{n}: not a CONFIG_<NAME>=<value> line (no trailing "
                f"comments): {raw!r}"
            )
            continue
        lines.append(Line(path, n, m.group(1), m.group(2)))
    if errors:
        raise ContractError("\n".join(errors))
    return lines


def read_defconfig(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(BR2_[A-Za-z0-9_]+)=(.*)$", raw.strip())
        if m:
            values[m.group(1)] = m.group(2).strip().strip('"')
    return values


def external_paths(value: str, root: Path) -> list[Path]:
    paths = []
    for word in value.split():
        if not word.startswith(EXTERNAL + "/"):
            raise ContractError(f"{word}: a U-Boot input must live under {EXTERNAL}")
        paths.append(root / word[len(EXTERNAL) + 1:])
    return paths


def effective(files: list[Path]) -> dict[str, Line]:
    eff: dict[str, Line] = {}
    for path in files:
        for line in parse_config_file(path):
            eff[line.symbol] = line
    return eff


def uboot_defconfigs(root: Path) -> list[Path]:
    """The defconfigs that build a board's U-Boot. suderra_aarch64_defconfig
    enables BR2_TARGET_UBOOT with no board defconfig (a template for a board
    the repository does not define), so there is no U-Boot to check there."""
    out = []
    for p in sorted((root / "configs").glob("*_defconfig")):
        values = read_defconfig(p)
        if values.get("BR2_TARGET_UBOOT") == "y" and values.get("BR2_TARGET_UBOOT_BOARD_DEFCONFIG"):
            out.append(p)
    return out


# --------------------------------------------------------------------------
# Environment file
# --------------------------------------------------------------------------
def parse_env(path: Path) -> dict[str, str]:
    """The default environment as U-Boot's Makefile (filechk_defaultenv.h) reads
    it: comment and empty lines dropped, a backslash at the end of a line joins
    the next line (its leading blanks removed)."""
    text = path.read_text(encoding="utf-8")
    kept = [ln for ln in text.split("\n") if not ln.startswith("#") and ln != ""]
    joined = re.sub(r"\\\n\s*", "", "\n".join(kept))
    env: dict[str, str] = {}
    errors = []
    for entry in joined.split("\n"):
        if not entry:
            continue
        name, eq, value = entry.partition("=")
        if not eq or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            errors.append(f"{path}: not a name=value line: {entry[:60]!r}")
        elif name in env:
            errors.append(f"{path}: {name} is defined twice")
        else:
            env[name] = value
    if errors:
        raise ContractError("\n".join(errors))
    return env


def run_closure(env: dict[str, str], start: str) -> list[str]:
    """The texts of variable `start` and of every variable it runs."""
    seen: list[str] = []
    todo = [start]
    while todo:
        name = todo.pop()
        if name in seen or name not in env:
            continue
        seen.append(name)
        todo += re.findall(r"\brun\s+([A-Za-z_][A-Za-z0-9_]*)", env[name])
    return seen


def commands_of(text: str) -> list[tuple[str, list[str]]]:
    """(command, arguments) of every statement of a U-Boot shell text. The
    arguments of echo are not looked at as commands: only the first word of a
    statement is."""
    out: list[tuple[str, list[str]]] = []
    for part in re.split(r";|&&|\|\||\n", text):
        words = part.split()
        while words and words[0] in SHELL_WORDS:
            words = words[1:]
        if not words or words[0] == "for":
            continue
        out.append((words[0], words[1:]))
    return out


def flag_list(patches: Path) -> dict[str, str]:
    """NAME -> flags of the CFG_ENV_FLAGS_LIST_STATIC the patch directory sets."""
    found: dict[str, str] = {}
    for patch in sorted(patches.glob("*.patch")):
        for m in re.finditer(r'^\+#define CFG_ENV_FLAGS_LIST_STATIC\s+"([^"]*)"',
                             patch.read_text(encoding="utf-8"), re.M):
            for item in m.group(1).split(","):
                name, _, flags = item.partition(":")
                found[name] = flags
    return found


def check_env(path: Path, patches: Path, label: str, root: Path) -> list[str]:
    problems: list[str] = []
    try:
        env = parse_env(path)
    except ContractError as e:
        return [f"{label}: {e}"]
    for name in REQUIRED_VARIABLES:
        if name not in env:
            problems.append(f"{label}: {rel(path, root)} does not define {name}")
    for name in FORBIDDEN_VARIABLES:
        if name in env:
            problems.append(
                f"{label}: {rel(path, root)} defines {name}: it would redirect or "
                f"replace what the signed FIT says (board code or the FIT's own "
                f"device tree provides it)"
            )
    want = {"bootdelay": "-2", "stdin": "nulldev"}
    for name, value in want.items():
        if env.get(name) != value:
            problems.append(f"{label}: {name} must be {value}, is {env.get(name)!r}")
    boot = env.get("bootcmd", "")
    if not boot.startswith("if run suderra_guard; then"):
        problems.append(f"{label}: bootcmd must start with 'if run suderra_guard; then'")
    if not re.search(r"(^|[;\s])reset\s*$", boot):
        problems.append(f"{label}: bootcmd must end in 'reset': it must never return to a prompt")
    steps = run_closure(env, "bootcmd")
    for need in ("suderra_guard", "suderra_pick", "suderra_boot", "suderra_rearm"):
        if need not in steps:
            problems.append(f"{label}: bootcmd does not run {need}")
    # The try a boot spends is saved BEFORE the slot boots: a boot that never
    # returns (a kernel that panics, a dm-verity restart) has then counted.
    # tests/image-contracts/uboot-env-exec-contract-test.sh executes the choice.
    boot_text = env.get("bootcmd", "")
    if not re.search(r"\bsaveenv\b[^;]*;\s*run suderra_boot\b", boot_text):
        problems.append(f"{label}: bootcmd must saveenv immediately before 'run suderra_boot': the try is spent before the kernel starts")
    for step in steps:
        for command, args in commands_of(env[step]):
            # A counter changes by one try or is armed with suderra_attempts. A
            # step that zeroes it turns one failed load into a slot that never
            # boots again (a factory board has no other slot).
            if command == "setenv" and args and re.fullmatch(r"BOOT_[A-Z]_LEFT", args[0]) and \
                    args[1:2] != ["${suderra_attempts}"]:
                problems.append(f"{label}: {step} sets {args[0]} to {' '.join(args[1:2]) or 'nothing'}: only suderra_attempts may arm a slot")
            if command == "setexpr" and args and re.fullmatch(r"BOOT_[A-Z]_LEFT", args[0]) and \
                    args[1:] != ["${" + args[0] + "}", "-", "1"]:
                problems.append(f"{label}: {step} changes {args[0]} other than by spending one try")
            if command in FORBIDDEN_COMMANDS:
                problems.append(f"{label}: {step} runs '{command}': a boot path the FIT check does not cover")
            if command == "env" and args[:1] in (["import"], ["run"]):
                problems.append(f"{label}: {step} runs 'env {args[0]}'")
            if command in ("setenv", "env") and set(args[:2]) & {"bootargs", "bootcmd", "stdin"}:
                problems.append(f"{label}: {step} sets {args[0] if command == 'setenv' else args[1:2]}: only the default environment may")
    if "fdt get value" not in env.get("suderra_guard", "") or \
            "/signature/key-fit-signing" not in env.get("suderra_guard", ""):
        problems.append(f"{label}: suderra_guard must read /signature/key-fit-signing of the control FDT")
    if "fdt addr ${fdtcontroladdr};" not in env.get("suderra_guard", ""):
        problems.append(f"{label}: suderra_guard must read the control FDT (fdt addr ${{fdtcontroladdr}}), not another tree")
    if not re.search(r"test\s+\"\$\{suderra_required\}\"\s+=\s+conf\s*$", env.get("suderra_guard", "")):
        problems.append(f"{label}: suderra_guard must end by requiring required = conf")
    if "bootm ${fitaddr}" not in env.get("suderra_boot", ""):
        problems.append(f"{label}: suderra_boot must bootm ${{fitaddr}} (the FIT is the only boot)")
    for name in ("BOOT_A_LEFT", "BOOT_B_LEFT", "suderra_attempts"):
        if name in env and not re.fullmatch(r"[0-9]", env[name]):
            problems.append(f"{label}: {name}={env[name]!r} must be one digit (setexpr works in hex)")
    if env.get("suderra_attempts") == "0":
        problems.append(f"{label}: suderra_attempts must be at least 1: an armed slot needs a try")
    armed = env.get("suderra_attempts", "")
    if env.get("BOOT_A_LEFT") != armed:
        problems.append(f"{label}: BOOT_A_LEFT must start at suderra_attempts ({armed}): the factory slot is armed")
    if env.get("BOOT_B_LEFT") != "0":
        problems.append(f"{label}: BOOT_B_LEFT must start at 0: the factory image has no slot B")
    flags = flag_list(patches)
    if not flags:
        problems.append(f"{label}: no patch in {rel(patches, root)} defines CFG_ENV_FLAGS_LIST_STATIC")
    writeable = {n for n, f in flags.items() if "w" in f}
    if writeable != WRITEABLE:
        problems.append(
            f"{label}: the writeable variables are {sorted(writeable)}, must be exactly "
            f"the RAUC boot counters {sorted(WRITEABLE)}"
        )
    for name in WRITEABLE & set(flags):
        if name not in env:
            problems.append(f"{label}: {name} is writeable but has no default in {rel(path, root)}")
    return problems


# --------------------------------------------------------------------------
# Policy over fragments and over a resolved .config
# --------------------------------------------------------------------------
def policy(profile: str) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    return {**REQUIRED, **PROFILES[profile]}, dict(FORBIDDEN)


def check_fragments(label: str, files: list[Path], profile: str, root: Path) -> list[str]:
    problems: list[str] = []
    try:
        eff = effective(files)
    except ContractError as e:
        return [str(e)]
    required, forbidden = policy(profile)
    for sym, (value, why) in required.items():
        line = eff.get(sym)
        if line is None or line.value != value:
            where = (f"{rel(line.path, root)}:{line.lineno} sets it to {line.value}"
                     if line else "no fragment declares it")
            problems.append(f"{label}: CONFIG_{sym} must be {value} ({why}); {where}")
    for sym, why in forbidden.items():
        line = eff.get(sym)
        if line is None or line.value != "n":
            where = (f"{rel(line.path, root)}:{line.lineno} sets it to {line.value}"
                     if line else "no fragment unsets it")
            problems.append(
                f"{label}: CONFIG_{sym} must be explicitly unset ({why}); {where}"
            )
    return problems


def check_image_inputs(defconfig: Path, root: Path) -> list[str]:
    label = defconfig.name
    values = read_defconfig(defconfig)
    problems: list[str] = []
    try:
        files = external_paths(values.get("BR2_TARGET_UBOOT_CONFIG_FRAGMENT_FILES", ""), root)
        env_files = external_paths(values.get("BR2_TARGET_UBOOT_DEFAULT_ENV_FILE", ""), root)
        patch_dirs = external_paths(values.get("BR2_TARGET_UBOOT_PATCH", ""), root)
    except ContractError as e:
        return [f"{label}: {e}"]
    for f in files:
        if not f.is_file():
            problems.append(f"{label}: fragment {rel(f, root)} does not exist")
    if problems:
        return problems
    if len(env_files) != 1 or not env_files[0].is_file():
        problems.append(f"{label}: BR2_TARGET_UBOOT_DEFAULT_ENV_FILE must name one existing file under {EXTERNAL}")
    if len(patch_dirs) != 1 or not patch_dirs[0].is_dir():
        problems.append(f"{label}: BR2_TARGET_UBOOT_PATCH must name one directory under {EXTERNAL}")
    problems += check_fragments(label, files, "production", root)
    if not problems:
        problems += check_env(env_files[0], patch_dirs[0], label, root)
    return problems


def qemu_test_inputs(root: Path) -> list[Path]:
    return [
        root / "board/suderra/uboot/hardening.config",
        root / "board/suderra/uboot/qemu-arm64.config",
    ]


def check_static(root: Path) -> list[str]:
    problems: list[str] = []
    defconfigs = uboot_defconfigs(root)
    if not defconfigs:
        return [f"no defconfig under {root / 'configs'} builds U-Boot"]
    for defconfig in defconfigs:
        problems += check_image_inputs(defconfig, root)
    qemu = qemu_test_inputs(root)
    if all(f.is_file() for f in qemu):
        problems += check_fragments("qemu-test", qemu, "qemu-test", root)
    return problems


def kconfig_symbols(tree: Path) -> set[str]:
    symbols: set[str] = set()
    for path in tree.rglob("Kconfig*"):
        if not path.is_file() or "doc" in path.relative_to(tree).parts[:1]:
            continue
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = KCONFIG_DEF.match(raw)
            if m:
                symbols.add(m.group(1))
    return symbols


def read_dotconfig(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = ASSIGN.match(raw)
        if m:
            values[m.group(1)] = m.group(2)
    return values


def check_resolved(
    label: str, files: list[Path], profile: str, env_file: Path, tree: Path,
    dotconfig: Path, root: Path,
) -> list[str]:
    if not dotconfig.is_file():
        raise ContractError(f"no U-Boot .config at {dotconfig}")
    cfg = read_dotconfig(dotconfig)
    known = kconfig_symbols(tree)
    if not known:
        raise ContractError(f"no Kconfig symbols found under {tree}")
    problems: list[str] = []
    required, forbidden = policy(profile)
    for sym, (value, why) in required.items():
        if cfg.get(sym, "n") != value:
            problems.append(f"{label}: resolved CONFIG_{sym}={cfg.get(sym, 'n')}, must be {value} ({why})")
    for sym, why in forbidden.items():
        if cfg.get(sym, "n") != "n":
            problems.append(f"{label}: resolved CONFIG_{sym}={cfg.get(sym)}, must be unset ({why})")
    for sym, line in sorted(effective(files).items()):
        if sym not in known:
            problems.append(
                f"{rel(line.path, root)}:{line.lineno}: CONFIG_{sym} does not exist in "
                f"this U-Boot; the line is dropped silently"
            )
        elif cfg.get(sym, "n") != line.value:
            problems.append(
                f"{rel(line.path, root)}:{line.lineno}: CONFIG_{sym}={line.value} is not "
                f"honoured: the resolved .config has {cfg.get(sym, 'n')} (an unmet "
                f"dependency, or a value the base defconfig set earlier, wins)"
            )
    named = cfg.get("DEFAULT_ENV_FILE", "").strip('"')
    if cfg.get("USE_DEFAULT_ENV_FILE") != "y":
        problems.append(f"{label}: resolved CONFIG_USE_DEFAULT_ENV_FILE is not y: the board's own environment would be built in")
    elif not named or not Path(named).is_file():
        problems.append(f"{label}: CONFIG_DEFAULT_ENV_FILE={named!r} is not a file")
    elif Path(named).read_bytes() != env_file.read_bytes():
        problems.append(f"{label}: the default environment the build used ({named}) differs from {rel(env_file, root)}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("static")
    r = sub.add_parser("resolved")
    r.add_argument("--defconfig", help="image defconfig name (production)")
    r.add_argument("--profile", choices=sorted(PROFILES), default="production")
    r.add_argument("--fragments", nargs="+", type=Path, help="fragment files, in merge order (qemu-test)")
    r.add_argument("--env-file", type=Path, help="the default environment file the build used")
    r.add_argument("--uboot-tree", type=Path, required=True)
    r.add_argument("--dotconfig", type=Path)
    args = ap.parse_args()
    root = args.root.resolve()
    try:
        if args.mode == "static":
            problems = check_static(root)
        else:
            if args.defconfig:
                name = args.defconfig if args.defconfig.endswith("_defconfig") else args.defconfig + "_defconfig"
                values = read_defconfig(root / "configs" / name)
                if not (values.get("BR2_TARGET_UBOOT") == "y"
                        and values.get("BR2_TARGET_UBOOT_BOARD_DEFCONFIG")):
                    print(f"{name} builds no board U-Boot; nothing to check")
                    return 0
                files = external_paths(values["BR2_TARGET_UBOOT_CONFIG_FRAGMENT_FILES"], root)
                env_file = external_paths(values["BR2_TARGET_UBOOT_DEFAULT_ENV_FILE"], root)[0]
                label = name
            elif args.fragments and args.env_file:
                files, env_file, label = args.fragments, args.env_file, "qemu-test"
            else:
                ap.error("resolved needs --defconfig, or --fragments with --env-file")
            tree = args.uboot_tree.resolve()
            problems = check_resolved(
                label, files, args.profile, env_file, tree,
                (args.dotconfig or tree / ".config").resolve(), root,
            )
    except (ContractError, OSError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        return 1
    print(f"U-Boot contract ({args.mode}) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Kernel config contract of every Suderra OS image (ADR-048 DEC-8.10).

The kernel symbols an image needs are not a matter of taste: they follow from
what the image runs. The nftables rulesets need conntrack, ct and limit; the
LUKS2 /data needs dm-crypt; the agent unit's DevicePolicy=closed needs the
cgroup BPF device controller; a production UKI or FIT needs initramfs support
for its dm-verity ramdisk; a tpm-ek-sha256 board needs its TPM driver. Each
requirement below names the file that creates it.

Two modes:

static
    For every configs/*_defconfig that builds a kernel, take the kernel
    config files the defconfig names (BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE,
    then BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES, in Buildroot's merge order)
    and require that the effective value of every required symbol is =y.
    Requirements are declared in the repository's files, never inherited
    from an upstream defconfig (x86_64_defconfig, bcm2711_defconfig) that
    can change under a kernel bump. Every line of those files must be a plain
    CONFIG_<NAME>=<value> or "# CONFIG_<NAME> is not set" line: a trailing
    comment hides a typo from every reader.

resolved
    Given the kernel tree Buildroot configured for one defconfig (its .config
    after merge, olddefconfig and Buildroot's fixups), require that
    (1) every required symbol is =y,
    (2) every symbol the defconfig's config files name exists in that tree's
        Kconfig (a nonexistent name such as CONFIG_SPIDEV is dropped silently),
    (3) every effective assignment of those files is honoured by the .config,
        except the tracked overrides in KNOWN_OVERRIDES; an override that no
        longer happens fails too, so the list cannot go stale.
    board/suderra/common/post-build.sh runs this mode for every image, so no
    image whose kernel lost a required symbol or a declared line is built.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# --------------------------------------------------------------------------
# Requirements: capability -> (symbols, reason). Every symbol must be =y:
# the production kernels are monolithic (kernel-fragment.config), and a module
# that nothing loads is not a capability.
# --------------------------------------------------------------------------
CAPABILITIES: dict[str, tuple[tuple[str, ...], str]] = {
    "firewall": (
        (
            "NETFILTER",
            "NF_TABLES",
            "NF_TABLES_INET",
            "NF_CONNTRACK",
            "NFT_CT",
            "NFT_LIMIT",
            "NFT_REJECT",
            "NFT_REJECT_INET",
            "NFT_LOG",
            "NF_LOG_SYSLOG",
        ),
        "rootfs-overlay/etc/nftables.conf and nftables.provisioning.conf use inet "
        "tables, ct state, limit and a per-source meter; NFT_LOG needs its "
        "NF_LOG_SYSLOG backend (DEC-8.10, DEC-11)",
    ),
    "luks": (
        ("BLK_DEV_DM", "DM_CRYPT", "CRYPTO_XTS", "CRYPTO_USER_API_SKCIPHER"),
        "suderra-data-unlock formats and opens the LUKS2 /data with cryptsetup "
        "(aes-xts-plain64, AF_ALG keyslot encryption) (DEC-8.10)",
    ),
    "agent-sandbox": (
        ("SECCOMP", "SECCOMP_FILTER", "BPF_SYSCALL", "CGROUP_BPF"),
        "contracts/suderra-edge/v1/unit-directives.json: SystemCallFilter= needs "
        "seccomp, and DevicePolicy=closed/DeviceAllow= are enforced on the "
        "unified cgroup hierarchy only by a cgroup BPF device program",
    ),
    "tpm-x86": (
        ("TCG_TPM", "TCG_TIS", "TCG_CRB"),
        "boards.json device_binding_method tpm-ek-sha256 on x86 (dTPM/PTT, swtpm)",
    ),
    "tpm-spi": (
        ("TCG_TPM", "TCG_TIS_SPI"),
        "boards.json device_binding_method tpm-ek-sha256 on the SPI TPM of "
        "aarch64 boards (RevPi Connect 4 SLB9670)",
    ),
    "verity-initramfs": (
        ("BLK_DEV_INITRD", "RD_GZIP", "BLK_DEV_DM", "DM_VERITY"),
        "scripts/production-artifacts.sh puts the gzip dm-verity initramfs into "
        "the signed UKI/FIT; root=/dev/mapper/suderra-root exists only through it "
        "(DEC-8.10, EI-009)",
    ),
    "x86-field-io": (
        (
            "SERIAL_8250",
            "PCI",
            "USB",
            "USB_XHCI_HCD",
            "USB_XHCI_PCI",
            "HID",
            "HID_GENERIC",
            "USB_HID",
            "USB_ACM",
            "USB_SERIAL",
            "USB_SERIAL_FTDI_SIO",
            "USB_SERIAL_CP210X",
            "USB_SERIAL_CH341",
            "USB_SERIAL_PL2303",
        ),
        "the x86 agent drop-in grants char-ttyS, char-ttyUSB and char-ttyACM: "
        "8250 UARTs, xHCI and the FTDI/CP210x/CH341/PL2303 and CDC-ACM "
        "RS485/RS232 adapters (DEC-8.10, EI-043)",
    ),
    "rpi-field-io": (
        ("I2C_CHARDEV", "SPI_SPIDEV", "SERIAL_AMBA_PL011"),
        "the rpi4-cm4 agent drop-in grants /dev/i2c-1, /dev/spidev0.* and "
        "/dev/ttyAMA0 (unit-directives.json board_dropins)",
    ),
    "revpi-field-io": (
        ("SERIAL_AMBA_PL011",),
        "the revpi-connect4 agent drop-in grants /dev/ttyAMA5 (RS485)",
    ),
}

BOARD_IO = {
    "qemu-x86_64": "x86-field-io",
    "x86-ipc": "x86-field-io",
    "rpi4-cm4": "rpi-field-io",
    "revpi-connect4": "revpi-field-io",
}

# --------------------------------------------------------------------------
# Tracked overrides: (config file name, symbol) -> reason. Resolved mode
# accepts exactly these unhonoured lines and fails when one is honoured again.
# All belong to EI-056 (hardening intent checked in fragments, not in the
# effective .config; owner and deadline in
# docs/assessments/2026-10-19-edge-agent-integration-audit.md#EI-056).
# --------------------------------------------------------------------------
KNOWN_OVERRIDES: dict[tuple[str, str], str] = {
    ("linux-x86_64.config", "GCC_PLUGIN_STACKLEAK"):
        "EI-056: buildroot linux/linux.mk disables CONFIG_GCC_PLUGINS",
    ("kernel-fragment.config", "USER_NS"):
        "EI-056: buildroot package/systemd/systemd.mk enables CONFIG_USER_NS",
    ("linux-rpi4-hardening.config", "USER_NS"):
        "EI-056: buildroot package/systemd/systemd.mk enables CONFIG_USER_NS",
    ("kernel-fragment.config", "INTEGRITY_TRUSTED_KEYRING"):
        "EI-056: depends on SYSTEM_TRUSTED_KEYRING and INTEGRITY_ASYMMETRIC_KEYS, "
        "which no x86 config enables",
    ("kernel-fragment.config", "SECONDARY_TRUSTED_KEYRING"):
        "EI-056: depends on SYSTEM_TRUSTED_KEYRING, which no x86 config enables",
}

ASSIGN = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")
NOT_SET = re.compile(r"^# CONFIG_([A-Za-z0-9_]+) is not set$")
VALUE = re.compile(r'^(y|m|n|"[^"\\]*"|-?[0-9]+|0x[0-9a-fA-F]+)$')
KCONFIG_DEF = re.compile(r"^\s*(?:menu)?config\s+([A-Za-z0-9_]+)\s*$")


class ContractError(Exception):
    pass


@dataclass(frozen=True)
class Line:
    path: Path
    lineno: int
    symbol: str
    value: str  # "n" for "is not set"


@dataclass(frozen=True)
class Image:
    defconfig: str
    kind: str  # board | family | excluded
    board: str  # board_profile, family name or ""
    arch: str
    binding: str
    prod: bool
    files: tuple[Path, ...]


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
            values[m.group(1)] = m.group(2)
    return values


def external_path(value: str, root: Path) -> list[Path]:
    text = value.strip().strip('"')
    out = []
    for item in text.split():
        resolved = item.replace("$(BR2_EXTERNAL_SUDERRA_PATH)", str(root))
        if "$(" in resolved:
            raise ContractError(f"unsupported variable in kernel config path {item!r}")
        out.append(Path(resolved))
    return out


def classify(root: Path) -> dict[str, tuple[str, str, str, str]]:
    boards = json.loads(
        (root / "contracts/suderra-edge/v1/boards.json").read_text(encoding="utf-8")
    )
    classes: dict[str, tuple[str, str, str, str]] = {}

    def put(defconfig: str, value: tuple[str, str, str, str]) -> None:
        if defconfig in classes:
            raise ContractError(f"{defconfig} is classified twice in boards.json")
        classes[defconfig] = value

    for b in boards["boards"]:
        for image in b["os_images"]:
            put(image["defconfig"],
                ("board", b["board_profile"], b["arch"], b["device_binding_method"]))
    for f in boards["pending_board_families"]:
        for image in f["os_images"]:
            put(image["defconfig"],
                ("family", f["family"], f["arch"], f["device_binding_method"]))
    for e in boards["excluded_os_images"]:
        put(e["defconfig"], ("excluded", "", "", ""))
    return classes


def images(root: Path) -> list[Image]:
    classes = classify(root)
    out = []
    for path in sorted((root / "configs").glob("*_defconfig")):
        values = read_defconfig(path)
        if values.get("BR2_LINUX_KERNEL") != "y":
            continue
        if path.name not in classes:
            raise ContractError(f"{path.name} builds a kernel but boards.json does not classify it")
        kind, board, arch, binding = classes[path.name]
        files: list[Path] = []
        if values.get("BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG") == "y":
            files += external_path(values["BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE"], root)
        if "BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES" in values:
            files += external_path(values["BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES"], root)
        for f in files:
            if not f.is_file():
                raise ContractError(f"{path.name}: kernel config file missing: {f}")
        out.append(
            Image(
                defconfig=path.name,
                kind=kind,
                board=board,
                arch=arch,
                binding=binding,
                prod=values.get("BR2_PACKAGE_SUDERRA_VARIANT_PROD") == "y",
                files=tuple(files),
            )
        )
    return out


def capabilities_of(image: Image) -> list[str]:
    if image.kind == "excluded":
        return []
    caps = ["firewall", "luks", "agent-sandbox"]
    if image.binding == "tpm-ek-sha256":
        caps.append("tpm-x86" if image.arch == "x86_64" else "tpm-spi")
    if image.prod:
        caps.append("verity-initramfs")
    io = BOARD_IO.get(image.board)
    if io is None:
        raise ContractError(f"{image.defconfig}: no field I/O requirement for board {image.board!r}")
    caps.append(io)
    return caps


def required(image: Image) -> dict[str, str]:
    req: dict[str, str] = {}
    for cap in capabilities_of(image):
        for sym in CAPABILITIES[cap][0]:
            req.setdefault(sym, cap)
    return req


def effective(image: Image) -> dict[str, Line]:
    eff: dict[str, Line] = {}
    for path in image.files:
        for line in parse_config_file(path):
            eff[line.symbol] = line
    return eff


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def check_static(root: Path) -> list[str]:
    problems = []
    for image in images(root):
        try:
            eff = effective(image)
        except ContractError as e:
            problems.append(str(e))
            continue
        for sym, cap in required(image).items():
            line = eff.get(sym)
            if line is None or line.value != "y":
                where = (
                    f"{rel(line.path, root)}:{line.lineno} sets it to {line.value}"
                    if line else "no config file of the image declares it"
                )
                problems.append(
                    f"{image.defconfig}: CONFIG_{sym} must be =y ({cap}: "
                    f"{CAPABILITIES[cap][1]}); {where}"
                )
    return problems


def kconfig_symbols(tree: Path) -> set[str]:
    symbols: set[str] = set()
    for path in tree.rglob("Kconfig*"):
        if not path.is_file() or "Documentation" in path.parts:
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
    root: Path, defconfig: str, tree: Path, dotconfig: Path | None = None
) -> list[str]:
    matches = [i for i in images(root) if i.defconfig == defconfig]
    if not matches:
        raise ContractError(f"{defconfig} is not a kernel-building defconfig under {root / 'configs'}")
    image = matches[0]
    dotconfig = dotconfig or tree / ".config"
    if not dotconfig.is_file():
        raise ContractError(f"no kernel .config at {dotconfig}")
    cfg = read_dotconfig(dotconfig)
    known = kconfig_symbols(tree)
    if not known:
        raise ContractError(f"no Kconfig symbols found under {tree}")
    problems = []
    for sym, cap in required(image).items():
        if cfg.get(sym) != "y":
            problems.append(
                f"{defconfig}: resolved CONFIG_{sym}={cfg.get(sym, 'n')}, must be y "
                f"({cap}: {CAPABILITIES[cap][1]})"
            )
    named: dict[str, Line] = {}
    for path in image.files:
        for line in parse_config_file(path):
            named.setdefault(line.symbol, line)
            if line.symbol not in known:
                problems.append(
                    f"{rel(path, root)}:{line.lineno}: CONFIG_{line.symbol} does not "
                    f"exist in this kernel; the line is dropped silently"
                )
    eff = effective(image)
    seen_overrides: set[tuple[str, str]] = set()
    for sym, line in sorted(eff.items()):
        if sym not in known:
            continue
        got = cfg.get(sym, "n")
        key = (line.path.name, sym)
        if got == line.value:
            continue
        if key in KNOWN_OVERRIDES:
            seen_overrides.add(key)
            continue
        problems.append(
            f"{rel(line.path, root)}:{line.lineno}: CONFIG_{sym}={line.value} is "
            f"not honoured: the resolved .config has {got} (an unmet dependency "
            f"or a Buildroot fixup overrides it)"
        )
    for key, reason in KNOWN_OVERRIDES.items():
        applies = any(p.name == key[0] for p in image.files) and key[1] in eff \
            and eff[key[1]].path.name == key[0] and key[1] in known
        if applies and key not in seen_overrides:
            problems.append(
                f"{defconfig}: tracked override {key[0]} CONFIG_{key[1]} ({reason}) "
                f"no longer happens; remove it from KNOWN_OVERRIDES"
            )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("static")
    r = sub.add_parser("resolved")
    r.add_argument("--defconfig", required=True)
    r.add_argument("--kernel-tree", type=Path, required=True,
                   help="kernel source tree whose Kconfig files define the symbols")
    r.add_argument("--config", type=Path,
                   help="resolved .config (default: <kernel-tree>/.config)")
    sub.add_parser("list")
    args = ap.parse_args()
    root = args.root.resolve()
    try:
        if args.mode == "static":
            problems = check_static(root)
            label = "static"
        elif args.mode == "resolved":
            problems = check_resolved(
                root, args.defconfig, args.kernel_tree.resolve(),
                args.config.resolve() if args.config else None,
            )
            label = f"resolved {args.defconfig}"
        else:
            for image in images(root):
                caps = capabilities_of(image)
                print(f"{image.defconfig}\t{','.join(caps) or '-'}\t"
                      f"{' '.join(rel(f, root) for f in image.files) or '-'}")
            return 0
    except ContractError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for p in problems:
        print(f"ERROR: {p}", file=sys.stderr)
    if problems:
        print(f"kernel config contract ({label}): {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print(f"kernel config contract ({label}) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

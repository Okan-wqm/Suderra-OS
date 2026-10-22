#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""suderra-data-unlock in a VM with a software TPM (ADR-048 DEC-14, DEC-24; EI-078).

The production first boot provisions /data: luksFormat, TPM2 enrolment, the
ext4 filesystem on the opened volume, the layout and the binds. A static test
cannot tell whether that sequence works, and the first image to run it found
that `mkfs.ext4` did not exist after the volume was already sealed. This test
runs the real script (board/suderra/common/rootfs-overlay/usr/sbin/
suderra-data-unlock) with the real cryptsetup, systemd-cryptenroll, mkfs.ext4
and systemd-tmpfiles in a QEMU guest whose TPM is an swtpm, on a blank virtio
disk, and drives it through tests/qemu/data-unlock-scenarios.sh.

The guest is a small initramfs built from the host's tools, booted with the
kernel of a Suderra OS x86_64 QEMU image (dm-crypt, TPM and virtio built in);
the script and the layout under test are the repository's own files. Only
suderra-installer is a test double: it records the results and lifecycle calls
the script makes, and refuses a result reason the contract does not allow
(contracts/suderra-edge/v1/schemas/result.schema.json), as the real one does.

The kernel is the bzImage of the image build (output/<defconfig>/images/
bzImage), or --kernel / SUDERRA_DATA_TEST_KERNEL. A missing tool or kernel
fails the test: a skipped gate is not a gate.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
UNLOCK = ROOT / "board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock"
LAYOUT = (
    ROOT
    / "board/suderra/common/rootfs-overlay/usr/lib/suderra/data-layout.tmpfiles.conf"
)
SCENARIOS = HERE / "data-unlock-scenarios.sh"
RESULT_SCHEMA = ROOT / "contracts/suderra-edge/v1/schemas/result.schema.json"
DEFAULT_KERNELS = (
    ROOT / "output/suderra_qemu_x86_64_defconfig/images/bzImage",
    ROOT / "output/suderra_qemu_x86_64_prod_ab_defconfig/images/bzImage",
)
EXPECTED_SCENARIOS = (
    "fresh-provisioning",
    "existing-volume-unlocks",
    "mkfs-failure-rolls-back",
    "enrol-failure-rolls-back",
    "interrupted-provisioning-is-redone",
    "foreign-signature-refused",
    "unseal-failure-keeps-the-volume",
)
SEARCH = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
# Executables the guest needs, besides BusyBox.
HOST_TOOLS = (
    "cryptsetup",
    "systemd-cryptenroll",
    "systemd-tmpfiles",
    "mke2fs",
    "blkid",
    "tpm2_pcrextend",
    "tpm2_pcrread",
    # BusyBox of Debian and Ubuntu has no mountpoint applet; the image's has.
    "mountpoint",
)
# Libraries systemd and the TPM tools dlopen: ldd does not list them.
DLOPENED = (
    "libgcc_s.so.1",
    "libtss2-esys.so.0",
    "libtss2-mu.so.0",
    "libtss2-rc.so.0",
    "libtss2-sys.so.1",
    "libtss2-tcti-device.so.0",
)


class TestError(Exception):
    pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def find_tool(name: str) -> Path:
    for directory in SEARCH:
        candidate = Path(directory) / name
        if candidate.is_file():
            return candidate.resolve()
    found = shutil.which(name)
    if found:
        return Path(found).resolve()
    raise TestError(
        f"{name} not found on the host; install cryptsetup-bin, systemd, e2fsprogs, "
        "tpm2-tools, swtpm, qemu-system-x86 and busybox-static"
    )


def library_closure(binary: Path) -> dict[str, Path]:
    """Library path as the dynamic loader names it -> the file behind it."""
    result: dict[str, Path] = {}
    output = subprocess.run(
        ["ldd", str(binary)], check=True, capture_output=True, text=True
    ).stdout
    for line in output.splitlines():
        match = re.search(r"=> (/\S+)", line) or re.match(r"\s*(/\S+) \(0x", line)
        if match:
            name = match.group(1)
            result[name] = Path(name).resolve()
    return result


class Cpio:
    """A newc cpio archive, written in memory."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.inode = 1
        self.seen: set[str] = set()

    def entry(self, name: str, mode: int, data: bytes = b"", nlink: int = 1) -> None:
        raw_name = name.encode() + b"\0"
        header = "070701" + "".join(
            f"{value:08X}"
            for value in (
                self.inode,
                mode,
                0,
                0,
                nlink,
                0,
                len(data),
                0,
                0,
                0,
                0,
                len(raw_name),
                0,
            )
        )
        self.inode += 1
        blob = header.encode() + raw_name
        blob += b"\0" * (-len(blob) % 4)
        blob += data
        blob += b"\0" * (-len(blob) % 4)
        self.chunks.append(blob)

    @staticmethod
    def merged_usr(name: str) -> str:
        """The image is merged-/usr like Buildroot's: /bin, /sbin, /lib and
        /lib64 are links into /usr, and libraries name themselves by either
        path (cryptsetup loads its token plugin from /lib/<triplet>/cryptsetup)."""
        name = name.strip("/")
        head = name.split("/", 1)[0]
        if head in ("bin", "sbin", "lib", "lib64") and "/" in name:
            return f"usr/{name}"
        return name

    def directory(self, name: str) -> None:
        name = (
            self.merged_usr(name)
            if name not in ("bin", "sbin", "lib", "lib64")
            else name
        )
        parts = name.strip("/").split("/")
        for depth in range(1, len(parts) + 1):
            path = "/".join(parts[:depth])
            if path not in self.seen:
                self.seen.add(path)
                self.entry(path, stat.S_IFDIR | 0o755)

    def file(self, name: str, data: bytes, mode: int = 0o644) -> None:
        name = self.merged_usr(name)
        self.directory(os.path.dirname(name) or ".")
        self.seen.add(name)
        self.entry(name, stat.S_IFREG | mode, data)

    def symlink(self, name: str, target: str) -> None:
        name = self.merged_usr(name) if "/" in name.strip("/") else name.strip("/")
        self.directory(os.path.dirname(name) or ".")
        self.seen.add(name)
        self.entry(name, stat.S_IFLNK | 0o777, target.encode())

    def finish(self) -> bytes:
        self.entry("TRAILER!!!", 0)
        return b"".join(self.chunks)


def contract_data_unlock_reasons() -> list[str]:
    schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
    for clause in schema["allOf"]:
        if clause["if"]["properties"]["kind"].get("const") == "data-unlock":
            return list(clause["then"]["properties"]["reason"]["enum"])
    raise TestError("result.schema.json has no data-unlock reason list")


INSTALLER_DOUBLE = """#!/bin/sh
# Test double of suderra-installer: records what suderra-data-unlock asks of it.
case "$1 $2" in
    "result write")
        shift 2
        kind=""; outcome=""; reason=""; detail=""
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --kind) kind="$2" ;;
                --outcome) outcome="$2" ;;
                --reason) reason="$2" ;;
                --detail) detail="$2" ;;
            esac
            shift 2
        done
        if [ -n "${reason}" ]; then
            case " __REASONS__ " in
                *" ${reason} "*) ;;
                *) echo "unknown reason ${reason}" >&2; exit 1 ;;
            esac
        fi
        echo "result --kind ${kind} --outcome ${outcome}${reason:+ --reason ${reason}}${detail:+ --detail ${detail}}" >> /run/installer.log
        ;;
    "lifecycle factory")
        echo "lifecycle factory" >> /run/installer.log
        printf 'FACTORY\\n' > /var/lib/suderra-os/lifecycle
        ;;
    *)
        echo "unexpected suderra-installer call: $*" >&2
        exit 2
        ;;
esac
"""

INIT = """#!/bin/busybox sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mkdir -p /run/suderra-os /dev/disk/by-partlabel
i=0
while [ ! -b /dev/vda ] || [ ! -e /dev/tpmrm0 ]; do
    i=$((i + 1))
    [ "${i}" -gt 100 ] && { echo "T-FAIL boot: /dev/vda or /dev/tpmrm0 missing"; ls /dev; break; }
    sleep 0.2
done
ln -sf /dev/vda /dev/disk/by-partlabel/data
sh /test/scenarios.sh
echo "T-POWEROFF"
poweroff -f
"""


def build_initramfs(work: Path, scenarios: Path, unlock: Path) -> Path:
    busybox = find_tool("busybox")
    cpio = Cpio()
    for link in ("bin", "sbin", "lib", "lib64"):
        cpio.symlink(link, f"usr/{link}")
    cpio.directory("proc")
    cpio.directory("sys")
    cpio.directory("dev")
    cpio.directory("run")
    cpio.directory("tmp")
    cpio.directory("etc/suderra")
    cpio.directory("var/lib/suderra-os")
    for mountpoint in (
        "data",
        "var/lib/suderra-installer",
        "var/lib/suderra-site",
        "var/lib/suderra",
        "var/log/suderra",
        "var/lib/chrony",
        "opt/suderra/edge",
        "etc/dropbear",
        "usr/lib/suderra",
    ):
        cpio.directory(mountpoint)
    cpio.file("bin/busybox", busybox.read_bytes(), 0o755)
    libraries: dict[str, Path] = {}
    for tool in HOST_TOOLS:
        path = find_tool(tool)
        # mke2fs is also mkfs.ext4 and e2fsck: the same binary under its names.
        cpio.file(
            f"usr/sbin/{tool}" if tool != "systemd-cryptenroll" else f"usr/bin/{tool}",
            path.read_bytes(),
            0o755,
        )
        libraries.update(library_closure(path))
    for name in ("mkfs.ext4", "mkfs.ext2", "mkfs.ext3"):
        cpio.symlink(f"usr/sbin/{name}", "mke2fs")
    # systemd-tmpfiles and systemd-cryptenroll load libsystemd-shared, found by
    # ldd; the TPM libraries and the cryptsetup token plugin are dlopen()ed.
    plugin = next(
        Path("/usr/lib").rglob("cryptsetup/libcryptsetup-token-systemd-tpm2.so"), None
    )
    if plugin is None:
        raise TestError(
            "libcryptsetup-token-systemd-tpm2.so not found: install systemd's cryptsetup plugin"
        )
    cpio.file(str(plugin).lstrip("/"), plugin.read_bytes(), 0o755)
    libraries.update(library_closure(plugin))
    for soname in DLOPENED:
        located = next(Path("/usr/lib").rglob(soname), None)
        if located is None:
            raise TestError(
                f"{soname} not found on the host: install libtss2 and tpm2-tools"
            )
        libraries[str(located)] = located.resolve()
        libraries.update(library_closure(located.resolve()))
    for name, target in sorted(libraries.items()):
        cpio.file(name.lstrip("/"), target.read_bytes(), 0o755)
    cpio.file("usr/sbin/suderra-data-unlock", unlock.read_bytes(), 0o755)
    cpio.file("usr/lib/suderra/data-layout.tmpfiles.conf", LAYOUT.read_bytes())
    cpio.file("etc/os-release", b'NAME="Suderra OS"\nID=suderra-os\nVARIANT="prod"\n')
    cpio.file("etc/suderra/board", b"BOARD_PROFILE=qemu-x86_64-prod\nARCH=x86_64\n")
    cpio.file(
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\nchrony:x:201:201::/:/bin/false\nsuderra:x:200:200::/:/bin/false\n",
    )
    cpio.file("etc/group", b"root:x:0:\nchrony:x:201:\nsuderra:x:200:\n")
    cpio.file(
        "usr/bin/suderra-installer",
        INSTALLER_DOUBLE.replace(
            "__REASONS__", " ".join(contract_data_unlock_reasons())
        ).encode(),
        0o755,
    )
    cpio.file("test/scenarios.sh", scenarios.read_bytes(), 0o755)
    cpio.file("init", INIT.encode(), 0o755)
    path = work / "initramfs.cpio.gz"
    path.write_bytes(gzip.compress(cpio.finish(), compresslevel=3))
    return path


def find_kernel(explicit: str | None) -> Path:
    candidates = [Path(explicit)] if explicit else []
    if os.environ.get("SUDERRA_DATA_TEST_KERNEL"):
        candidates.append(Path(os.environ["SUDERRA_DATA_TEST_KERNEL"]))
    candidates.extend(DEFAULT_KERNELS)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise TestError(
        "no kernel image: pass --kernel or set SUDERRA_DATA_TEST_KERNEL to the bzImage of a "
        "Suderra OS x86_64 image build (it needs dm-crypt, a TPM driver and virtio-blk built in)"
    )


def boot(work: Path, kernel: Path, initramfs: Path, timeout: int) -> str:
    for tool in ("qemu-system-x86_64", "swtpm"):
        find_tool(tool)
    disk = work / "data.img"
    with disk.open("wb") as handle:
        handle.truncate(256 * 1024 * 1024)
    tpm_state = work / "tpm"
    tpm_state.mkdir()
    # A unix socket path is limited to about 100 bytes: not under a long TMPDIR.
    socket_dir = Path(tempfile.mkdtemp(prefix="sdu.", dir="/tmp"))
    ctrl = socket_dir / "swtpm.sock"
    swtpm = subprocess.Popen(
        [
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={tpm_state}",
            "--ctrl",
            f"type=unixio,path={ctrl}",
            "--log",
            f"file={work / 'swtpm.log'},level=1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not ctrl.exists():
            if swtpm.poll() is not None or time.monotonic() > deadline:
                raise TestError("swtpm did not start")
            time.sleep(0.1)
        serial = work / "serial.log"
        accel = (
            ["-accel", "kvm"]
            if os.access("/dev/kvm", os.R_OK | os.W_OK)
            else ["-accel", "tcg"]
        )
        args = [
            "qemu-system-x86_64",
            "-machine",
            "q35",
            *accel,
            "-cpu",
            "max",
            "-m",
            "1024",
            "-smp",
            "2",
            "-display",
            "none",
            "-no-reboot",
            "-kernel",
            str(kernel),
            "-initrd",
            str(initramfs),
            "-append",
            "console=ttyS0 panic=-1 loglevel=4",
            "-drive",
            f"file={disk},format=raw,if=virtio",
            "-chardev",
            f"socket,id=chrtpm,path={ctrl}",
            "-tpmdev",
            "emulator,id=tpm0,chardev=chrtpm",
            "-device",
            "tpm-tis,tpmdev=tpm0",
            "-serial",
            f"file:{serial}",
        ]
        qemu = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
        try:
            qemu.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            qemu.kill()
            qemu.wait()
            raise TestError(
                f"the guest did not finish within {timeout} s; serial log tail:\n"
                + serial.read_text(errors="replace")[-3000:]
            ) from None
        return serial.read_text(errors="replace")
    finally:
        if swtpm.poll() is None:
            swtpm.terminate()
            try:
                swtpm.wait(timeout=10)
            except subprocess.TimeoutExpired:
                swtpm.kill()
        shutil.rmtree(socket_dir, ignore_errors=True)


def evaluate(console: str) -> int:
    passed: list[str] = []
    failed: list[str] = []
    for line in console.splitlines():
        line = line.strip()
        if line.startswith("T-PASS "):
            passed.append(line[len("T-PASS ") :])
        elif line.startswith("T-FAIL "):
            failed.append(line[len("T-FAIL ") :])
    for line in console.splitlines():
        if line.startswith("    | "):
            print(line)
    missing = [name for name in EXPECTED_SCENARIOS if name not in passed]
    for name in passed:
        log(f"PASS {name}")
    for item in failed:
        log(f"FAIL {item}")
    if "T-DONE" not in console:
        log("the guest never reached the end of the scenarios; serial log tail:")
        print(console[-3000:])
        return 1
    if failed or missing:
        if missing:
            log(f"scenarios without a PASS: {', '.join(missing)}")
        return 1
    log(f"{len(passed)} scenarios passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--kernel", help="bzImage with dm-crypt, a TPM driver and virtio-blk"
    )
    parser.add_argument("--timeout", type=int, default=1500)
    parser.add_argument("--keep", action="store_true", help="keep the work directory")
    parser.add_argument(
        "--unlock",
        default=str(UNLOCK),
        help="script to run instead of the repository's suderra-data-unlock "
        "(to prove that the scenarios fail on an older or broken one)",
    )
    parser.add_argument(
        "--scenarios",
        default=str(SCENARIOS),
        help="guest scenario script (to debug the guest with a script of your own)",
    )
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="suderra-data-unlock-vm."))
    try:
        kernel = find_kernel(args.kernel)
        log(f"kernel {kernel}")
        initramfs = build_initramfs(work, Path(args.scenarios), Path(args.unlock))
        log(
            f"initramfs {initramfs.stat().st_size // 1024} KiB; booting (this is slow without KVM)"
        )
        console = boot(work, kernel, initramfs, args.timeout)
        (work / "console.log").write_text(console)
        status = evaluate(console)
        if status and args.keep:
            log(f"work directory kept: {work}")
        return status
    except TestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

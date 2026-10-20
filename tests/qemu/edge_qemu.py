# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""QEMU harness of the edge e2e tests (ADR-048 P0 exit criterion).

Boots the dev QEMU image (suderra_qemu_x86_64_defconfig) on a private copy of
its disk image with OVMF and an swtpm TPM 2.0, user networking (the guest
reaches the fake cloud as 10.0.2.2; the host reaches the guest's SSH on a
forwarded loopback port), the serial console in a log file and the
virtio-serial port org.suderra.e2e.0 of the image's e2e probe
(board/suderra/common/rootfs-overlay/usr/sbin/suderra-e2e-probe).

Used by edge-provisioning-e2e.py, edge-readonly-sandbox-test.py and
nft-ruleset-smoke-test.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFCONFIG = "suderra_qemu_x86_64_defconfig"
DEFAULT_IMAGE = ROOT / "output" / DEFCONFIG / "images" / "disk.img"
DEFAULT_KEYS = Path.home() / ".suderra-keys" / "dev"
PROBE_PORT = "org.suderra.e2e.0"
OVMF_PAIRS = (
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
)
ANSI = re.compile(r"\x1b\[[0-9;=?]*[A-Za-z]")


class HarnessError(Exception):
    pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def kvm_available() -> bool:
    return os.access("/dev/kvm", os.R_OK | os.W_OK)


def find_ovmf() -> tuple[Path, Path]:
    code = os.environ.get("OVMF_CODE")
    variables = os.environ.get("OVMF_VARS")
    if code and variables:
        return Path(code), Path(variables)
    for code_path, vars_path in OVMF_PAIRS:
        if Path(code_path).is_file() and Path(vars_path).is_file():
            return Path(code_path), Path(vars_path)
    raise HarnessError("OVMF firmware not found; set OVMF_CODE and OVMF_VARS")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tpm_ek_sha256(state: Path, work: Path) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo of the TPM's RSA-2048
    endorsement key (default TCG template), read on the host from the swtpm
    state the guest will boot with: the hardware binding suderra-identity
    must record (tpm-ek-sha256, boards.json), computed independently of the
    device."""
    port, ctrl = free_port(), free_port()
    swtpm = subprocess.Popen(
        ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
         "--server", f"type=tcp,port={port},bindaddr=127.0.0.1",
         "--ctrl", f"type=tcp,port={ctrl},bindaddr=127.0.0.1",
         "--flags", "not-need-init,startup-clear"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if swtpm.poll() is not None or time.monotonic() > deadline:
                    raise HarnessError("the host swtpm for the EK read did not start")
                time.sleep(0.2)
        der = work / "ek.der"
        subprocess.run(["tpm2_createek", "-T", f"swtpm:host=127.0.0.1,port={port}", "-G", "rsa",
                        "-c", str(work / "ek.ctx"), "-u", str(der), "-f", "der"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return hashlib.sha256(der.read_bytes()).hexdigest()
    finally:
        swtpm.terminate()
        swtpm.wait(timeout=10)


class Probe:
    """Client of the guest's e2e probe on the virtio-serial port."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.sock: socket.socket | None = None
        self.buffer = b""

    def _connect(self, deadline: float) -> socket.socket:
        while self.sock is None:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(str(self.path))
                self.sock = sock
            except OSError:
                if time.monotonic() > deadline:
                    raise HarnessError(f"probe socket {self.path} did not come up")
                time.sleep(0.5)
        return self.sock

    def run(self, name: str, timeout: float = 300, resend: bool = True) -> dict[str, str]:
        """Runs one named probe; returns its keys with decoded values.

        A request sent before the guest probe listens is lost, so a
        read-only probe is resent until the guest answers; a probe with side
        effects (`resend=False`) is sent once, after a read-only one showed
        the guest is listening."""
        deadline = time.monotonic() + timeout
        sock = self._connect(deadline)
        request_id = secrets.token_hex(8)
        end = re.compile(rb"SUDERRA_E2E " + request_id.encode() + rb" END (\d+)\n")
        begin = b"SUDERRA_E2E " + request_id.encode() + b" BEGIN\n"
        sent_at = 0.0
        while True:
            now = time.monotonic()
            # The guest probe may not be listening yet (early boot): resend
            # until it answers; a request id answered once is complete.
            if begin not in self.buffer and (sent_at == 0.0 or (resend and now - sent_at > 15)):
                sock.sendall(f"{request_id} {name}\n".encode())
                sent_at = now
            match = end.search(self.buffer)
            if match and begin in self.buffer:
                start = self.buffer.index(begin) + len(begin)
                body = self.buffer[start:match.start()]
                self.buffer = self.buffer[match.end():]
                result: dict[str, str] = {"_rc": match.group(1).decode()}
                for line in body.decode(errors="replace").splitlines():
                    key, _, value = line.partition(" ")
                    if not key:
                        continue
                    result[key] = base64.b64decode(value).decode(errors="replace") if value else ""
                return result
            if now > deadline:
                raise HarnessError(f"probe {name!r} timed out after {timeout:.0f}s")
            sock.settimeout(1.0)
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                continue
            if not chunk:
                raise HarnessError("probe connection closed")
            self.buffer += chunk

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None


class Vm:
    """One boot of a private copy of the dev QEMU image."""

    def __init__(self, image: Path, work: Path, ssh_port: int = 2222, memory: str = "2048",
                 smp: str = "2") -> None:
        self.image = Path(image)
        self.work = Path(work)
        self.ssh_port = ssh_port
        self.memory = memory
        self.smp = smp
        self.disk = self.work / "disk.img"
        self.serial_log = self.work / "serial.log"
        self.qemu: subprocess.Popen | None = None
        self.swtpm: subprocess.Popen | None = None
        self.probe = Probe(self.work / "probe.sock")
        self.ek_sha256 = ""

    def start(self, fresh_disk: bool = True) -> Vm:
        if not self.image.is_file():
            raise HarnessError(f"image {self.image} is missing; run make build-qemu")
        self.work.mkdir(parents=True, exist_ok=True)
        if fresh_disk or not self.disk.exists():
            shutil.copyfile(self.image, self.disk)
        code, variables = find_ovmf()
        vars_copy = self.work / "ovmf-vars.fd"
        if fresh_disk or not vars_copy.exists():
            shutil.copyfile(variables, vars_copy)
        tpm_state = self.work / "tpm"
        if fresh_disk:
            shutil.rmtree(tpm_state, ignore_errors=True)
        tpm_state.mkdir(exist_ok=True)
        self.ek_sha256 = tpm_ek_sha256(tpm_state, self.work)
        tpm_sock = self.work / "swtpm.sock"
        tpm_sock.unlink(missing_ok=True)
        self.swtpm = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={tpm_state}",
             "--ctrl", f"type=unixio,path={tpm_sock}",
             "--log", f"file={self.work / 'swtpm.log'},level=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 20
        while not tpm_sock.exists():
            if self.swtpm.poll() is not None or time.monotonic() > deadline:
                raise HarnessError("swtpm did not start")
            time.sleep(0.1)
        (self.work / "probe.sock").unlink(missing_ok=True)
        accel = ["-accel", "kvm"] if kvm_available() else ["-accel", "tcg"]
        args = [
            "qemu-system-x86_64", "-machine", "q35", *accel, "-cpu", "max",
            "-m", self.memory, "-smp", self.smp, "-display", "none", "-no-reboot",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_copy}",
            "-drive", f"file={self.disk},format=raw,if=virtio",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-device", "virtio-net-pci,netdev=net0",
            "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-crb,tpmdev=tpm0",
            "-device", "virtio-serial-pci,id=vser0",
            "-chardev", f"socket,id=e2e,path={self.work / 'probe.sock'},server=on,wait=off",
            "-device", f"virtserialport,bus=vser0.0,chardev=e2e,name={PROBE_PORT}",
            "-serial", f"file:{self.serial_log}",
            "-qmp", f"unix:{self.work / 'qmp.sock'},server=on,wait=off",
        ]
        (self.work / "qemu-args.json").write_text(json.dumps(args, indent=1))
        self.qemu = subprocess.Popen(args, stdout=(self.work / "qemu.log").open("ab"),
                                     stderr=subprocess.STDOUT, start_new_session=True)
        log(f"QEMU started ({'kvm' if kvm_available() else 'tcg'}), serial log {self.serial_log}")
        return self

    def serial(self) -> str:
        try:
            return ANSI.sub("", self.serial_log.read_text(errors="replace"))
        except FileNotFoundError:
            return ""

    def wait_serial(self, pattern: str, timeout: float, after: int = 0) -> re.Match[str]:
        regex = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            text = self.serial()
            match = regex.search(text, after)
            if match:
                return match
            self.check_alive()
            if time.monotonic() > deadline:
                raise HarnessError(f"serial console never showed /{pattern}/ within {timeout:.0f}s")
            time.sleep(2)

    def check_alive(self) -> None:
        if self.qemu is not None and self.qemu.poll() is not None:
            raise HarnessError(f"QEMU exited with {self.qemu.returncode}; see {self.serial_log}")

    def facts(self, timeout: float = 300) -> dict[str, str]:
        return self.run_probe("facts", timeout)

    def run_probe(self, name: str, timeout: float = 300, resend: bool = True) -> dict[str, str]:
        """A probe whose last answer is also kept in the work directory."""
        result = self.probe.run(name, timeout, resend)
        (self.work / f"probe-{name}.json").write_text(json.dumps(result, indent=1))
        return result

    def stop(self) -> None:
        self.probe.close()
        if self.qemu is not None and self.qemu.poll() is None:
            try:
                qmp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                qmp.connect(str(self.work / "qmp.sock"))
                qmp.sendall(b'{"execute":"qmp_capabilities"}\n{"execute":"quit"}\n')
                qmp.close()
                self.qemu.wait(timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                self.qemu.kill()
        if self.swtpm is not None and self.swtpm.poll() is None:
            self.swtpm.terminate()
            try:
                self.swtpm.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.swtpm.kill()

    def __enter__(self) -> Vm:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


TIMESPAN_UNITS = {"us": 1e-6, "ms": 1e-3, "s": 1.0, "min": 60.0, "h": 3600.0, "d": 86400.0}


def timespan_seconds(text: str) -> float:
    """A systemd time span as `systemctl show` prints it ("1min 30s", "500ms",
    "infinity", "0") in seconds."""
    text = text.strip()
    if text in ("", "0", "infinity"):
        return 0.0 if text != "infinity" else float("inf")
    total = 0.0
    for number, unit in re.findall(r"([0-9.]+)\s*([a-z]+)", text):
        if unit not in TIMESPAN_UNITS:
            raise HarnessError(f"unknown time span unit in {text!r}")
        total += float(number) * TIMESPAN_UNITS[unit]
    return total


def unit_props(facts: dict[str, str], unit: str) -> dict[str, str]:
    text = facts.get(f"unit.{unit}", "")
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def wait_facts(vm: Vm, predicate, timeout: float, what: str, interval: float = 10) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    last: dict[str, str] = {}
    while True:
        last = vm.facts()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise HarnessError(f"timed out after {timeout:.0f}s waiting for {what}; "
                               f"lifecycle={last.get('lifecycle')!r}")
        time.sleep(interval)


class ProvisioningConsole:
    """What the device shows the technician on its console (DEC-5.3)."""

    def __init__(self, otp: str, host_key: str, fingerprint: str) -> None:
        self.otp = otp
        self.host_key = host_key
        self.fingerprint = fingerprint


def read_console(vm: Vm, timeout: float, after: int = 0) -> tuple[ProvisioningConsole, int]:
    box = vm.wait_serial(
        r"one-time password:\s+([A-Z2-9]{20})\s*\n\s*SSH host key:\s+(\S.*?)\s*\n"
        r"\s*known_hosts key:\s+(ssh-ed25519 [A-Za-z0-9+/=]+)", timeout, after)
    return ProvisioningConsole(box.group(1), box.group(3), box.group(2)), box.end()


def technician_provision(vm: Vm, console: ProvisioningConsole, device_code: str, token: str,
                         timeout: float = 3000) -> tuple[int, str]:
    """`ssh provision@<device> provision <device-code>`, token on stdin, with
    the console's one-time password and its host key pinned (DEC-5.3, DEC-5.5)."""
    with tempfile.TemporaryDirectory(prefix="suderra-ssh-") as tmp:
        known = Path(tmp) / "known_hosts"
        known.write_text(f"[127.0.0.1]:{vm.ssh_port} {console.host_key}\n")
        askpass = Path(tmp) / "askpass"
        askpass.write_text(f"#!/bin/sh\nprintf '%s\\n' '{console.otp}'\n")
        askpass.chmod(0o700)
        env = dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force",
                   DISPLAY=os.environ.get("DISPLAY", ":0"))
        proc = subprocess.run(
            ["ssh", "-p", str(vm.ssh_port), "-F", "/dev/null",
             "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=yes",
             "-o", "PreferredAuthentications=password,keyboard-interactive",
             "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
             "-o", "ConnectTimeout=60", "-o", "ServerAliveInterval=30",
             "provision@127.0.0.1", "provision", device_code],
            input=f"{token}\n", capture_output=True, text=True, env=env, timeout=timeout,
            start_new_session=True)
        return proc.returncode, proc.stdout + proc.stderr


def ssh_banner(port: int, timeout: float = 20) -> bytes:
    """The first bytes an SSH server sends on the forwarded port (empty when
    nothing in the guest answers)."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(64)
    except OSError:
        return b""


def results(facts: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for line in facts.get("results", "").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


class Checks:
    """Named pass/fail checks with a final report."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.items: list[tuple[str, bool, str]] = []

    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        self.items.append((label, bool(ok), detail))
        log(f"{'PASS' if ok else 'FAIL'} {label}{(': ' + detail) if detail and not ok else ''}")
        return bool(ok)

    def require(self, label: str, ok: bool, detail: str = "") -> None:
        if not self.check(label, ok, detail):
            raise HarnessError(f"{label} failed: {detail}")

    def report(self) -> int:
        failed = [i for i in self.items if not i[1]]
        print(f"\n{self.name}: {len(self.items) - len(failed)} passed, {len(failed)} failed")
        for label, ok, detail in self.items:
            print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))
        return 1 if failed else 0


def save_debug(vm: Vm, out: Path) -> None:
    """Journals of the units under test, for the CI artifact."""
    for probe in ("journal-all",):
        try:
            data = vm.probe.run(probe, timeout=120)
            (out / f"{probe}.log").write_text(data.get("journal", ""))
        except HarnessError as e:
            (out / f"{probe}.log").write_text(f"probe failed: {e}\n")


def common_args(parser, release: bool = True) -> None:
    parser.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
    parser.add_argument("--keys-dir", type=Path, default=DEFAULT_KEYS)
    if release:
        parser.add_argument("--release-dir", type=Path, required=True,
                            help="the signed qemu-x86_64 release (fake_cloud.py release)")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--boot-timeout", type=float, default=600 if kvm_available() else 1800)


if __name__ == "__main__":
    sys.exit("edge_qemu.py is a library of the edge e2e tests")

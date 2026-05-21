#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""QEMU/QMP boot acceptance harness for Suderra OS images."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "suderra.qemu-acceptance.v3"
SEMANTIC_MARKER_BEGIN = "SUDERRA_QEMU_SEMANTIC_JSON_BEGIN"
SEMANTIC_MARKER_END = "SUDERRA_QEMU_SEMANTIC_JSON_END"
PASS_PATTERNS = {
    "banner": re.compile(r"Suderra OS"),
    "systemd": re.compile(r"(Welcome to|Reached target|systemd\[1\])"),
    "provisioning-ready": re.compile(r"(suderra login| login:|Reached target|reached target|multi-user\.target)"),
}
SMOKE_REQUIRED_PASS_PATTERNS = ("banner", "provisioning-ready")
RELEASE_CANDIDATE_REQUIRED_PASS_PATTERNS = ("banner", "provisioning-ready")
RELEASE_CHECK_NAMES = (
    "boot",
    "systemd",
    "zero-failed-units",
    "no-kernel-panic",
    "no-emergency-mode",
    "os-release",
    "kernel",
    "rootfs",
    "network",
    "firstboot-idempotence",
    "lockdown-transition",
    "listeners",
    "firewall",
)
FAIL_PATTERNS = {
    "kernel-panic": re.compile(r"Kernel panic"),
    "oom-or-systemd-failure": re.compile(
        r"(Out of memory|oom-kill|Failed to start|Dependency failed|You are in emergency mode)"
    ),
}
OVMF_CODE_CANDIDATES = (
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    "/usr/share/qemu/edk2-x86_64-code.fd",
    "/usr/share/qemu/OVMF.fd",
    "/usr/share/ovmf/OVMF.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
    "/usr/share/edk2/x64/OVMF_CODE.fd",
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE_4M.fd",
)
OVMF_SEARCH_ROOTS = (
    Path("/usr/share/OVMF"),
    Path("/usr/share/ovmf"),
    Path("/usr/share/qemu"),
    Path("/usr/share/edk2"),
    Path("/usr/share/edk2-ovmf"),
)


@dataclass(frozen=True)
class FirmwareConfig:
    mode: str
    code: Path
    vars_template: Path | None
    vars_runtime: Path | None

    def evidence(self) -> dict[str, str | None]:
        return {
            "mode": self.mode,
            "code": str(self.code),
            "vars_template": str(self.vars_template) if self.vars_template else None,
            "vars_runtime": str(self.vars_runtime) if self.vars_runtime else None,
        }


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def qmp_connect(path: Path, timeout: int) -> tuple[socket.socket, list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout
    events: list[dict[str, Any]] = []
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while time.monotonic() < deadline:
        try:
            sock.connect(str(path))
            break
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.1)
    else:
        sock.close()
        raise TimeoutError(f"QMP socket did not become ready: {path}")

    sock.settimeout(2)
    greeting = qmp_read_line(sock)
    if greeting:
        events.append(greeting)
    qmp_execute(sock, "qmp_capabilities")
    sock.setblocking(False)
    return sock, events


def qmp_read_line(sock: socket.socket) -> dict[str, Any] | None:
    chunks = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            return None
        if chunk == b"\n":
            break
        chunks.extend(chunk)
    if not chunks:
        return None
    return json.loads(chunks.decode("utf-8"))


def qmp_drain(sock: socket.socket, events: list[dict[str, Any]]) -> None:
    buffer = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            break
        if not chunk:
            break
        buffer.extend(chunk)
    for line in buffer.splitlines():
        if not line:
            continue
        try:
            events.append(json.loads(line.decode("utf-8")))
        except json.JSONDecodeError:
            events.append({"unparsed": line.decode("utf-8", errors="replace")})


def qmp_execute(sock: socket.socket, command: str) -> None:
    payload = json.dumps({"execute": command}, separators=(",", ":")).encode("utf-8") + b"\r\n"
    sock.sendall(payload)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def evaluate(serial: str) -> tuple[dict[str, bool], dict[str, bool]]:
    passed = {name: bool(pattern.search(serial)) for name, pattern in PASS_PATTERNS.items()}
    failed = {name: bool(pattern.search(serial)) for name, pattern in FAIL_PATTERNS.items()}
    return passed, failed


def required_pass_patterns(profile: str) -> tuple[str, ...]:
    if profile == "release-candidate":
        return RELEASE_CANDIDATE_REQUIRED_PASS_PATTERNS
    return SMOKE_REQUIRED_PASS_PATTERNS


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_or_zero(path: Path) -> str:
    if path.is_file():
        return sha256_file(path)
    return "0" * 64


def qemu_version() -> str:
    try:
        return subprocess.check_output(
            ["qemu-system-x86_64", "--version"],
            text=True,
            stderr=subprocess.STDOUT,
        ).splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        return "not_collected"


def relative_log_entry(evidence_dir: Path, role: str, path: Path, allow_empty: bool = False) -> dict[str, str] | None:
    if not path.is_file() or (path.stat().st_size <= 0 and not allow_empty):
        return None
    try:
        rel = path.relative_to(evidence_dir)
    except ValueError:
        return None
    return {
        "role": role,
        "path": rel.as_posix(),
        "sha256": sha256_file(path),
    }


def parse_semantic_guest_facts(serial: str) -> dict[str, Any]:
    pattern = re.compile(
        re.escape(SEMANTIC_MARKER_BEGIN)
        + r"\s*(\{.*?\})\s*"
        + re.escape(SEMANTIC_MARKER_END),
        re.DOTALL,
    )
    for raw in reversed(pattern.findall(serial)):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def non_empty_fact(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and value.strip() not in {"not_collected", "TO_BE_COLLECTED"}
    if isinstance(value, dict):
        return any(non_empty_fact(item) for item in value.values())
    if isinstance(value, list):
        return True
    return value is not None


def semantic_result(passed: bool, evidence: str, source: str) -> dict[str, str]:
    return {
        "status": "passed" if passed else "failed",
        "evidence": evidence,
        "source": source,
    }


def release_checks(
    passed: dict[str, bool],
    failed: dict[str, bool],
    profile: str = "smoke",
    guest_facts: dict[str, Any] | None = None,
) -> dict[str, dict[str, str]]:
    uncollected_status = "failed" if profile == "release-candidate" else "not_applicable"
    checks = {
        name: {
            "status": uncollected_status,
            "evidence": f"not collected by {profile} QEMU harness profile",
            "source": "harness-profile",
        }
        for name in RELEASE_CHECK_NAMES
    }
    checks["boot"] = {
        "status": "passed" if passed.get("banner") or passed.get("provisioning-ready") else "failed",
        "evidence": "serial banner or login prompt observed",
        "source": "serial",
    }
    facts = guest_facts or {}
    failed_units = facts.get("failed_units")
    failed_count = None
    if isinstance(failed_units, dict) and isinstance(failed_units.get("count"), int):
        failed_count = failed_units["count"]
    if passed.get("systemd"):
        checks["systemd"] = {
            "status": "passed",
            "evidence": "systemd boot text observed on serial",
            "source": "serial",
        }
    elif failed_count is not None:
        checks["systemd"] = {
            "status": "passed",
            "evidence": f"systemctl --failed executed and reported {failed_count} failed unit(s)",
            "source": "guest: systemctl --failed --no-legend --plain",
        }
    elif profile == "release-candidate":
        checks["systemd"] = {
            "status": "failed",
            "evidence": "systemd proof was not collected by serial text or semantic collector",
            "source": "serial or guest: systemctl --failed --no-legend --plain",
        }
    else:
        checks["systemd"] = {
            "status": "not_applicable",
            "evidence": "smoke profile observed boot/login readiness but did not collect systemd proof",
            "source": "harness-profile",
        }
    checks["no-kernel-panic"] = {
        "status": "failed" if failed.get("kernel-panic") else "passed",
        "evidence": "serial log scanned for Kernel panic",
        "source": "serial",
    }
    checks["no-emergency-mode"] = {
        "status": "failed" if failed.get("oom-or-systemd-failure") else "passed",
        "evidence": "serial log scanned for emergency/failure patterns",
        "source": "serial",
    }
    if facts:
        checks["zero-failed-units"] = semantic_result(
            failed_count == 0,
            f"systemctl --failed reported {failed_count} failed unit(s)"
            if failed_count is not None else "systemctl --failed result was not collected",
            "guest: systemctl --failed --no-legend --plain",
        )

        os_release = facts.get("os_release")
        os_id = os_release.get("ID") if isinstance(os_release, dict) else None
        checks["os-release"] = semantic_result(
            non_empty_fact(os_id),
            f"/etc/os-release ID={os_id}" if isinstance(os_id, str) else "/etc/os-release was not collected",
            "guest: /etc/os-release",
        )

        kernel = facts.get("kernel")
        kernel_release = kernel.get("release") if isinstance(kernel, dict) else kernel
        checks["kernel"] = semantic_result(
            non_empty_fact(kernel_release),
            f"uname release={kernel_release}" if isinstance(kernel_release, str) else "uname was not collected",
            "guest: uname -a",
        )

        rootfs = facts.get("rootfs")
        rootfs_ok = isinstance(rootfs, dict) and any(
            non_empty_fact(rootfs.get(key))
            for key in ("cmdline_root", "mount_source", "partlabel", "fstype")
        )
        checks["rootfs"] = semantic_result(
            rootfs_ok,
            "rootfs mount and kernel root argument collected" if rootfs_ok else "rootfs identity was not collected",
            "guest: /proc/cmdline and /proc/mounts",
        )

        network = facts.get("network")
        network_state = network.get("state") if isinstance(network, dict) else None
        checks["network"] = semantic_result(
            non_empty_fact(network_state),
            f"network state={network_state}" if isinstance(network_state, str) else "network state was not collected",
            "guest: networkctl is-online or ip addr",
        )

        firstboot = facts.get("firstboot")
        firstboot_done = firstboot.get("done_marker") if isinstance(firstboot, dict) else None
        if firstboot_done is None and isinstance(firstboot, dict):
            firstboot_done = firstboot.get("idempotent")
        checks["firstboot-idempotence"] = semantic_result(
            firstboot_done is True,
            "/var/lib/suderra/.firstboot-done marker exists"
            if firstboot_done is True else "firstboot done marker was not observed",
            "guest: /var/lib/suderra/.firstboot-done",
        )

        lockdown = facts.get("lockdown")
        lockdown_state = lockdown.get("status") if isinstance(lockdown, dict) else None
        checks["lockdown-transition"] = semantic_result(
            non_empty_fact(lockdown_state),
            f"suderra-lockdown-status reported {lockdown_state}"
            if isinstance(lockdown_state, str) else "lockdown status was not collected",
            "guest: /usr/sbin/suderra-lockdown-status",
        )

        listeners = facts.get("listeners")
        checks["listeners"] = semantic_result(
            isinstance(listeners, list),
            f"ss reported {len(listeners)} listener line(s)"
            if isinstance(listeners, list)
            else "listeners were not collected",
            "guest: ss -H -lntup",
        )

        firewall = facts.get("firewall")
        firewall_loaded = firewall.get("loaded") if isinstance(firewall, dict) else None
        if firewall_loaded is None and isinstance(firewall, dict):
            firewall_loaded = firewall.get("nft") == "loaded"
        checks["firewall"] = semantic_result(
            firewall_loaded is True,
            "nft ruleset was collected" if firewall_loaded is True else "nft ruleset was not loaded",
            "guest: nft list ruleset",
        )
    return checks


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_ovmf_code_split(path: Path) -> bool:
    name = path.name.lower()
    return "code" in name or name.startswith("edk2-x86_64-code")


def sibling_vars_candidates(code: Path) -> list[Path]:
    name = code.name
    replacements = (
        ("CODE_4M.secboot", "VARS_4M"),
        ("CODE_4M", "VARS_4M"),
        ("CODE.secboot", "VARS"),
        ("CODE", "VARS"),
        ("code", "vars"),
    )
    candidates: list[Path] = []
    for old, new in replacements:
        if old in name:
            candidates.append(code.with_name(name.replace(old, new)))
    candidates.extend(
        candidate
        for pattern in ("*VARS*.fd", "*vars*.fd", "*-vars.fd")
        for candidate in sorted(code.parent.glob(pattern))
    )

    seen: set[Path] = set()
    unique: list[Path] = []
    for candidate in candidates:
        lowered = candidate.name.lower()
        if any(token in lowered for token in ("ia32", "arm", "aarch64", "riscv")):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        unique.append(candidate)
    return unique


def find_ovmf_code() -> Path | None:
    for candidate in (Path(item) for item in OVMF_CODE_CANDIDATES):
        if candidate.is_file():
            return candidate

    candidates: list[Path] = []
    for root in OVMF_SEARCH_ROOTS:
        if not root.exists():
            continue
        for pattern in ("OVMF_CODE*.fd", "OVMF.fd", "edk2-x86_64-code*.fd"):
            candidates.extend(root.glob(f"**/{pattern}"))

    for candidate in sorted(candidates):
        lowered = candidate.name.lower()
        if any(token in lowered for token in ("vars", "ia32", "arm", "aarch64", "riscv")):
            continue
        if candidate.is_file():
            return candidate
    return None


def find_ovmf_vars(code: Path) -> Path | None:
    for candidate in sibling_vars_candidates(code):
        if candidate.is_file():
            return candidate
    return None


def copy_vars_template(vars_template: Path, prefix: Path) -> Path:
    vars_runtime = prefix.with_suffix(".ovmf-vars.fd")
    shutil.copyfile(vars_template, vars_runtime)
    vars_runtime.chmod(0o600)
    return vars_runtime


def resolve_ovmf_firmware(args: argparse.Namespace, prefix: Path) -> FirmwareConfig:
    requested = str(args.ovmf)
    code = find_ovmf_code() if requested == "auto" else args.ovmf
    if code is None or not code.is_file():
        raise FileNotFoundError(f"OVMF firmware not found: {requested}")

    if args.ovmf_mode == "auto":
        mode = "pflash" if is_ovmf_code_split(code) else "bios"
    else:
        mode = args.ovmf_mode

    if mode == "bios":
        return FirmwareConfig(mode=mode, code=code, vars_template=None, vars_runtime=None)

    vars_template = args.ovmf_vars or (Path(os.environ["OVMF_VARS"]) if os.environ.get("OVMF_VARS") else None)
    if vars_template is None:
        vars_template = find_ovmf_vars(code)
    if vars_template is None or not vars_template.is_file():
        raise FileNotFoundError(
            "OVMF pflash variables template not found for "
            f"{code}; set OVMF_VARS=/path/to/OVMF_VARS.fd"
        )

    return FirmwareConfig(
        mode=mode,
        code=code,
        vars_template=vars_template,
        vars_runtime=copy_vars_template(vars_template, prefix),
    )


def firmware_qemu_args(firmware: FirmwareConfig) -> list[str]:
    if firmware.mode == "bios":
        return ["-bios", str(firmware.code)]
    if firmware.vars_runtime is None:
        raise ValueError("pflash firmware requires a runtime vars store")
    return [
        "-drive",
        f"if=pflash,format=raw,unit=0,readonly=on,file={firmware.code}",
        "-drive",
        f"if=pflash,format=raw,unit=1,file={firmware.vars_runtime}",
    ]


def launch_qemu(
    args: argparse.Namespace,
    firmware: FirmwareConfig,
    qmp_socket: Path,
    serial_log: Path,
    stdout_log: Path,
    stderr_log: Path,
):
    qemu_args = [
        "qemu-system-x86_64",
        "-machine",
        "q35",
        "-m",
        args.memory,
        "-smp",
        args.smp,
        "-cpu",
        "max,+pdpe1gb",
        "-drive",
        f"file={args.image},format=raw,if=virtio",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-display",
        "none",
        "-serial",
        f"file:{serial_log}",
        "-no-reboot",
        "-fw_cfg",
        "name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes",
        *firmware_qemu_args(firmware),
        "-qmp",
        f"unix:{qmp_socket},server=on,wait=off",
    ]
    stdout_handle = stdout_log.open("wb")
    stderr_handle = stderr_log.open("wb")
    try:
        process = subprocess.Popen(qemu_args, stdout=stdout_handle, stderr=stderr_handle)
    except Exception:
        stdout_handle.close()
        stderr_handle.close()
        raise
    return process, stdout_handle, stderr_handle, qemu_args


def run(args: argparse.Namespace) -> int:
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = Path(tempfile.mktemp(prefix=f"boot-test-{stamp}-", dir=log_dir))
    serial_log = prefix.with_suffix(".serial.log")
    stdout_log = prefix.with_suffix(".qemu-stdout.log")
    stderr_log = prefix.with_suffix(".qemu-stderr.log")
    qmp_log = prefix.with_suffix(".qmp.json")
    qemu_semantic_log = prefix.with_suffix(".qemu-semantic.json")
    evidence_log = args.evidence_output or prefix.with_suffix(".acceptance.json")
    evidence_log.parent.mkdir(parents=True, exist_ok=True)
    qmp_socket = Path(
        tempfile.mktemp(
            prefix="suderra-qmp-",
            suffix=".sock",
            dir=os.environ.get("TMPDIR", "/tmp"),
        )
    )

    process = None
    stdout_handle = None
    stderr_handle = None
    qmp_sock: socket.socket | None = None
    qmp_events: list[dict[str, Any]] = []
    start = now_utc()
    qemu_args: list[str] = []
    error: str | None = None
    firmware: FirmwareConfig | None = None
    serial = ""

    try:
        firmware = resolve_ovmf_firmware(args, prefix)
        process, stdout_handle, stderr_handle, qemu_args = launch_qemu(
            args, firmware, qmp_socket, serial_log, stdout_log, stderr_log
        )
        qmp_sock, qmp_events = qmp_connect(qmp_socket, min(args.timeout, 30))
        deadline = time.monotonic() + args.timeout
        passed: dict[str, bool] = {}
        failed: dict[str, bool] = {}
        while time.monotonic() < deadline:
            if qmp_sock is not None:
                qmp_drain(qmp_sock, qmp_events)
            serial = read_text(serial_log)
            passed, failed = evaluate(serial)
            semantic_ready = bool(parse_semantic_guest_facts(serial))
            if any(failed.values()):
                break
            required_observed = all(passed.get(name) for name in required_pass_patterns(args.profile))
            if required_observed and (args.profile != "release-candidate" or semantic_ready):
                break
            if process.poll() is not None:
                break
            time.sleep(1)
        serial = read_text(serial_log)
        passed, failed = evaluate(serial)
    except Exception as exc:  # evidence must still be written on harness failure
        passed = {}
        failed = {"harness-error": True}
        error = str(exc)
    finally:
        if qmp_sock is not None:
            try:
                qmp_drain(qmp_sock, qmp_events)
                qmp_execute(qmp_sock, "quit")
            except OSError:
                pass
            qmp_sock.close()
        if process is not None:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if stdout_handle is not None:
            stdout_handle.close()
        if stderr_handle is not None:
            stderr_handle.close()
        try:
            qmp_socket.unlink()
        except FileNotFoundError:
            pass

    qemu_status = process.returncode if process is not None else None
    failed_checks = [name for name, hit in failed.items() if hit]
    missing_checks = [name for name in required_pass_patterns(args.profile) if not passed.get(name)]
    semantic_guest_facts = parse_semantic_guest_facts(serial)
    checks = release_checks(passed, failed, args.profile, semantic_guest_facts)
    success = not failed_checks and not missing_checks and error is None
    if args.profile == "release-candidate":
        release_failures = [
            name for name, check in checks.items()
            if check.get("status") != "passed"
        ]
        if release_failures:
            failed_checks.extend(f"release-check-{name}" for name in release_failures)
            success = False
    if qemu_status not in (0, None) and not success:
        failed_checks.append(f"qemu-exit-{qemu_status}")

    qmp_log.write_text(json.dumps(qmp_events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if semantic_guest_facts:
        qemu_semantic_log.write_text(
            json.dumps(semantic_guest_facts, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    log_entries = [
        entry
        for entry in (
            relative_log_entry(evidence_log.parent, "serial", serial_log),
            relative_log_entry(evidence_log.parent, "qmp-events", qmp_log),
            relative_log_entry(evidence_log.parent, "qemu-semantic", qemu_semantic_log),
            relative_log_entry(evidence_log.parent, "qemu-stdout", stdout_log),
            relative_log_entry(evidence_log.parent, "qemu-stderr", stderr_log, allow_empty=True),
        )
        if entry is not None
    ]
    guest_facts = dict(semantic_guest_facts)
    guest_facts["firmware"] = firmware.evidence() if firmware else {"requested": str(args.ovmf), "mode": args.ovmf_mode}
    guest_facts["legacy_checks"] = {
        "passed": passed,
        "failed": failed,
        "missing": missing_checks,
        "failing": failed_checks,
    }
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "version": args.version,
        "target": args.target,
        "generated_at": now_utc(),
        "started_at": start,
        "completed_at": now_utc(),
        "image": str(args.image),
        "image_sha256": sha256_file(args.image),
        "ovmf": str(firmware.code if firmware else args.ovmf),
        "firmware": str(firmware.code if firmware else args.ovmf),
        "firmware_sha256": sha256_or_zero(firmware.code if firmware else args.ovmf),
        "qemu_version": qemu_version(),
        "timeout_seconds": args.timeout,
        "qemu_exit_status": qemu_status,
        "qemu_args": qemu_args,
        "profile": args.profile,
        "source_sha": os.environ.get("SUDERRA_SOURCE_SHA"),
        "checks": checks,
        "logs": log_entries,
        "guest_facts": guest_facts,
        "error": error,
        "status": "passed" if success else "failed",
        "result": "passed" if success else "failed",
    }
    write_evidence(evidence_log, evidence)

    print(f"Serial log: {serial_log}")
    print(f"QEMU stdout: {stdout_log}")
    print(f"QEMU stderr: {stderr_log}")
    print(f"QMP events: {qmp_log}")
    print(f"Acceptance JSON: {evidence_log}")
    print(f"Result: {evidence['result']}")
    for name, hit in passed.items():
        print(f"  {'PASS' if hit else 'MISS'} {name}")
    for name, hit in failed.items():
        if hit:
            print(f"  FAIL {name}")
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
    if not success:
        serial_tail = "\n".join(read_text(serial_log).splitlines()[-50:])
        if serial_tail:
            print("--- Serial tail ---")
            print(serial_tail)
    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ovmf", type=Path, default=Path("auto"))
    parser.add_argument("--ovmf-vars", type=Path)
    parser.add_argument("--ovmf-mode", choices=("auto", "bios", "pflash"), default="auto")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path)
    parser.add_argument("--version", default=os.environ.get("SUDERRA_RELEASE_VERSION", "dev"))
    parser.add_argument("--target", default=os.environ.get("SUDERRA_TARGET", "qemu-x86_64"))
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--smp", default="2")
    parser.add_argument("--profile", choices=("smoke", "release-candidate"), default="smoke")
    args = parser.parse_args()

    if not args.image.is_file():
        print(f"ERROR: image not found: {args.image}", file=sys.stderr)
        return 2
    if str(args.ovmf) != "auto" and not args.ovmf.is_file():
        print(f"ERROR: OVMF not found: {args.ovmf}", file=sys.stderr)
        return 2
    if args.ovmf_vars is not None and not args.ovmf_vars.is_file():
        print(f"ERROR: OVMF vars template not found: {args.ovmf_vars}", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("ERROR: timeout must be positive", file=sys.stderr)
        return 2
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""QEMU/QMP boot acceptance harness for Suderra OS images."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PASS_PATTERNS = {
    "banner": re.compile(r"Suderra OS"),
    "systemd": re.compile(r"(Welcome to|Reached target|systemd\[1\])"),
    "provisioning-ready": re.compile(r"(suderra login| login:|Reached target|reached target|multi-user\.target)"),
}
FAIL_PATTERNS = {
    "kernel-panic": re.compile(r"Kernel panic"),
    "oom-or-systemd-failure": re.compile(
        r"(Out of memory|oom-kill|Failed to start|Dependency failed|You are in emergency mode)"
    ),
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


def launch_qemu(args: argparse.Namespace, qmp_socket: Path, serial_log: Path, stdout_log: Path, stderr_log: Path):
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
        "-bios",
        str(args.ovmf),
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


def evaluate(serial: str) -> tuple[dict[str, bool], dict[str, bool]]:
    passed = {name: bool(pattern.search(serial)) for name, pattern in PASS_PATTERNS.items()}
    failed = {name: bool(pattern.search(serial)) for name, pattern in FAIL_PATTERNS.items()}
    return passed, failed


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = Path(tempfile.mktemp(prefix=f"boot-test-{stamp}-", dir=log_dir))
    serial_log = prefix.with_suffix(".serial.log")
    stdout_log = prefix.with_suffix(".qemu-stdout.log")
    stderr_log = prefix.with_suffix(".qemu-stderr.log")
    qmp_log = prefix.with_suffix(".qmp.json")
    evidence_log = prefix.with_suffix(".acceptance.json")
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

    try:
        process, stdout_handle, stderr_handle, qemu_args = launch_qemu(
            args, qmp_socket, serial_log, stdout_log, stderr_log
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
            if all(passed.values()) or any(failed.values()):
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
    missing_checks = [name for name, hit in passed.items() if not hit]
    success = not failed_checks and not missing_checks and error is None
    if qemu_status not in (0, None) and not success:
        failed_checks.append(f"qemu-exit-{qemu_status}")

    qmp_log.write_text(json.dumps(qmp_events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence = {
        "schema_version": "suderra.qemu-acceptance.v1",
        "started_at": start,
        "completed_at": now_utc(),
        "image": str(args.image),
        "ovmf": str(args.ovmf),
        "timeout_seconds": args.timeout,
        "qemu_exit_status": qemu_status,
        "qemu_args": qemu_args,
        "checks": {
            "passed": passed,
            "failed": failed,
            "missing": missing_checks,
            "failing": failed_checks,
        },
        "logs": {
            "serial": str(serial_log),
            "qemu_stdout": str(stdout_log),
            "qemu_stderr": str(stderr_log),
            "qmp_events": str(qmp_log),
        },
        "error": error,
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
    parser.add_argument("--ovmf", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--smp", default="2")
    args = parser.parse_args()

    if not args.image.is_file():
        print(f"ERROR: image not found: {args.image}", file=sys.stderr)
        return 2
    if not args.ovmf.is_file():
        print(f"ERROR: OVMF not found: {args.ovmf}", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("ERROR: timeout must be positive", file=sys.stderr)
        return 2
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

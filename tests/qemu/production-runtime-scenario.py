#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Run one production-runtime QEMU scenario and emit measured result JSON."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


SEMANTIC_BEGIN = "SUDERRA_QEMU_SEMANTIC_JSON_BEGIN"
SEMANTIC_END = "SUDERRA_QEMU_SEMANTIC_JSON_END"
OBSERVATION_SCHEMA_VERSION = "suderra.runtime-observation.v1"
OUTCOME_PREFIXES = (
    "SUDERRA_PRODUCTION_RUNTIME_OUTCOME=",
    "observed_outcome=",
)
EXPECTED_OUTCOMES = {
    "booted",
    "firmware-rejected",
    "kernel-rejected",
    "userspace-rejected",
    "rollback-completed",
}
OUTCOME_LAYERS = {
    "booted": "runtime",
    "firmware-rejected": "firmware",
    "kernel-rejected": "kernel",
    "userspace-rejected": "userspace",
    "rollback-completed": "userspace",
}
SCENARIO_OBSERVED_LAYERS = {
    "anti-rollback-downgrade-rejection": "userspace",
    "cmdline-tamper-rejection": "kernel",
    "data-luks-swtpm": "storage",
    "dm-verity-rootfs-tamper-rejection": "kernel",
    "rauc-bad-signature-rejection": "userspace",
    "rauc-good-update": "userspace",
    "rauc-health-rollback": "userspace",
    "signed-boot": "runtime",
    "unsigned-boot-rejection": "firmware",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return "0" * 64
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    value = digest.hexdigest()
    return value if value != hashlib.sha256(b"").hexdigest() else "0" * 64


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def qmp_read_line(sock: socket.socket) -> dict[str, Any] | None:
    buffer = bytearray()
    while True:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            return None
        if not chunk:
            return None
        if chunk == b"\n":
            break
        buffer.extend(chunk)
    if not buffer:
        return None
    try:
        payload = json.loads(buffer.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def qmp_execute(sock: socket.socket, command: str, command_id: str | None = None) -> None:
    payload: dict[str, Any] = {"execute": command}
    if command_id:
        payload["id"] = command_id
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def qmp_connect(path: Path, timeout: int) -> tuple[socket.socket | None, list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout
    events: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect(str(path))
            greeting = qmp_read_line(sock)
            if greeting is not None:
                events.append(greeting)
            qmp_execute(sock, "qmp_capabilities")
            response = qmp_read_line(sock)
            if response is not None:
                events.append(response)
            return sock, events
        except OSError:
            sock.close()
            time.sleep(0.2)
    return None, events


def qmp_drain(sock: socket.socket | None, events: list[dict[str, Any]]) -> None:
    if sock is None:
        return
    previous = sock.gettimeout()
    sock.settimeout(0.01)
    try:
        while True:
            event = qmp_read_line(sock)
            if event is None:
                break
            events.append(event)
    finally:
        sock.settimeout(previous)


def qmp_quit_ack_observed(events: list[dict[str, Any]], start_index: int) -> bool:
    for event in events[start_index:]:
        if event.get("event") == "SHUTDOWN":
            return True
        if event.get("id") == "suderra-production-runtime-quit" and "return" in event:
            return True
    return False


def parse_semantic(serial: str) -> dict[str, Any]:
    start = serial.find(SEMANTIC_BEGIN)
    end = serial.find(SEMANTIC_END, start + len(SEMANTIC_BEGIN))
    if start == -1 or end == -1:
        return {}
    raw = serial[start + len(SEMANTIC_BEGIN) : end].strip()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def observed_outcome(serial: str, semantic: dict[str, Any], process_returncode: int | None) -> str:
    return classify_observation("", serial, semantic, process_returncode)["observed_outcome"]


def classify_observation(
    scenario: str,
    serial: str,
    semantic: dict[str, Any],
    process_returncode: int | None,
) -> dict[str, Any]:
    outcome = "userspace-rejected"
    source = "qmp-events"
    signal_value = "nonzero-exit-or-no-semantic"
    for line in serial.splitlines():
        stripped = line.strip()
        for prefix in OUTCOME_PREFIXES:
            if stripped.startswith(prefix):
                value = stripped[len(prefix) :].strip()
                if value in EXPECTED_OUTCOMES:
                    outcome = value
                    source = "serial-marker"
                    signal_value = prefix.rstrip("=")
                    return {
                        "schema_version": OBSERVATION_SCHEMA_VERSION,
                        "producer": "tests/qemu/production-runtime-scenario.py",
                        "scenario": scenario,
                        "source": source,
                        "observed_outcome": outcome,
                        "observed_layer": SCENARIO_OBSERVED_LAYERS.get(scenario, OUTCOME_LAYERS[outcome]),
                        "signal": signal_value,
                    }
    lowered = serial.lower()
    if "rollback-completed" in lowered or "rollback completed" in lowered:
        outcome = "rollback-completed"
        source = "suderra-ota-event"
        signal_value = "rollback-completed"
        return {
            "schema_version": OBSERVATION_SCHEMA_VERSION,
            "producer": "tests/qemu/production-runtime-scenario.py",
            "scenario": scenario,
            "source": source,
            "observed_outcome": outcome,
            "observed_layer": SCENARIO_OBSERVED_LAYERS.get(scenario, OUTCOME_LAYERS[outcome]),
            "signal": signal_value,
        }
    if "security violation" in lowered or "access denied" in lowered or ("secure boot" in lowered and "denied" in lowered):
        outcome = "firmware-rejected"
        source = "secure-boot-event"
        signal_value = "secure-boot-denied"
    elif "dm-verity" in lowered and any(token in lowered for token in ("corrupt", "verification failed", "root hash")):
        outcome = "kernel-rejected"
        source = "kernel-verity-event"
        signal_value = "dm-verity-rejection"
    elif "rauc" in lowered and any(token in lowered for token in ("signature", "downgrade", "rollback floor", "rejected")):
        outcome = "userspace-rejected"
        source = "suderra-ota-event"
        signal_value = "rauc-rejection"
    elif semantic:
        outcome = "booted"
        source = "guest-semantic"
        signal_value = "semantic-json"
    elif process_returncode == 0:
        outcome = "booted"
        source = "qmp-events"
        signal_value = "zero-exit"
    return {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "producer": "tests/qemu/production-runtime-scenario.py",
        "scenario": scenario,
        "source": source,
        "observed_outcome": outcome,
        "observed_layer": SCENARIO_OBSERVED_LAYERS.get(scenario, OUTCOME_LAYERS[outcome]),
        "signal": signal_value,
    }


def start_swtpm(swtpm_state: Path, scenario_dir: Path) -> tuple[subprocess.Popen[bytes], Path]:
    swtpm = shutil.which("swtpm")
    if swtpm is None:
        raise RuntimeError("swtpm is required for production-runtime QEMU scenarios")
    state = scenario_dir / "swtpm-state"
    if state.exists():
        shutil.rmtree(state)
    shutil.copytree(swtpm_state, state)
    socket_path = scenario_dir / "swtpm.sock"
    ctrl_path = scenario_dir / "swtpm.ctrl"
    process = subprocess.Popen(
        [
            swtpm,
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={state}",
            "--ctrl",
            f"type=unixio,path={ctrl_path}",
            "--server",
            f"type=unixio,path={socket_path}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if socket_path.exists():
            return process, socket_path
        if process.poll() is not None:
            stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
            raise RuntimeError(f"swtpm exited before creating socket: {stderr}")
        time.sleep(0.1)
    raise RuntimeError("swtpm socket did not appear before timeout")


def snapshot_drive(image: Path, scenario_dir: Path) -> tuple[list[str], dict[str, Any]]:
    qemu_img = shutil.which("qemu-img")
    overlay = scenario_dir / "disk-overlay.qcow2"
    if qemu_img is not None:
        subprocess.run(
            [
                qemu_img,
                "create",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                str(image),
                str(overlay),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return [f"file={overlay},format=qcow2,if=virtio"], {
            "mode": "qcow2-overlay",
            "path": overlay.as_posix(),
            "base_sha256": sha256_file(image),
        }
    return [f"file={image},format=raw,if=virtio", "-snapshot"], {
        "mode": "qemu-snapshot",
        "path": image.as_posix(),
        "base_sha256": sha256_file(image),
    }


def qemu_version() -> str:
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        return "not_collected"
    result = subprocess.run([qemu, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return (result.stdout or result.stderr).splitlines()[0] if (result.stdout or result.stderr) else "not_collected"


def run_scenario(args: argparse.Namespace) -> int:
    scenario_dir = Path(os.environ["SUDERRA_SCENARIO_DIR"])
    scenario_dir.mkdir(parents=True, exist_ok=True)
    result_path = Path(os.environ.get("SUDERRA_SCENARIO_RESULT", scenario_dir / "scenario-result.json"))
    image = Path(os.environ["SUDERRA_IMAGE"])
    ovmf_code = Path(os.environ["SUDERRA_OVMF_CODE"])
    ovmf_vars = Path(os.environ["SUDERRA_OVMF_VARS"])
    swtpm_state = Path(os.environ["SUDERRA_SWTPM_STATE"])
    expected = os.environ.get("SUDERRA_EXPECTED_OUTCOME", "")
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        raise RuntimeError("qemu-system-x86_64 is required for production-runtime scenarios")
    for path in (image, ovmf_code, ovmf_vars):
        if not path.is_file() or path.stat().st_size <= 0:
            raise RuntimeError(f"required runtime input missing or empty: {path}")
    if not swtpm_state.is_dir():
        raise RuntimeError(f"swtpm state directory missing: {swtpm_state}")

    serial_log = scenario_dir / f"{args.scenario}.serial.log"
    stdout_log = scenario_dir / "qemu.stdout.log"
    stderr_log = scenario_dir / "qemu.stderr.log"
    qmp_log = scenario_dir / f"{args.scenario}.qmp.json"
    qmp_socket = scenario_dir / "qmp.sock"
    vars_runtime = scenario_dir / "OVMF_VARS.runtime.fd"
    shutil.copy2(ovmf_vars, vars_runtime)
    swtpm_before = sha256_tree(swtpm_state)
    swtpm_process: subprocess.Popen[bytes] | None = None
    qemu_process: subprocess.Popen[bytes] | None = None
    qmp_sock: socket.socket | None = None
    qmp_events: list[dict[str, Any]] = []
    termination: dict[str, Any] = {
        "class": "not-started",
        "reason": "harness did not start QEMU",
        "qmp_quit_sent": False,
        "qmp_quit_ack": False,
        "timeout": False,
        "exit_status": None,
    }
    qemu_args: list[str] = []
    started_at = now_utc()
    try:
        swtpm_process, swtpm_socket = start_swtpm(swtpm_state, scenario_dir)
        drive_args, snapshot = snapshot_drive(image, scenario_dir)
        drive_option = drive_args[0]
        extra_drive_args = drive_args[1:]
        qemu_args = [
            qemu,
            "-machine",
            "q35",
            "-m",
            str(args.memory),
            "-smp",
            str(args.smp),
            "-cpu",
            "max,+pdpe1gb",
            "-drive",
            drive_option,
            *extra_drive_args,
            "-drive",
            f"if=pflash,format=raw,unit=0,readonly=on,file={ovmf_code}",
            "-drive",
            f"if=pflash,format=raw,unit=1,file={vars_runtime}",
            "-chardev",
            f"socket,id=chrtpm,path={swtpm_socket}",
            "-tpmdev",
            "emulator,id=tpm0,chardev=chrtpm",
            "-device",
            "tpm-tis,tpmdev=tpm0",
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
            f"name=opt/suderra/runtime-scenario,string={args.scenario}",
            "-qmp",
            f"unix:{qmp_socket},server=on,wait=off",
        ]
        with stdout_log.open("wb") as stdout, stderr_log.open("wb") as stderr:
            qemu_process = subprocess.Popen(qemu_args, stdout=stdout, stderr=stderr, start_new_session=True)
            qmp_sock, qmp_events = qmp_connect(qmp_socket, min(args.timeout, 30))
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                qmp_drain(qmp_sock, qmp_events)
                serial = read_text(serial_log)
                semantic = parse_semantic(serial)
                observation = classify_observation(args.scenario, serial, semantic, qemu_process.poll())
                outcome = observation["observed_outcome"]
                if outcome == expected and (outcome != "booted" or semantic):
                    break
                if qemu_process.poll() is not None:
                    break
                time.sleep(1)
            else:
                termination["timeout"] = True
        qmp_drain(qmp_sock, qmp_events)
        if qmp_sock is not None:
            try:
                quit_event_start = len(qmp_events)
                qmp_execute(qmp_sock, "quit", "suderra-production-runtime-quit")
                termination["qmp_quit_sent"] = True
                quit_deadline = time.monotonic() + args.qmp_quit_grace
                while time.monotonic() < quit_deadline:
                    qmp_drain(qmp_sock, qmp_events)
                    if qmp_quit_ack_observed(qmp_events, quit_event_start):
                        termination["qmp_quit_ack"] = True
                        break
                    time.sleep(0.1)
            except OSError:
                pass
        if qemu_process is not None:
            try:
                qemu_process.wait(timeout=args.qmp_quit_grace)
            except subprocess.TimeoutExpired:
                termination["class"] = "timeout"
                termination["reason"] = "QEMU did not exit after QMP quit"
                termination["timeout"] = True
                try:
                    os.killpg(qemu_process.pid, signal.SIGKILL)
                except OSError:
                    qemu_process.kill()
                qemu_process.wait(timeout=10)
            else:
                termination["class"] = "qmp-quit" if termination["qmp_quit_sent"] else "process-exit"
                termination["reason"] = "QEMU exited after measured scenario"
            termination["exit_status"] = qemu_process.returncode
        termination["acceptable"] = (
            termination.get("timeout") is False
            and termination.get("qmp_quit_sent") is True
            and termination.get("qmp_quit_ack") is True
        )
        serial = read_text(serial_log)
        semantic = parse_semantic(serial)
        observation = classify_observation(args.scenario, serial, semantic, qemu_process.returncode if qemu_process else None)
        outcome = observation["observed_outcome"]
        mutation_artifact = None
        mutation_path = os.environ.get("SUDERRA_MUTATION_ARTIFACT")
        if mutation_path:
            mutation = Path(mutation_path)
            if not mutation.is_absolute():
                mutation = scenario_dir / mutation
            if mutation.is_file():
                before_sha = os.environ.get("SUDERRA_MUTATION_BEFORE_SHA256", "")
                after_sha = sha256_file(mutation)
                mutation_artifact = {
                    "role": os.environ.get("SUDERRA_MUTATION_ROLE", args.scenario),
                    "path": mutation.relative_to(scenario_dir).as_posix(),
                    "before_sha256": before_sha,
                    "after_sha256": after_sha,
                }
        if args.scenario != "signed-boot" and mutation_artifact is None:
            termination["class"] = "operator-error"
            termination["reason"] = "negative scenario did not provide SUDERRA_MUTATION_ARTIFACT"
            status = "failed"
        else:
            status = "passed" if outcome == expected and termination.get("acceptable") is True else "failed"
        qmp_log.write_text(json.dumps(qmp_events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result = {
            "schema_version": "suderra.production-runtime-scenario-result.v1",
            "scenario": args.scenario,
            "status": status,
            "expected_outcome": expected,
            "observed_outcome": outcome,
            "observation": observation,
            "started_at": started_at,
            "completed_at": now_utc(),
            "qemu_version": qemu_version(),
            "qemu_argv": qemu_args,
            "termination": termination,
            "disk_snapshot": snapshot,
            "swtpm_state_before_sha256": swtpm_before,
            "swtpm_state_after_sha256": sha256_tree(scenario_dir / "swtpm-state"),
            "raw_evidence": {
                "serial_sha256": sha256_file(serial_log) if serial_log.is_file() else "0" * 64,
                "qmp_events_sha256": sha256_file(qmp_log),
            },
            "guest_facts": semantic,
        }
        if mutation_artifact is not None:
            result["mutation_artifact"] = mutation_artifact
        write_json(result_path, result)
        return 0 if status == "passed" else 1
    finally:
        if qmp_sock is not None:
            qmp_sock.close()
        if qemu_process is not None and qemu_process.poll() is None:
            qemu_process.kill()
        if swtpm_process is not None and swtpm_process.poll() is None:
            swtpm_process.terminate()
            try:
                swtpm_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                swtpm_process.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("SUDERRA_QEMU_TIMEOUT", "300")))
    parser.add_argument("--qmp-quit-grace", type=int, default=30)
    parser.add_argument("--memory", default=os.environ.get("SUDERRA_QEMU_MEMORY", "2048"))
    parser.add_argument("--smp", default=os.environ.get("SUDERRA_QEMU_SMP", "2"))
    args = parser.parse_args()
    try:
        return run_scenario(args)
    except Exception as exc:
        scenario_dir = Path(os.environ.get("SUDERRA_SCENARIO_DIR", tempfile.gettempdir()))
        result_path = Path(os.environ.get("SUDERRA_SCENARIO_RESULT", scenario_dir / "scenario-result.json"))
        write_json(
            result_path,
            {
                "schema_version": "suderra.production-runtime-scenario-result.v1",
                "scenario": args.scenario,
                "status": "failed",
                "expected_outcome": os.environ.get("SUDERRA_EXPECTED_OUTCOME", ""),
                "observed_outcome": "userspace-rejected",
                "observation": {
                    "schema_version": OBSERVATION_SCHEMA_VERSION,
                    "producer": "tests/qemu/production-runtime-scenario.py",
                    "scenario": args.scenario,
                    "source": "harness-failure",
                    "observed_outcome": "userspace-rejected",
                    "observed_layer": SCENARIO_OBSERVED_LAYERS.get(args.scenario, "userspace"),
                    "signal": str(exc),
                },
                "started_at": now_utc(),
                "completed_at": now_utc(),
                "qemu_version": qemu_version(),
                "qemu_argv": [],
                "termination": {"class": "harness-failure", "reason": str(exc), "timeout": False},
                "swtpm_state_before_sha256": "0" * 64,
                "swtpm_state_after_sha256": "0" * 64,
                "raw_evidence": {"serial_sha256": "0" * 64, "qmp_events_sha256": "0" * 64},
                "guest_facts": {},
                "error": str(exc),
            },
        )
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

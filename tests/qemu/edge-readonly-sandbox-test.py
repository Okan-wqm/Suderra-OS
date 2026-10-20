#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only root behaviour of the edge chain on the dev QEMU image (ADR-048 P0).

The dev image's root is read-write, so the EROFS paths of a verity root
(K3, K9, K11) do not arise by themselves. This test runs the real programs
under the production units' own sandbox instead: the image's e2e probe reads
the [Service] sandbox settings from the unit files in the image, runs the
program as a transient unit with them (`systemd-run`), and binds a canary
copy of /etc in which every file is writable by the sandboxed user, so any
write attempt the read-only /etc would have refused shows up as a
difference.

* `suderra-installer edge request` and `edge install` (the offline delivery
  path) under suderra-provision-worker.service's sandbox (K3, K9): both
  succeed, nothing under /etc changes, and verify-current passes after.
* the installed release binary under suderra-agent.service's sandbox (K1,
  K11): it reaches READY and keeps running, writes nothing under /etc, and
  everything it writes lies under /var/lib/suderra (and its log and health
  directories, the unit's other ReadWritePaths).

The settings the probe used are compared with the overlay unit files of this
repository, so the test runs the units as shipped.

    edge-readonly-sandbox-test.py --release-dir DIR --work-dir DIR [--image disk.img] [--keys-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import edge_qemu as eq
from fake_cloud import FakeCloud

UNITS = eq.ROOT / "board" / "suderra" / "common" / "rootfs-overlay" / "etc" / "systemd" / "system"
SKIPPED = re.compile(
    r"^(Exec[A-Za-z]*|Type|Restart|RestartSec|RemainAfterExit|NotifyAccess|WatchdogSec|TimeoutSec|"
    r"TimeoutStartSec|TimeoutStopSec|RuntimeMaxSec|StartLimit[A-Za-z]*|StandardInput|StandardOutput|"
    r"StandardError|SyslogIdentifier|SyslogLevelPrefix)$")


def repo_sandbox(unit: str, dropins: list[str]) -> list[str]:
    """The probe's sandbox filter over this repository's unit files."""
    out: list[str] = []
    for path in [UNITS / unit, *(UNITS / f"{unit}.d" / d for d in dropins)]:
        service = False
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if line.startswith("["):
                service = line == "[Service]"
                continue
            if not service or not line or line[0] in "#;":
                continue
            if SKIPPED.match(line.split("=", 1)[0]):
                continue
            out.append(line)
    return out


def under(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def run(args: argparse.Namespace, c: eq.Checks) -> None:
    work = args.work_dir
    cloud = FakeCloud(args.keys_dir, args.release_dir, work / "cloud").start()
    vm = eq.Vm(args.image, work / "vm", ssh_port=args.ssh_port)
    try:
        vm.start()
        eq.read_console(vm, args.boot_timeout)
        facts = vm.facts()
        c.require("first boot is PROVISIONING", facts.get("lifecycle") == "PROVISIONING",
                  facts.get("lifecycle", ""))

        # K3, K9: the root installer under the provisioning worker's sandbox.
        worker = repo_sandbox("suderra-provision-worker.service", [])
        request = vm.probe.run("sandbox-request", timeout=600, resend=False)
        c.check("installer sandbox is the shipped worker unit's",
                request.get("properties", "").splitlines() == worker,
                f"{request.get('properties', '').splitlines()} != {worker}")
        nonce = request.get("request", "").strip().splitlines()[-1:] or [""]
        c.require("edge request succeeds under the worker sandbox",
                  request.get("request.rc") == "0" and re.fullmatch(r"[0-9a-f]{32,128}", nonce[0]) is not None,
                  request.get("request", "")[-400:])
        c.check("edge request writes nothing under /etc", request.get("etc_diff", "") == "",
                request.get("etc_diff", "")[:400])
        binding = json.loads(facts.get("binding") or "{}")
        cloud.prepare_sandbox_delivery(nonce[0], binding)
        install = vm.probe.run("sandbox-install", timeout=1800, resend=False)
        c.check("the delivery and artifact reach the device",
                install.get("fetch.delivery.rc") == "0" and install.get("fetch.artifact.rc") == "0",
                install.get("fetch.delivery", "") + install.get("fetch.artifact", ""))
        c.require("edge install succeeds under the worker sandbox", install.get("install.rc") == "0",
                  install.get("install", "")[-600:])
        c.check("edge install writes nothing under /etc", install.get("etc_diff", "") == "",
                install.get("etc_diff", "")[:400])
        c.check("verify-current passes after the sandboxed install", install.get("verify_current.rc") == "0",
                install.get("verify_current", "")[-400:])

        # K1, K11: the release binary under the agent unit's sandbox.
        agent_props = repo_sandbox("suderra-agent.service", ["10-board-qemu-x86_64.conf"])
        sandbox = vm.probe.run("sandbox-agent", timeout=1800, resend=False)
        c.check("agent sandbox is the shipped agent unit's (with the board drop-in)",
                sandbox.get("properties", "").splitlines() == agent_props,
                f"{sandbox.get('properties', '').splitlines()} != {agent_props}")
        c.check("the agent reaches READY under the production sandbox", sandbox.get("start.rc") == "0",
                sandbox.get("start", "") + sandbox.get("journal", "")[-1500:])
        state = dict(line.split("=", 1) for line in sandbox.get("state", "").splitlines() if "=" in line)
        c.check("the agent keeps running under the sandbox and its watchdog",
                state.get("ActiveState") == "active" and state.get("SubState") == "running", str(state))
        c.check("the agent writes nothing under /etc", sandbox.get("etc_diff", "") == "",
                sandbox.get("etc_diff", "")[:600])
        allowed = [p for p in sandbox.get("allowed", "").splitlines() if p]
        written = [p for p in sandbox.get("written", "").splitlines() if p]
        state_root = allowed[0] if allowed else "/var/lib/suderra"
        c.check("the agent writes only inside its ReadWritePaths", all(under(p, allowed) for p in written),
                str([p for p in written if not under(p, allowed)]))
        c.check("the agent's state goes under /var/lib/suderra",
                any(under(p, [state_root]) for p in written), str(written[:20]))
        journal = sandbox.get("journal", "")
        c.check("no read-only file system error in the agent's journal",
                "Read-only file system" not in journal and "os error 30" not in journal,
                "\n".join(line for line in journal.splitlines() if "os error 30" in line or "Read-only" in line)[:600])
    finally:
        try:
            eq.save_debug(vm, work)
        finally:
            vm.stop()
            cloud.stop()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    eq.common_args(ap)
    args = ap.parse_args()
    c = eq.Checks("edge-readonly-sandbox-test")
    try:
        run(args, c)
    except Exception as e:
        c.check(f"aborted: {type(e).__name__}", False, str(e))
        traceback.print_exc()
    return c.report()


if __name__ == "__main__":
    sys.exit(main())

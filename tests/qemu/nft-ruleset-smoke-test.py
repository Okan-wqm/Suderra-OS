#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""nftables ruleset smoke test on the dev QEMU image (ADR-048 DEC-5.4, DEC-11).

Boots the image into its first-boot provisioning window and checks, in the
guest's own kernel and nft:

* the base, appliance and provisioning rulesets compile (`nft -c`), so every
  kernel symbol they need is built in (DEC-8.10);
* the loaded ruleset is exactly the provisioning ruleset scoped to the
  interface that carries the default route, as `suderra-installer policy
  apply` renders it, and SSH is admitted only there with a per-source limit;
* the appliance ruleset drops by default and admits no inbound SSH; its
  expected loaded form (in a fresh network namespace) is deterministic, which
  is what edge-provisioning-e2e.py compares the post-lockdown ruleset with.

    nft-ruleset-smoke-test.py --work-dir DIR [--image disk.img]
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import edge_qemu as eq


def chain(ruleset: str, name: str) -> str:
    match = re.search(r"chain " + name + r" \{(.*?)\n\t\}", ruleset, re.DOTALL)
    return match.group(1) if match else ""


def run(args: argparse.Namespace, c: eq.Checks) -> None:
    vm = eq.Vm(args.image, args.work_dir / "vm", ssh_port=args.ssh_port)
    try:
        vm.start()
        eq.read_console(vm, args.boot_timeout)
        facts = vm.facts()
        c.require("first boot is in the provisioning window",
                  facts.get("lifecycle") == "PROVISIONING" and facts.get("provisioning_open") == "yes",
                  facts.get("lifecycle", ""))
        smoke = vm.probe.run("nft-smoke")
        for name in ("base", "appliance", "provisioning"):
            c.check(f"{name} ruleset compiles in the guest kernel", smoke.get(f"check.{name}.rc") == "0",
                    smoke.get(f"check.{name}", "")[-400:])
        iface = facts.get("default_route_iface", "")
        c.check("the provisioning ruleset is scoped to the default-route interface",
                bool(iface) and smoke.get("provisioning_iface") == iface, iface)
        provisioning = smoke.get("expected.provisioning", "")
        c.check("the loaded ruleset is the rendered provisioning ruleset",
                facts.get("nft_ruleset_sha256") == hashlib.sha256(provisioning.encode()).hexdigest())
        inbound = chain(provisioning, "input")
        ssh_rules = [line.strip() for line in inbound.splitlines() if "dport 22" in line]
        c.check("SSH is admitted only on the default-route interface",
                bool(ssh_rules) and all(f'iifname "{iface}"' in r for r in ssh_rules), str(ssh_rules))
        c.check("SSH admission is limited per source",
                any(("meter" in r or "limit rate" in r) and "saddr" in r for r in ssh_rules)
                or ("meter" in inbound and "saddr" in inbound), str(ssh_rules))
        appliance = smoke.get("expected.appliance", "")
        c.check("the appliance ruleset loads in a fresh namespace", smoke.get("expected.appliance.rc") == "0",
                appliance[-400:])
        for hook in ("input", "forward", "output"):
            c.check(f"appliance {hook} chain drops by default", "policy drop;" in chain(appliance, hook))
        c.check("the appliance ruleset admits no inbound SSH", "dport 22" not in chain(appliance, "input"))
        again = vm.probe.run("nft-smoke")
        c.check("the appliance ruleset's loaded form is deterministic",
                again.get("expected.appliance") == appliance)
        c.check("policy verify matches the recorded provisioning ruleset", facts.get("policy_verify.rc") == "0",
                facts.get("policy_verify", ""))
    finally:
        try:
            eq.save_debug(vm, args.work_dir)
        finally:
            vm.stop()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    eq.common_args(ap, release=False)
    args = ap.parse_args()
    c = eq.Checks("nft-ruleset-smoke-test")
    try:
        run(args, c)
    except Exception as e:
        c.check(f"aborted: {type(e).__name__}", False, str(e))
        traceback.print_exc()
    return c.report()


if __name__ == "__main__":
    sys.exit(main())

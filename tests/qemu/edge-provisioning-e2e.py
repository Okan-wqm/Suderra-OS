#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Edge provisioning end-to-end test: the ADR-048 P0 exit criterion.

Boots the dev QEMU image (OVMF, swtpm) against the local fake cloud
(fake_cloud.py) and checks the chain:

  1. first boot: no /data/suderra/os/lifecycle -> PROVISIONING (DEC-12 dev
     rule); the provisioning ruleset admits SSH only on the interface that
     carries the default route (DEC-5.4);
  2. the scripted technician SSH command (token on stdin) -> the device
     fetches its manifest with the X-Provisioning-Token header;
  3. the fake cloud answers with a suderra.edge-provisioning.v1 manifest
     signed with the dev keys and bound to the device (swtpm EK hash); root
     verifies the release statement, the manifest, the nested site-config
     and the trust-anchor bundle signed by the dev fleet-root;
  4. the agent is installed atomically under /data/suderra/edge and
     verify-current passes;
  5. the agent is active with NRestarts=0 for at least three WatchdogSec
     periods (K2);
  6. activation -> 8883 TLS CONNECT with the device credential -> root
     verifies the activation receipt the fake cloud signed -> ACTIVE;
  7. lockdown: SSH is closed and the loaded ruleset's hash equals the
     appliance ruleset's.

Negative cases, each refused with the lifecycle unchanged: wrong device
binding, expired manifest, modified artifact, unsigned receipt.

    edge-provisioning-e2e.py --release-dir DIR --work-dir DIR [--image disk.img] [--keys-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import edge_qemu as eq
from fake_cloud import FakeCloud

# Unit descriptions of the provisioning chain, as systemd logs a failure.
CHAIN_UNIT_NAMES = (
    "Suderra mutable data partition", "Suderra OS device identity",
    "Suderra OS device lifecycle evaluation", "Suderra OS provisioning mode",
    "Suderra OS nftables firewall", "Watch Suderra OS provisioning requests",
    "Suderra OS provisioning worker", "Watch the agent's activation receipt",
    "Verify the activation receipt", "Suderra edge agent", "Path Units",
)

NEGATIVE_DELIVERIES = (
    ("wrong-binding", "device-binding-mismatch"),
    ("expired", "expired"),
    ("tampered-artifact", "artifact-digest-mismatch"),
)


def last_provisioning_result(facts: dict[str, str]) -> dict:
    found = [r for r in eq.results(facts) if r.get("kind") == "provisioning"]
    return found[-1] if found else {}


def unchanged_provisioning(c: eq.Checks, facts: dict[str, str], label: str) -> None:
    c.check(f"{label}: lifecycle stays PROVISIONING", facts.get("lifecycle") == "PROVISIONING",
            facts.get("lifecycle", ""))
    c.check(f"{label}: no install receipt", facts.get("receipt", "") == "")
    agent = eq.unit_props(facts, "suderra-agent.service")
    c.check(f"{label}: agent not started", agent.get("ActiveState") != "active", str(agent))


def run(args: argparse.Namespace, c: eq.Checks) -> None:
    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    cloud = FakeCloud(args.keys_dir, args.release_dir, work / "cloud").start()
    vm = eq.Vm(args.image, work / "vm", ssh_port=args.ssh_port)
    try:
        vm.start()
        drive(args, c, cloud, vm)
    finally:
        try:
            eq.save_debug(vm, work)
        finally:
            vm.stop()
            cloud.stop()
            (work / "cloud-events.json").write_text(json.dumps(
                [{"at": e.at, "kind": e.kind, **e.data} for e in cloud.events], indent=1, default=str))


def drive(args: argparse.Namespace, c: eq.Checks, cloud: FakeCloud, vm: eq.Vm) -> None:
    device = cloud.device
    # --- 1. first boot -> PROVISIONING, interface-scoped provisioning ruleset
    console, pos = eq.read_console(vm, args.boot_timeout)
    eq.log(f"console: one-time password shown, host key {console.fingerprint}")
    facts = vm.facts()
    c.require("1 first boot: lifecycle PROVISIONING", facts.get("lifecycle") == "PROVISIONING",
              facts.get("lifecycle", ""))
    c.check("1 provisioning window open", facts.get("provisioning_open") == "yes")
    first_lifecycle = [r for r in eq.results(facts) if r.get("kind") == "lifecycle"][:1]
    c.check("1 no lifecycle store on the first boot: root recorded FACTORY -> PROVISIONING",
            bool(first_lifecycle) and first_lifecycle[0].get("outcome") == "ok"
            and first_lifecycle[0].get("subject") == {"lifecycle_from": "FACTORY",
                                                      "lifecycle_to": "PROVISIONING"},
            json.dumps(first_lifecycle)[:300])
    journal = vm.run_probe("journal-all").get("journal", "")
    banner = next((line for line in journal.splitlines() if "running in system mode" in line), "")
    c.check("1 systemd enforces the units' seccomp sandbox (+SECCOMP)", "+SECCOMP" in banner, banner[-300:])
    c.check("1 the boot has no ordering cycle", "ordering cycle" not in journal,
            "\n".join(line for line in journal.splitlines() if "cycle" in line)[:600])
    chain_failures = [line for line in journal.splitlines()
                      if ("Failed to start" in line or "Dependency failed" in line)
                      and any(u in line for u in CHAIN_UNIT_NAMES)]
    c.check("1 no unit of the provisioning chain failed at boot", not chain_failures,
            "\n".join(chain_failures[:6]))
    c.check("1 the USB self-installer is not on a device image",
            "USB self-installer" not in journal and "suderra-os-install" not in journal)
    smoke = vm.run_probe("nft-smoke")
    iface = facts.get("default_route_iface", "")
    c.check("1 default route interface present", bool(iface))
    c.check("1 loaded ruleset is the provisioning ruleset scoped to the default-route interface",
            facts.get("nft_ruleset_sha256") == smoke.get("expected.provisioning.sha256")
            and smoke.get("provisioning_iface") == iface,
            f"iface={iface} smoke_iface={smoke.get('provisioning_iface')}")
    ruleset = facts.get("nft_ruleset", "")
    c.check("1 SSH is admitted only on the default-route interface",
            f'iifname "{iface}" tcp dport 22' in ruleset
            and ruleset.count("dport 22") == ruleset.count(f'iifname "{iface}" tcp dport 22'),
            ruleset[-600:])
    c.check("1 an SSH server answers in the provisioning window",
            eq.ssh_banner(args.ssh_port).startswith(b"SSH-"))

    # --- negative deliveries: refused, lifecycle unchanged
    for scenario, reason in NEGATIVE_DELIVERIES:
        mark = cloud.mark()
        cloud.next_delivery = scenario
        rc, out = eq.technician_provision(vm, console, device.device_code, device.token)
        eq.log(f"technician ({scenario}): rc={rc} {out.strip()[-300:]}")
        c.check(f"neg {scenario}: technician command reports an error",
                rc != 0 and "status=error" in out, out[-300:])
        served = [e for e in cloud.events[mark:] if e.kind == "delivery"]
        c.check(f"neg {scenario}: the device fetched a delivery",
                bool(served) and served[-1].data.get("scenario") == scenario)
        facts = vm.facts()
        result = last_provisioning_result(facts)
        c.check(f"neg {scenario}: root refused it with {reason}",
                result.get("outcome") in ("rejected", "failed") and result.get("reason") == reason,
                json.dumps(result)[:400])
        unchanged_provisioning(c, facts, f"neg {scenario}")

    # --- 2./3./4. the scripted technician command installs the delivery
    mark = cloud.mark()
    cloud.next_delivery = "valid"
    rc, out = eq.technician_provision(vm, console, device.device_code, device.token)
    eq.log(f"technician (valid): rc={rc} {out.strip()[-300:]}")
    c.require("2 technician command installs the delivery",
              rc == 0 and "status=installed" in out and "waiting for activation" in out, out[-400:])
    delivered = [e for e in cloud.events[mark:] if e.kind == "delivery"]
    c.check("2 manifest fetched with the X-Provisioning-Token header, not in the URL",
            bool(delivered) and not any(e.kind == "install-refused" for e in cloud.events[mark:]))
    query = delivered[-1].data["query"] if delivered else {}
    binding = json.loads(vm.facts().get("binding") or "{}")
    c.check("3 the device's binding is the SHA-256 of the swtpm's EK, read on the host",
            bool(vm.ek_sha256) and (binding.get("digest") or {}).get("sha256") == vm.ek_sha256
            and binding.get("method") == "tpm-ek-sha256", f"{binding} vs EK {vm.ek_sha256}")
    c.check("3 the request carries that binding",
            query.get("binding_method") == "tpm-ek-sha256" and query.get("binding_sha256") == vm.ek_sha256,
            f"{query.get('binding_method')} {query.get('binding_sha256')}")
    c.check("3 the manifest is bound to that binding",
            device.binding == {"method": "tpm-ek-sha256", "digest": {"sha256": query.get("binding_sha256")}})
    facts = vm.facts()
    receipt = json.loads(facts.get("receipt") or "{}")
    c.require("4 install receipt recorded", bool(receipt), facts.get("receipt", "")[:300])
    served = cloud.deliveries[delivered[-1].data["delivery"]] if delivered else {}
    artifact = cloud.release.body["artifact"]
    expected = {
        "version": cloud.release.body["version"],
        "artifact_digest": artifact["digest"],
        "binary_digest": artifact["binary_digest"],
        "release_statement_digest": {"sha256": served.get("release_statement_digest")},
        "manifest_digest": {"sha256": served.get("manifest_digest")},
        "trust_anchors_digest": {"sha256": served.get("trust_anchors_digest")},
        "site_config_digest": {"sha256": served.get("site_config_digest")},
        "rbac_manifest_digest": {"sha256": served.get("rbac_manifest_digest")},
    }
    differing = {k: (receipt.get(k), v) for k, v in expected.items() if receipt.get(k) != v}
    c.check("4 the install receipt records exactly the delivered statements and artifact",
            not differing, json.dumps(differing)[:600])
    result = last_provisioning_result(facts)
    c.check("4 provisioning result ok", result.get("outcome") == "ok", json.dumps(result)[:300])

    # --- 5. agent active, verify-current passed, NRestarts=0 for 3 x WatchdogSec
    facts = eq.wait_facts(vm, lambda f: eq.unit_props(f, "suderra-agent.service").get("SubState") == "running",
                          args.agent_timeout, "suderra-agent running")
    agent = eq.unit_props(facts, "suderra-agent.service")
    verify = [r for r in eq.results(facts) if r.get("kind") == "verify-current"]
    c.check("4 verify-current passed before the agent started",
            bool(verify) and verify[-1].get("outcome") == "ok", json.dumps(verify[-1:])[:300])
    watchdog_s = eq.timespan_seconds(agent.get("WatchdogUSec", ""))
    c.check("5 the agent unit arms the watchdog", watchdog_s > 0, agent.get("WatchdogUSec", ""))
    pid = agent.get("MainPID")
    hold = 3 * watchdog_s + 30
    eq.log(f"holding {hold:.0f}s (3 x WatchdogSec) to watch NRestarts")
    deadline = time.monotonic() + hold
    stable = True
    while time.monotonic() < deadline:
        time.sleep(30)
        current = eq.unit_props(vm.facts(), "suderra-agent.service")
        if current.get("NRestarts") != "0" or current.get("MainPID") != pid \
                or current.get("ActiveState") != "active":
            stable = False
            c.check("5 agent stays up without restarts", False, str(current))
            break
    if stable:
        c.check("5 agent active with NRestarts=0 for three WatchdogSec periods", True)

    # --- 6. activation, 8883 TLS CONNECT with the device credential, receipt
    cloud.wait_for(lambda e: e.kind == "activated", args.agent_timeout)
    c.check("6 the agent activated with its provisioning token", True)
    cloud.wait_for(lambda e: e.kind == "mqtt" and e.data["topic"].startswith(
        f"tenants/{device.tenant_id}/devices/{device.device_id}/"), args.agent_timeout)
    broker_log = (args.work_dir / "cloud" / "mosquitto.log").read_text(errors="replace")
    c.check("6 the device connected over the 8883 TLS listener with its credential",
            f"u'{device.mqtt_username}'" in broker_log and "8883" in (args.work_dir / "cloud" / "mosquitto.conf").read_text())
    time.sleep(10)  # the agent subscribes to its command topic after CONNACK

    jti, _ = cloud.send_receipt(signed=False)
    response = cloud.wait_response(jti, 300)
    c.check("neg unsigned receipt: the agent refuses it",
            response.get("success") is False and (response.get("result") or {}).get("handed_to_root") is False,
            json.dumps(response)[:300])
    time.sleep(20)
    unchanged = vm.facts()
    c.check("neg unsigned receipt: lifecycle stays PROVISIONING",
            unchanged.get("lifecycle") == "PROVISIONING", unchanged.get("lifecycle", ""))

    jti, receipt_digest = cloud.send_receipt(signed=True)
    response = cloud.wait_response(jti, 300)
    result = response.get("result") or {}
    c.require("6 the agent hands the signed receipt to root",
              response.get("success") is True and result.get("handed_to_root") is True
              and result.get("statement_digest") == {"sha256": receipt_digest},
              json.dumps(response)[:300])
    facts = eq.wait_facts(vm, lambda f: f.get("lifecycle") == "ACTIVE", 1200, "lifecycle ACTIVE")
    activation = [r for r in eq.results(facts) if r.get("kind") == "lifecycle"
                  and (r.get("subject") or {}).get("lifecycle_to") == "ACTIVE"]
    c.check("6 root accepted that receipt: lifecycle PROVISIONING -> ACTIVE",
            bool(activation) and activation[-1].get("outcome") == "ok"
            and activation[-1]["subject"].get("lifecycle_from") == "PROVISIONING"
            and activation[-1]["subject"].get("statement_digest") == {"sha256": receipt_digest},
            json.dumps(activation[-1:])[:400])

    # --- 7. lockdown
    facts = eq.wait_facts(vm, lambda f: any(r.get("kind") == "lockdown" for r in eq.results(f)),
                          1200, "a lockdown result")
    lockdown = [r for r in eq.results(facts) if r.get("kind") == "lockdown"][-1]
    c.check("7 lockdown result ok", lockdown.get("outcome") == "ok", json.dumps(lockdown)[:300])
    c.check("7 dropbear stopped", eq.unit_props(facts, "dropbear.service").get("ActiveState") != "active")
    c.check("7 nothing listens on :22", ":22 " not in facts.get("listeners", ""), facts.get("listeners", ""))
    c.check("7 SSH is closed from the network", not eq.ssh_banner(args.ssh_port).startswith(b"SSH-"))
    smoke = vm.run_probe("nft-smoke")
    expected = smoke.get("expected.appliance.sha256")
    c.check("7 loaded ruleset hash equals the appliance ruleset's",
            facts.get("nft_ruleset_sha256") == expected and smoke.get("expected.appliance.rc") == "0",
            f"{facts.get('nft_ruleset_sha256')} != {expected}")
    c.check("7 policy verify agrees", facts.get("policy_verify.rc") == "0", facts.get("policy_verify", ""))
    agent = eq.unit_props(facts, "suderra-agent.service")
    c.check("7 agent still running without restarts", agent.get("NRestarts") == "0"
            and agent.get("ActiveState") == "active", str(agent))
    c.check("chain: nothing under /etc was written since boot", facts.get("etc_changed", "") == "",
            facts.get("etc_changed", ""))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    eq.common_args(ap)
    ap.add_argument("--agent-timeout", type=float, default=1200)
    args = ap.parse_args()
    c = eq.Checks("edge-provisioning-e2e")
    try:
        run(args, c)
    except Exception as e:  # report every failure with what passed before it
        c.check(f"aborted: {type(e).__name__}", False, str(e))
        traceback.print_exc()
    return c.report()


if __name__ == "__main__":
    sys.exit(main())

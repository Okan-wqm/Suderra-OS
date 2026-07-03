#!/usr/bin/env python3
"""Hermetic unit test for the production-runtime mutation harness wiring (B2b).

Verifies without booting QEMU:
  * production-runtime.py::produce_scenario_mutation produces a real mutation
    artifact and exports SUDERRA_MUTATION_ARTIFACT/_ROLE/_BEFORE_SHA256 when the
    plan carries mutation_inputs, and nothing for signed-boot.
  * production-runtime-scenario.py::mutation_boot_plan dispatches disk-image
    roles to a boot image, payload roles to a labelled drive, and fails closed
    on a missing artifact.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    runtime = _load("production_runtime", HERE / "production-runtime.py")
    scenario = _load("production_runtime_scenario", HERE / "production-runtime-scenario.py")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        # --- produce_scenario_mutation: signed-boot yields nothing ---
        assert runtime.produce_scenario_mutation({}, "signed-boot", work / "s") == {}, "signed-boot must not mutate"

        # --- produce_scenario_mutation: no mutation_inputs -> {} (runner fails it) ---
        assert runtime.produce_scenario_mutation({}, "anti-rollback-downgrade-rejection", work / "n") == {}

        # --- produce_scenario_mutation: real downgrade manifest mutation ---
        key = work / "ota.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        plan = {
            "mutation_inputs": {
                "anti-rollback-downgrade-rejection": {
                    "package": "suderra-os",
                    "downgrade_version": "1.0.0",
                    "rollback_floor": "2.0.0",
                    "sign_key": str(key),
                }
            }
        }
        env = runtime.produce_scenario_mutation(plan, "anti-rollback-downgrade-rejection", work / "d")
        assert env.get("SUDERRA_MUTATION_ROLE") == "manifest", env
        assert Path(env["SUDERRA_MUTATION_ARTIFACT"]).is_file(), env
        assert len(env.get("SUDERRA_MUTATION_BEFORE_SHA256", "")) == 64, env

        # --- mutation_boot_plan dispatch ---
        rootfs = work / "rootfs.img"
        rootfs.write_bytes(b"\x00" * 4096)
        disk = scenario.mutation_boot_plan("rootfs", rootfs)
        assert disk["boot_image"] == rootfs and disk["extra_drives"] == [], disk

        payload = work / "bundle.raucb"
        payload.write_bytes(b"payload")
        pay = scenario.mutation_boot_plan("bundle", payload)
        assert pay["boot_image"] is None, pay
        joined = " ".join(pay["extra_drives"])
        assert scenario.PAYLOAD_SERIAL in joined and "readonly=on" in joined, pay

        # data / no-role -> pristine boot
        assert scenario.mutation_boot_plan("data", payload)["boot_image"] is None
        assert scenario.mutation_boot_plan("", None) == {"boot_image": None, "extra_drives": []}

        # fail-closed: disk/payload role with a missing artifact must raise
        for role in ("rootfs", "bundle", "uki"):
            try:
                scenario.mutation_boot_plan(role, work / "does-not-exist")
            except RuntimeError:
                pass
            else:
                print(f"ERROR: mutation_boot_plan({role}) must fail closed on missing artifact", file=sys.stderr)
                return 1

    print("harness wiring test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Per-scenario mutation producers for the QEMU production-runtime suite.

Each negative production-runtime scenario must exercise a REAL mutated
artifact so the firmware/kernel/userspace rejection is genuinely observed,
not asserted. Fabricating "rejected" outcomes (or reusing an unmutated
artifact) would make the evidence meaningless — this module produces the
actual mutations and reports the ``(artifact, role, before_sha256)`` triple
the scenario harness exports via ``SUDERRA_MUTATION_ARTIFACT`` /
``SUDERRA_MUTATION_ROLE`` / ``SUDERRA_MUTATION_BEFORE_SHA256``.

Mutation classes (mapped to ci/evidence-contract.yml scenario_contracts):

  secureboot-signature (unsigned-boot-rejection)  -> firmware-rejected
      A validly-built UKI with its Authenticode signature stripped. The
      enrolled db no longer matches -> OVMF refuses to load it.
  signed-cmdline (cmdline-tamper-rejection)        -> kernel-rejected
      A UKI re-signed with the REAL db key but carrying a tampered
      dm-verity roothash in .cmdline. Firmware accepts (signature valid);
      the kernel's dm-verity refuses the mismatched rootfs.
  rootfs-tamper (dm-verity-rootfs-tamper-rejection)-> kernel-rejected
      A byte flip inside the rootfs partition payload -> dm-verity hash
      mismatch at runtime.
  rauc-signature (rauc-bad-signature-rejection)    -> userspace-rejected
      A RAUC bundle signed with an untrusted key -> rauc install refuses.
  rauc-install (rauc-good-update)                  -> booted
      A validly dev-signed RAUC bundle for the inactive slot.
  rauc-health (rauc-health-rollback)               -> rollback-completed
      A validly-signed bundle whose payload trips the health gate.
  rollback-floor (anti-rollback-downgrade-rejection)-> userspace-rejected
      A signed OS update manifest with a version below the rollback floor.
  swtpm-state (data-luks-swtpm)                     -> booted
      The swtpm NV snapshot captured before the guest seals the LUKS key;
      the after-state differs once the guest completes sealing.

Disk-targeting mutations (secureboot-signature, signed-cmdline,
rootfs-tamper) are applied by the harness into the per-scenario boot-disk
snapshot; payload mutations (rauc-*, rollback-floor) are attached to the
guest as a labelled drive/blob consumed by suderra-runtime-scenario (B3).
This module only PRODUCES the artifacts and never fabricates outcomes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

# Scenario name -> mutation role recorded in the evidence artifact.
SCENARIO_ROLE = {
    "unsigned-boot-rejection": "uki",
    "cmdline-tamper-rejection": "uki-cmdline",
    "dm-verity-rootfs-tamper-rejection": "rootfs",
    "rauc-bad-signature-rejection": "bundle",
    "rauc-good-update": "inactive-slot",
    "rauc-health-rollback": "health-gate",
    "anti-rollback-downgrade-rejection": "manifest",
    "data-luks-swtpm": "data",
}

# Scenarios with no mutation (positive path).
NO_MUTATION = {"signed-boot"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"required tool not found: {name}")
    return resolved


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def _need(path: Path, what: str) -> Path:
    if not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError(f"{what} missing or empty: {path}")
    return path


# --------------------------------------------------------------------------
# Disk-targeting producers
# --------------------------------------------------------------------------
def produce_unsigned_uki(
    *,
    signed_uki: Path,
    work_dir: Path,
    image: Path | None = None,
    esp_offset: int | None = None,
    esp_dest: str | None = None,
    **_: Any,
) -> Path:
    """Strip the Authenticode signature from a validly-built UKI. When image +
    esp_offset + esp_dest are supplied, emit a full boot disk whose ESP UKI is
    the unsigned one (firmware will refuse it); otherwise emit the bare UKI."""
    _require_tool("sbattach")
    _need(signed_uki, "signed UKI")
    out = work_dir / "unsigned-suderra.efi"
    shutil.copy2(signed_uki, out)
    _run(["sbattach", "--remove", str(out)])
    # Fail-closed: the produced UKI must carry no signature table at all
    # (sbverify --list exits 0 even when empty, so parse its output).
    if shutil.which("sbverify") is not None and _has_signature(out):
        raise RuntimeError("unsigned UKI still carries a signature — strip failed")
    if image is not None and esp_offset is not None and esp_dest is not None:
        return _apply_uki_to_image(image, out, esp_offset, esp_dest, work_dir / "unsigned-image.img")
    return out


def produce_cmdline_tamper(
    *,
    stub: Path,
    kernel: Path,
    osrel: Path,
    initrd: Path,
    cmdline_tampered: Path,
    sign_key: Path,
    sign_cert: Path,
    work_dir: Path,
    image: Path | None = None,
    esp_offset: int | None = None,
    esp_dest: str | None = None,
    **_: Any,
) -> Path:
    """Rebuild a UKI with a tampered dm-verity roothash and re-sign with the
    REAL db key: firmware accepts (valid signature), kernel rejects (bad hash).
    With image + esp_offset + esp_dest, emit a full boot disk carrying it."""
    objcopy = _require_tool("objcopy")
    _require_tool("sbsign")
    for path, what in ((stub, "UKI stub"), (kernel, "kernel"), (osrel, "os-release"),
                       (initrd, "initrd"), (cmdline_tampered, "tampered cmdline"),
                       (sign_key, "signing key"), (sign_cert, "signing cert")):
        _need(path, what)
    unsigned = work_dir / "cmdline-tamper-unsigned.efi"
    signed = work_dir / "cmdline-tamper-suderra.efi"
    _run([
        objcopy,
        "--add-section", f".osrel={osrel}", "--change-section-vma", ".osrel=0x20000",
        "--add-section", f".cmdline={cmdline_tampered}", "--change-section-vma", ".cmdline=0x30000",
        "--add-section", f".initrd={initrd}", "--change-section-vma", ".initrd=0x3000000",
        "--add-section", f".linux={kernel}", "--change-section-vma", ".linux=0x2000000",
        str(stub), str(unsigned),
    ])
    _run(["sbsign", "--key", str(sign_key), "--cert", str(sign_cert), "--output", str(signed), str(unsigned)])
    if not _sbverify_ok(signed, cert=sign_cert):
        raise RuntimeError("cmdline-tamper UKI must remain validly signed (firmware must accept it)")
    if image is not None and esp_offset is not None and esp_dest is not None:
        return _apply_uki_to_image(image, signed, esp_offset, esp_dest, work_dir / "cmdline-tamper-image.img")
    return signed


def produce_rootfs_tamper(*, image: Path, offset: int, length: int, work_dir: Path, **_: Any) -> Path:
    """Flip bytes inside the rootfs region so dm-verity's Merkle check fails.

    ``offset``/``length`` locate a rootfs data block (derived by the caller
    from the genimage layout). The mutation is emitted as a copy the harness
    applies to the boot-disk snapshot; the original image is never modified.
    """
    _need(image, "disk image")
    if offset <= 0 or length <= 0:
        raise RuntimeError("rootfs tamper requires positive offset/length from the genimage layout")
    out = work_dir / "rootfs-tamper.img"
    shutil.copy2(image, out)
    size = out.stat().st_size
    if offset + length > size:
        raise RuntimeError(f"tamper window {offset}+{length} exceeds image size {size}")
    with out.open("r+b") as handle:
        handle.seek(offset)
        original = handle.read(length)
        flipped = bytes(b ^ 0xFF for b in original)
        if flipped == original:
            raise RuntimeError("byte flip produced identical bytes")
        handle.seek(offset)
        handle.write(flipped)
    return out


# --------------------------------------------------------------------------
# Payload producers (guest-consumed)
# --------------------------------------------------------------------------
def produce_downgrade_manifest(
    *,
    package: str,
    downgrade_version: str,
    rollback_floor: str,
    sign_key: Path,
    work_dir: Path,
    **_: Any,
) -> Path:
    """Emit a signed OS update manifest whose version is below the rollback
    floor so suderra-ota refuses it as an anti-rollback downgrade."""
    _require_tool("openssl")
    _need(sign_key, "manifest signing key")
    if _version_tuple(downgrade_version) >= _version_tuple(rollback_floor):
        raise RuntimeError(
            f"downgrade version {downgrade_version} must be strictly below floor {rollback_floor}"
        )
    manifest = {
        "schema": "suderra.os-update-manifest.v1",
        "package": package,
        "version": downgrade_version,
        "rollback_floor": rollback_floor,
    }
    payload = work_dir / "downgrade-manifest.json"
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload.write_bytes(canonical)
    sig = work_dir / "downgrade-manifest.json.sig"
    _run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(sign_key),
          "-in", str(payload), "-out", str(sig)])
    return payload


def produce_swtpm_snapshot(*, swtpm_state: Path, work_dir: Path, **_: Any) -> Path:
    """Capture the swtpm NV state before the guest seals the LUKS key.

    The mutation is the before/after divergence: the harness records this
    snapshot and the suite validator asserts before != after once the guest
    completes TPM2 sealing during the data-luks-swtpm boot.
    """
    if not swtpm_state.is_dir():
        raise RuntimeError(f"swtpm state dir missing: {swtpm_state}")
    out = work_dir / "swtpm-state-before"
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(swtpm_state, out)
    return out


def _rauc_bundle(*, kind: str, work_dir: Path, bundle_tool: Path, **_: Any) -> Path:
    """RAUC bundle producers require the rauc host tool + build artifacts and
    only run inside the production-runtime workflow. Kept explicit (never a
    silent stub) so the harness fails loudly if invoked without rauc."""
    _require_tool("rauc")
    _need(bundle_tool, "rauc bundle tool")
    raise RuntimeError(
        f"rauc bundle mutation '{kind}' must be produced by {bundle_tool} in the "
        "production-runtime workflow (rauc host tool + built slot images required)"
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _apply_uki_to_image(base_image: Path, uki: Path, esp_offset: int, esp_dest: str, out: Path) -> Path:
    """Copy the boot disk and replace the ESP UKI with ``uki`` via mtools,
    addressing the FAT ESP inside the image at ``esp_offset`` bytes. Returns the
    full mutated disk image the harness boots. mtools keeps this root-free."""
    _require_tool("mcopy")
    _need(base_image, "base disk image")
    _need(uki, "replacement UKI")
    if esp_offset <= 0:
        raise RuntimeError("esp_offset must be the ESP partition byte offset from the layout")
    dest = esp_dest if esp_dest.startswith("::") else f"::{esp_dest.lstrip('/')}"
    shutil.copy2(base_image, out)
    _run(["mcopy", "-i", f"{out}@@{esp_offset}", "-o", str(uki), dest])
    return out


def _sbverify_ok(binary: Path, cert: Path) -> bool:
    """True if ``binary`` verifies against ``cert`` (reliable exit code)."""
    sbverify = shutil.which("sbverify")
    if sbverify is None:
        return False
    proc = subprocess.run(
        [sbverify, "--cert", str(cert), str(binary)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    return proc.returncode == 0


def _has_signature(binary: Path) -> bool:
    """True if ``binary`` carries a signature table. ``sbverify --list`` exits
    0 even when empty ("No signature table present"), so parse its output."""
    sbverify = shutil.which("sbverify")
    if sbverify is None:
        return False
    proc = subprocess.run(
        [sbverify, "--list", str(binary)],
        capture_output=True, text=True, check=False,
    )
    text = (proc.stdout + proc.stderr).lower()
    return "no signature table" not in text and "signature" in text


def _version_tuple(version: str) -> tuple[int, ...]:
    core = version.lstrip("vV").split("-", 1)[0]
    parts = []
    for chunk in core.split("."):
        if not chunk.isdigit():
            raise RuntimeError(f"non-numeric version component in {version!r}")
        parts.append(int(chunk))
    if not parts:
        raise RuntimeError(f"empty version: {version!r}")
    return tuple(parts)


PRODUCERS: dict[str, Callable[..., Path]] = {
    "unsigned-boot-rejection": produce_unsigned_uki,
    "cmdline-tamper-rejection": produce_cmdline_tamper,
    "dm-verity-rootfs-tamper-rejection": produce_rootfs_tamper,
    "anti-rollback-downgrade-rejection": produce_downgrade_manifest,
    "data-luks-swtpm": produce_swtpm_snapshot,
    "rauc-bad-signature-rejection": lambda **kw: _rauc_bundle(kind="bad-signature", **kw),
    "rauc-good-update": lambda **kw: _rauc_bundle(kind="good", **kw),
    "rauc-health-rollback": lambda **kw: _rauc_bundle(kind="health", **kw),
}


def produce(scenario: str, *, work_dir: Path, inputs: dict[str, Any]) -> dict[str, Any] | None:
    """Produce the mutation artifact for ``scenario``. Returns the evidence
    triple, or None for the positive (no-mutation) scenario."""
    if scenario in NO_MUTATION:
        return None
    producer = PRODUCERS.get(scenario)
    if producer is None:
        raise RuntimeError(f"no mutation producer for scenario: {scenario}")
    work_dir.mkdir(parents=True, exist_ok=True)
    artifact = producer(work_dir=work_dir, **inputs)
    before_source = inputs.get("before_source")
    if before_source is not None:
        before = sha256_file(Path(before_source))
    elif artifact.is_file():
        before = sha256_file(artifact)
    else:
        before = ""
    return {
        "artifact": str(artifact),
        "role": SCENARIO_ROLE[scenario],
        "before_sha256": before,
    }


def _coerce_inputs(raw: list[str]) -> dict[str, Any]:
    inputs: dict[str, Any] = {}
    for item in raw:
        if "=" not in item:
            raise RuntimeError(f"--input must be key=value: {item!r}")
        key, value = item.split("=", 1)
        if key in {"stub", "kernel", "osrel", "initrd", "cmdline_tampered", "sign_key",
                   "sign_cert", "signed_uki", "image", "swtpm_state", "bundle_tool",
                   "before_source"}:
            inputs[key] = Path(value)
        elif key in {"offset", "length", "esp_offset"}:
            inputs[key] = int(value)
        else:
            inputs[key] = value
    return inputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--input", action="append", default=[], metavar="KEY=VALUE")
    args = parser.parse_args()
    try:
        result = produce(args.scenario, work_dir=args.work_dir, inputs=_coerce_inputs(args.input))
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result) if result is not None else "null")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Pin the edge keys of a trust-root set into the image (ADR-048 DEC-3.4, DEC-3.9).

The root installer verifies edge-release, edge-provisioning, trust-anchors
and device-lifecycle statements only against keys pinned on the verity
rootfs at /etc/suderra/keys/<purpose>/<epoch>.pub. This installs them from
<trust-roots>/edge/<purpose>/<epoch>.pub (scripts/ci/edge-dev-keys.py).

* dev images (and the QEMU targets) pin the dev/CI keys of the set; every
  os-image purpose must be present, each file an Ed25519
  SubjectPublicKeyInfo, no key shared by two purposes.
* production images pin only keyids the P1 key ceremony records in
  docs/security/key-management.md. None is recorded yet, so a production
  build whose trust-root set carries edge keys fails, and a production image
  pins no edge key (its installer then provisions nothing).

The contract's TEST-ONLY keys are refused before this runs
(scripts/ci/check-no-contract-test-keys.py in suderra-keys.mk).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import shutil
import sys
from pathlib import Path

OS_PINNED = ("edge-release", "edge-provisioning", "fleet-root", "device-lifecycle")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
EPOCH_FILE = re.compile(r"^[1-9][0-9]{0,4}\.pub$")


def raw_key(path: Path) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise ValueError(f"{path}: not a PEM PUBLIC KEY block")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(der) != 44 or not der.startswith(SPKI_PREFIX):
        raise ValueError(f"{path}: not an Ed25519 SubjectPublicKeyInfo")
    return der[len(SPKI_PREFIX):]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--trust-roots", type=Path, required=True)
    ap.add_argument("--target", type=Path, required=True)
    ap.add_argument("--variant", choices=("dev", "prod"), required=True)
    args = ap.parse_args()

    edge = args.trust_roots / "edge"
    pins = args.target / "etc/suderra/keys"
    if pins.exists():
        shutil.rmtree(pins)

    if args.variant == "prod":
        if edge.exists():
            print(
                f"ERROR: {edge}: a production image pins only keyids the P1 key ceremony "
                "inventories (ADR-048 DEC-3.9), and none is inventoried yet",
                file=sys.stderr,
            )
            return 1
        print("suderra-keys: production image, no edge key pinned (no inventoried keyid)")
        return 0

    seen: dict[bytes, str] = {}
    staged: list[tuple[Path, Path, str]] = []
    for purpose in OS_PINNED:
        source = edge / purpose
        files = sorted(p for p in source.glob("*.pub")) if source.is_dir() else []
        if not files:
            print(f"ERROR: {source}: no <epoch>.pub (run scripts/gen-dev-keys.sh or "
                  "scripts/ci/prepare-ci-keyring.sh)", file=sys.stderr)
            return 1
        for f in files:
            if not EPOCH_FILE.match(f.name):
                print(f"ERROR: {f}: not <epoch>.pub", file=sys.stderr)
                return 1
            try:
                raw = raw_key(f)
            except (ValueError, UnicodeDecodeError) as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 1
            if raw in seen:
                print(f"ERROR: {f} is the {seen[raw]} key; every purpose has its own key "
                      "(ADR-048 DEC-3.3)", file=sys.stderr)
                return 1
            seen[raw] = f"{purpose}/{f.name}"
            staged.append((f, pins / purpose / f.name, hashlib.sha256(raw).hexdigest()))

    for source, dest, keyid in staged:
        dest.parent.mkdir(parents=True, exist_ok=True)
        for d in (pins, dest.parent):
            d.chmod(0o755)
        shutil.copyfile(source, dest)
        dest.chmod(0o644)
        print(f"suderra-keys: pinned {dest.relative_to(args.target)} keyid {keyid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

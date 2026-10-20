#!/usr/bin/env python3
"""Refuse the Suderra edge contract's TEST-ONLY keys wherever an image could trust them.

The vendored contract (contracts/suderra-edge/v*/test-keys/keyring.json,
ADR-048 DEC-25) signs its golden fixtures with Ed25519 keys whose private
halves anyone can derive from published seed labels. No image of any variant
may pin one (DEC-3.9: dev and CI images pin the keys of scripts/gen-dev-keys.sh
and scripts/ci/prepare-ci-keyring.sh), so their key material must never reach
a trust-root directory, a board overlay or a built rootfs.

    check-no-contract-test-keys.py --tree DIR [DIR ...]   # every file under DIR
    check-no-contract-test-keys.py --repo                 # every tracked file

--tree is what package/suderra-keys runs on SUDERRA_TRUST_ROOTS_DIR before it
installs anything; --repo is what tests/image-contracts runs on the checkout
(the vendored contract itself excepted). The script searches for every form a
key can take in a file: seed label, private seed (hex, base64, raw), keyid,
public key (base64, hex, raw), the PEM body of its SubjectPublicKeyInfo and
its DER, and the MQTT test CA certificate. Exit 1 lists every hit.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VENDOR = "contracts/suderra-edge"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def needles(root: Path) -> dict[bytes, str]:
    out: dict[bytes, str] = {}
    keyrings = sorted((root / VENDOR).glob("v*/test-keys/keyring.json"))
    if not keyrings:
        raise SystemExit(
            f"ERROR: no {VENDOR}/v*/test-keys/keyring.json to take the deny-list from"
        )
    for keyring in keyrings:
        data = json.loads(keyring.read_text(encoding="utf-8"))
        if data.get("test_only") is not True:
            raise SystemExit(f"ERROR: {keyring} is not marked test_only")
        for entry in [*data["keys"], *data.get("unanchored_keys", [])]:
            label = entry["seed_label"]
            name = label.rsplit("TEST-ONLY:", 1)[-1]
            seed = hashlib.sha256(label.encode()).digest()
            raw = base64.b64decode(entry["public_key"], validate=True)
            spki = ED25519_SPKI_PREFIX + raw
            forms = {
                label.encode(): "seed label",
                seed: "private seed (raw)",
                seed.hex().encode(): "private seed (hex)",
                base64.b64encode(seed): "private seed (base64)",
                entry["keyid"].encode(): "keyid",
                raw: "public key (raw)",
                raw.hex().encode(): "public key (hex)",
                entry["public_key"].encode(): "public key (base64)",
                spki: "public key (SubjectPublicKeyInfo DER)",
                base64.b64encode(spki): "public key (PEM body)",
            }
            for value, form in forms.items():
                out[value] = f"TEST-ONLY {name} {form}"
        for ca in data["mqtt_ca"]:
            pem = ca["certificate"]
            body = "".join(
                line for line in pem.splitlines() if not line.startswith("-----")
            )
            der = base64.b64decode(body, validate=True)
            out[der] = "TEST-ONLY MQTT CA certificate (DER)"
            out[pem.splitlines()[1].encode()] = "TEST-ONLY MQTT CA certificate (PEM)"
            out[ca["certificate_sha256"].encode()] = (
                "TEST-ONLY MQTT CA certificate digest"
            )
    return out


def scan(
    paths: list[Path], deny: dict[bytes, str], label: Callable[[Path], str]
) -> list[str]:
    hits = []
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            hits.append(f"{label(path)}: unreadable ({exc})")
            continue
        for value, form in deny.items():
            if value in data:
                hits.append(f"{label(path)}: {form}")
    return hits


def tree_files(directories: list[str]) -> list[Path]:
    files = []
    for directory in directories:
        top = Path(directory)
        if not top.is_dir():
            raise SystemExit(f"ERROR: {top} is not a directory")
        files.extend(sorted(p for p in top.rglob("*") if p.is_file()))
    return files


def repo_files(root: Path) -> list[Path]:
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True
    ).stdout.split(b"\0")
    return [
        root / rel.decode()
        for rel in tracked
        if rel
        and not rel.decode().startswith(f"{VENDOR}/")
        and (root / rel.decode()).is_file()
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--tree", nargs="+", metavar="DIR", help="scan every file under DIR"
    )
    mode.add_argument(
        "--repo", action="store_true", help="scan every tracked file of the checkout"
    )
    args = parser.parse_args()

    deny = needles(ROOT)
    if args.repo:
        hits = scan(repo_files(ROOT), deny, lambda p: p.relative_to(ROOT).as_posix())
    else:
        hits = scan(tree_files(args.tree), deny, lambda p: p.as_posix())
    for hit in hits:
        print(f"ERROR: contract TEST-ONLY key material: {hit}", file=sys.stderr)
    if hits:
        print(
            "ERROR: TEST-ONLY contract keys are derivable by anyone; no image, overlay or "
            "trust-root directory may contain them (ADR-048 DEC-3.9, DEC-25.1).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

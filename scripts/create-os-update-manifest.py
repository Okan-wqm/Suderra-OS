#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create a signed suderra-ota OS update manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = "suderra.os-update-manifest.v1"
SIGNATURE_ALGORITHM = "ed25519-suderra-os-update-manifest-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def public_key_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="ignore").strip()
    if len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text):
        return bytes.fromhex(text)
    if len(raw) == 32:
        return raw
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) < 32:
        raise ValueError(f"public key must be raw/hex Ed25519 or PEM readable by openssl: {path}")
    return result.stdout[-32:]


def unsigned_manifest(args: argparse.Namespace) -> dict[str, Any]:
    bundle_sha = sha256_file(args.bundle)
    return {
        "schema_version": SCHEMA_VERSION,
        "version": args.version,
        "target": args.target,
        "artifact_sha256": bundle_sha,
        "bundle": {
            "name": args.bundle.name,
            "sha256": bundle_sha,
            "bytes": args.bundle.stat().st_size,
        },
        "key_epoch": args.key_epoch,
        "expires_at": args.expires_at,
        "min_current_version": args.min_current_version,
        "rollback_floor": args.rollback_floor,
        "release_notes": args.release_notes,
    }


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_ed25519(signing_key: Path, payload: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(prefix="suderra-os-update-manifest-", delete=False) as handle:
        handle.write(payload)
        handle.flush()
        canonical = Path(handle.name)
    signature = canonical.with_suffix(".sig")
    try:
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(signing_key),
                "-in",
                str(canonical),
                "-out",
                str(signature),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip() or "openssl pkeyutl failed")
        return signature.read_bytes()
    finally:
        canonical.unlink(missing_ok=True)
        signature.unlink(missing_ok=True)


def create_command(args: argparse.Namespace) -> int:
    if not args.bundle.is_file() or args.bundle.stat().st_size <= 0:
        print(f"ERROR: bundle is missing or empty: {args.bundle}", file=sys.stderr)
        return 1
    if not args.signing_key.is_file() or args.signing_key.stat().st_size <= 0:
        print(f"ERROR: signing key is missing or empty: {args.signing_key}", file=sys.stderr)
        return 1
    if not args.public_key.is_file() or args.public_key.stat().st_size <= 0:
        print(f"ERROR: public key is missing or empty: {args.public_key}", file=sys.stderr)
        return 1
    try:
        datetime.fromisoformat(args.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        public = public_key_bytes(args.public_key)
        payload = unsigned_manifest(args)
        signature = sign_ed25519(args.signing_key, canonical_bytes(payload))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    payload["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": args.key_id,
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "signature_hex": signature.hex(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote OS update manifest: {args.output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--bundle", type=Path, required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--target", required=True)
    create.add_argument("--min-current-version", required=True)
    create.add_argument("--rollback-floor", required=True)
    create.add_argument("--key-epoch", type=int, required=True)
    create.add_argument("--key-id", required=True)
    create.add_argument("--expires-at", required=True)
    create.add_argument("--release-notes")
    create.add_argument("--signing-key", type=Path, required=True)
    create.add_argument("--public-key", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=create_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

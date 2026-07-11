#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create a signed suderra-ota OS update manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = "suderra.os-update-manifest.v1"
# -v2: imza baytlari sorted-key kanonik JSON'dur (Rust dogrulayicidaki
# suderra_config::canonical ile bayt-bayt ayni; golden vektorler:
# tests/ota/fixtures/canonical-vectors/). -v1 insertion-order imzaliyordu ve
# dosyaya sort_keys ile yazildigindan bu script'in kendi verify'i bile kendi
# ciktisini dogrulayamiyordu; -v2 bu tutarsizligi kapatir.
SIGNATURE_ALGORITHM = "ed25519-suderra-os-update-manifest-v2"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def production_mode() -> bool:
    return os.environ.get("SUDERRA_SIGNING_MODE") == "prod" or os.environ.get("SUDERRA_RELEASE_TIER") == "production"


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
    """Imza baytlari — Rust `suderra_config::canonical` ile ayni sozlesme.

    sort_keys=True: anahtarlar Unicode code-point sirasiyla (UTF-8 bayt sirasi
    ile ozdes — Rust BTreeMap ile ayni). ensure_ascii=False: non-ASCII ham UTF-8
    (serde_json ile ayni). Float bu sozlesmede YASAK (platform-bagimli
    formatlama); manifest semasi yalniz int/string/bool/null icerir.
    """
    _reject_floats(payload)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("float degerler imza sozlesmesinde yasak (kanonik form belirsiz)")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


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


def verify_ed25519(public_key: Path, payload: bytes, signature: bytes) -> None:
    with tempfile.NamedTemporaryFile(prefix="suderra-os-update-manifest-", delete=False) as payload_handle:
        payload_handle.write(payload)
        payload_handle.flush()
        canonical = Path(payload_handle.name)
    with tempfile.NamedTemporaryFile(prefix="suderra-os-update-manifest-", suffix=".sig", delete=False) as sig_handle:
        sig_handle.write(signature)
        sig_handle.flush()
        signature_path = Path(sig_handle.name)
    try:
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-sigfile",
                str(signature_path),
                "-in",
                str(canonical),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip() or "openssl pkeyutl verify failed")
    finally:
        canonical.unlink(missing_ok=True)
        signature_path.unlink(missing_ok=True)


def create_command(args: argparse.Namespace) -> int:
    if production_mode() and os.environ.get("SUDERRA_OS_UPDATE_MANIFEST_ALLOW_FILE_KEY") != "1":
        print(
            "ERROR: production OS update manifest signing requires HSM-bound signing evidence; file keys are lab-only",
            file=sys.stderr,
        )
        return 1
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


def verify_command(args: argparse.Namespace) -> int:
    if not args.manifest.is_file() or args.manifest.stat().st_size <= 0:
        print(f"ERROR: manifest is missing or empty: {args.manifest}", file=sys.stderr)
        return 1
    if not args.public_key.is_file() or args.public_key.stat().st_size <= 0:
        print(f"ERROR: public key is missing or empty: {args.public_key}", file=sys.stderr)
        return 1
    try:
        payload = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("manifest must be a JSON object")
        signature = payload.pop("signature", None)
        if not isinstance(signature, dict):
            raise ValueError("manifest signature block is required")
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
        if signature.get("algorithm") != SIGNATURE_ALGORITHM:
            raise ValueError(f"signature.algorithm must be {SIGNATURE_ALGORITHM}")
        public = public_key_bytes(args.public_key)
        public_sha = hashlib.sha256(public).hexdigest()
        if signature.get("public_key_sha256") != public_sha:
            raise ValueError("signature.public_key_sha256 does not match public key")
        signature_hex = signature.get("signature_hex")
        if not isinstance(signature_hex, str) or len(signature_hex) % 2 != 0:
            raise ValueError("signature.signature_hex must be hex")
        verify_ed25519(args.public_key, canonical_bytes(payload), bytes.fromhex(signature_hex))
        if args.bundle is not None:
            if not args.bundle.is_file() or args.bundle.stat().st_size <= 0:
                raise ValueError(f"bundle is missing or empty: {args.bundle}")
            bundle = payload.get("bundle")
            if not isinstance(bundle, dict):
                raise ValueError("manifest.bundle is required")
            if bundle.get("sha256") != sha256_file(args.bundle):
                raise ValueError("manifest bundle digest does not match bundle file")
            if bundle.get("bytes") != args.bundle.stat().st_size:
                raise ValueError("manifest bundle size does not match bundle file")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"verified OS update manifest: {args.manifest}")
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
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--bundle", type=Path)
    verify.set_defaults(func=verify_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

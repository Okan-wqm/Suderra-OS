#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Dev/CI edge keys, dev fleet-root and the signed dev trust-anchor bundle.

ADR-048 DEC-3 gives every signing purpose its own Ed25519 key and epoch,
pins edge-release, edge-provisioning, fleet-root and device-lifecycle in the
OS image (/etc/suderra/keys/<purpose>/<epoch>.pub, DEC-3.4) and puts the
agent's anchors in a suderra.trust-anchors.v1 bundle signed by fleet-root
(DEC-3.7). In P0 only dev/CI keys exist (DEC-3.9): scripts/gen-dev-keys.sh
and scripts/ci/prepare-ci-keyring.sh call this tool, and only dev images and
the QEMU targets pin what it makes. It never touches the contract's TEST-ONLY
keys (contracts/suderra-edge/v1/test-keys), and the result is checked against
them.

Layout under <keys-dir>/edge/ (consumed by package/suderra-keys and by the
QEMU fake cloud):

    <purpose>/<epoch>.key        Ed25519 private key, PKCS#8 PEM, 0600
    <purpose>/<epoch>.pub        Ed25519 SubjectPublicKeyInfo PEM, 0644
    mqtt-ca/ca.key, ca.crt       root CA of the dev/QEMU test broker
    cloud-ca/ca.key, ca.crt      root CA of the QEMU fake cloud's provisioning
                                 API (https); dev images and the QEMU targets
                                 carry ca.crt as /etc/suderra/cloud-ca.pem
    trust-anchors.dsse.json      DSSE envelope of the dev bundle, signed by
                                 fleet-root/<epoch>.key

    edge-dev-keys.py generate --keys-dir DIR --profile dev|ci [--tenant-id UUID]...
    edge-dev-keys.py verify   --keys-dir DIR [--public-only]

generate keeps existing keys and an existing bundle whose content still
matches; a changed bundle gets bundle_seq + 1, because a device refuses an
equal bundle_seq with different bytes (statements.json sequences).
verify checks every file, the bundle's signature (openssl) and payload, that
the bundle anchors exactly these keys, and that no TEST-ONLY key is present.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EPOCH = 1
PURPOSES = (
    "edge-release",
    "edge-provisioning",
    "fleet-root",
    "device-lifecycle",
    "config-integrity",
    "rbac-manifest",
    "command",
)
OS_PINNED = ("edge-release", "edge-provisioning", "fleet-root", "device-lifecycle")
BUNDLE_ED25519 = ("command", "rbac-manifest", "config-integrity", "edge-release", "edge-provisioning")
PAYLOAD_TYPE = "application/vnd.suderra.trust-anchors.v1+json"
BUNDLE = "trust-anchors.dsse.json"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
CERT_RE = re.compile(r"^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n$")


class KeyError_(Exception):
    pass


def openssl(*args: str, data: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    except FileNotFoundError as e:
        raise KeyError_("the openssl CLI (OpenSSL 3, Ed25519 -rawin) is required") from e
    if proc.returncode != 0:
        raise KeyError_(f"openssl {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def raw_public_key(pub_pem: Path) -> bytes:
    der = openssl("pkey", "-pubin", "-in", str(pub_pem), "-outform", "DER")
    if len(der) != 44 or not der.startswith(SPKI_PREFIX):
        raise KeyError_(f"{pub_pem} is not an Ed25519 SubjectPublicKeyInfo")
    return der[len(SPKI_PREFIX):]


def keyid(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def write_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    os.chmod(path, 0o600)


def write_public(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(content)
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def ensure_ed25519(edge: Path, purpose: str) -> None:
    key = edge / purpose / f"{EPOCH}.key"
    pub = edge / purpose / f"{EPOCH}.pub"
    (edge / purpose).mkdir(parents=True, exist_ok=True)
    os.chmod(edge / purpose, 0o755)
    if not key.is_file() or key.stat().st_size == 0:
        write_private(key, openssl("genpkey", "-algorithm", "ED25519"))
    write_public(pub, openssl("pkey", "-in", str(key), "-pubout"))


def ensure_test_ca(edge: Path, name: str, subject: str, profile: str, days: int) -> None:
    ca_dir = edge / name
    ca_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(ca_dir, 0o755)
    key, crt = ca_dir / "ca.key", ca_dir / "ca.crt"
    if key.is_file() and crt.is_file() and crt.stat().st_size:
        return
    write_private(key, openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"))
    label = "Dev" if profile == "dev" else "CI"
    cert = openssl(
        "req", "-new", "-x509", "-key", str(key), "-sha256", "-days", str(days),
        "-subj", f"/CN=Suderra {label} {subject}/",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    write_public(crt, cert)


def ensure_mqtt_ca(edge: Path, profile: str, days: int) -> None:
    ensure_test_ca(edge, "mqtt-ca", "QEMU MQTT test broker CA", profile, days)


def ensure_cloud_ca(edge: Path, profile: str, days: int) -> None:
    ensure_test_ca(edge, "cloud-ca", "QEMU provisioning API test CA", profile, days)


def anchors(edge: Path) -> list[dict]:
    out: list[dict] = []
    for purpose in BUNDLE_ED25519:
        raw = raw_public_key(edge / purpose / f"{EPOCH}.pub")
        out.append({
            "purpose": purpose,
            "algorithm": "ed25519",
            "keyid": keyid(raw),
            "epoch": EPOCH,
            "public_key": base64.b64encode(raw).decode(),
        })
    out.append({
        "purpose": "mqtt-ca",
        "algorithm": "x509",
        "certificates": [(edge / "mqtt-ca" / "ca.crt").read_text(encoding="ascii")],
    })
    return out


def read_bundle(edge: Path) -> tuple[dict, dict] | None:
    path = edge / BUNDLE
    if not path.is_file():
        return None
    envelope = json.loads(path.read_text(encoding="utf-8"))
    payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
    return envelope, payload


def sign_bundle(edge: Path, tenant_scope: list[str]) -> None:
    fleet_key = edge / "fleet-root" / f"{EPOCH}.key"
    fleet_raw = raw_public_key(edge / "fleet-root" / f"{EPOCH}.pub")
    wanted = anchors(edge)
    previous = read_bundle(edge)
    seq = 1
    if previous is not None:
        _, old = previous
        if old.get("anchors") == wanted and old.get("tenant_scope") == tenant_scope:
            return
        seq = int(old.get("bundle_seq", 0)) + 1
    payload = json.dumps(
        {
            "_type": "suderra.trust-anchors.v1",
            "bundle_seq": seq,
            "issued_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tenant_scope": tenant_scope,
            "anchors": wanted,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with tempfile.TemporaryDirectory() as tmp:
        message = Path(tmp) / "pae"
        message.write_bytes(pae(PAYLOAD_TYPE, payload))
        sig = openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(fleet_key), "-in", str(message))
    if len(sig) != 64:
        raise KeyError_("fleet-root signature is not 64 bytes")
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid(fleet_raw), "sig": base64.b64encode(sig).decode()}],
    }
    write_public(edge / BUNDLE, (json.dumps(envelope, indent=2) + "\n").encode())


def generate(keys_dir: Path, profile: str, tenant_ids: list[str], days: int) -> None:
    if profile not in ("dev", "ci"):
        raise KeyError_("edge dev keys are for the dev and ci profiles only (DEC-3.9)")
    edge = keys_dir / "edge"
    edge.mkdir(parents=True, exist_ok=True)
    os.chmod(edge, 0o755)
    for purpose in PURPOSES:
        ensure_ed25519(edge, purpose)
    ensure_mqtt_ca(edge, profile, days)
    ensure_cloud_ca(edge, profile, days)
    for t in tenant_ids:
        if not UUID_RE.match(t):
            raise KeyError_(f"tenant id {t!r} is not a lowercase RFC 9562 UUID")
    if not tenant_ids:
        previous = read_bundle(edge)
        tenant_ids = previous[1]["tenant_scope"] if previous else [str(uuid.uuid4())]
    sign_bundle(edge, sorted(set(tenant_ids)))


def verify(keys_dir: Path, public_only: bool) -> list[str]:
    edge = keys_dir / "edge"
    problems: list[str] = []
    if not edge.is_dir():
        return [f"{edge} is missing (dev/CI per-purpose edge keys, DEC-3.9)"]
    raws: dict[str, bytes] = {}
    for purpose in PURPOSES:
        pub = edge / purpose / f"{EPOCH}.pub"
        key = edge / purpose / f"{EPOCH}.key"
        try:
            raws[purpose] = raw_public_key(pub)
        except (KeyError_, FileNotFoundError) as e:
            problems.append(f"{purpose}: {e}")
            continue
        if public_only:
            if key.exists():
                problems.append(f"{key}: private key in a public-only trust-root set")
            continue
        if not key.is_file():
            problems.append(f"{key} is missing")
            continue
        if key.stat().st_mode & 0o077:
            problems.append(f"{key} is readable by group or others")
        derived = openssl("pkey", "-in", str(key), "-pubout", "-outform", "DER")
        if derived[len(SPKI_PREFIX):] != raws.get(purpose):
            problems.append(f"{key} does not match {pub}")
    if len({k for k in raws.values()}) != len(raws):
        problems.append("two purposes share one key; every purpose has its own key (DEC-3.3)")
    crt = edge / "mqtt-ca" / "ca.crt"
    if not crt.is_file():
        problems.append(f"{crt} is missing")
    else:
        text = openssl("x509", "-in", str(crt), "-noout", "-text").decode()
        if "CA:TRUE" not in text:
            problems.append(f"{crt} is not a CA certificate")
    if public_only and (edge / "mqtt-ca" / "ca.key").exists():
        problems.append("mqtt-ca/ca.key in a public-only trust-root set")
    cloud_crt = edge / "cloud-ca" / "ca.crt"
    if not cloud_crt.is_file():
        problems.append(f"{cloud_crt} is missing")
    else:
        text = openssl("x509", "-in", str(cloud_crt), "-noout", "-text").decode()
        if "CA:TRUE" not in text:
            problems.append(f"{cloud_crt} is not a CA certificate")
    if public_only and (edge / "cloud-ca" / "ca.key").exists():
        problems.append("cloud-ca/ca.key in a public-only trust-root set")
    bundle = read_bundle(edge)
    if bundle is None:
        problems.append(f"{edge / BUNDLE} is missing")
        return problems
    envelope, payload = bundle
    if set(envelope) != {"payloadType", "payload", "signatures"} or envelope["payloadType"] != PAYLOAD_TYPE:
        problems.append("bundle envelope is not a suderra.trust-anchors.v1 DSSE envelope")
    sigs = envelope.get("signatures", [])
    if len(sigs) != 1:
        problems.append("bundle must carry exactly one signature")
    elif "fleet-root" in raws:
        if sigs[0].get("keyid") != keyid(raws["fleet-root"]):
            problems.append("bundle is not signed by the fleet-root key (DEC-3.7)")
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
        with tempfile.TemporaryDirectory() as tmp:
            message, sig = Path(tmp) / "pae", Path(tmp) / "sig"
            message.write_bytes(pae(PAYLOAD_TYPE, payload_bytes))
            sig.write_bytes(base64.b64decode(sigs[0]["sig"], validate=True))
            try:
                openssl("pkeyutl", "-verify", "-rawin", "-pubin",
                        "-inkey", str(edge / "fleet-root" / f"{EPOCH}.pub"),
                        "-in", str(message), "-sigfile", str(sig))
            except KeyError_:
                problems.append("bundle signature does not verify against fleet-root")
    if set(payload) != {"_type", "bundle_seq", "issued_at", "tenant_scope", "anchors"}:
        problems.append(f"bundle payload fields {sorted(payload)} differ from suderra.trust-anchors.v1")
    if payload.get("_type") != "suderra.trust-anchors.v1":
        problems.append("bundle payload _type is not suderra.trust-anchors.v1")
    if not isinstance(payload.get("bundle_seq"), int) or payload["bundle_seq"] < 1:
        problems.append("bundle_seq must be a positive integer")
    if not re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", str(payload.get("issued_at"))):
        problems.append("issued_at must be a second-precision UTC timestamp")
    scope = payload.get("tenant_scope")
    if not isinstance(scope, list) or not scope or not all(isinstance(t, str) and UUID_RE.match(t) for t in scope):
        problems.append("tenant_scope must be a non-empty list of lowercase UUIDs")
    if len(raws) == len(PURPOSES) and crt.is_file():
        if payload.get("anchors") != anchors(edge):
            problems.append("bundle anchors differ from the per-purpose keys of this trust-root set")
    for anchor in payload.get("anchors", []):
        if anchor.get("purpose") in ("fleet-root", "device-lifecycle"):
            problems.append(f"bundle anchors {anchor['purpose']}, which only the OS image pins (DEC-3.7)")
        for cert in anchor.get("certificates", []):
            if not CERT_RE.match(cert):
                problems.append("mqtt-ca certificate is not a single PEM certificate")
    proc = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts/ci/check-no-contract-test-keys.py"), "--tree", str(edge)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        problems.append("contract TEST-ONLY key material in the edge keys:\n" + proc.stdout + proc.stderr)
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--keys-dir", type=Path, required=True)
    g.add_argument("--profile", required=True)
    g.add_argument("--tenant-id", action="append", default=[])
    g.add_argument("--days", type=int, default=365)
    v = sub.add_parser("verify")
    v.add_argument("--keys-dir", type=Path, required=True)
    v.add_argument("--public-only", action="store_true")
    args = ap.parse_args()
    try:
        if args.mode == "generate":
            generate(args.keys_dir, args.profile, args.tenant_id, args.days)
            problems = verify(args.keys_dir, public_only=False)
        else:
            problems = verify(args.keys_dir, args.public_only)
    except KeyError_ as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for p in problems:
        print(f"ERROR: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

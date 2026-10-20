#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Local fake cloud of the QEMU edge e2e tests (ADR-048 P0 exit criterion).

It stands in for the platform's provisioning API, release hosting, MQTT
broker and statement signer, so the dev QEMU image can run the whole
Suderra OS provisioning chain offline:

* HTTPS on 127.0.0.1:443 (the guest reaches it as https://10.0.2.2, the QEMU
  image's /etc/suderra/cloud-endpoint, through the standard HTTPS port the
  device firewall lets out; binding 443 needs root or
  net.ipv4.ip_unprivileged_port_start <= 443), with a leaf certificate issued by the
  keys directory's edge/cloud-ca (the image's /etc/suderra/cloud-ca.pem):
    GET  /install/{device_code}/suderra-os   the provisioning delivery
         (contracts delivery.json `network`: the token only in the
         X-Provisioning-Token header, every refusal 404 {"error":"unavailable"})
    GET  /releases/{delivery}/{version}/{artifact}   the release artifact
    POST /api/devices/activate                the agent's activation request
    GET  /e2e/sandbox/{delivery.json,artifact.tar.gz}   the offline delivery
         of edge-readonly-sandbox-test.py
* an MQTT broker (mosquitto) with a TLS listener on 127.0.0.1:8883 (the
  guest's 10.0.2.2:8883, the broker the signed site config names), its leaf
  issued by edge/mqtt-ca (the trust-anchors bundle's mqtt-ca anchor), device
  credentials from activation, and a unix-socket listener for the cloud side;
* a signer with the dev/CI edge keys of scripts/gen-dev-keys.sh or
  scripts/ci/prepare-ci-keyring.sh (never the contract's TEST-ONLY keys,
  which this module refuses): the release statement (`release` command),
  the provisioning manifest, site config, RBAC manifest, the activation
  receipt, and the platform actor's CommandEnvelope v3 for the root
  hand-off commands. The trust-anchors bundle is the keys directory's own
  dev bundle, signed by its dev fleet-root.

Command line:
    fake_cloud.py release --agent-repo DIR --binary FILE --keys-dir DIR --out-dir DIR
    fake_cloud.py serve --keys-dir DIR --release-dir DIR --work-dir DIR
    fake_cloud.py features --agent-repo DIR
    fake_cloud.py selftest --agent-repo DIR

The e2e tests import this module and drive one FakeCloud object directly.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
import pwd
import secrets
import signal
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts" / "suderra-edge" / "v1"
BOARD = "qemu-x86_64"
GUEST_HOST = "10.0.2.2"
BIND_HOST = "127.0.0.1"
HTTPS_PORT = 443
MQTT_PORT = 8883
EPOCH = 1
DELIVERY_CONTENT_TYPE = "application/vnd.suderra.edge-provisioning-delivery.v1+json"
REFUSAL_BODY = b'{"error":"unavailable"}'
TOKEN_HEADER = "X-Provisioning-Token"
# apps/sensor-service/src/edge-device/rbac-manifest.service.ts PLATFORM_ROLE_PERMISSIONS.
PLATFORM_PERMISSIONS = ["FailoverControl", "ReadAuditLog", "ReadTag", "WatchSubscribe"]
PARAMS_TAG = b"command-envelope-v1"
SIG_TAG = b"command-envelope-sig-v3"


class CloudError(Exception):
    pass


# --------------------------------------------------------------------------
# encoding helpers (contracts statements.json dsse)
# --------------------------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def payload_type_of(statement_type: str) -> str:
    kind, version = statement_type.removeprefix("suderra.").rsplit(".", 1)
    return f"application/vnd.suderra.{kind}.{version}+json"


def timestamp(at: dt.datetime) -> str:
    return at.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def statement_digest(envelope: dict) -> str:
    """SHA-256 over the base64-decoded DSSE payload (statements.json)."""
    return sha256_hex(base64.b64decode(envelope["payload"], validate=True))


# --------------------------------------------------------------------------
# dev/CI keys
# --------------------------------------------------------------------------


def _test_only_keyids(contract: Path) -> set[str]:
    keyring = contract / "test-keys" / "keyring.json"
    if not keyring.is_file():
        return set()
    return {k["keyid"] for k in json.loads(keyring.read_text())["keys"]}


class DevKeys:
    """The per-purpose Ed25519 keys and test CAs under <keys-dir>/edge/."""

    def __init__(self, keys_dir: Path, contract: Path = CONTRACT) -> None:
        self.edge = Path(keys_dir) / "edge"
        if not self.edge.is_dir():
            raise CloudError(f"{self.edge} is missing: run scripts/gen-dev-keys.sh first")
        self._keys: dict[str, Ed25519PrivateKey] = {}
        forbidden = _test_only_keyids(contract)
        for purpose in ("edge-release", "edge-provisioning", "fleet-root", "config-integrity",
                        "rbac-manifest", "command", "device-lifecycle"):
            key = serialization.load_pem_private_key(
                (self.edge / purpose / f"{EPOCH}.key").read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise CloudError(f"{purpose}/{EPOCH}.key is not an Ed25519 key")
            if self._keyid(key) in forbidden:
                raise CloudError(f"{purpose}/{EPOCH}.key is a contract TEST-ONLY key (DEC-3.9)")
            self._keys[purpose] = key
        self.bundle = json.loads((self.edge / "trust-anchors.dsse.json").read_text())
        self.bundle_payload = json.loads(base64.b64decode(self.bundle["payload"]))
        if self.bundle["signatures"][0]["keyid"] != self.keyid("fleet-root"):
            raise CloudError("the dev trust-anchor bundle is not signed by this fleet-root")

    @staticmethod
    def _keyid(key: Ed25519PrivateKey) -> str:
        return sha256_hex(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def raw_public(self, purpose: str) -> bytes:
        return self._keys[purpose].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def keyid(self, purpose: str) -> str:
        return self._keyid(self._keys[purpose])

    def sign(self, purpose: str, message: bytes) -> bytes:
        return self._keys[purpose].sign(message)

    def envelope(self, purpose: str, statement_type: str, body: dict,
                 signed: bool = True) -> dict:
        payload = canonical(body)
        ptype = payload_type_of(statement_type)
        signatures = []
        if signed:
            signatures = [{"keyid": self.keyid(purpose), "sig": b64(self.sign(purpose, pae(ptype, payload)))}]
        return {"payloadType": ptype, "payload": b64(payload), "signatures": signatures}

    def ca(self, name: str) -> tuple[x509.Certificate, Any]:
        cert = x509.load_pem_x509_certificate((self.edge / name / "ca.crt").read_bytes())
        key = serialization.load_pem_private_key((self.edge / name / "ca.key").read_bytes(), password=None)
        return cert, key

    @property
    def tenant(self) -> str:
        return self.bundle_payload["tenant_scope"][0]


def issue_server_cert(keys: DevKeys, ca_name: str, out_dir: Path, stem: str) -> tuple[Path, Path]:
    """A leaf for 10.0.2.2 / 127.0.0.1 / localhost under a dev test CA (30 days,
    well inside CaAnchored's 398-day leaf ceiling)."""
    ca_cert, ca_key = keys.ca(ca_name)
    key = ec.generate_private_key(ec.SECP256R1())
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Suderra QEMU e2e {stem}")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=True, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address(GUEST_HOST)),
            x509.IPAddress(ipaddress.ip_address(BIND_HOST)),
            x509.DNSName("localhost"),
        ]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                       critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    crt_path, key_path = out_dir / f"{stem}.crt", out_dir / f"{stem}.key"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    return crt_path, key_path


# --------------------------------------------------------------------------
# release packaging and the signed release statement
# --------------------------------------------------------------------------


def load_edge_release(agent_repo: Path):
    path = Path(agent_repo) / "scripts" / "edge" / "edge_release.py"
    spec = importlib.util.spec_from_file_location("edge_release", path)
    if spec is None or spec.loader is None:
        raise CloudError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["edge_release"] = module
    spec.loader.exec_module(module)
    return module


def build_release(agent_repo: Path, binary: Path, keys: DevKeys, out_dir: Path,
                  source_date_epoch: int) -> Path:
    """Packages the agent binary with the release tool (artifact-naming.json,
    ELF and glibc checks), states a local provenance, and signs the
    statement the release tool derives with the dev edge-release key."""
    er = load_edge_release(agent_repo)
    out_dir.mkdir(parents=True, exist_ok=True)
    tool = Path(agent_repo) / "scripts" / "edge" / "edge_release.py"
    subprocess.run(
        [sys.executable, str(tool), "package", "--channel", er.CHANNEL_OS, "--id", BOARD,
         "--binary", str(binary), "--out-dir", str(out_dir),
         "--source-date-epoch", str(source_date_epoch)],
        check=True, stdout=subprocess.DEVNULL,
    )
    release = er.Release(er.DEFAULT_FACTS, er.DEFAULT_CARGO_TOML, er.CONTRACT)
    row = release.row(er.CHANNEL_OS, BOARD)
    artifact = out_dir / row.artifact
    facts = er.artifact_facts(release, row, artifact)
    commit = subprocess.run(["git", "-C", str(agent_repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": row.artifact, "digest": facts["digest"]}],
        "predicateType": release.release_schema["properties"]["provenance"]["properties"][
            "predicate_type"]["const"],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/Okan-wqm/suderra-os/tests/qemu/fake_cloud.py@v1",
                "externalParameters": {"channel": row.channel, "target": row.id,
                                       "rustTarget": row.rust_target,
                                       "features": ",".join(row.features)},
                "resolvedDependencies": [{"uri": "git+https://github.com/Okan-wqm/aquaculture_platform",
                                          "digest": {"gitCommit": commit}}],
            },
            "runDetails": {"builder": {"id": "local QEMU edge e2e build (dev keys, not a release)"}},
        },
    }
    prov_bytes = (json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (out_dir / f"{row.base}.intoto.jsonl").write_bytes(prov_bytes)
    payload = er._expected_body(release, row, facts, sha256_hex(prov_bytes))
    ptype = release.payload_type
    envelope = {
        "payloadType": ptype,
        "payload": b64(payload),
        "signatures": [{"keyid": keys.keyid("edge-release"),
                        "sig": b64(keys.sign("edge-release", pae(ptype, payload)))}],
    }
    statement = out_dir / row.statement
    statement.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    return statement


@dataclass
class Release:
    artifact_name: str
    artifact: bytes
    envelope: dict
    body: dict

    @classmethod
    def load(cls, release_dir: Path) -> Release:
        statements = sorted(Path(release_dir).glob(f"suderra-agent-os-*-{BOARD}-x86_64.tar.gz.release.dsse.json"))
        if len(statements) != 1:
            raise CloudError(f"{release_dir} must hold exactly one {BOARD} release statement")
        envelope = json.loads(statements[0].read_text())
        body = json.loads(base64.b64decode(envelope["payload"]))
        name = body["artifact"]["name"]
        artifact = (Path(release_dir) / name).read_bytes()
        if sha256_hex(artifact) != body["artifact"]["digest"]["sha256"]:
            raise CloudError(f"{name} does not match its release statement")
        return cls(name, artifact, envelope, body)


# --------------------------------------------------------------------------
# CommandEnvelope v3 (sens-api-gateway src/command_envelope, the cloud's
# command-envelope-signer.service.ts; layout pinned by
# sens-api-gateway/tests/fixtures/command-envelope-v3/platform-command.json)
# --------------------------------------------------------------------------


def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def canonical_params(cmd: str, params: dict) -> bytes:
    body = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return _u32(len(cmd.encode())) + cmd.encode() + body + PARAMS_TAG


def envelope_transcript(cmd: str, params_bytes: bytes, actor: str, tenant: str, iat: int,
                        exp: int, policy_version: int, jti: str, nonce: str,
                        cmd_hash: bytes) -> bytes:
    return b"".join([
        _u32(len(cmd.encode())), cmd.encode(),
        _u32(len(params_bytes)), params_bytes,
        uuid.UUID(actor).bytes, uuid.UUID(tenant).bytes,
        struct.pack(">q", iat), struct.pack(">q", exp), struct.pack(">Q", policy_version),
        b"\x00",
        _u32(len(jti.encode())), jti.encode(),
        _u32(len(nonce.encode())), nonce.encode(),
        cmd_hash, SIG_TAG,
    ])


def sign_command(sign: Callable[[bytes], bytes], cmd: str, params: dict, actor: str, tenant: str,
                 policy_version: int, jti: str, iat: int | None = None, validity: int = 300,
                 nonce: str | None = None) -> dict:
    iat = int(time.time()) if iat is None else iat
    exp = iat + validity
    nonce = nonce or uuid.uuid4().hex
    params_bytes = canonical_params(cmd, params)
    cmd_hash = hashlib.sha256(params_bytes).digest()
    signature = sign(envelope_transcript(cmd, params_bytes, actor, tenant, iat, exp,
                                         policy_version, jti, nonce, cmd_hash))
    return {
        "cmd": cmd, "params": params,
        "actor": list(uuid.UUID(actor).bytes), "tenant_id": list(uuid.UUID(tenant).bytes),
        "iat_unix_secs": iat, "exp_unix_secs": exp, "claimed_policy_version": policy_version,
        "jti": jti, "nonce": nonce, "cmd_hash": list(cmd_hash), "signature": list(signature),
        "co_approver_actor": None, "co_approver_signature": None,
    }


def selftest(agent_repo: Path) -> None:
    """The envelope layout reproduces the cross-language vector byte for byte."""
    vector = json.loads((Path(agent_repo) / "sens-api-gateway/tests/fixtures/command-envelope-v3/"
                         "platform-command.json").read_text())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["seed_hex"]))
    i = vector["inputs"]
    wire = sign_command(key.sign, i["cmd"], i["params"], i["actor"], i["tenant"],
                        i["claimed_policy_version"], i["jti"], iat=i["iat_unix_secs"],
                        validity=i["exp_unix_secs"] - i["iat_unix_secs"], nonce=i["nonce"])
    if canonical_params(i["cmd"], i["params"]).hex() != vector["canonical_params_hex"]:
        raise CloudError("canonical params differ from the cross-language vector")
    if bytes(wire["signature"]).hex() != vector["signature_hex"]:
        raise CloudError("the envelope signature differs from the cross-language vector")


# --------------------------------------------------------------------------
# the fake cloud
# --------------------------------------------------------------------------


@dataclass
class Device:
    device_code: str
    device_id: str
    tenant_id: str
    token: str
    binding: dict | None = None
    seq: int = 0
    installed_manifest_digest: str | None = None
    installed_manifest: dict | None = None
    mqtt_username: str | None = None
    mqtt_password: str | None = None
    token_spent: bool = False
    activation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Event:
    at: float
    kind: str
    data: dict


class FakeCloud:
    """One provisioning API, release host, MQTT broker and signer."""

    def __init__(self, keys_dir: Path, release_dir: Path, work_dir: Path,
                 https_port: int = HTTPS_PORT, mqtt_port: int = MQTT_PORT,
                 device_code: str = "QEMU-E2E-0001") -> None:
        self.keys = DevKeys(keys_dir)
        self.release = Release.load(release_dir)
        self.work = Path(work_dir)
        self.work.mkdir(parents=True, exist_ok=True)
        self.https_port = https_port
        self.mqtt_port = mqtt_port
        # The URL the guest reaches the API at; 10.0.2.2 is the host's
        # loopback under QEMU user networking.
        self.endpoint = f"https://{GUEST_HOST}" + ("" if https_port == 443 else f":{https_port}")
        self.device = Device(device_code=device_code, device_id=str(uuid.uuid4()),
                             tenant_id=self.keys.tenant, token=secrets.token_hex(32))
        self.platform_actor = str(uuid.uuid4())
        self.policy_version = 1
        self.next_delivery = "valid"
        self.deliveries: dict[str, dict] = {}
        self.sandbox: dict[str, bytes] = {}
        self.events: list[Event] = []
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self._httpd: ThreadingHTTPServer | None = None
        self._mosquitto: subprocess.Popen | None = None
        self._sub: subprocess.Popen | None = None
        self._cloud_password = secrets.token_hex(16)
        self.rbac_envelope = self._rbac_manifest()

    # ------------------------------------------------------------- events
    def record(self, kind: str, **data: Any) -> None:
        with self.cond:
            self.events.append(Event(time.time(), kind, data))
            self.cond.notify_all()

    def wait_for(self, predicate: Callable[[Event], bool], timeout: float,
                 since: int = 0) -> Event:
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for event in self.events[since:]:
                    if predicate(event):
                        return event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"no matching fake-cloud event within {timeout:.0f}s")
                self.cond.wait(min(remaining, 5))

    def mark(self) -> int:
        with self.lock:
            return len(self.events)

    # ------------------------------------------------------------ statements
    def _rbac_manifest(self) -> dict:
        now = utcnow()
        body = {
            "_type": "suderra.rbac-manifest.v1",
            "tenant_id": self.device.tenant_id,
            "policy_version": self.policy_version,
            "not_before": timestamp(now - dt.timedelta(hours=1)),
            "expires_at": timestamp(now + dt.timedelta(days=30)),
            "actors": [{
                "actor_id": self.platform_actor,
                "kind": "platform",
                "keyid": self.keys.keyid("command"),
                "public_key": b64(self.keys.raw_public("command")),
                "roles": ["platform-authenticated"],
            }],
            "roles": [{
                "name": "platform-authenticated",
                "permissions": sorted(PLATFORM_PERMISSIONS),
                "not_before": timestamp(now - dt.timedelta(hours=1)),
                "expires_at": timestamp(now + dt.timedelta(days=30)),
            }],
        }
        return self.keys.envelope("rbac-manifest", "suderra.rbac-manifest.v1", body)

    def agent_config(self) -> bytes:
        """renderSuderraOsAgentConfig (site-config-manifest.service.ts)."""
        d = self.device
        q = json.dumps
        lines = [
            "# Suderra edge agent configuration, delivered in a signed site config (ADR-048 DEC-4.12).",
            f"device_id: {q(d.device_id)}",
            f"device_code: {q(d.device_code)}",
            f"tenant_id: {q(d.tenant_id)}",
            f"api_url: {q(self.endpoint)}",
            f"provisioning_token: {q(d.token)}",
            "mqtt:",
            f"  broker: {q(GUEST_HOST)}",
            f"  port: {self.mqtt_port}",
            "  tls:",
            "    enabled: true",
            "    verify_hostname: true",
            "",
        ]
        return "\n".join(lines).encode()

    def build_delivery(self, nonce: str, binding: dict, scenario: str) -> tuple[str, dict]:
        """A delivery for one request: valid, or one single defect."""
        d = self.device
        with self.lock:
            d.seq += 1
            seq = d.seq
        now = utcnow()
        window = (now - dt.timedelta(minutes=5), now + dt.timedelta(hours=2))
        if scenario == "expired":
            window = (now - dt.timedelta(hours=4), now - dt.timedelta(hours=2))
        if scenario == "wrong-binding":
            binding = {"method": binding["method"],
                       "digest": {"sha256": sha256_hex(b"another device's binding " + nonce.encode())}}
        site_files = {"config.yaml": self.agent_config()}
        rbac_payload = base64.b64decode(self.rbac_envelope["payload"])
        site_body = {
            "_type": "suderra.site-config.v1",
            "tenant_id": d.tenant_id,
            "device_id": d.device_id,
            "device_binding": binding,
            "update_seq": seq,
            "not_before": timestamp(window[0]),
            "expires_at": timestamp(window[1]),
            "files": {p: {"digest": {"sha256": sha256_hex(b)}, "size_bytes": len(b)}
                      for p, b in sorted(site_files.items())},
            "rbac_manifest": {"digest": {"sha256": sha256_hex(rbac_payload)},
                              "policy_version": self.policy_version},
        }
        site = self.keys.envelope("config-integrity", "suderra.site-config.v1", site_body)
        delivery_id = uuid.uuid4().hex
        rel = self.release.body
        manifest_body = {
            "_type": "suderra.edge-provisioning.v1",
            "tenant_id": d.tenant_id,
            "device_id": d.device_id,
            "device_code": d.device_code,
            "device_binding": binding,
            "nonce": nonce,
            "board": rel["board_profile"],
            "arch": rel["arch"],
            "agent_profile": rel["agent_profile"],
            "version": rel["version"],
            "security_version": rel["security_version"],
            "key_epoch": EPOCH,
            "update_seq": seq,
            "not_before": timestamp(window[0]),
            "expires_at": timestamp(window[1]),
            "release_statement": {"digest": {"sha256": statement_digest(self.release.envelope)}},
            "artifact_url": f"{self.endpoint}/releases/{delivery_id}/{rel['version']}/{self.release.artifact_name}",
            "site_config": {"digest": {"sha256": statement_digest(site)}, "update_seq": seq},
            "trust_anchors": {"digest": {"sha256": statement_digest(self.keys.bundle)},
                              "bundle_seq": self.keys.bundle_payload["bundle_seq"]},
        }
        manifest = self.keys.envelope("edge-provisioning", "suderra.edge-provisioning.v1", manifest_body)
        delivery = {
            "_type": "suderra.edge-provisioning-delivery.v1",
            "manifest": manifest,
            "release_statement": self.release.envelope,
            "trust_anchors": self.keys.bundle,
            "site_config": site,
            "rbac_manifest": self.rbac_envelope,
            "site_files": {p: b64(b) for p, b in sorted(site_files.items())},
        }
        with self.lock:
            self.deliveries[delivery_id] = {
                "scenario": scenario, "manifest": manifest,
                "manifest_digest": statement_digest(manifest),
                "site_config_digest": statement_digest(site),
                "rbac_manifest_digest": statement_digest(self.rbac_envelope),
                "trust_anchors_digest": statement_digest(self.keys.bundle),
                "release_statement_digest": statement_digest(self.release.envelope),
            }
        return delivery_id, delivery

    def artifact_bytes(self, delivery_id: str) -> bytes | None:
        with self.lock:
            info = self.deliveries.get(delivery_id)
        if info is None:
            return None
        data = self.release.artifact
        if info["scenario"] == "tampered-artifact":
            # Same size, one byte different: only the digest check can see it.
            data = data[:-1] + bytes([data[-1] ^ 0x01])
        return data

    def receipt(self, signed: bool = True) -> dict:
        d = self.device
        if d.installed_manifest_digest is None or d.binding is None:
            raise CloudError("no manifest was delivered to activate")
        now = utcnow()
        body = {
            "_type": "suderra.edge-activation-receipt.v1",
            "tenant_id": d.tenant_id,
            "device_id": d.device_id,
            "device_binding": d.binding,
            "manifest_digest": {"sha256": d.installed_manifest_digest},
            "activation_id": d.activation_id,
            "activated_at": timestamp(now),
            "not_before": timestamp(now - dt.timedelta(minutes=5)),
            "expires_at": timestamp(now + dt.timedelta(hours=24)),
        }
        return self.keys.envelope("edge-provisioning", "suderra.edge-activation-receipt.v1", body,
                                  signed=signed)

    def prepare_sandbox_delivery(self, nonce: str, binding: dict) -> str:
        """The offline delivery of edge-readonly-sandbox-test.py for the nonce
        root issued with `edge request`, served under /e2e/sandbox/."""
        delivery_id, delivery = self.build_delivery(nonce, binding, "valid")
        with self.lock:
            self.device.binding = binding
            self.device.installed_manifest_digest = self.deliveries[delivery_id]["manifest_digest"]
            self.sandbox = {
                "delivery.json": json.dumps(delivery, indent=2).encode(),
                "artifact.tar.gz": self.release.artifact,
            }
        return delivery_id

    # ------------------------------------------------------------- commands
    def topic(self, kind: str) -> str:
        return f"tenants/{self.device.tenant_id}/devices/{self.device.device_id}/{kind}"

    def publish_command(self, cmd: str, params: dict) -> str:
        jti = str(uuid.uuid4())
        wire = sign_command(lambda m: self.keys.sign("command", m), cmd, params,
                            self.platform_actor, self.device.tenant_id, self.policy_version, jti)
        self._mqtt_pub(self.topic("commands"), json.dumps(wire, separators=(",", ":")).encode())
        self.record("command-sent", command=cmd, jti=jti)
        return jti

    def send_receipt(self, signed: bool = True) -> tuple[str, str]:
        """Publishes an activation_receipt command; returns its jti and the
        receipt's statement digest."""
        envelope = self.receipt(signed=signed)
        jti = self.publish_command("activation_receipt",
                                   {"statement": json.dumps(envelope, separators=(",", ":"))})
        return jti, statement_digest(envelope)

    def wait_response(self, jti: str, timeout: float) -> dict:
        event = self.wait_for(lambda e: e.kind == "mqtt" and e.data.get("topic") == self.topic("responses")
                              and isinstance(e.data.get("json"), dict)
                              and e.data["json"].get("commandId") == jti, timeout)
        return event.data["json"]

    # ---------------------------------------------------------------- MQTT
    def _passwd(self, user: str, password: str, create: bool = False) -> None:
        args = ["mosquitto_passwd", "-b"]
        if create:
            args.append("-c")
        subprocess.run([*args, str(self.work / "mqtt.passwd"), user, password],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _start_mqtt(self) -> None:
        crt, key = issue_server_cert(self.keys, "mqtt-ca", self.work / "tls", "mqtt")
        self._passwd("cloud", self._cloud_password, create=True)
        sock = self.work / "mqtt.sock"
        conf = self.work / "mosquitto.conf"
        conf.write_text("\n".join([
            "per_listener_settings true",
            # Started as root, mosquitto would drop to a "mosquitto" user that
            # cannot read this work directory; it stays the invoking user.
            f"user {pwd.getpwuid(os.getuid()).pw_name}",
            "persistence false",
            "log_dest stdout",
            "log_type error",
            "log_type warning",
            "log_type notice",
            "log_type information",
            "connection_messages true",
            f"listener {self.mqtt_port} {BIND_HOST}",
            f"certfile {crt}",
            f"keyfile {key}",
            "tls_version tlsv1.3",
            "allow_anonymous false",
            f"password_file {self.work / 'mqtt.passwd'}",
            f"listener 0 {sock}",
            "allow_anonymous false",
            f"password_file {self.work / 'mqtt.passwd'}",
            "",
        ]))
        log = (self.work / "mosquitto.log").open("ab")
        self._mosquitto = subprocess.Popen(["mosquitto", "-c", str(conf)], stdout=log,
                                           stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 20
        while not sock.exists():
            if self._mosquitto.poll() is not None or time.monotonic() > deadline:
                raise CloudError(f"mosquitto did not start; see {self.work / 'mosquitto.log'}")
            time.sleep(0.2)
        self._sub = subprocess.Popen(
            ["mosquitto_sub", "--unix", str(sock), "-u", "cloud", "-P", self._cloud_password,
             "-q", "1", "-F", "%t %x", "-t", "tenants/#", "-t", "suderra/#"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._read_mqtt, daemon=True).start()

    def _read_mqtt(self) -> None:
        assert self._sub is not None and self._sub.stdout is not None
        for line in self._sub.stdout:
            topic, _, hexpayload = line.rstrip("\n").partition(" ")
            try:
                payload = bytes.fromhex(hexpayload)
            except ValueError:
                payload = b""
            try:
                parsed: Any = json.loads(payload)
            except ValueError:
                parsed = None
            self.record("mqtt", topic=topic, size=len(payload), json=parsed)

    def _mqtt_pub(self, topic: str, payload: bytes) -> None:
        subprocess.run(
            ["mosquitto_pub", "--unix", str(self.work / "mqtt.sock"), "-u", "cloud",
             "-P", self._cloud_password, "-q", "1", "-t", topic, "-s"],
            input=payload, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def _grant_device(self, username: str, password: str) -> None:
        self._passwd(username, password)
        if self._mosquitto is not None:
            self._mosquitto.send_signal(signal.SIGHUP)

    # --------------------------------------------------------------- HTTPS
    def _start_https(self) -> None:
        crt, key = issue_server_cert(self.keys, "cloud-ca", self.work / "tls", "https")
        cloud = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:  # quiet; events record requests
                return

            def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                url = urlsplit(self.path)
                parts = [p for p in url.path.split("/") if p]
                if len(parts) == 3 and parts[0] == "install" and parts[2] == "suderra-os":
                    cloud._install(self, parts[1], dict(parse_qsl(url.query)), url.query)
                    return
                if len(parts) == 4 and parts[0] == "releases":
                    data = cloud.artifact_bytes(parts[1])
                    cloud.record("artifact", delivery=parts[1], served=data is not None)
                    if data is None or parts[3] != cloud.release.artifact_name:
                        self._send(404, REFUSAL_BODY)
                        return
                    self._send(200, data, "application/gzip")
                    return
                if len(parts) == 3 and parts[:2] == ["e2e", "sandbox"] and parts[2] in cloud.sandbox:
                    cloud.record("sandbox-fetch", file=parts[2])
                    self._send(200, cloud.sandbox[parts[2]], "application/octet-stream")
                    return
                self._send(404, REFUSAL_BODY)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, 1 << 20))
                if urlsplit(self.path).path == "/api/devices/activate":
                    cloud._activate(self, body)
                    return
                self._send(404, REFUSAL_BODY)

        httpd = ThreadingHTTPServer((BIND_HOST, self.https_port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(crt), str(key))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self._httpd = httpd
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def _install(self, handler: Any, device_code: str, query: dict, raw_query: str) -> None:
        d = self.device
        token = handler.headers.get(TOKEN_HEADER)
        token_in_query = d.token in raw_query
        reason = None
        if token_in_query:
            reason = "token-in-query"
        elif device_code != d.device_code:
            reason = "unknown-device-code"
        elif token != d.token or d.token_spent:
            reason = "token-invalid"
        required = {"binding_method", "binding_sha256", "nonce", "board_profile", "os_version", "agent_abi"}
        if reason is None and set(query) != required:
            reason = "request-invalid"
        binding = None
        if reason is None:
            binding = {"method": query["binding_method"], "digest": {"sha256": query["binding_sha256"]}}
            if d.binding is not None and d.binding != binding:
                reason = "binding-reserved-elsewhere"
            elif query["board_profile"] != BOARD:
                reason = "board-mismatch"
        if reason is not None:
            self.record("install-refused", reason=reason, query=query)
            handler._send(404, REFUSAL_BODY)
            return
        assert binding is not None
        with self.lock:
            scenario = self.next_delivery
            self.next_delivery = "valid"
            if scenario == "valid":
                d.binding = binding
        delivery_id, delivery = self.build_delivery(query["nonce"], binding, scenario)
        if scenario == "valid":
            with self.lock:
                d.installed_manifest = self.deliveries[delivery_id]["manifest"]
                d.installed_manifest_digest = self.deliveries[delivery_id]["manifest_digest"]
        self.record("delivery", scenario=scenario, delivery=delivery_id, query=query,
                    manifest_digest=self.deliveries[delivery_id]["manifest_digest"])
        handler._send(200, json.dumps(delivery).encode(), DELIVERY_CONTENT_TYPE)

    def _activate(self, handler: Any, body: bytes) -> None:
        d = self.device
        try:
            request = json.loads(body)
        except ValueError:
            request = {}
        ok = (isinstance(request, dict) and request.get("deviceId") == d.device_id
              and request.get("token") == d.token and d.installed_manifest_digest is not None)
        if not ok or d.token_spent:
            code, err = ("TOKEN_ALREADY_USED", 409) if d.token_spent else ("INVALID_TOKEN", 401)
            self.record("activation-refused", code=code)
            handler._send(err, json.dumps({"success": False, "error": "activation refused",
                                           "errorCode": code}).encode())
            return
        username = f"suderra-{d.device_code}"
        password = secrets.token_urlsafe(24)
        self._grant_device(username, password)
        with self.lock:
            d.mqtt_username, d.mqtt_password, d.token_spent = username, password, True
        self.record("activated", agent_version=request.get("agentVersion"))
        handler._send(200, json.dumps({
            "success": True,
            "mqtt_broker": GUEST_HOST,
            "mqtt_port": self.mqtt_port,
            "mqtt_username": username,
            "mqtt_password": password,
            "tenant_id": d.tenant_id,
            "device_code": d.device_code,
            "mqtt_tls_enabled": True,
            "config": None,
        }).encode())

    # ------------------------------------------------------------ lifecycle
    def start(self) -> FakeCloud:
        self._start_mqtt()
        self._start_https()
        self.record("started", endpoint=self.endpoint)
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        for proc in (self._sub, self._mosquitto):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def __enter__(self) -> FakeCloud:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("release", help="package and sign the qemu-x86_64 agent release")
    r.add_argument("--agent-repo", type=Path, required=True)
    r.add_argument("--binary", type=Path, required=True)
    r.add_argument("--keys-dir", type=Path, required=True)
    r.add_argument("--out-dir", type=Path, required=True)
    r.add_argument("--source-date-epoch", type=int)
    s = sub.add_parser("serve", help="run the fake cloud until interrupted")
    s.add_argument("--keys-dir", type=Path, required=True)
    s.add_argument("--release-dir", type=Path, required=True)
    s.add_argument("--work-dir", type=Path, required=True)
    f = sub.add_parser("features", help="the cargo features of the qemu-x86_64 release build")
    f.add_argument("--agent-repo", type=Path, required=True)
    t = sub.add_parser("selftest", help="check the envelope layout against the agent's vector")
    t.add_argument("--agent-repo", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        if args.command == "release":
            epoch = args.source_date_epoch
            if epoch is None:
                epoch = int(subprocess.run(["git", "-C", str(args.agent_repo), "log", "-1", "--format=%ct"],
                                           capture_output=True, text=True, check=True).stdout)
            print(build_release(args.agent_repo, args.binary, DevKeys(args.keys_dir), args.out_dir, epoch))
        elif args.command == "features":
            er = load_edge_release(args.agent_repo)
            release = er.Release(er.DEFAULT_FACTS, er.DEFAULT_CARGO_TOML, er.CONTRACT)
            print(",".join(release.row(er.CHANNEL_OS, BOARD).features))
        elif args.command == "serve":
            with FakeCloud(args.keys_dir, args.release_dir, args.work_dir) as cloud:
                d = cloud.device
                print(f"endpoint={cloud.endpoint} device_code={d.device_code} token={d.token}", flush=True)
                stop = threading.Event()
                signal.signal(signal.SIGTERM, lambda *_: stop.set())
                try:
                    stop.wait()
                except KeyboardInterrupt:
                    pass
        else:
            selftest(args.agent_repo)
            print("command envelope layout matches the cross-language vector")
    except (CloudError, subprocess.CalledProcessError) as e:
        print(f"fake_cloud: error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

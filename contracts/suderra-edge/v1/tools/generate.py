#!/usr/bin/env python3
"""Regenerate the TEST-ONLY keys and golden fixtures of the Suderra edge contract.

Contract: contracts/suderra-edge/v1 (ADR-048 DEC-25). Requires Python >= 3.10 and
the `cryptography` package.

    python3 -B contracts/suderra-edge/v1/tools/generate.py          # rewrite + SHA256SUMS
    python3 -B contracts/suderra-edge/v1/tools/generate.py --check  # exit 1 on any drift

CI runs the --check form on every pull request (npm run test:suderra-edge-fixtures).

What it writes: test-keys/, fixtures/ and SHA256SUMS. Everything else in the
contract (VERSION, statements.json, boards.json, artifact-naming.json,
delivery.json, lifecycle.json, unit-directives.json, mutable-state.json,
schemas/) is authored by hand and only read here; the release fixtures take
their features from boards.json and their artifact names from
artifact-naming.json, the unit fixtures their drop-ins from
unit-directives.json, so a change there shows up as fixture drift.

TEST-ONLY KEY DERIVATION (public on purpose)
    seed = SHA-256(UTF-8 "suderra-edge-contract:v1:TEST-ONLY:<label>:<epoch>")
    key  = the Ed25519 private key whose RFC 8032 seed is `seed`
Anyone can re-derive these private keys from this docstring. That is what
makes the fixtures reproducible, and it is why nothing may trust them: no OS
image of any variant pins them (dev and CI images use the keys of Suderra-OS
scripts/gen-dev-keys.sh and scripts/ci/prepare-ci-keyring.sh, ADR-048 DEC-3.9)
and no signer holds them. Suderra-OS suderra-keys refuses to install them and
both repositories fail CI when their key material appears outside
contracts/suderra-edge/. Only public keys are written to test-keys/, under
names that cannot be mistaken for the OS pin layout; private keys exist only in
this process. Ed25519 signing is deterministic, so the same inputs always
produce byte-identical fixtures.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

CONTRACT = Path(__file__).resolve().parents[1]
GENERATED_DIRS = ("fixtures", "test-keys")
SEED_PREFIX = "suderra-edge-contract:v1:TEST-ONLY:"
# Group order of edwards25519; S + L is the classic malleated signature.
ED25519_L = 2**252 + 27742317777372353535851937790883648493
# y = p + 1: a non-canonical encoding of the identity point (y < p is canonical).
NON_CANONICAL_IDENTITY = bytes([0xEE]) + b"\xff" * 30 + bytes([0x7F])
IDENTITY = bytes([1]) + bytes(31)

EVALUATION_TIME = "2026-10-20T12:00:00Z"
VALID = ("2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z")
EXPIRED = ("2026-10-19T00:00:00Z", "2026-10-19T06:00:00Z")
FUTURE = ("2026-10-21T00:00:00Z", "2026-10-22T00:00:00Z")
INSTALLED_YESTERDAY = ("2026-10-18T00:00:00Z", "2026-10-19T00:00:00Z")
RBAC_WINDOW = ("2026-10-01T00:00:00Z", "2027-01-01T00:00:00Z")
# The window edges are exact: not_before == now is inside the window, expires_at == now is not.
EXPIRES_NOW = ("2026-10-20T11:00:00Z", EVALUATION_TIME)
STARTS_NOW = (EVALUATION_TIME, "2026-10-20T15:00:00Z")

TENANT = "7e570000-0000-4000-8000-000000000001"
OTHER_TENANT = "7e570000-0000-4000-8000-000000000002"
DEVICE = "7e570000-0000-4000-8000-0000000000d1"
OTHER_DEVICE = "7e570000-0000-4000-8000-0000000000d2"
ACTIVATION = "7e570000-0000-4000-8000-0000000000a1"
PLATFORM_ACTOR = "7e570000-0000-4000-8000-0000000000c1"
DEVICE_CODE = "RPI-7E57C0DE"
RELEASE_HOST = "https://edge-releases.example.com/agent"
OS_HOST = "https://edge-releases.example.com/os"
SITE_HOST = "https://edge-releases.example.com/site"
BUNDLE_SIZE = 201326592
COMMAND_ID = "7e570000-0000-4000-8000-0000000000e1"

ST_RELEASE = "suderra.edge-release.v1"
ST_PROV = "suderra.edge-provisioning.v1"
ST_RECEIPT = "suderra.edge-activation-receipt.v1"
ST_TA = "suderra.trust-anchors.v1"
ST_LIFE = "suderra.device-lifecycle.v1"
ST_SITE = "suderra.site-config.v1"
ST_RBAC = "suderra.rbac-manifest.v1"
ST_EDGE_UPDATE = "suderra.edge-update.v1"
ST_OS_UPDATE = "suderra.os-update.v1"
ST_NETPOL = "suderra.site-netpolicy.v1"

OS_VERSION = "1.0.0"
OS_ROLLBACK_FLOOR = "1.0.0"
AGENT_ABI_RANGE = "1-1"
INSTALLED_AGENT_ABI = 1
KERNEL_CONFIG = [
    "CONFIG_DM_CRYPT=y",
    "CONFIG_I2C_CHARDEV=y",
    "CONFIG_NFT_CT=y",
    "CONFIG_SECCOMP_FILTER=y",
    "CONFIG_SPI_SPIDEV=m",
    "CONFIG_TCG_TPM=y",
]
BOARD_KERNEL = {
    "revpi-connect4": ["CONFIG_SECCOMP_FILTER"],
    "rpi4-cm4": ["CONFIG_I2C_CHARDEV", "CONFIG_SECCOMP_FILTER", "CONFIG_SPI_SPIDEV"],
    "qemu-x86_64": ["CONFIG_CAN", "CONFIG_SECCOMP_FILTER"],
}
PLATFORM_PERMISSIONS = ["FailoverControl", "ReadAuditLog", "ReadTag", "WatchSubscribe"]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def label_digest(text: str) -> str:
    """Digest of a TEST-ONLY label, used for every stand-in artifact digest."""
    return sha256_hex(f"TEST-ONLY {text}".encode())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def canonical(value: object) -> bytes:
    """Deterministic payload bytes. Verifiers never depend on this form."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def pae(payload_type: str, body: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)


def payload_type(statement_type: str) -> str:
    kind, version = statement_type.removeprefix("suderra.").rsplit(".", 1)
    return f"application/vnd.suderra.{kind}.{version}+json"


def digest_of(body: bytes) -> dict:
    return {"sha256": sha256_hex(body)}


@dataclass(frozen=True)
class TestKey:
    label: str
    epoch: int
    private: Ed25519PrivateKey

    @staticmethod
    def derive(label: str, epoch: int) -> TestKey:
        seed = hashlib.sha256(f"{SEED_PREFIX}{label}:{epoch}".encode()).digest()
        return TestKey(label, epoch, Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def seed_label(self) -> str:
        return f"{SEED_PREFIX}{self.label}:{self.epoch}"

    @property
    def seed(self) -> bytes:
        return hashlib.sha256(self.seed_label.encode()).digest()

    @property
    def scalar(self) -> int:
        """RFC 8032 secret scalar a, with [a]B = A."""
        h = bytearray(hashlib.sha512(self.seed).digest()[:32])
        h[0] &= 248
        h[31] &= 127
        h[31] |= 64
        return int.from_bytes(h, "little")

    @property
    def raw_public(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def keyid(self) -> str:
        return sha256_hex(self.raw_public)

    @property
    def pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


# (purpose, epoch, where the fixtures' simulated device anchors it). These are
# fixture roles only: no real image pins any of these keys (module docstring).
KEY_SPECS = [
    ("edge-release", 1, "os-image"),
    ("edge-provisioning", 1, "os-image"),
    ("edge-provisioning", 2, "os-image"),
    ("fleet-root", 1, "os-image"),
    ("device-lifecycle", 1, "os-image"),
    ("config-integrity", 1, "trust-anchors-bundle"),
    ("rbac-manifest", 1, "trust-anchors-bundle"),
    ("command", 1, "trust-anchors-bundle"),
]
KEYS = {(purpose, epoch): TestKey.derive(purpose, epoch) for purpose, epoch, _ in KEY_SPECS}
# In no key store at all: signs the key-unknown and anchor-not-os-pinned fixtures.
UNPINNED = TestKey.derive("unpinned", 1)
# Commitment key of the non-canonical-A signature vector; signs no statement.
SIGVEC_R = TestKey.derive("sigvec-r", 1)


def key(purpose: str, epoch: int = 1) -> TestKey:
    return KEYS[(purpose, epoch)]


def key_pem_file(k: TestKey) -> bytes:
    header = (
        f"TEST-ONLY public key of the Suderra edge contract fixtures: {k.label} epoch {k.epoch}.\n"
        "Anyone can derive its private key (keyring.json derivation). No image, keyid\n"
        "allowlist or signer may contain it (ADR-048 DEC-3.9, DEC-25.1).\n"
    )
    return header.encode() + k.pem


def envelope(statement_type: str, body: bytes, signer: TestKey, **overrides: object) -> dict:
    ptype = str(overrides.get("payload_type", payload_type(statement_type)))
    signature = signer.sign(pae(ptype, body))
    return {
        "payloadType": ptype,
        "payload": b64(body),
        "signatures": [{"keyid": signer.keyid, "sig": b64(signature)}],
    }


def malleate(env: dict) -> dict:
    """Same signature with S replaced by S + L: rejected by verify_strict."""
    out = copy.deepcopy(env)
    sig = base64.b64decode(out["signatures"][0]["sig"])
    s_value = int.from_bytes(sig[32:], "little") + ED25519_L
    out["signatures"][0]["sig"] = b64(sig[:32] + s_value.to_bytes(32, "little"))
    return out


def tamper(env: dict) -> dict:
    """Insert one space after the first colon of the signed payload: the JSON and
    its meaning are unchanged, the signed bytes are not."""
    out = copy.deepcopy(env)
    out["payload"] = b64(base64.b64decode(out["payload"]).replace(b":", b": ", 1))
    return out


def two_signatures(env: dict, extra: TestKey, statement_type: str) -> dict:
    out = copy.deepcopy(env)
    body = base64.b64decode(env["payload"])
    out["signatures"].append(envelope(statement_type, body, extra)["signatures"][0])
    return out


def duplicate_type_member(body: bytes) -> bytes:
    """Prepend a second _type member with a wrong value. A strict parser rejects
    the payload; a last-member-wins parser reads the real _type and accepts."""
    assert body.startswith(b'{"_type":'), body[:20]
    return b'{"_type":"suderra.edge-update.v1",' + body[1:]


def mqtt_ca_certificate() -> bytes:
    ca = TestKey.derive("mqtt-ca", 1)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Suderra edge contract fixtures"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TEST-ONLY Suderra MQTT root CA 1"),
        ]
    )
    public = ca.private.public_key()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(0x7E57)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
        .sign(ca.private, None)
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


SITE_FILES = {
    "v1/config.yaml": (
        b"# TEST-ONLY site config of the Suderra edge contract fixtures (version 1).\n"
        b"# config.yaml is the agent's configuration document; the contract binds it by digest.\n"
        b"device_id: 7e570000-0000-4000-8000-0000000000d1\ndevice_code: RPI-7E57C0DE\n"
        b"device:\n  board_profile: revpi-connect4\nmodbus: []\n"
    ),
    "v1/revpi/config.rsc": b'{"TEST-ONLY": "PiCtory configuration of the contract fixtures"}\n',
    "v2/config.yaml": (
        b"# TEST-ONLY site config of the Suderra edge contract fixtures (version 2).\n"
        b"# config.yaml is the agent's configuration document; the contract binds it by digest.\n"
        b"device_id: 7e570000-0000-4000-8000-0000000000d1\ndevice_code: RPI-7E57C0DE\n"
        b"device:\n  board_profile: revpi-connect4\nmodbus:\n  - name: pond-1-sensors\n    allow_writes: false\n"
    ),
    "tampered/config.yaml": (
        b"# TEST-ONLY site config of the Suderra edge contract fixtures (version 2).\n"
        b"# config.yaml is the agent's configuration document; the contract binds it by digest.\n"
        b"device_id: 7e570000-0000-4000-8000-0000000000d1\ndevice_code: RPI-7E57C0DE\n"
        b"device:\n  board_profile: revpi-connect4\nmodbus:\n  - name: pond-1-sensors\n    allow_writes: true\n"
    ),
    "extra/hardware-inventory.yaml": b"# TEST-ONLY hardware inventory the site config does not name.\n",
    "v3/io-config.yaml": (
        b"# TEST-ONLY I/O map of the Suderra edge contract fixtures (site config version 3).\n"
        b"# io-config.yaml is the I/O map document; the contract binds it by digest.\n"
        b"tags:\n  - name: pond-1-oxygen\n    io_type: analog_input\n    unit: mg/L\n"
    ),
}
FILES_V1 = {
    "config.yaml": "site-files/v1/config.yaml",
    "revpi/config.rsc": "site-files/v1/revpi/config.rsc",
}
FILES_V2 = {
    "config.yaml": "site-files/v2/config.yaml",
    "revpi/config.rsc": "site-files/v1/revpi/config.rsc",
}
FILES_V3 = {
    "config.yaml": "site-files/v2/config.yaml",
    "io-config.yaml": "site-files/v3/io-config.yaml",
    "revpi/config.rsc": "site-files/v1/revpi/config.rsc",
}


class Generator:
    def __init__(self) -> None:
        self.boards = {
            row["board_profile"]: row
            for row in json.loads((CONTRACT / "boards.json").read_text())["boards"]
        }
        self.naming = json.loads((CONTRACT / "artifact-naming.json").read_text())[
            "suderra_os_channel"
        ]
        self.unit_spec = json.loads((CONTRACT / "unit-directives.json").read_text())
        self.files: dict[str, bytes] = {}
        self.statements: list[dict] = []
        self.deliveries: list[dict] = []
        self.documents: list[dict] = []
        self.runtime: list[dict] = []
        self.units: list[dict] = []
        self.payloads: dict[str, bytes] = {}
        self.envelopes: dict[str, dict] = {}
        self.ca_pem = mqtt_ca_certificate()
        self.binding = {
            "method": "tpm-ek-sha256",
            "digest": {
                "sha256": label_digest("TPM EK public key of the revpi-connect4 fixture device")
            },
        }
        self.other_binding = {
            "method": "tpm-ek-sha256",
            "digest": {"sha256": label_digest("TPM EK public key of another device")},
        }
        self.nonce_first = label_digest("nonce of the first provisioning request")[:32]
        self.nonce_again = label_digest("nonce of the re-provisioning request")[:32]

    # ------------------------------------------------------------------ output
    def put(self, rel: str, data: bytes) -> None:
        if rel in self.files:
            raise SystemExit(f"generator wrote {rel} twice")
        self.files[rel] = data

    def site_bytes(self, rel: str) -> bytes:
        return SITE_FILES[rel.removeprefix("site-files/")]

    def entry(
        self,
        rel: str,
        statement_type: str,
        *,
        expect: str,
        context: str | None,
        description: str,
        reason: str | None = None,
        inputs: dict | None = None,
        verifier: str = "os-root",
        mode: str = "accept",
    ) -> None:
        item: dict = {
            "path": rel,
            "statement_type": statement_type,
            "expect": expect,
            "device_context": context,
            "verifier": verifier,
            "mode": mode,
            "inputs": inputs or {},
            "description": description,
        }
        if reason is not None:
            item["reason"] = reason
        self.statements.append(item)

    def write(self, rel: str, env: dict, body: bytes, statement_type: str, **index: object) -> None:
        """Write one envelope fixture and index it once."""
        self.put(f"fixtures/{rel}", pretty(env))
        self.payloads[rel] = body
        self.envelopes[rel] = env
        self.entry(rel, statement_type, **index)  # type: ignore[arg-type]

    def signed(
        self, rel: str, statement_type: str, body: bytes, signer: TestKey, **index: object
    ) -> dict:
        env = envelope(statement_type, body, signer)
        self.write(rel, env, body, statement_type, **index)
        return env

    def envelope_negatives(
        self,
        kind_dir: str,
        statement_type: str,
        body: bytes,
        signer: TestKey,
        wrong_purpose: TestKey,
        *,
        context: str | None,
        inputs: dict | None = None,
        skip: tuple[str, ...] = (),
    ) -> None:
        """One-defect negatives for every envelope-stage reason that needs its own
        bytes: envelope-invalid, key-unknown, key-purpose-mismatch,
        signature-invalid, payload-json-invalid. payload-type-mismatch and
        key-epoch-below-ratchet reuse existing files (see alias)."""
        good = envelope(statement_type, body, signer)
        cases = [
            (
                "two-signatures",
                two_signatures(good, signer, statement_type),
                "envelope-invalid",
                "Two signatures; contract 1.x envelopes carry exactly one.",
            ),
            (
                "unknown-keyid",
                envelope(statement_type, body, UNPINNED),
                "key-unknown",
                "Signed by a key in no key store of the device.",
            ),
            (
                "wrong-purpose-key",
                envelope(statement_type, body, wrong_purpose),
                "key-purpose-mismatch",
                f"Signed by the {wrong_purpose.label} key, which does not sign {statement_type} (DEC-3.3).",
            ),
            (
                "bad-signature",
                tamper(good),
                "signature-invalid",
                "Payload bytes changed after signing (one added space; still the same JSON).",
            ),
        ]
        dup = duplicate_type_member(body)
        cases.append(
            (
                "duplicate-member",
                envelope(statement_type, dup, signer),
                "payload-json-invalid",
                "_type appears twice; a last-member-wins parser would read the real one and accept. Duplicate members are rejected.",
            )
        )
        for name, env, reason, text in cases:
            if name in skip:
                continue
            self.write(
                f"{kind_dir}/invalid/{name}.dsse.json",
                env,
                base64.b64decode(env["payload"]),
                statement_type,
                expect="reject",
                reason=reason,
                context=context,
                inputs=inputs,
                description=text,
            )

    def alias(self, rel: str, statement_type: str, **index: object) -> None:
        """Index an existing envelope again: another call site, context, verifier or mode."""
        assert f"fixtures/{rel}" in self.files, rel
        self.entry(rel, statement_type, **index)  # type: ignore[arg-type]

    # -------------------------------------------------------------------- keys
    def keys(self) -> None:
        entries = []
        for purpose, epoch, anchor in KEY_SPECS:
            k = key(purpose, epoch)
            rel = f"test-keys/{purpose}-{epoch}.TEST-ONLY.pub"
            self.put(rel, key_pem_file(k))
            entries.append(
                {
                    "purpose": purpose,
                    "epoch": epoch,
                    "keyid": k.keyid,
                    "public_key": b64(k.raw_public),
                    "path": rel,
                    "fixture_anchor": anchor,
                    "seed_label": k.seed_label,
                }
            )
        keyring = {
            "test_only": True,
            "description": "TEST-ONLY keys of the Suderra edge contract fixtures. No image of any variant (production, dev, QEMU or CI), no keyid allowlist and no signer may pin or hold any key listed here: dev and CI images pin the keys of Suderra-OS scripts/gen-dev-keys.sh and scripts/ci/prepare-ci-keyring.sh (ADR-048 DEC-3.9). Suderra-OS package/suderra-keys refuses to install them, and Suderra-OS tests/image-contracts/contracts-test-keys-not-pinned-test.sh and aquaculture_platform tests/invariants/suderra-edge-contracts.spec.ts fail when their key material appears outside contracts/suderra-edge/. fixture_anchor says only where the fixtures' simulated device anchors a key.",
            "derivation": "seed = SHA-256(UTF-8 seed_label); the Ed25519 private key is the RFC 8032 key with that seed. The derivation is public, so these keys prove nothing outside tests (tools/generate.py).",
            "keys": entries,
            "unanchored_keys": [
                {
                    "role": "Signs the key-unknown and anchor-not-os-pinned fixtures; in no key store.",
                    "keyid": UNPINNED.keyid,
                    "public_key": b64(UNPINNED.raw_public),
                    "seed_label": UNPINNED.seed_label,
                },
                {
                    "role": "Commitment key of the non-canonical-a signature vector; signs no statement.",
                    "keyid": SIGVEC_R.keyid,
                    "public_key": b64(SIGVEC_R.raw_public),
                    "seed_label": SIGVEC_R.seed_label,
                },
            ],
            "mqtt_ca": [
                {
                    "epoch": 1,
                    "certificate": self.ca_pem.decode(),
                    "certificate_sha256": sha256_hex(self.ca_pem),
                    "seed_label": f"{SEED_PREFIX}mqtt-ca:1",
                }
            ],
        }
        self.put("test-keys/keyring.json", pretty(keyring))

    # ---------------------------------------------------------------- payloads
    def release(self, board: str, version: str, security_version: int, **changes: object) -> dict:
        row = self.boards[board]
        artifact = self.naming["artifact"].format(
            version=version, board_profile=board, arch=row["arch"]
        )
        body = {
            "_type": ST_RELEASE,
            "name": "suderra-agent",
            "version": version,
            "security_version": security_version,
            "board_profile": board,
            "arch": row["arch"],
            "agent_profile": row["agent_profile"],
            "cargo_features": sorted(row["cargo_features"]),
            "artifact": {
                "name": artifact,
                "format": "tar.gz",
                "size_bytes": 7340032 + len(artifact),
                "digest": {"sha256": label_digest(f"artifact {artifact}")},
                "binary_name": "suderra-agent",
                "binary_digest": {"sha256": label_digest(f"binary in {artifact}")},
            },
            "min_os_version": "1.0.0",
            "agent_abi": 1,
            "required_kernel_config": sorted(BOARD_KERNEL[board]),
            "provenance": {
                "predicate_type": "https://slsa.dev/provenance/v1",
                "digest": {"sha256": label_digest(f"provenance of {artifact}")},
            },
        }
        body.update(changes)
        return body

    def trust_anchors(self, bundle_seq: int, **changes: object) -> dict:
        anchors = []
        for purpose, epoch in [
            ("command", 1),
            ("rbac-manifest", 1),
            ("config-integrity", 1),
            ("edge-release", 1),
            ("edge-provisioning", 1),
            ("edge-provisioning", 2),
        ]:
            k = key(purpose, epoch)
            anchors.append(
                {
                    "purpose": purpose,
                    "algorithm": "ed25519",
                    "keyid": k.keyid,
                    "epoch": epoch,
                    "public_key": b64(k.raw_public),
                }
            )
        anchors.append(
            {"purpose": "mqtt-ca", "algorithm": "x509", "certificates": [self.ca_pem.decode()]}
        )
        body = {
            "_type": ST_TA,
            "bundle_seq": bundle_seq,
            "issued_at": "2026-10-19T00:00:00Z",
            "tenant_scope": [TENANT],
            "anchors": anchors,
        }
        body.update(changes)
        return body

    def rbac(self, policy_version: int, **changes: object) -> dict:
        actor_key: TestKey = changes.pop("actor_key", key("command"))  # type: ignore[assignment]
        permissions = changes.pop("permissions", PLATFORM_PERMISSIONS)
        body = {
            "_type": ST_RBAC,
            "tenant_id": TENANT,
            "policy_version": policy_version,
            "not_before": RBAC_WINDOW[0],
            "expires_at": RBAC_WINDOW[1],
            "actors": [
                {
                    "actor_id": PLATFORM_ACTOR,
                    "kind": "platform",
                    "keyid": actor_key.keyid,
                    "public_key": b64(actor_key.raw_public),
                    "roles": ["platform-authenticated"],
                }
            ],
            "roles": [
                {
                    "name": "platform-authenticated",
                    "permissions": permissions,
                    "not_before": RBAC_WINDOW[0],
                    "expires_at": RBAC_WINDOW[1],
                }
            ],
        }
        body.update(changes)
        return body

    def site_config(
        self,
        update_seq: int,
        files: dict[str, str],
        rbac_rel: str,
        window: tuple[str, str],
        **changes: object,
    ) -> dict:
        rbac = json.loads(self.payloads[rbac_rel])
        body = {
            "_type": ST_SITE,
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": self.binding,
            "update_seq": update_seq,
            "not_before": window[0],
            "expires_at": window[1],
            "files": {
                path: {
                    "digest": digest_of(self.site_bytes(rel)),
                    "size_bytes": len(self.site_bytes(rel)),
                }
                for path, rel in sorted(files.items())
            },
            "rbac_manifest": {
                "digest": digest_of(self.payloads[rbac_rel]),
                "policy_version": rbac["policy_version"],
            },
        }
        body.update(changes)
        return body

    def manifest(
        self,
        *,
        release_rel: str,
        ta_rel: str,
        site_rel: str,
        nonce: str,
        update_seq: int,
        **changes: object,
    ) -> dict:
        release = json.loads(self.payloads[release_rel])
        ta = json.loads(self.payloads[ta_rel])
        site = json.loads(self.payloads[site_rel])
        version = release["version"]
        body = {
            "_type": ST_PROV,
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_code": DEVICE_CODE,
            "device_binding": self.binding,
            "nonce": nonce,
            "board": release["board_profile"],
            "arch": release["arch"],
            "agent_profile": release["agent_profile"],
            "version": version,
            "security_version": release["security_version"],
            "key_epoch": 1,
            "update_seq": update_seq,
            "not_before": VALID[0],
            "expires_at": VALID[1],
            "release_statement": {"digest": digest_of(self.payloads[release_rel])},
            "artifact_url": f"{RELEASE_HOST}/{version}/{release['artifact']['name']}",
            "site_config": {
                "digest": digest_of(self.payloads[site_rel]),
                "update_seq": site["update_seq"],
            },
            "trust_anchors": {
                "digest": digest_of(self.payloads[ta_rel]),
                "bundle_seq": ta["bundle_seq"],
            },
        }
        body.update(changes)
        return body

    # -------------------------------------------------------------- statements
    REL_160 = "edge-release/valid/revpi-connect4-aarch64-1.6.0.dsse.json"
    REL_140 = "edge-release/valid/revpi-connect4-aarch64-1.4.0.dsse.json"
    REL_RPI = "edge-release/valid/rpi4-cm4-aarch64-1.6.0.dsse.json"
    TA1 = "trust-anchors/valid/bundle-seq-1.dsse.json"
    TA2 = "trust-anchors/valid/bundle-seq-2.dsse.json"
    RBAC1 = "rbac-manifest/valid/platform-actor-policy-1.dsse.json"
    RBAC2 = "rbac-manifest/valid/platform-actor-policy-2.dsse.json"
    SITE_FIRST = "site-config/valid/revpi-connect4-first.dsse.json"
    SITE_INSTALLED = "site-config/valid/revpi-connect4-installed-yesterday.dsse.json"
    SITE_SEQ2 = "site-config/valid/revpi-connect4-seq-2.dsse.json"
    PROV_FIRST = "edge-provisioning/valid/revpi-connect4-first.dsse.json"
    PROV_AGAIN = "edge-provisioning/valid/revpi-connect4-reprovision.dsse.json"
    RECEIPT = "edge-activation-receipt/valid/revpi-connect4.dsse.json"
    LIFE = "device-lifecycle/valid/enter-maintenance-reprovision.dsse.json"
    REL_150 = "edge-release/valid/revpi-connect4-aarch64-1.5.0.dsse.json"
    REL_170 = "edge-release/valid/revpi-connect4-aarch64-1.7.0.dsse.json"
    SITE_SEQ3 = "site-config/valid/revpi-connect4-seq-3-io-config.dsse.json"
    SITE_BUNDLE3 = "site-bundle/valid/revpi-connect4-seq-3.json"
    EDGE_UPDATE = "edge-update/valid/revpi-connect4-1.7.0-seq-4.dsse.json"
    OS_UPDATE = "os-update/valid/revpi-connect4-1.1.0-seq-3.dsse.json"
    NETPOL1 = "site-netpolicy/valid/policy-seq-1.dsse.json"
    NETPOL2 = "site-netpolicy/valid/policy-seq-2.dsse.json"

    def releases(self) -> None:
        st = ST_RELEASE
        signer = key("edge-release")
        for board in sorted(self.boards):
            arch = self.boards[board]["arch"]
            body = canonical(self.release(board, "1.6.0", 6))
            self.signed(
                f"edge-release/valid/{board}-{arch}-1.6.0.dsse.json",
                st,
                body,
                signer,
                expect="accept",
                context=None,
                description=f"Release statement for {board}/{arch} whose features and artifact name match boards.json.",
            )
        body = canonical(self.release("revpi-connect4", "1.4.0", 4))
        self.signed(
            self.REL_140,
            st,
            body,
            signer,
            expect="accept",
            context=None,
            description="Older revpi-connect4 release (security_version 4) used by the rollback fixture.",
        )
        for rel, version, security_version, text in [
            (
                self.REL_150,
                "1.5.0",
                5,
                "Older revpi-connect4 release whose security_version 5 equals the device's rollback floor: not below it (boundary of rollback-below-floor, DEC-2.5).",
            ),
            (
                self.REL_170,
                "1.7.0",
                7,
                "Newer revpi-connect4 release (security_version 7) that the edge-update fixtures install.",
            ),
        ]:
            self.signed(
                rel,
                st,
                canonical(self.release("revpi-connect4", version, security_version)),
                signer,
                expect="accept",
                context=None,
                description=text,
            )
        self.alias(
            self.REL_160,
            st,
            expect="accept",
            context="revpi-active",
            description="The revpi-connect4 release on a revpi-connect4 device whose OS satisfies min_os_version, agent_abi and the kernel config.",
        )
        self.alias(
            self.REL_RPI,
            st,
            expect="reject",
            reason="board-mismatch",
            context="revpi-active",
            description="A correct rpi4-cm4 release on a revpi-connect4, whose CM4 GPIO lines drive PiBridge relays (DEC-8.2).",
        )
        self.alias(
            self.REL_160,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            description="Signed by edge-release epoch 1 on a device whose edge-release ratchet is 2.",
        )
        self.alias(
            self.REL_160,
            st,
            expect="accept",
            context="revpi-active",
            mode="reverify",
            description="verify-current before a start: the installed release statement re-verifies.",
        )
        self.alias(
            self.REL_140,
            st,
            expect="reject",
            reason="installed-digest-mismatch",
            context="revpi-active",
            mode="reverify",
            description="verify-current finds a release statement other than the receipted one.",
        )
        self.alias(
            self.REL_160,
            st,
            expect="accept",
            context="revpi-active-ratchets-2",
            verifier="agent",
            description="The agent checks the release profile against its board without root's ratchets (DEC-8.5).",
        )

        base = canonical(self.release("revpi-connect4", "1.6.0", 6))
        self.envelope_negatives(
            "edge-release", st, base, signer, key("edge-provisioning"), context=None
        )
        unsafe_version = "1.6.0-../../etc"
        unsafe = self.release(
            "revpi-connect4",
            unsafe_version,
            6,
            artifact={
                **self.release("revpi-connect4", "1.6.0", 6)["artifact"],
                "name": self.naming["artifact"].format(
                    version=unsafe_version, board_profile="revpi-connect4", arch="aarch64"
                ),
            },
        )
        extra = self.release("revpi-connect4", "1.6.0", 6)
        extra["download_mirror"] = f"{RELEASE_HOST}/mirror"
        missing_gpio = [f for f in self.boards["rpi4-cm4"]["cargo_features"] if f != "gpio"]
        cases = [
            (
                "path-unsafe-version",
                unsafe,
                None,
                "schema-invalid",
                "version is a path component, so a traversal string fails the path-safe semver pattern (DEC-1.10); the artifact name is derived from that same version.",
            ),
            (
                "unknown-field",
                extra,
                None,
                "schema-invalid",
                "Signed payload with a member the schema does not define; unknown members are rejected, never dropped (EI-054).",
            ),
            (
                "missing-board-feature",
                self.release("rpi4-cm4", "1.6.0", 6, cargo_features=sorted(missing_gpio)),
                None,
                "release-profile-mismatch",
                "rpi4-cm4 release built without the gpio feature (INFRA-CRITICAL-236 class).",
            ),
            (
                "os-too-old",
                self.release("revpi-connect4", "1.6.0", 6, min_os_version="1.1.0"),
                "revpi-active",
                "os-version-too-old",
                "Needs OS 1.1.0; the device runs 1.0.0 (DEC-23).",
            ),
            (
                "agent-abi-2",
                self.release("revpi-connect4", "1.6.0", 6, agent_abi=2),
                "revpi-active",
                "agent-abi-unsupported",
                "agent_abi 2 outside the device's SUDERRA_AGENT_ABI range 1-1 (DEC-23).",
            ),
            (
                "kernel-config-missing",
                self.release(
                    "revpi-connect4",
                    "1.6.0",
                    6,
                    required_kernel_config=sorted(
                        BOARD_KERNEL["revpi-connect4"] + ["CONFIG_CAN_RAW"]
                    ),
                ),
                "revpi-active",
                "kernel-config-missing",
                "Requires CONFIG_CAN_RAW, which the device kernel config does not list (DEC-23).",
            ),
        ]
        for name, payload, context, reason, text in cases:
            body = canonical(payload)
            self.signed(
                f"edge-release/invalid/{name}.dsse.json",
                st,
                body,
                signer,
                expect="reject",
                reason=reason,
                context=context,
                description=text,
            )

    def trust_anchor_bundles(self) -> None:
        st = ST_TA
        root = key("fleet-root")
        body = canonical(self.trust_anchors(1))
        self.signed(
            self.TA1,
            st,
            body,
            root,
            expect="accept",
            context="revpi-factory",
            description="P0 bundle (command, rbac-manifest, config-integrity, edge-release, edge-provisioning, mqtt-ca) signed by fleet-root.",
        )
        self.alias(
            self.TA1,
            st,
            expect="accept",
            context="revpi-active",
            description="The same bundle on a device that accepted exactly it at bundle_seq 1: an identical re-presentation is accepted (DEC-2.4).",
        )
        body2 = canonical(self.trust_anchors(2))
        self.signed(
            self.TA2,
            st,
            body2,
            root,
            expect="accept",
            context="revpi-active",
            description="Next bundle for a device that accepted bundle_seq 1.",
        )
        self.envelope_negatives(
            "trust-anchors", st, body2, root, key("edge-provisioning"), context="revpi-active"
        )

        ta = self.trust_anchors(2)
        keyid_wrong = copy.deepcopy(ta)
        keyid_wrong["anchors"][0]["keyid"] = key("config-integrity").keyid
        keyid_unrelated = copy.deepcopy(ta)
        keyid_unrelated["anchors"][0]["keyid"] = label_digest("a keyid no key has")
        dup_slot = copy.deepcopy(ta)
        dup_slot["anchors"].insert(1, copy.deepcopy(ta["anchors"][0]))
        unpinned = copy.deepcopy(ta)
        for anchor in unpinned["anchors"]:
            if anchor.get("purpose") == "edge-provisioning" and anchor["epoch"] == 2:
                anchor["keyid"] = UNPINNED.keyid
                anchor["public_key"] = b64(UNPINNED.raw_public)
        extra = {**ta, "valid_for_devices": [DEVICE]}
        cases = [
            (
                "tenant-scope-excludes-device",
                self.trust_anchors(2, tenant_scope=[OTHER_TENANT]),
                "tenant-scope-mismatch",
                "Correctly signed bundle whose tenant_scope does not contain the device's tenant (DEC-22).",
            ),
            (
                "anchor-not-os-pinned",
                unpinned,
                "anchor-not-os-pinned",
                "edge-provisioning anchor whose keyid no OS image pins; root rejects the bundle (DEC-3.3).",
            ),
            (
                "anchor-keyid-mismatch",
                keyid_wrong,
                "anchor-invalid",
                "The command anchor's keyid is the config-integrity anchor's keyid, not the SHA-256 of its own public key.",
            ),
            (
                "anchor-keyid-unrelated",
                keyid_unrelated,
                "anchor-invalid",
                "The command anchor's keyid is the SHA-256 of nothing: not the digest of its public key and not another anchor's keyid either, so no duplicate-keyid check can catch it.",
            ),
            (
                "anchor-duplicate-slot",
                dup_slot,
                "anchor-invalid",
                "command epoch 1 appears twice; one (purpose, epoch) maps to one key.",
            ),
            (
                "same-seq-different-bundle",
                self.trust_anchors(1, issued_at="2026-10-19T12:00:00Z"),
                "sequence-replay",
                "bundle_seq 1 again but not the bundle the device accepted at 1 (DEC-2.4).",
            ),
            (
                "unknown-field",
                extra,
                "schema-invalid",
                "Signed payload with a member the schema does not define.",
            ),
        ]
        for name, payload, reason, text in cases:
            self.signed(
                f"trust-anchors/invalid/{name}.dsse.json",
                st,
                canonical(payload),
                root,
                expect="reject",
                reason=reason,
                context="revpi-active",
                description=text,
            )
        self.alias(
            self.TA2,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-fleet-root-ratchet-2",
            description="Valid bundle signed by fleet-root epoch 1 on a device whose fleet-root ratchet is 2 (DEC-3.5).",
        )
        self.alias(
            self.REL_160,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            description="A release statement presented where a trust-anchors bundle is expected.",
        )
        self.alias(
            self.TA1,
            st,
            expect="accept",
            context="revpi-active",
            mode="reverify",
            description="Re-verification of the installed bundle.",
        )
        self.alias(
            self.TA2,
            st,
            expect="reject",
            reason="installed-digest-mismatch",
            context="revpi-active",
            mode="reverify",
            description="Re-verification finds a bundle other than the installed one.",
        )
        self.alias(
            self.TA2,
            st,
            expect="accept",
            context="revpi-active-fleet-root-ratchet-2",
            verifier="agent",
            description="The agent has no view of root's ratchets, so it does not reject on the fleet-root ratchet; root does.",
        )

    def rbac_manifests(self) -> None:
        st = ST_RBAC
        signer = key("rbac-manifest")
        inp = {"trust_anchors": self.TA1}
        body1 = canonical(self.rbac(1))
        self.signed(
            self.RBAC1,
            st,
            body1,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inp,
            description="The installed platform-actor RBAC manifest: an identical re-presentation is accepted (DEC-9.9).",
        )
        body2 = canonical(self.rbac(2))
        self.signed(
            self.RBAC2,
            st,
            body2,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inp,
            description="policy_version 2 after 1; the platform actor's key is the bundle's command anchor (DEC-9.4).",
        )
        self.envelope_negatives(
            "rbac-manifest",
            st,
            body2,
            signer,
            key("config-integrity"),
            context="revpi-active",
            inputs=inp,
        )
        tpi = PLATFORM_PERMISSIONS + ["Reboot"]
        inverted = PLATFORM_PERMISSIONS + [
            {"ModbusWrite": {"device_id": 1, "register_range": {"start": 10, "end": 1}}}
        ]
        cases = [
            (
                "not-yet-valid",
                self.rbac(2, not_before=FUTURE[0], expires_at=FUTURE[1]),
                "not-yet-valid",
                "Validity window starts after the evaluation time.",
            ),
            (
                "expired",
                self.rbac(2, not_before=EXPIRED[0], expires_at=EXPIRED[1]),
                "expired",
                "Validity window ended before the evaluation time.",
            ),
            (
                "wrong-tenant",
                self.rbac(2, tenant_id=OTHER_TENANT),
                "tenant-mismatch",
                "Another tenant's RBAC manifest (DEC-22).",
            ),
            (
                "actor-key-not-anchored",
                self.rbac(2, actor_key=UNPINNED),
                "actor-key-not-anchored",
                "Maps the platform actor to a key that is not the bundle's command anchor (DEC-9.4).",
            ),
            (
                "actor-key-other-purpose",
                self.rbac(2, actor_key=key("rbac-manifest")),
                "actor-key-not-anchored",
                "Maps the platform actor to the bundle's rbac-manifest key: an anchored key, but not a command-purpose one (DEC-3.3, DEC-9.4).",
            ),
            (
                "same-policy-version-changed",
                self.rbac(1, permissions=["ReadAuditLog", "ReadTag"]),
                "sequence-replay",
                "policy_version 1 again but not the manifest the device accepted at 1.",
            ),
            (
                "tpi-permission",
                self.rbac(2, permissions=tpi),
                "schema-invalid",
                "Grants Reboot, a two-person-integrity permission no 1.x manifest can grant (DEC-9.4).",
            ),
            (
                "inverted-register-range",
                self.rbac(2, permissions=inverted),
                "schema-invalid",
                "ModbusWrite range with start above end, which the agent's ModbusRegisterRange refuses.",
            ),
        ]
        for name, payload, reason, text in cases:
            self.signed(
                f"rbac-manifest/invalid/{name}.dsse.json",
                st,
                canonical(payload),
                signer,
                expect="reject",
                reason=reason,
                context="revpi-active",
                inputs=inp,
                description=text,
            )
        self.alias(
            self.RBAC2,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            inputs=inp,
            description="Signed by rbac-manifest epoch 1 on a device whose rbac-manifest ratchet is 2.",
        )
        self.alias(
            self.RBAC1,
            st,
            expect="accept",
            context="revpi-active",
            inputs=inp,
            mode="reverify",
            description="Re-verification of the installed RBAC manifest at agent start.",
        )
        self.alias(
            self.RBAC2,
            st,
            expect="reject",
            reason="installed-digest-mismatch",
            context="revpi-active",
            inputs=inp,
            mode="reverify",
            description="Re-verification finds a manifest other than the installed one.",
        )

    def site_configs(self) -> None:
        st = ST_SITE
        signer = key("config-integrity")

        def inputs(files: dict[str, str] = FILES_V2, rbac: str = self.RBAC1) -> dict:
            return {"trust_anchors": self.TA1, "rbac_manifest": rbac, "site_files": dict(files)}

        first = canonical(self.site_config(1, FILES_V1, self.RBAC1, VALID))
        self.signed(
            self.SITE_FIRST,
            st,
            first,
            signer,
            expect="accept",
            context="revpi-factory",
            inputs=inputs(FILES_V1),
            description="First site config of a factory-fresh device, delivered by its first provisioning (DEC-4.12).",
        )
        installed = canonical(self.site_config(1, FILES_V1, self.RBAC1, INSTALLED_YESTERDAY))
        self.signed(
            self.SITE_INSTALLED,
            st,
            installed,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(FILES_V1),
            description="The site config the active device installed yesterday; its window has passed, and re-presenting the identical statement is a re-verification (DEC-4.10).",
        )
        seq2 = canonical(self.site_config(2, FILES_V2, self.RBAC1, VALID))
        self.signed(
            self.SITE_SEQ2,
            st,
            seq2,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="Changed config.yaml at update_seq 2; the unchanged RBAC manifest is re-presented.",
        )
        self.alias(
            self.SITE_FIRST,
            st,
            expect="reject",
            reason="sequence-replay",
            context="revpi-active",
            inputs=inputs(FILES_V1),
            description="update_seq 1 again but not the site config the device accepted at 1 (DEC-4.10).",
        )
        self.envelope_negatives(
            "site-config",
            st,
            seq2,
            signer,
            key("rbac-manifest"),
            context="revpi-active",
            inputs=inputs(),
        )
        rbac2 = json.loads(self.payloads[self.RBAC2])
        size_only = self.site_config(2, FILES_V2, self.RBAC1, VALID)
        size_only["files"]["config.yaml"]["size_bytes"] += 1
        self.signed(
            "site-config/valid/revpi-connect4-not-before-now.dsse.json",
            st,
            canonical(self.site_config(2, FILES_V2, self.RBAC1, STARTS_NOW)),
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="not_before equal to the evaluation time is inside the window: not_before <= now (statements.json dsse.time_window).",
        )
        cases = [
            (
                "not-yet-valid",
                self.site_config(2, FILES_V2, self.RBAC1, FUTURE),
                inputs(),
                "not-yet-valid",
                "Validity window starts after the evaluation time.",
            ),
            (
                "expired",
                self.site_config(2, FILES_V2, self.RBAC1, EXPIRED),
                inputs(),
                "expired",
                "Validity window ended before the evaluation time.",
            ),
            (
                "wrong-device-binding",
                self.site_config(2, FILES_V2, self.RBAC1, VALID, device_binding=self.other_binding),
                inputs(),
                "device-binding-mismatch",
                "Bound to another device's TPM EK hash.",
            ),
            (
                "wrong-device-id",
                self.site_config(2, FILES_V2, self.RBAC1, VALID, device_id=OTHER_DEVICE),
                inputs(),
                "device-id-mismatch",
                "Another device's site config.",
            ),
            (
                "wrong-tenant",
                self.site_config(2, FILES_V2, self.RBAC1, VALID, tenant_id=OTHER_TENANT),
                inputs(),
                "tenant-mismatch",
                "Another tenant's site config (DEC-22).",
            ),
            (
                "unknown-field",
                {**self.site_config(2, FILES_V2, self.RBAC1, VALID), "debug_shell": True},
                inputs(),
                "schema-invalid",
                "Signed payload with a member the schema does not define.",
            ),
            (
                "rbac-digest-mismatch",
                self.site_config(
                    2,
                    FILES_V2,
                    self.RBAC1,
                    VALID,
                    rbac_manifest={
                        "digest": digest_of(self.payloads[self.RBAC2]),
                        "policy_version": rbac2["policy_version"],
                    },
                ),
                inputs(),
                "rbac-manifest-digest-mismatch",
                "Names RBAC manifest policy 2 while policy 1 is delivered.",
            ),
            (
                "rbac-policy-version-only",
                self.site_config(
                    2,
                    FILES_V2,
                    self.RBAC1,
                    VALID,
                    rbac_manifest={
                        "digest": digest_of(self.payloads[self.RBAC1]),
                        "policy_version": 2,
                    },
                ),
                inputs(),
                "rbac-manifest-digest-mismatch",
                "Names the delivered RBAC manifest's digest but policy_version 2 instead of 1: the digest alone is not the whole reference.",
            ),
            (
                "expires-at-now",
                self.site_config(2, FILES_V2, self.RBAC1, EXPIRES_NOW),
                inputs(),
                "expired",
                "expires_at equal to the evaluation time is outside the window: now < expires_at (statements.json dsse.time_window).",
            ),
            (
                "file-size-only",
                size_only,
                inputs(),
                "site-file-digest-mismatch",
                "config.yaml's size_bytes is one more than the delivered file while its digest matches: size and digest are both part of the reference (DEC-4.10).",
            ),
        ]
        for name, payload, inp, reason, text in cases:
            self.signed(
                f"site-config/invalid/{name}.dsse.json",
                st,
                canonical(payload),
                signer,
                expect="reject",
                reason=reason,
                context="revpi-active",
                inputs=inp,
                description=text,
            )
        tampered = {**FILES_V2, "config.yaml": "site-files/tampered/config.yaml"}
        extra = {**FILES_V2, "hardware-inventory.yaml": "site-files/extra/hardware-inventory.yaml"}
        self.alias(
            self.SITE_SEQ2,
            st,
            expect="reject",
            reason="site-file-digest-mismatch",
            context="revpi-active",
            inputs=inputs(tampered),
            description="config.yaml delivered with allow_writes flipped after signing (DEC-4.10).",
        )
        self.alias(
            self.SITE_SEQ2,
            st,
            expect="reject",
            reason="site-file-digest-mismatch",
            context="revpi-active",
            inputs=inputs(extra),
            description="A site file the site config does not name is delivered; root installs exactly the named files.",
        )
        self.alias(
            self.SITE_SEQ2,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            inputs=inputs(),
            description="Signed by config-integrity epoch 1 on a device whose config-integrity ratchet is 2.",
        )
        self.alias(
            self.RBAC1,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs=inputs(),
            description="An RBAC manifest presented where a site config is expected.",
        )
        self.alias(
            self.SITE_SEQ2,
            st,
            expect="accept",
            context="revpi-active-ratchets-2",
            verifier="agent",
            inputs=inputs(),
            description="The agent has no view of root's ratchets; its own version gate and every other check pass.",
        )
        self.alias(
            self.SITE_INSTALLED,
            st,
            expect="accept",
            context="revpi-active",
            inputs=inputs(FILES_V1),
            mode="reverify",
            description="Agent start: the installed site config re-verifies although its window has passed (EDGE-HIGH-054 class).",
        )
        self.alias(
            self.SITE_SEQ2,
            st,
            expect="reject",
            reason="installed-digest-mismatch",
            context="revpi-active",
            inputs=inputs(),
            mode="reverify",
            description="Re-verification finds a site config other than the installed one.",
        )
        # Cross-type confusion within config-integrity and rbac-manifest call sites.
        self.alias(
            self.SITE_SEQ2,
            ST_RBAC,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs={"trust_anchors": self.TA1},
            description="A site config presented where an RBAC manifest is expected.",
        )

    def provisioning_manifests(self) -> None:
        st = ST_PROV
        signer = key("edge-provisioning")

        def inputs(
            release: str = self.REL_160,
            ta: str = self.TA2,
            site: str = self.SITE_SEQ2,
            files: dict[str, str] = FILES_V2,
            nonce: str | None = None,
        ) -> dict:
            return {
                "release_statement": release,
                "trust_anchors": ta,
                "site_config": site,
                "rbac_manifest": self.RBAC1,
                "site_files": dict(files),
                "request_nonce": nonce or self.nonce_again,
            }

        first = canonical(
            self.manifest(
                release_rel=self.REL_160,
                ta_rel=self.TA1,
                site_rel=self.SITE_FIRST,
                nonce=self.nonce_first,
                update_seq=1,
            )
        )
        self.signed(
            self.PROV_FIRST,
            st,
            first,
            signer,
            expect="accept",
            context="revpi-factory",
            inputs=inputs(
                ta=self.TA1, site=self.SITE_FIRST, files=FILES_V1, nonce=self.nonce_first
            ),
            description="First provisioning of a factory-fresh revpi-connect4: binds tenant, device, binding and nonce to release 1.6.0, bundle_seq 1 and the first site config; the delivered statements are checked against the manifest's identity.",
        )

        def manifest(**changes: object) -> dict:
            return self.manifest(
                release_rel=str(changes.pop("release_rel", self.REL_160)),
                ta_rel=str(changes.pop("ta_rel", self.TA2)),
                site_rel=str(changes.pop("site_rel", self.SITE_SEQ2)),
                nonce=str(changes.pop("nonce", self.nonce_again)),
                update_seq=int(str(changes.pop("update_seq", 4))),
                **changes,
            )

        again = canonical(manifest())
        self.signed(
            self.PROV_AGAIN,
            st,
            again,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="Re-provisioning in MAINTENANCE: update_seq 4 after 3, security_version 6 above floor 5, bundle_seq 2, site config 2 (DEC-5.14).",
        )
        unchanged = canonical(manifest(ta_rel=self.TA1, site_rel=self.SITE_INSTALLED))
        self.signed(
            "edge-provisioning/valid/revpi-connect4-reprovision-unchanged-bundle.dsse.json",
            st,
            unchanged,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(ta=self.TA1, site=self.SITE_INSTALLED, files=FILES_V1),
            description="Re-provisioning that re-presents the installed bundle_seq 1 and the installed site config unchanged: identical statements are accepted, so no fresh fleet-root signature is needed (DEC-2.4, DEC-4.10).",
        )
        loose = dict(reversed(list(manifest().items())))
        loose_body = (json.dumps(loose, indent=4, ensure_ascii=False) + "\n").encode()
        self.signed(
            "edge-provisioning/valid/revpi-connect4-noncanonical-json.dsse.json",
            st,
            loose_body,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="Same manifest with reversed member order, 4-space indentation and a trailing newline: the signature covers these exact bytes, so a verifier that re-serializes before verifying fails here (EI-054).",
        )
        epoch2 = canonical(manifest(key_epoch=2))
        self.signed(
            "edge-provisioning/valid/revpi-connect4-key-epoch-2.dsse.json",
            st,
            epoch2,
            key("edge-provisioning", 2),
            expect="accept",
            context="revpi-active-ratchet-2",
            inputs=inputs(),
            description="Signed with the epoch-2 provisioning key on a device whose provisioning ratchet is at 2 (DEC-3.5).",
        )

        self.envelope_negatives(
            "edge-provisioning",
            st,
            again,
            signer,
            key("edge-release"),
            context="revpi-active",
            inputs=inputs(),
        )
        good = envelope(st, again, signer)
        extra_env = [
            (
                "non-canonical-signature",
                malleate(good),
                "signature-invalid",
                "S replaced by S + L. verify_strict requires S < L; a verifier that reduces S accepts it.",
            ),
            (
                "edge-update-payload-type",
                envelope(
                    st, again, signer, payload_type="application/vnd.suderra.edge-update.v1+json"
                ),
                "payload-type-mismatch",
                "Correctly signed by the provisioning key but as edge-update: a manifest cannot be replayed as another statement kind (DEC-2.4).",
            ),
        ]
        for name, env, reason, text in extra_env:
            self.write(
                f"edge-provisioning/invalid/{name}.dsse.json",
                env,
                base64.b64decode(env["payload"]),
                st,
                expect="reject",
                reason=reason,
                context="revpi-active",
                inputs=inputs(),
                description=text,
            )
        for name, number, text in [
            (
                "fractional-number",
                b"4.0",
                "update_seq written as 4.0: JSON Schema calls it an integer, serde's u64 refuses it.",
            ),
            (
                "exponent-number",
                b"4e0",
                "update_seq written as 4e0: JSON Schema calls it an integer, serde's u64 refuses it.",
            ),
        ]:
            body = again.replace(b'"update_seq":4,', b'"update_seq":' + number + b",", 1)
            assert body != again
            self.signed(
                f"edge-provisioning/invalid/{name}.dsse.json",
                st,
                body,
                signer,
                expect="reject",
                reason="payload-json-invalid",
                context="revpi-active",
                inputs=inputs(),
                description=text,
            )
        self.alias(
            "edge-provisioning/valid/revpi-connect4-reprovision.dsse.json",
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchet-2",
            inputs=inputs(),
            description="Valid epoch-1 manifest on a device whose provisioning ratchet advanced to 2 (DEC-3.5).",
        )

        semantic = [
            (
                "unknown-field",
                {"debug_shell": True},
                {},
                "schema-invalid",
                "Signed payload with a member the schema does not define.",
            ),
            (
                "key-epoch-mismatch",
                {"key_epoch": 2},
                {},
                "key-epoch-mismatch",
                "Signed with the epoch-1 key but claims key_epoch 2; the claim never selects a key (DEC-3.4).",
            ),
            (
                "wrong-device-binding",
                {"device_binding": self.other_binding},
                {},
                "device-binding-mismatch",
                "Bound to another device's TPM EK hash: replay to a second device of the same board (EI-038).",
            ),
            (
                "wrong-device-id",
                {"device_id": OTHER_DEVICE},
                {},
                "device-id-mismatch",
                "device_id differs from the identity root recorded at first provisioning.",
            ),
            (
                "wrong-tenant",
                {"tenant_id": OTHER_TENANT},
                {},
                "tenant-mismatch",
                "Another tenant's manifest for this device; the bundle's tenant_scope is checked against the recorded tenant, which it contains (DEC-22).",
            ),
            (
                "nonce-mismatch",
                {"nonce": self.nonce_first},
                {},
                "nonce-mismatch",
                "Echoes the nonce of an earlier request instead of this one (DEC-5.5).",
            ),
            (
                "expired",
                {"not_before": EXPIRED[0], "expires_at": EXPIRED[1]},
                {},
                "expired",
                "Validity window ended before the evaluation time.",
            ),
            (
                "not-yet-valid",
                {"not_before": FUTURE[0], "expires_at": FUTURE[1]},
                {},
                "not-yet-valid",
                "Validity window starts after the evaluation time.",
            ),
            (
                "wrong-board",
                {"release_rel": self.REL_RPI},
                {"release": self.REL_RPI},
                "board-mismatch",
                "Consistent rpi4-cm4 manifest and release delivered to a revpi-connect4, whose CM4 GPIO lines drive PiBridge relays (DEC-8.2).",
            ),
            (
                "rollback-below-floor",
                {"release_rel": self.REL_140},
                {"release": self.REL_140},
                "rollback-below-floor",
                "Consistent manifest for release 1.4.0 (security_version 4) on a device whose floor is 5 (DEC-2.5).",
            ),
            (
                "sequence-replay",
                {"update_seq": 3},
                {},
                "sequence-replay",
                "update_seq equal to the last accepted one; provisioning manifests never repeat a sequence (DEC-2.4).",
            ),
            (
                "release-digest-mismatch",
                {"release_statement": {"digest": digest_of(self.payloads[self.REL_140])}},
                {},
                "release-digest-mismatch",
                "Names the 1.4.0 release statement digest while release 1.6.0 is delivered.",
            ),
            (
                "release-mismatch",
                {"version": "1.6.1"},
                {},
                "release-mismatch",
                "Claims version 1.6.1 for the 1.6.0 release statement it names (DEC-3.1).",
            ),
            (
                "site-config-digest-mismatch",
                {
                    "site_config": {
                        "digest": digest_of(self.payloads[self.SITE_INSTALLED]),
                        "update_seq": 2,
                    }
                },
                {},
                "site-config-digest-mismatch",
                "Names another site config than the update_seq 2 one delivered.",
            ),
            (
                "trust-anchors-digest-mismatch",
                {"trust_anchors": {"digest": digest_of(self.payloads[self.TA2]), "bundle_seq": 3}},
                {},
                "trust-anchors-digest-mismatch",
                "Names bundle_seq 3 for the bundle_seq 2 bundle it digests.",
            ),
            (
                "trust-anchors-tenant-scope",
                {"ta_rel": "trust-anchors/invalid/tenant-scope-excludes-device.dsse.json"},
                {"ta": "trust-anchors/invalid/tenant-scope-excludes-device.dsse.json"},
                "tenant-scope-mismatch",
                "Delivers, and binds by digest, a fleet-root bundle whose tenant_scope excludes the device's tenant (DEC-22).",
            ),
        ]
        for name, changes, inp, reason, text in semantic:
            body = canonical(manifest(**changes))
            self.signed(
                f"edge-provisioning/invalid/{name}.dsse.json",
                st,
                body,
                signer,
                expect="reject",
                reason=reason,
                context="revpi-active",
                inputs=inputs(
                    release=str(inp.get("release", self.REL_160)), ta=str(inp.get("ta", self.TA2))
                ),
                description=text,
            )

    def receipts(self) -> None:
        st = ST_RECEIPT
        signer = key("edge-provisioning")
        installed = self.payloads[self.PROV_FIRST]

        def receipt(**changes: object) -> bytes:
            body = {
                "_type": st,
                "tenant_id": TENANT,
                "device_id": DEVICE,
                "device_binding": self.binding,
                "manifest_digest": digest_of(installed),
                "activation_id": ACTIVATION,
                "activated_at": "2026-10-20T11:30:00Z",
                "not_before": "2026-10-20T11:30:00Z",
                "expires_at": "2026-10-21T11:30:00Z",
            }
            body.update(changes)
            return canonical(body)

        body = receipt()
        self.signed(
            self.RECEIPT,
            st,
            body,
            signer,
            expect="accept",
            context="revpi-provisioning",
            description="Receipt for the manifest root installed; root accepts it and records ACTIVE (DEC-5.8).",
        )
        self.envelope_negatives(
            "edge-activation-receipt",
            st,
            body,
            signer,
            key("device-lifecycle"),
            context="revpi-provisioning",
        )
        cases = [
            (
                "wrong-manifest-digest",
                receipt(manifest_digest=digest_of(self.payloads[self.PROV_AGAIN])),
                "manifest-digest-mismatch",
                "Names a manifest other than the one root installed.",
            ),
            (
                "wrong-device-binding",
                receipt(device_binding=self.other_binding),
                "device-binding-mismatch",
                "Receipt for another device's binding.",
            ),
            (
                "wrong-device-id",
                receipt(device_id=OTHER_DEVICE),
                "device-id-mismatch",
                "Receipt for another device id.",
            ),
            (
                "wrong-tenant",
                receipt(tenant_id=OTHER_TENANT),
                "tenant-mismatch",
                "Receipt for another tenant (DEC-22).",
            ),
            (
                "expired",
                receipt(not_before=EXPIRED[0], expires_at=EXPIRED[1]),
                "expired",
                "Receipt presented after its window.",
            ),
            (
                "not-yet-valid",
                receipt(not_before=FUTURE[0], expires_at=FUTURE[1]),
                "not-yet-valid",
                "Receipt presented before its window.",
            ),
            (
                "unknown-field",
                receipt(lockdown="skip"),
                "schema-invalid",
                "Signed payload with a member the schema does not define.",
            ),
        ]
        for name, payload, reason, text in cases:
            self.signed(
                f"edge-activation-receipt/invalid/{name}.dsse.json",
                st,
                payload,
                signer,
                expect="reject",
                reason=reason,
                context="revpi-provisioning",
                description=text,
            )
        self.alias(
            self.RECEIPT,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-provisioning-ratchets-2",
            description="Signed by edge-provisioning epoch 1 on a device whose provisioning ratchet is 2.",
        )
        self.alias(
            self.PROV_FIRST,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-provisioning",
            description="The provisioning manifest, signed by the same key, presented where the activation receipt is expected.",
        )
        self.alias(
            self.RECEIPT,
            ST_PROV,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs={
                "release_statement": self.REL_160,
                "trust_anchors": self.TA2,
                "site_config": self.SITE_SEQ2,
                "rbac_manifest": self.RBAC1,
                "site_files": dict(FILES_V2),
                "request_nonce": self.nonce_again,
            },
            description="The activation receipt, signed by the same key, presented where a provisioning manifest is expected.",
        )
        self.alias(
            "edge-activation-receipt/invalid/wrong-manifest-digest.dsse.json",
            st,
            expect="accept",
            context="revpi-provisioning",
            verifier="agent",
            description="The agent cannot see which manifest root installed, so it does not check manifest_digest; root does (verified_by.agent.omits).",
        )

    def lifecycle(self) -> None:
        st = ST_LIFE
        signer = key("device-lifecycle")

        def statement(**changes: object) -> bytes:
            body: dict = {
                "_type": st,
                "tenant_id": TENANT,
                "device_id": DEVICE,
                "device_binding": self.binding,
                "action": "enter-maintenance",
                "purpose": "reprovision",
                "update_seq": 3,
                "not_before": "2026-10-20T11:00:00Z",
                "expires_at": "2026-10-20T15:00:00Z",
            }
            for name, value in changes.items():
                if value is None:
                    body.pop(name)
                else:
                    body[name] = value
            return canonical(body)

        body = statement()
        self.signed(
            self.LIFE,
            st,
            body,
            signer,
            expect="accept",
            context="revpi-active",
            description="ACTIVE -> MAINTENANCE for re-provisioning until expires_at (DEC-5.14, DEC-12).",
        )
        self.envelope_negatives(
            "device-lifecycle", st, body, signer, key("edge-provisioning"), context="revpi-active"
        )
        cases = [
            (
                "expired",
                statement(not_before=EXPIRED[0], expires_at=EXPIRED[1]),
                "expired",
                "Maintenance request presented after its window.",
            ),
            (
                "not-yet-valid",
                statement(not_before=FUTURE[0], expires_at=FUTURE[1]),
                "not-yet-valid",
                "Maintenance request presented before its window.",
            ),
            (
                "wrong-device-binding",
                statement(device_binding=self.other_binding),
                "device-binding-mismatch",
                "Maintenance request for another device's binding.",
            ),
            (
                "wrong-device-id",
                statement(device_id=OTHER_DEVICE),
                "device-id-mismatch",
                "Maintenance request for another device id.",
            ),
            (
                "wrong-tenant",
                statement(tenant_id=OTHER_TENANT),
                "tenant-mismatch",
                "Maintenance request from another tenant (DEC-22).",
            ),
            (
                "sequence-replay",
                statement(update_seq=2),
                "sequence-replay",
                "update_seq equal to the last accepted lifecycle statement; a transition is never applied twice.",
            ),
            (
                "maintenance-without-purpose",
                statement(purpose=None),
                "schema-invalid",
                "enter-maintenance must say why (reprovision or break-glass).",
            ),
        ]
        for name, payload, reason, text in cases:
            self.signed(
                f"device-lifecycle/invalid/{name}.dsse.json",
                st,
                payload,
                signer,
                expect="reject",
                reason=reason,
                context="revpi-active",
                description=text,
            )
        self.alias(
            self.LIFE,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            description="Signed by device-lifecycle epoch 1 on a device whose device-lifecycle ratchet is 2.",
        )
        self.alias(
            self.RECEIPT,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            description="An activation receipt presented where a lifecycle statement is expected.",
        )
        # Remaining cross-type call sites.
        self.alias(
            self.PROV_AGAIN,
            ST_RELEASE,
            expect="reject",
            reason="payload-type-mismatch",
            context=None,
            description="A provisioning manifest presented where a release statement is expected.",
        )

    # ------------------------------------------------------- update channel statements
    def negatives(
        self,
        kind_dir: str,
        st: str,
        signer: TestKey,
        cases: list[tuple],
        *,
        context: str = "revpi-active",
        inputs: dict | None = None,
    ) -> None:
        """One signed one-defect negative per case: (name, payload, reason, description
        [, inputs]). The case's inputs replace the default ones."""
        for item in cases:
            name, payload, reason, text = item[:4]
            self.signed(
                f"{kind_dir}/invalid/{name}.dsse.json",
                st,
                canonical(payload),
                signer,
                expect="reject",
                reason=reason,
                context=context,
                inputs=item[4] if len(item) > 4 else inputs,
                description=text,
            )

    def provisioning_inputs(self) -> dict:
        """Inputs of a provisioning-manifest call site on the revpi-active device."""
        return {
            "release_statement": self.REL_160,
            "trust_anchors": self.TA2,
            "site_config": self.SITE_SEQ2,
            "rbac_manifest": self.RBAC1,
            "site_files": dict(FILES_V2),
            "request_nonce": self.nonce_again,
        }

    def edge_update(
        self,
        release_rel: str,
        update_seq: int,
        window: tuple[str, str] = VALID,
        **changes: object,
    ) -> dict:
        release = json.loads(self.payloads[release_rel])
        version = release["version"]
        artifact = release["artifact"]["name"]
        body = {
            "_type": ST_EDGE_UPDATE,
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": self.binding,
            "board": release["board_profile"],
            "arch": release["arch"],
            "agent_profile": release["agent_profile"],
            "version": version,
            "security_version": release["security_version"],
            "update_seq": update_seq,
            "not_before": window[0],
            "expires_at": window[1],
            "release_statement": {
                "digest": digest_of(self.payloads[release_rel]),
                "url": f"{RELEASE_HOST}/{version}/{self.naming['statement'].format(artifact=artifact)}",
            },
            "artifact_url": f"{RELEASE_HOST}/{version}/{artifact}",
            "local_approval": False,
            "max_outage_seconds": 120,
        }
        body.update(changes)
        return body

    def edge_updates(self) -> None:
        st = ST_EDGE_UPDATE
        signer = key("edge-provisioning")

        def inputs(release: str = self.REL_170) -> dict:
            return {"release_statement": release}

        def update(release: str = self.REL_170, seq: int = 4, **changes: object) -> dict:
            return self.edge_update(release, seq, **changes)

        good = canonical(update())
        self.signed(
            self.EDGE_UPDATE,
            st,
            good,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="Update of the active revpi-connect4 to release 1.7.0 (security_version 7) at update_seq 4 after 3; root fetches the release statement it names and verifies both (DEC-2.4).",
        )
        self.signed(
            "edge-update/valid/revpi-connect4-1.5.0-at-floor-seq-4.dsse.json",
            st,
            canonical(update(self.REL_150)),
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(self.REL_150),
            description="security_version 5 equals the device's rollback floor 5: not below it, so the update is accepted (DEC-2.5).",
        )
        self.signed(
            "edge-update/valid/revpi-connect4-1.7.0-not-before-now.dsse.json",
            st,
            canonical(update(window=STARTS_NOW)),
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="not_before equal to the evaluation time is inside the window, which is the maintenance window (statements.json dsse.time_window, DEC-13.4).",
        )
        release_ref = update()["release_statement"]
        nested_os = "edge-release/invalid/os-too-old.dsse.json"
        nested_abi = "edge-release/invalid/agent-abi-2.dsse.json"
        nested_kernel = "edge-release/invalid/kernel-config-missing.dsse.json"
        self.negatives(
            "edge-update",
            st,
            signer,
            [
                (
                    "not-yet-valid",
                    update(window=FUTURE),
                    "not-yet-valid",
                    "The maintenance window opens after the evaluation time: root holds the statement and refuses it until then.",
                ),
                (
                    "expired",
                    update(window=EXPIRED),
                    "expired",
                    "The maintenance window closed before the evaluation time.",
                ),
                (
                    "expires-at-now",
                    update(window=EXPIRES_NOW),
                    "expired",
                    "expires_at equal to the evaluation time is outside the window: now < expires_at (statements.json dsse.time_window).",
                ),
                (
                    "wrong-device-binding",
                    update(device_binding=self.other_binding),
                    "device-binding-mismatch",
                    "Bound to another device's TPM EK hash: an update for a second device of the same board cannot be replayed here (EI-038 class).",
                ),
                (
                    "wrong-device-id",
                    update(device_id=OTHER_DEVICE),
                    "device-id-mismatch",
                    "device_id differs from the identity root recorded at first provisioning.",
                ),
                (
                    "wrong-tenant",
                    update(tenant_id=OTHER_TENANT),
                    "tenant-mismatch",
                    "Another tenant's update for this device (DEC-22).",
                ),
                (
                    "wrong-board",
                    update(self.REL_RPI),
                    "board-mismatch",
                    "Consistent rpi4-cm4 update and release statement on a revpi-connect4, whose CM4 GPIO lines drive PiBridge relays (DEC-8.2).",
                    inputs(self.REL_RPI),
                ),
                (
                    "rollback-below-floor",
                    update(self.REL_140),
                    "rollback-below-floor",
                    "Consistent update for release 1.4.0 (security_version 4) on a device whose floor is 5 (DEC-2.5).",
                    inputs(self.REL_140),
                ),
                (
                    "sequence-replay-equal",
                    update(seq=3),
                    "sequence-replay",
                    "update_seq equal to the last accepted one: equal_seq is reject for updates, because every update causes a transition and is never applied twice (DEC-2.4).",
                ),
                (
                    "sequence-replay-lower",
                    update(seq=2),
                    "sequence-replay",
                    "update_seq below the last accepted one: an old valid update replayed by a compromised agent (DEC-2.4).",
                ),
                (
                    "release-digest-mismatch",
                    update(
                        release_statement={
                            **release_ref,
                            "digest": digest_of(self.payloads[self.REL_140]),
                        }
                    ),
                    "release-digest-mismatch",
                    "Names the 1.4.0 release statement digest while the 1.7.0 release statement is what the location serves.",
                ),
                (
                    "release-mismatch",
                    update(security_version=8),
                    "release-mismatch",
                    "Claims security_version 8 for the 1.7.0 release statement it names (security_version 7, DEC-3.1).",
                ),
                (
                    "nested-os-too-old",
                    update(nested_os),
                    "os-version-too-old",
                    "The update is valid but the release statement it names needs OS 1.1.0 and the device runs 1.0.0: the release's compatibility is checked as for an install (DEC-23).",
                    inputs(nested_os),
                ),
                (
                    "nested-agent-abi",
                    update(nested_abi),
                    "agent-abi-unsupported",
                    "The release statement it names has agent_abi 2, outside the device's SUDERRA_AGENT_ABI range 1-1 (DEC-23).",
                    inputs(nested_abi),
                ),
                (
                    "nested-kernel-config",
                    update(nested_kernel),
                    "kernel-config-missing",
                    "The release statement it names requires CONFIG_CAN_RAW, which the device kernel config does not list (DEC-23).",
                    inputs(nested_kernel),
                ),
                (
                    "approvals-member",
                    {**update(), "approvals": []},
                    "schema-invalid",
                    "An approvals member: contract 1.x edge-update.v1 has none, and the two-person approval of P2 arrives as suderra.edge-update.v2, which a v1 verifier must not read as v1 (DEC-2.4, statements.json planned_successors).",
                ),
                (
                    "http-artifact-url",
                    update(artifact_url=f"http://edge-releases.example.com/agent/1.7.0/{json.loads(self.payloads[self.REL_170])['artifact']['name']}"),
                    "schema-invalid",
                    "The artifact is named by a plain http URL; the update channel is https only.",
                ),
                (
                    "outage-budget-zero",
                    update(max_outage_seconds=0),
                    "schema-invalid",
                    "An outage budget of 0 seconds: no update can restart an agent in no time, so the budget is at least 1.",
                ),
            ],
            inputs=inputs(),
        )
        self.envelope_negatives(
            "edge-update",
            st,
            good,
            signer,
            key("edge-release"),
            context="revpi-active",
            inputs=inputs(),
        )
        self.alias(
            self.EDGE_UPDATE,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            inputs=inputs(),
            description="Signed by edge-provisioning epoch 1 on a device whose provisioning ratchet is 2.",
        )
        self.alias(
            self.PROV_AGAIN,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs=inputs(),
            description="A provisioning manifest, signed by the same key, presented as an update request: it cannot be replayed as another statement kind (DEC-2.4).",
        )
        self.alias(
            self.EDGE_UPDATE,
            ST_PROV,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs=self.provisioning_inputs(),
            description="An update statement, signed by the same key, presented where a provisioning manifest is expected: an update is not a provisioning (DEC-2.4).",
        )
        self.alias(
            self.REL_170,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs=inputs(),
            description="A release statement presented as an update request, as contract 1.0 agents carried it: it is not device-bound and authorizes nothing.",
        )

    def os_update(self, update_seq: int, window: tuple[str, str] = VALID, **changes: object) -> dict:
        version = "1.1.0"
        body = {
            "_type": ST_OS_UPDATE,
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": self.binding,
            "version": version,
            "compatible": self.boards["revpi-connect4"]["rauc_compatible"],
            "min_current_version": OS_VERSION,
            "rollback_floor": OS_ROLLBACK_FLOOR,
            "supported_agent_abi": "1-2",
            "update_seq": update_seq,
            "not_before": window[0],
            "expires_at": window[1],
            "bundle": {
                "url": f"{OS_HOST}/{version}/suderra-os-revpi-connect4-{version}.raucb",
                "digest": {"sha256": label_digest(f"RAUC bundle {version} of revpi-connect4")},
                "size_bytes": BUNDLE_SIZE,
            },
            "local_approval": True,
            "max_outage_seconds": 600,
        }
        body.update(changes)
        return body

    def os_updates(self) -> None:
        st = ST_OS_UPDATE
        signer = key("edge-provisioning")

        def update(seq: int = 3, **changes: object) -> dict:
            return self.os_update(seq, **changes)

        good = canonical(update())
        self.signed(
            self.OS_UPDATE,
            st,
            good,
            signer,
            expect="accept",
            context="revpi-active",
            description="RAUC bundle for OS 1.1.0 on the running 1.0.0 revpi-connect4 at update_seq 3 after 2: min_current_version equals the running version, and the installed agent ABI 1 is inside the new OS's 1-2 (DEC-2.9, DEC-23).",
        )
        self.signed(
            "os-update/valid/revpi-connect4-1.0.0-at-floor-seq-3.dsse.json",
            st,
            canonical(update(version="1.0.0")),
            signer,
            expect="accept",
            context="revpi-active",
            description="version 1.0.0 equals the device's OS rollback floor 1.0.0: not below it, so the bundle is accepted (DEC-2.5).",
        )
        self.signed(
            "os-update/valid/revpi-connect4-1.1.0-not-before-now.dsse.json",
            st,
            canonical(update(window=STARTS_NOW)),
            signer,
            expect="accept",
            context="revpi-active",
            description="not_before equal to the evaluation time is inside the window (statements.json dsse.time_window).",
        )
        self.signed(
            "os-update/valid/revpi-connect4-abi-at-max.dsse.json",
            st,
            canonical(update(supported_agent_abi="0-1")),
            signer,
            expect="accept",
            context="revpi-active",
            description="The installed agent's ABI 1 equals the highest ABI the new OS supports (range 0-1): the range is inclusive at both ends (DEC-23).",
        )
        other_compatible = self.boards["rpi4-cm4"]["rauc_compatible"]
        self.negatives(
            "os-update",
            st,
            signer,
            [
                (
                    "not-yet-valid",
                    update(window=FUTURE),
                    "not-yet-valid",
                    "The maintenance window opens after the evaluation time.",
                ),
                (
                    "expired",
                    update(window=EXPIRED),
                    "expired",
                    "The maintenance window closed before the evaluation time.",
                ),
                (
                    "wrong-device-binding",
                    update(device_binding=self.other_binding),
                    "device-binding-mismatch",
                    "Bound to another device's TPM EK hash.",
                ),
                (
                    "wrong-device-id",
                    update(device_id=OTHER_DEVICE),
                    "device-id-mismatch",
                    "Another device's OS update.",
                ),
                (
                    "wrong-tenant",
                    update(tenant_id=OTHER_TENANT),
                    "tenant-mismatch",
                    "Another tenant's OS update for this device (DEC-22).",
                ),
                (
                    "compatible-mismatch",
                    update(compatible=other_compatible),
                    "compatible-mismatch",
                    "A correctly signed bundle for the rpi4-cm4 image on a revpi-connect4: a bundle for another board never installs (DEC-8.3).",
                ),
                (
                    "os-version-too-old",
                    update(version="1.2.0", min_current_version="1.1.0"),
                    "os-version-too-old",
                    "Needs a running OS of at least 1.1.0 and the device runs 1.0.0: the update path skips no required intermediate (DEC-23).",
                ),
                (
                    "rollback-below-floor",
                    update(version="0.9.0", min_current_version="0.8.0", rollback_floor="0.9.0"),
                    "rollback-below-floor",
                    "Installs OS 0.9.0 on a device whose OS rollback floor is 1.0.0 (DEC-2.5).",
                ),
                (
                    "agent-abi-unsupported",
                    update(supported_agent_abi="2-3"),
                    "agent-abi-unsupported",
                    "The new OS supports agent ABIs 2-3 and the installed agent has ABI 1: the OTA preflight refuses it before anything is written (DEC-23).",
                ),
                (
                    "agent-abi-empty-range",
                    update(supported_agent_abi="3-2"),
                    "agent-abi-unsupported",
                    "A range with MIN above MAX contains no ABI, so every installed agent lies outside it (statements.json suderra.os-update.v1 notes).",
                ),
                (
                    "sequence-replay-equal",
                    update(seq=2),
                    "sequence-replay",
                    "update_seq equal to the last accepted one: equal_seq is reject for updates (DEC-2.4).",
                ),
                (
                    "sequence-replay-lower",
                    update(seq=1),
                    "sequence-replay",
                    "update_seq below the last accepted one (DEC-2.4).",
                ),
                (
                    "rollback-floor-above-version",
                    update(rollback_floor="1.2.0"),
                    "schema-invalid",
                    "rollback_floor 1.2.0 above the installed version 1.1.0: the update would forbid the very slot it installs, which JSON Schema cannot state and every verifier reports as schema-invalid.",
                ),
                (
                    "bundle-size-zero",
                    update(
                        bundle={
                            "url": f"{OS_HOST}/1.1.0/suderra-os-revpi-connect4-1.1.0.raucb",
                            "digest": {"sha256": label_digest("RAUC bundle 1.1.0 of revpi-connect4")},
                            "size_bytes": 0,
                        }
                    ),
                    "schema-invalid",
                    "An empty RAUC bundle.",
                ),
                (
                    "unknown-field",
                    {**update(), "debug_shell": True},
                    "schema-invalid",
                    "Signed payload with a member the schema does not define.",
                ),
            ],
        )
        self.envelope_negatives(
            "os-update", st, good, signer, key("edge-release"), context="revpi-active"
        )
        self.alias(
            self.OS_UPDATE,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            description="Signed by edge-provisioning epoch 1 on a device whose provisioning ratchet is 2.",
        )
        self.alias(
            self.EDGE_UPDATE,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            description="An agent update statement, signed by the same key, presented as an OS update: the two cannot be replayed as each other (DEC-2.4).",
        )
        self.alias(
            self.OS_UPDATE,
            ST_EDGE_UPDATE,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs={"release_statement": self.REL_170},
            description="An OS update statement, signed by the same key, presented as an agent update request.",
        )
        self.alias(
            "os-update/invalid/agent-abi-unsupported.dsse.json",
            st,
            expect="accept",
            context="revpi-no-agent",
            description="The same ABI range the agent-abi-unsupported fixture refuses, on a device with no agent release installed: there is nothing to be incompatible with, so the check passes (statements.json suderra.os-update.v1 notes).",
        )

    def netpolicy(self, update_seq: int, window: tuple[str, str] = VALID, **changes: object) -> dict:
        body = {
            "_type": ST_NETPOL,
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": self.binding,
            "update_seq": update_seq,
            "not_before": window[0],
            "expires_at": window[1],
            "interfaces": [
                {"role": "wan", "mac": "02:00:00:7e:57:01"},
                {"role": "ot", "pci_path": "0000:01:00.0"},
            ],
            "ot_rules": [
                {
                    "id": "plc-modbus",
                    "proto": "tcp",
                    "dst": "192.168.10.0/24",
                    "ports": [{"from": 502, "to": 502}],
                },
                {
                    "id": "plc-opcua",
                    "proto": "tcp",
                    "dst": "192.168.10.20/32",
                    "ports": [{"from": 4840, "to": 4840}],
                },
            ],
            "time_sources": [{"id": "site-ntp", "host": "ntp.site.example.com", "nts": True}],
        }
        body.update(changes)
        return body

    def netpolicies(self) -> None:
        st = ST_NETPOL
        signer = key("config-integrity")
        inputs = {"trust_anchors": self.TA1}
        installed = canonical(self.netpolicy(1, INSTALLED_YESTERDAY))
        self.signed(
            self.NETPOL1,
            st,
            installed,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs,
            description="The site policy the active device installed yesterday at update_seq 1; its window has passed, and re-presenting the identical statement is a re-verification (statements.json sequences, DEC-11.7).",
        )
        wide = canonical(
            self.netpolicy(
                2,
                ot_rules=[
                    {
                        "id": "plc-modbus",
                        "proto": "tcp",
                        "dst": "192.168.10.0/24",
                        "ports": [{"from": 502, "to": 502}, {"from": 5020, "to": 5029}],
                    },
                    {
                        "id": "bacnet-site",
                        "proto": "udp",
                        "dst": "10.0.0.0/8",
                        "ports": [{"from": 47808, "to": 47808}],
                        "wide": True,
                    },
                ],
                time_sources=[
                    {"id": "site-ntp", "host": "ntp.site.example.com", "nts": True},
                    {"id": "plant-clock", "host": "10.1.1.1", "nts": False, "unauthenticated": True},
                ],
            )
        )
        self.signed(
            self.NETPOL2,
            st,
            wide,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs,
            description="Next policy at update_seq 2: a port range, a flagged /8 (wide true) and a plain-NTP source that is explicitly marked unauthenticated (DEC-7.1, DEC-11.7).",
        )
        self.signed(
            "site-netpolicy/valid/policy-empty-seq-2.dsse.json",
            st,
            canonical(self.netpolicy(2, interfaces=[], ot_rules=[], time_sources=[])),
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs,
            description="A policy with no interface override, no OT rule and no site NTP source: the board profile's roles stay, the OT side allows nothing and only the pinned NTS servers are used.",
        )
        self.signed(
            "site-netpolicy/valid/policy-not-before-now.dsse.json",
            st,
            canonical(self.netpolicy(2, STARTS_NOW)),
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs,
            description="not_before equal to the evaluation time is inside the window (statements.json dsse.time_window).",
        )

        def rules(**first: object) -> list[dict]:
            rule = {
                "id": "plc-modbus",
                "proto": "tcp",
                "dst": "192.168.10.0/24",
                "ports": [{"from": 502, "to": 502}],
            }
            rule.update(first)
            return [rule]

        self.negatives(
            "site-netpolicy",
            st,
            signer,
            [
                (
                    "not-yet-valid",
                    self.netpolicy(2, FUTURE),
                    "not-yet-valid",
                    "Validity window starts after the evaluation time.",
                ),
                (
                    "expired",
                    self.netpolicy(2, EXPIRED),
                    "expired",
                    "Validity window ended before the evaluation time.",
                ),
                (
                    "wrong-device-binding",
                    self.netpolicy(2, device_binding=self.other_binding),
                    "device-binding-mismatch",
                    "Bound to another device's TPM EK hash: another site's allowlist cannot be replayed here.",
                ),
                (
                    "wrong-device-id",
                    self.netpolicy(2, device_id=OTHER_DEVICE),
                    "device-id-mismatch",
                    "Another device's policy.",
                ),
                (
                    "wrong-tenant",
                    self.netpolicy(2, tenant_id=OTHER_TENANT),
                    "tenant-mismatch",
                    "Another tenant's policy for this device (DEC-22).",
                ),
                (
                    "sequence-replay",
                    self.netpolicy(1, ot_rules=rules(proto="udp")),
                    "sequence-replay",
                    "update_seq 1 again but not the policy the device accepted at 1: equal is accepted only for the identical statement (DEC-2.4).",
                ),
                (
                    "unknown-field",
                    {**self.netpolicy(2), "default_allow": True},
                    "schema-invalid",
                    "Signed payload with a member the schema does not define: there is no way to switch the default deny off (DEC-11.1).",
                ),
                (
                    "dst-host-bits",
                    self.netpolicy(2, ot_rules=rules(dst="192.168.10.5/24")),
                    "schema-invalid",
                    "192.168.10.5/24 has host bits set; a CIDR names a network, and a renderer must not guess which was meant.",
                ),
                (
                    "all-addresses-without-flag",
                    self.netpolicy(2, ot_rules=rules(dst="0.0.0.0/0")),
                    "schema-invalid",
                    "0.0.0.0/0 without wide true: the whole address space is forbidden unless the policy flags it explicitly (DEC-11.7).",
                ),
                (
                    "wide-prefix-without-flag",
                    self.netpolicy(2, ot_rules=rules(dst="10.0.0.0/8")),
                    "schema-invalid",
                    "A /8 without wide true: every prefix shorter than /16 needs the flag.",
                ),
                (
                    "wide-flag-on-narrow-prefix",
                    self.netpolicy(2, ot_rules=rules(wide=True)),
                    "schema-invalid",
                    "wide true on a /24: the flag marks a deliberate wide prefix and is not a way to waive nothing.",
                ),
                (
                    "port-range-reversed",
                    self.netpolicy(2, ot_rules=rules(ports=[{"from": 600, "to": 500}])),
                    "schema-invalid",
                    "A port range whose from is above its to; JSON Schema cannot state it.",
                ),
                (
                    "duplicate-rule-id",
                    self.netpolicy(2, ot_rules=rules() + rules(dst="192.168.20.0/24")),
                    "schema-invalid",
                    "Two rules with the id plc-modbus: a rule is named once.",
                ),
                (
                    "duplicate-interface-mac",
                    self.netpolicy(
                        2,
                        interfaces=[
                            {"role": "wan", "mac": "02:00:00:7e:57:01"},
                            {"role": "ot", "mac": "02:00:00:7e:57:01"},
                        ],
                    ),
                    "schema-invalid",
                    "One MAC address mapped to both roles: an interface has one role.",
                ),
                (
                    "plain-ntp-without-mark",
                    self.netpolicy(
                        2, time_sources=[{"id": "plant-clock", "host": "10.1.1.1", "nts": False}]
                    ),
                    "schema-invalid",
                    "A source without NTS and without unauthenticated true: DEC-7.1 uses such a server only when the policy marks it explicitly.",
                ),
                (
                    "duplicate-time-source-id",
                    self.netpolicy(
                        2,
                        time_sources=[
                            {"id": "site-ntp", "host": "ntp.site.example.com", "nts": True},
                            {"id": "site-ntp", "host": "ntp2.site.example.com", "nts": True},
                        ],
                    ),
                    "schema-invalid",
                    "Two time sources with the id site-ntp: a source is named once.",
                ),
                (
                    "duplicate-time-source-host",
                    self.netpolicy(
                        2,
                        time_sources=[
                            {"id": "site-ntp", "host": "ntp.site.example.com", "nts": True},
                            {"id": "site-ntp-2", "host": "ntp.site.example.com", "nts": True},
                        ],
                    ),
                    "schema-invalid",
                    "The same host listed twice as a time source.",
                ),
            ],
            inputs=inputs,
        )
        self.envelope_negatives(
            "site-netpolicy",
            st,
            wide,
            signer,
            key("rbac-manifest"),
            context="revpi-active",
            inputs=inputs,
        )
        self.alias(
            self.NETPOL2,
            st,
            expect="reject",
            reason="key-epoch-below-ratchet",
            context="revpi-active-ratchets-2",
            inputs=inputs,
            description="Signed by config-integrity epoch 1 on a device whose config-integrity ratchet is 2.",
        )
        self.alias(
            self.SITE_SEQ2,
            st,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs=inputs,
            description="A site config, signed by the same key, presented as a site policy: the two are separate statements with separate sequences.",
        )
        self.alias(
            self.NETPOL2,
            ST_SITE,
            expect="reject",
            reason="payload-type-mismatch",
            context="revpi-active",
            inputs={
                "trust_anchors": self.TA1,
                "rbac_manifest": self.RBAC1,
                "site_files": dict(FILES_V2),
            },
            description="A site policy, signed by the same key, presented where a site config is expected.",
        )
        self.alias(
            self.NETPOL1,
            st,
            expect="accept",
            context="revpi-active",
            inputs=inputs,
            mode="reverify",
            description="Root's re-verification of the installed site policy before the ruleset is loaded again: the window has passed, the statement re-verifies (statements.json reverification).",
        )
        self.alias(
            self.NETPOL2,
            st,
            expect="reject",
            reason="installed-digest-mismatch",
            context="revpi-active",
            inputs=inputs,
            mode="reverify",
            description="Re-verification finds a policy other than the installed one.",
        )

    def site_updates(self) -> None:
        """Site config version 3 on the update channel: it adds the I/O map file and
        names the site bundle that root fetches in place of a provisioning delivery."""
        st = ST_SITE
        signer = key("config-integrity")
        bundle_url = f"{SITE_HOST}/{DEVICE}/3/site-bundle.json"
        body = canonical(
            self.site_config(3, FILES_V3, self.RBAC1, VALID, site_bundle_url=bundle_url)
        )
        bundle = self.site_bundle(FILES_V3, self.RBAC1)
        self.runtime_doc(
            self.SITE_BUNDLE3,
            bundle,
            "suderra.site-bundle.v1",
            description="The site bundle site config version 3 names: its three site files and the RBAC manifest.",
        )
        inputs = {"trust_anchors": self.TA1, "site_bundle": self.SITE_BUNDLE3}
        self.signed(
            self.SITE_SEQ3,
            st,
            body,
            signer,
            expect="accept",
            context="revpi-active",
            inputs=inputs,
            description="Site config version 3 as it arrives on the update channel: it names the I/O map io-config.yaml and a site_bundle_url, and the delivered bundle carries exactly the named files and RBAC manifest (DEC-4.12).",
        )
        self.alias(
            self.SITE_SEQ3,
            st,
            expect="accept",
            context="revpi-active",
            inputs={
                "trust_anchors": self.TA1,
                "rbac_manifest": self.RBAC1,
                "site_files": dict(FILES_V3),
            },
            description="The same site config with its files delivered one by one, as a provisioning delivery carries them: the bundle is only a transport (DEC-4.12).",
        )
        tampered = copy.deepcopy(bundle)
        tampered["site_files"]["io-config.yaml"] = b64(
            self.site_bytes("site-files/v3/io-config.yaml") + b"# changed in transit\n"
        )
        swapped = copy.deepcopy(bundle)
        swapped["rbac_manifest"] = self.envelopes[self.RBAC2]
        extra = copy.deepcopy(bundle)
        extra["site_files"]["hardware-inventory.yaml"] = b64(
            self.site_bytes("site-files/extra/hardware-inventory.yaml")
        )
        for name, doc, reason, text in [
            (
                "site-file-tampered",
                tampered,
                "site-file-digest-mismatch",
                "io-config.yaml altered in transit: the bundle is unsigned and every byte is checked against the signed site config, so the update fails.",
            ),
            (
                "rbac-manifest-swapped",
                swapped,
                "rbac-manifest-digest-mismatch",
                "The bundle carries RBAC manifest policy 2 while the site config names policy 1.",
            ),
            (
                "unnamed-site-file",
                extra,
                "site-file-digest-mismatch",
                "The bundle carries hardware-inventory.yaml, which the site config does not name; root installs exactly the named files.",
            ),
        ]:
            rel = f"site-bundle/mismatched/{name}.json"
            self.runtime_doc(
                rel,
                doc,
                "suderra.site-bundle.v1",
                description=f"A well-formed bundle that fails against its site config: {text}",
            )
            self.alias(
                self.SITE_SEQ3,
                st,
                expect="reject",
                reason=reason,
                context="revpi-active",
                inputs={"trust_anchors": self.TA1, "site_bundle": rel},
                description=text,
            )

        self.family(
            "suderra.site-bundle.v1",
            "site-bundle",
            {},
            {
                "no-config-yaml": (
                    {
                        **bundle,
                        "site_files": {
                            k: v for k, v in bundle["site_files"].items() if k != "config.yaml"
                        },
                    },
                    "schema-invalid",
                    "A bundle without config.yaml: every site config names it.",
                ),
                "unknown-site-path": (
                    {
                        **bundle,
                        "site_files": {**bundle["site_files"], "etc/passwd": b64(b"root::0:0\n")},
                    },
                    "schema-invalid",
                    "A file path outside the fixed site names: no path component comes from a document (DEC-1.10).",
                ),
                "padded-base64": (
                    {
                        **bundle,
                        "site_files": {**bundle["site_files"], "config.yaml": "dGVzdA"},
                    },
                    "schema-invalid",
                    "Base64 without its padding is not the canonical encoding.",
                ),
                "no-rbac-manifest": (
                    {k: v for k, v in bundle.items() if k != "rbac_manifest"},
                    "schema-invalid",
                    "A bundle without the RBAC manifest the site config names.",
                ),
                "unknown-member": (
                    {**bundle, "restart": True},
                    "schema-invalid",
                    "A member the schema does not define: a bundle carries data, never instructions.",
                ),
            },
        )

    def site_bundle(self, files: dict[str, str], rbac_rel: str) -> dict:
        return {
            "_type": "suderra.site-bundle.v1",
            "rbac_manifest": self.envelopes[rbac_rel],
            "site_files": {path: b64(self.site_bytes(rel)) for path, rel in sorted(files.items())},
        }

    # --------------------------------------------------------- runtime documents
    def runtime_doc(
        self,
        rel: str,
        doc: object,
        document_type: str,
        *,
        description: str,
        expect: str = "accept",
        reason: str | None = None,
        raw: bytes | None = None,
    ) -> None:
        self.put(f"fixtures/{rel}", raw if raw is not None else pretty(doc))
        item: dict = {"path": rel, "document_type": document_type, "expect": expect}
        if reason is not None:
            item["reason"] = reason
        item["description"] = description
        self.runtime.append(item)

    def family(self, document_type: str, folder: str, valid: dict, invalid: dict) -> None:
        for name, (doc, text) in valid.items():
            self.runtime_doc(f"{folder}/valid/{name}.json", doc, document_type, description=text)
        for name, (doc, reason, text) in invalid.items():
            self.runtime_doc(
                f"{folder}/invalid/{name}.json",
                doc,
                document_type,
                expect="reject",
                reason=reason,
                description=text,
            )

    def runtime_documents(self) -> None:
        # /run/suderra/identity.json
        identity = {"board_profile": "revpi-connect4", "device_binding": self.binding}
        device = {"tenant_id": TENANT, "device_id": DEVICE, "device_code": DEVICE_CODE}
        duplicated = (
            b'{"board_profile":"revpi-connect4","board_profile":"rpi4-cm4","device_binding":'
            + canonical(self.binding)
            + b"}\n"
        )
        self.family(
            "suderra.identity.v1",
            "identity",
            {
                "factory": (
                    identity,
                    "A device with a hardware identity and no tenant yet: the mirror before the first manifest is installed.",
                ),
                "provisioned": (
                    {**identity, "device": device},
                    "After the first manifest was installed: device.json embedded as the P0 mirror writes it.",
                ),
                "installed-manifest": (
                    {
                        **identity,
                        "device": {
                            **device,
                            "installed_manifest": digest_of(self.payloads[self.PROV_FIRST]),
                        },
                    },
                    "The same, plus the digest of the manifest root installed, which the agent sends with its activation request (mutable-state.json ownership_notes identity-installed-manifest).",
                ),
            },
            {
                "machine-id": (
                    {**identity, "machine_id": "0123456789abcdef0123456789abcdef"},
                    "schema-invalid",
                    "A machine-id member: Suderra OS has no machine-id identity, and nothing in the identity may depend on one (DEC-4.9).",
                ),
                "device-without-code": (
                    {**identity, "device": {"tenant_id": TENANT, "device_id": DEVICE}},
                    "schema-invalid",
                    "A device record without its device code.",
                ),
                "unknown-binding-method": (
                    {
                        **identity,
                        "device_binding": {
                            "method": "machine-id-sha256",
                            "digest": digest_of(b"machine id"),
                        },
                    },
                    "schema-invalid",
                    "A binding method outside the closed set of the contract.",
                ),
                "unknown-board": (
                    {**identity, "board_profile": "revpi-core3"},
                    "schema-invalid",
                    "A board outside boards.json.",
                ),
                "uppercase-tenant": (
                    {**identity, "device": {**device, "tenant_id": TENANT.upper()}},
                    "schema-invalid",
                    "A tenant UUID that is not the lowercase canonical form.",
                ),
            },
        )
        self.runtime_doc(
            "identity/invalid/duplicate-member.json",
            None,
            "suderra.identity.v1",
            expect="reject",
            reason="payload-json-invalid",
            raw=duplicated,
            description="board_profile appears twice: a last-member-wins parser would read rpi4-cm4. Duplicate members are rejected for every document of the contract (statements.json dsse.json).",
        )

        # /run/suderra/time-state
        time_base = {
            "_type": "suderra.time-state.v1",
            "floor_at": "2026-10-20T00:00:00Z",
            "updated_at": "2026-10-20T11:59:59Z",
        }
        self.family(
            "suderra.time-state.v1",
            "time-state",
            {
                "synced-nts": (
                    {
                        **time_base,
                        "state": "synced-nts",
                        "last_sync_at": "2026-10-20T11:58:00Z",
                        "offset_ms": -12,
                    },
                    "A clock chrony disciplines against pinned NTS servers.",
                ),
                "synced-unauthenticated": (
                    {
                        **time_base,
                        "state": "synced-unauthenticated",
                        "last_sync_at": "2026-10-20T11:58:00Z",
                        "offset_ms": 40,
                    },
                    "A clock disciplined by a site NTP server the signed site policy marked unauthenticated (DEC-7.1).",
                ),
                "unsynced": (
                    {**time_base, "state": "unsynced", "last_sync_at": None, "offset_ms": None},
                    "A clock that only passed the time floor: not a synchronized one.",
                ),
            },
            {
                "unsynced-with-offset": (
                    {**time_base, "state": "unsynced", "last_sync_at": None, "offset_ms": 5},
                    "schema-invalid",
                    "An unsynced clock reports no offset: there is no source to measure one against.",
                ),
                "synced-without-sync-time": (
                    {**time_base, "state": "synced-nts", "last_sync_at": None, "offset_ms": 3},
                    "schema-invalid",
                    "A synchronized clock names the instant of its last synchronization.",
                ),
                "unknown-state": (
                    {**time_base, "state": "synced-gps", "last_sync_at": None, "offset_ms": None},
                    "schema-invalid",
                    "A clock state outside the closed set.",
                ),
                "fractional-seconds": (
                    {
                        **time_base,
                        "updated_at": "2026-10-20T11:59:59.250Z",
                        "state": "unsynced",
                        "last_sync_at": None,
                        "offset_ms": None,
                    },
                    "schema-invalid",
                    "toISOString()-style fractional seconds are not the contract timestamp form.",
                ),
            },
        )

        # /run/suderra/agent-health/health.json
        loops = {
            "live": True,
            "loops": [
                {"loop": "io_poll", "fresh": True, "exited": False, "never_ticked": False},
                {"loop": "script_engine", "fresh": True, "exited": False, "never_ticked": False},
            ],
        }
        health = {
            "schema": "suderra.agent-health.v1",
            "agent_version": "2.0.0-rc.4",
            "pid": 412,
            "phase": "running",
            "degraded": False,
            "control": "enabled",
            "reasons": [],
            "safe_state": {"registered": 4, "applied": 4, "failed": 0},
            "loops": loops,
            "update_blockers": [],
            "status": "running: 4/4 outputs driven safe at boot, control enabled",
            "updated_at": "2026-10-20T11:59:58.123456789+00:00",
        }
        degraded = {
            **health,
            "degraded": True,
            "control": "disabled",
            "reasons": [
                {
                    "code": "gpio-backend-unavailable",
                    "detail": "gpio is configured but this agent build has no gpio driver",
                }
            ],
            "safe_state": {"registered": 4, "applied": 3, "failed": 1},
            "status": "degraded: control disabled, outputs held in their safe state",
        }
        standby = {
            **health,
            "phase": "standby",
            "degraded": True,
            "control": "disabled",
            "reasons": [
                {"code": "config-unverified", "detail": "config.yaml differs from site-config.dsse"}
            ],
            "safe_state": None,
            "loops": None,
            "status": "standby: waiting for a verified configuration",
        }
        self.family(
            "suderra.agent-health.v1",
            "agent-health",
            {
                "running": (health, "READY sent, outputs safe, control enabled, nothing blocks an update."),
                "running-alarm-blocks-update": (
                    {**health, "update_blockers": ["active-alarm"]},
                    "Control is enabled and an alarm is active: root's update worker refuses an update now (DEC-13.4).",
                ),
                "running-forced-output": (
                    {**health, "update_blockers": ["active-alarm", "forced-output"]},
                    "Both blockers at once.",
                ),
                "degraded": (degraded, "Control disabled, outputs held safe, one backend missing (DEC-6.3)."),
                "standby": (
                    standby,
                    "Waiting, with no output touched and no READY, for a configuration the agent can verify (config-unverified).",
                ),
            },
            {
                "standby-not-degraded": (
                    {**standby, "degraded": False, "control": "enabled"},
                    "schema-invalid",
                    "Standby is a degraded state: control stays disabled while the configuration is unverified.",
                ),
                "degraded-with-control-enabled": (
                    {**degraded, "control": "enabled"},
                    "schema-invalid",
                    "degraded true and control enabled contradict each other.",
                ),
                "unknown-reason-code": (
                    {**degraded, "reasons": [{"code": "disk-full", "detail": "no space left"}]},
                    "schema-invalid",
                    "A reason code outside the closed set.",
                ),
                "blockers-missing": (
                    {k: v for k, v in health.items() if k != "update_blockers"},
                    "schema-invalid",
                    "A health view without update_blockers: root treats it as blocked, and the contract calls it non-conforming.",
                ),
                "unknown-blocker": (
                    {**health, "update_blockers": ["low-battery"]},
                    "schema-invalid",
                    "A blocker outside the closed set.",
                ),
                "duplicate-blocker": (
                    {**health, "update_blockers": ["active-alarm", "active-alarm"]},
                    "schema-invalid",
                    "The same blocker twice.",
                ),
                "offset-timestamp": (
                    {**health, "updated_at": "2026-10-20T13:59:58+02:00"},
                    "schema-invalid",
                    "updated_at in a non-UTC offset: the writer's chrono to_rfc3339 of a UTC instant ends in Z or +00:00.",
                ),
                "unknown-member": (
                    {**health, "healthy": True},
                    "schema-invalid",
                    "A member the schema does not define.",
                ),
            },
        )

        # POST /api/devices/activate
        activation = {
            "deviceId": DEVICE,
            "token": "TEST-ONLY-provisioning-token",
            "fingerprint": {
                "macAddresses": [sha256_hex(b"TEST-ONLY mac 02:00:00:7e:57:01")],
                "hostname": "revpi-7e57c0de",
            },
            "agentVersion": "2.0.0-rc.4",
            "deviceBinding": self.binding,
            "installedManifest": digest_of(self.payloads[self.PROV_FIRST]),
        }
        self.family(
            "suderra.edge-activation-request.v1",
            "edge-activation-request",
            {
                "installed-manifest": (
                    activation,
                    "A device that fetched its manifest once: it names the manifest root installed so the receipt can name it too.",
                ),
                "no-installed-manifest": (
                    {k: v for k, v in activation.items() if k != "installedManifest"},
                    "Without installedManifest the cloud names the manifest it issued last in the receipt.",
                ),
            },
            {
                "raw-mac": (
                    {
                        **activation,
                        "fingerprint": {"macAddresses": ["02:00:00:7e:57:01"]},
                    },
                    "schema-invalid",
                    "A raw MAC address: only its SHA-256 leaves the device.",
                ),
                "no-binding": (
                    {k: v for k, v in activation.items() if k != "deviceBinding"},
                    "schema-invalid",
                    "An activation without the hardware binding: a token alone must never activate another device.",
                ),
                "machine-id": (
                    {
                        **activation,
                        "fingerprint": {
                            "macAddresses": activation["fingerprint"]["macAddresses"],
                            "machineId": "0123456789abcdef0123456789abcdef",
                        },
                    },
                    "schema-invalid",
                    "A machine-id in the fingerprint: Suderra OS has none and sends none (DEC-4.9).",
                ),
            },
        )
        response = {
            "success": True,
            "mqtt_broker": "mqtt.example.com",
            "mqtt_port": 8883,
            "mqtt_username": f"device-{DEVICE}",
            "mqtt_password": "TEST-ONLY-mqtt-password-0123456789abcdef",
            "tenant_id": TENANT,
            "device_code": DEVICE_CODE,
            "mqtt_tls_enabled": True,
        }
        self.family(
            "suderra.edge-activation-response.v1",
            "edge-activation-response",
            {"credentials": (response, "The per-device MQTT credentials of a Suderra OS device.")},
            {
                "plain-mqtt-port": (
                    {**response, "mqtt_port": 1883},
                    "schema-invalid",
                    "Port 1883: the only transport is TLS on 8883 (DEC-10.1).",
                ),
                "tls-disabled": (
                    {**response, "mqtt_tls_enabled": False},
                    "schema-invalid",
                    "TLS switched off.",
                ),
                "short-password": (
                    {**response, "mqtt_password": "short"},
                    "schema-invalid",
                    "A password too short to be a generated credential.",
                ),
                "no-tenant": (
                    {k: v for k, v in response.items() if k != "tenant_id"},
                    "schema-invalid",
                    "A response without the tenant the credentials belong to.",
                ),
            },
        )

        # the agent's answer to a hand-off command
        accepted = {
            "commandId": COMMAND_ID,
            "deviceId": DEVICE,
            "success": True,
            "result": {
                "handed_to_root": True,
                "statement_digest": digest_of(self.payloads[self.EDGE_UPDATE]),
            },
            "timestamp": "2026-10-20T12:00:00Z",
        }
        refused = {
            "commandId": COMMAND_ID,
            "deviceId": DEVICE,
            "success": False,
            "result": {"handed_to_root": False, "reasons": ["update-requests-backlog"]},
            "timestamp": "2026-10-20T12:00:00.250Z",
            "error": "4 update requests (262144 bytes) are pending for root; the agent keeps at most 4 (262144 bytes)",
        }
        self.family(
            "suderra.command-handoff-response.v1",
            "command-handoff-response",
            {
                "handed-to-root": (accepted, "The statement is now a file root reads; its digest settles it in the cloud."),
                "refused-backlog": (refused, "Root has not consumed the pending requests: nothing was written."),
                "refused-rejected": (
                    {
                        **refused,
                        "result": {
                            "handed_to_root": False,
                            "reasons": ["payload-type-mismatch", "statement-too-large"],
                        },
                        "error": "statement rejected",
                    },
                    "Several reasons at once.",
                ),
            },
            {
                "success-with-reasons": (
                    {**accepted, "result": {**accepted["result"], "reasons": ["io-error"]}},
                    "schema-invalid",
                    "A success that also names reasons.",
                ),
                "refused-without-error": (
                    {k: v for k, v in refused.items() if k != "error"},
                    "schema-invalid",
                    "A refusal carries the error text the command response always has.",
                ),
                "handed-but-failed": (
                    {**accepted, "success": False, "error": "io"},
                    "schema-invalid",
                    "handed_to_root true cannot be a failed command.",
                ),
                "refused-with-digest": (
                    {**refused, "result": {**refused["result"], "statement_digest": digest_of(b"x")}},
                    "schema-invalid",
                    "A refusal names no statement digest: nothing was written for it.",
                ),
                "uppercase-reason": (
                    {**refused, "result": {"handed_to_root": False, "reasons": ["Statement-Too-Large"]}},
                    "schema-invalid",
                    "Reasons are lowercase hyphenated slugs.",
                ),
                "empty-reasons": (
                    {**refused, "result": {"handed_to_root": False, "reasons": []}},
                    "schema-invalid",
                    "A refusal names at least one reason.",
                ),
            },
        )

    # ------------------------------------------------- update channel and USB vectors
    def channel_vectors(self) -> None:
        spool = json.loads((CONTRACT / "channels.json").read_text())["update_channel"]["spool"]
        usb = json.loads((CONTRACT / "delivery.json").read_text())["usb"]["ingress"]
        limit = int(spool["max_entry_bytes"])
        name = lambda label: sha256_hex(f"TEST-ONLY spool entry {label}".encode()) + ".dsse"  # noqa: E731
        stale = "." + name("crashed writer") + ".tmp-4242"
        entries = [
            ("regular-file", name("a"), "file", 4096, "consume", None, "An ordinary entry."),
            (
                "regular-file-at-limit",
                name("b"),
                "file",
                limit,
                "consume",
                None,
                "Exactly max_entry_bytes: allowed.",
            ),
            (
                "one-byte-over-limit",
                name("c"),
                "file",
                limit + 1,
                "refuse",
                "request-too-large",
                "One byte beyond max_entry_bytes, by fstat on the open descriptor: not read.",
            ),
            (
                "symlink",
                name("d"),
                "symlink",
                0,
                "refuse",
                "request-not-regular-file",
                "A symlink with a valid name: openat(O_NOFOLLOW) refuses it and nothing it points at is read.",
            ),
            (
                "fifo",
                name("e"),
                "fifo",
                0,
                "refuse",
                "request-not-regular-file",
                "A FIFO would block a reader: opened with O_NONBLOCK and refused after fstat.",
            ),
            (
                "directory",
                name("f"),
                "dir",
                0,
                "refuse",
                "request-not-regular-file",
                "A directory with a valid name.",
            ),
            (
                "device-node",
                name("g"),
                "device",
                0,
                "refuse",
                "request-not-regular-file",
                "A device node with a valid name.",
            ),
            (
                "agent-temporary-file",
                stale,
                "file",
                100,
                "ignore",
                None,
                "A dot-file the agent's atomic writer left behind: root never reads one, and the agent removes it before it counts the directory.",
            ),
            (
                "uppercase-hex-name",
                name("h").upper().replace(".DSSE", ".dsse"),
                "file",
                100,
                "ignore",
                None,
                "A name that is not name_pattern (hex must be lowercase) is ignored, not refused.",
            ),
            (
                "wrong-suffix",
                name("i").removesuffix(".dsse") + ".json",
                "file",
                100,
                "ignore",
                None,
                "Another suffix.",
            ),
            (
                "short-name",
                name("j")[1:],
                "file",
                100,
                "ignore",
                None,
                "63 hex digits instead of 64.",
            ),
            (
                "foreign-name",
                "notes.txt",
                "file",
                100,
                "ignore",
                None,
                "A file that belongs to nobody the channel knows.",
            ),
        ]
        content = []
        for rel_id, rel, expect, reason, text in [
            (
                "edge-update",
                self.EDGE_UPDATE,
                "consume",
                None,
                "An edge-update statement: carried.",
            ),
            (
                "os-update",
                self.OS_UPDATE,
                "consume",
                None,
                "An os-update statement: carried.",
            ),
            (
                "site-config",
                self.SITE_SEQ3,
                "consume",
                None,
                "A site-config statement: carried.",
            ),
            (
                "site-netpolicy",
                self.NETPOL2,
                "consume",
                None,
                "A site-netpolicy statement: carried.",
            ),
            (
                "trust-anchors",
                self.TA2,
                "consume",
                None,
                "A trust-anchors statement: carried.",
            ),
            (
                "release-statement",
                self.REL_170,
                "refuse",
                "request-unsupported",
                "A release statement alone: not device-bound, installs nothing; contract 1.0 carried it for want of an update statement.",
            ),
            (
                "provisioning-manifest",
                self.PROV_AGAIN,
                "refuse",
                "request-unsupported",
                "A provisioning manifest travels in a delivery, never on the update channel.",
            ),
            (
                "activation-receipt",
                self.RECEIPT,
                "refuse",
                "request-unsupported",
                "An activation receipt has its own hand-over command and file.",
            ),
            (
                "device-lifecycle",
                self.LIFE,
                "refuse",
                "request-unsupported",
                "A lifecycle statement has its own hand-over command and file.",
            ),
            (
                "rbac-manifest",
                self.RBAC1,
                "refuse",
                "request-unsupported",
                "An RBAC manifest travels inside a site bundle, never alone.",
            ),
        ]:
            content.append(
                {
                    "id": rel_id,
                    "name": digest_of(self.payloads[rel])["sha256"] + ".dsse",
                    "fixture": rel,
                    "expect": expect,
                    **({"reason": reason} if reason is not None else {}),
                    "note": text,
                }
            )
        pending = lambda *sizes: [  # noqa: E731
            {"name": name(f"pending {i}"), "size_bytes": size} for i, size in enumerate(sizes)
        ]
        request = {"name": name("new request"), "size_bytes": 4096}
        full = pending(4096, 4096, 4096, 4096)
        backlog = [
            ("empty-directory", [], request, "write", None, "Nothing pending."),
            ("three-pending", pending(4096, 4096, 4096), request, "write", None, "One below max_pending_entries."),
            (
                "four-pending",
                full,
                request,
                "refuse",
                "update-requests-backlog",
                "max_pending_entries reached: nothing is written until root consumed one.",
            ),
            (
                "four-pending-same-name",
                full,
                {"name": full[0]["name"], "size_bytes": 4096},
                "write",
                None,
                "A request for a statement already in the directory replaces it and is never counted twice.",
            ),
            (
                "bytes-over-limit",
                pending(200000),
                {"name": request["name"], "size_bytes": limit},
                "refuse",
                "update-requests-backlog",
                "One pending entry of 200000 bytes and a request of max_entry_bytes: 265536 bytes exceed max_pending_bytes (262144), although only one entry is pending.",
            ),
            (
                "bytes-at-limit",
                pending(limit, limit, limit),
                {"name": request["name"], "size_bytes": limit},
                "write",
                None,
                "Three full entries and a fourth of max_entry_bytes: exactly max_pending_bytes, allowed.",
            ),
            (
                "stale-temporary-not-counted",
                pending(4096, 4096, 4096) + [{"name": stale, "size_bytes": 4096}],
                request,
                "write",
                None,
                "A dot-file of another process is removed first and does not count against the bound.",
            ),
        ]
        self.put(
            "fixtures/update-channel/spool-vectors.json",
            pretty(
                {
                    "test_only": True,
                    "description": "Vectors of the update-request spool (channels.json update_channel.spool). directory_entries: what root's worker does with one directory entry (consume, ignore or refuse with a result reason); content_entries: what it does with a regular entry holding the named fixture; backlog: whether the agent writes a request into a directory that holds the pending entries.",
                    "limits": {
                        "max_entry_bytes": limit,
                        "max_pending_entries": spool["max_pending_entries"],
                        "max_pending_bytes": spool["max_pending_bytes"],
                    },
                    "name_pattern": spool["name_pattern"],
                    "temporary_name_pattern": spool["temporary_name_pattern"],
                    "directory_entries": [
                        {
                            "id": i,
                            "name": n,
                            "type": ty,
                            "size_bytes": sz,
                            "expect": ex,
                            **({"reason": rs} if rs is not None else {}),
                            "note": nt,
                        }
                        for i, n, ty, sz, ex, rs, nt in entries
                    ],
                    "content_entries": content,
                    "backlog": [
                        {
                            "id": i,
                            "pending": pend,
                            "request": req,
                            "expect": ex,
                            **({"reason": rs} if rs is not None else {}),
                            "note": nt,
                        }
                        for i, pend, req, ex, rs, nt in backlog
                    ],
                }
            ),
        )

        top = usb["layout"]["top_directory"]
        directory = f"{top}/{DEVICE_CODE}"
        artifact = self.naming["artifact"].format(
            version="1.6.0", board_profile="revpi-connect4", arch="aarch64"
        )
        delivery_max = int(usb["limits"]["max_delivery_bytes"])
        artifact_max = int(usb["limits"]["max_artifact_bytes"])

        def entry(path: str, kind: str = "file", size: int = 0) -> dict:
            return {"path": path, "type": kind, "size_bytes": size}

        def device(code: str, *files: tuple[str, str, int]) -> list[dict]:
            return [entry(f"{top}/{code}", "dir")] + [
                entry(f"{top}/{code}/{n}", k, s) for n, k, s in files
            ]

        good = [
            entry(top, "dir"),
            *device(
                DEVICE_CODE,
                ("delivery.json", "file", 48213),
                (artifact, "file", 7340032 + len(artifact)),
            ),
        ]
        sixteen = [entry(top, "dir")] + [
            e for i in range(16) for e in device(f"RPI-{i:08X}", ("delivery.json", "file", 48213))
        ]
        usb_cases = [
            ("device-bundle", good, "accept", None, "One device directory: delivery.json and the artifact."),
            (
                "outside-files-ignored",
                [
                    entry("README.txt", "file", 120),
                    entry("System Volume Information", "dir"),
                    entry("other-bundle", "dir"),
                    entry("other-bundle/payload.bin", "file", 10**9),
                    *good,
                ],
                "accept",
                None,
                "Anything outside the top directory is never read, whatever it is.",
            ),
            (
                "two-devices",
                good + device("RPI-000000A2", ("delivery.json", "file", 48213)),
                "accept",
                None,
                "A medium prepared for two devices: the ingress considers both and processes the one that verifies.",
            ),
            (
                "sixteen-directories",
                sixteen,
                "accept",
                None,
                "Exactly max_directories device directories.",
            ),
            (
                "seventeen-directories",
                sixteen + device("RPI-00000010", ("delivery.json", "file", 48213)),
                "reject",
                "usb-layout-invalid",
                "One directory beyond max_directories: the listing is refused before any file is opened.",
            ),
            (
                "three-files",
                good + [entry(f"{directory}/extra.bin", "file", 10)],
                "reject",
                "usb-layout-invalid",
                "More files than max_files_per_directory.",
            ),
            (
                "unnamed-file",
                device(DEVICE_CODE, ("delivery.json", "file", 48213), ("notes.txt", "file", 10)),
                "reject",
                "usb-layout-invalid",
                "A file that is neither delivery.json nor named like the artifact.",
            ),
            (
                "symlink-delivery",
                device(DEVICE_CODE, ("delivery.json", "symlink", 0)),
                "reject",
                "usb-layout-invalid",
                "delivery.json is a symlink: opened with O_NOFOLLOW and refused.",
            ),
            (
                "fifo-artifact",
                device(DEVICE_CODE, ("delivery.json", "file", 48213), (artifact, "fifo", 0)),
                "reject",
                "usb-layout-invalid",
                "The artifact is a FIFO.",
            ),
            (
                "delivery-at-limit",
                device(DEVICE_CODE, ("delivery.json", "file", delivery_max)),
                "accept",
                None,
                "delivery.json of exactly max_delivery_bytes.",
            ),
            (
                "delivery-over-limit",
                device(DEVICE_CODE, ("delivery.json", "file", delivery_max + 1)),
                "reject",
                "usb-layout-invalid",
                "delivery.json one byte over max_delivery_bytes.",
            ),
            (
                "artifact-at-limit",
                device(
                    DEVICE_CODE,
                    ("delivery.json", "file", 48213),
                    (artifact, "file", artifact_max),
                ),
                "accept",
                None,
                "An artifact of exactly max_artifact_bytes.",
            ),
            (
                "artifact-over-limit",
                device(
                    DEVICE_CODE,
                    ("delivery.json", "file", 48213),
                    (artifact, "file", artifact_max + 1),
                ),
                "reject",
                "usb-layout-invalid",
                "An artifact one byte over max_artifact_bytes.",
            ),
            (
                "file-below-top",
                [entry(top, "dir"), entry(f"{top}/delivery.json", "file", 48213)],
                "reject",
                "usb-layout-invalid",
                "A file directly under the top directory: only device directories belong there.",
            ),
            (
                "nested-directory",
                good + [entry(f"{directory}/nested", "dir")],
                "reject",
                "usb-layout-invalid",
                "A directory inside a device directory.",
            ),
            (
                "bad-directory-name",
                device("RPI 7E57", ("delivery.json", "file", 48213)),
                "reject",
                "usb-layout-invalid",
                "A directory name that is no device code (a space).",
            ),
            (
                "no-delivery",
                device(DEVICE_CODE, (artifact, "file", 7340032)),
                "reject",
                "usb-layout-invalid",
                "A device directory without delivery.json.",
            ),
        ]
        self.put(
            "fixtures/delivery-usb/layout-vectors.json",
            pretty(
                {
                    "test_only": True,
                    "description": "Vectors of the USB provisioning medium's layout (delivery.json usb.ingress.layout and limits): the listing of the medium as the ingress reads it without following links, and whether the layout is acceptable before any file is copied. path is relative to the medium's root and type is file, dir, symlink, fifo or device.",
                    "limits": usb["limits"],
                    "layout": {
                        "top_directory": top,
                        "artifact_name_pattern": usb["layout"]["artifact_name_pattern"],
                    },
                    "vectors": [
                        {
                            "id": i,
                            "entries": ents,
                            "expect": ex,
                            **({"reason": rs} if rs is not None else {}),
                            "note": nt,
                        }
                        for i, ents, ex, rs, nt in usb_cases
                    ],
                }
            ),
        )

    # ----------------------------------------------------------- point-decoding vectors
    def point_vectors(self) -> None:
        p = 2**255 - 19
        d = (-121665 * pow(121666, -1, p)) % p

        def decode(y: int) -> int | None:
            u = (y * y - 1) % p
            v = (d * y * y + 1) % p
            x = pow(u * pow(v, -1, p) % p, (p + 3) // 8, p)
            if (x * x * v - u) % p != 0:
                x = x * pow(2, (p - 1) // 4, p) % p
            return x if (x * x * v - u) % p == 0 else None

        def add(a: tuple, b: tuple) -> tuple:
            (x1, y1, z1, t1), (x2, y2, z2, t2) = a, b
            aa, bb = (y1 - x1) * (y2 - x2) % p, (y1 + x1) * (y2 + x2) % p
            cc, dd = t1 * 2 * d * t2 % p, z1 * 2 * z2 % p
            e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
            return (e * f % p, g * h % p, f * g % p, e * h % p)

        def small_order(x: int, y: int) -> bool:
            acc, base = (0, 1, 1, 0), (x, y, 1, x * y % p)
            for _ in range(3):  # [8]P
                base = add(base, base)
            acc = base
            return acc[0] % p == 0 and (acc[1] - acc[2]) % p == 0

        vectors = []
        for y in range(19):
            x = decode(y)
            if x is None:
                continue
            small = small_order(x, y)
            for sign in (0, 1):
                if x == 0 and sign == 1:
                    continue  # x = 0 with the sign bit set ("negative zero") fails to decode
                high = sign << 255
                for label, value, canonical_point in (("canonical", y, True), ("non-canonical", y + p, False)):
                    encoding = ((value | high).to_bytes(32, "little"))
                    vectors.append(
                        {
                            "id": f"y{y}-{label}-sign{sign}",
                            "encoding_hex": encoding.hex(),
                            "y": y,
                            "sign_bit": sign,
                            "canonical": canonical_point,
                            "small_order": small,
                            "note": (
                                f"y = {y}{' + p' if not canonical_point else ''}, sign bit {sign}: "
                                + ("a canonical encoding" if canonical_point else "a non-canonical encoding (y >= p) of the same point")
                                + (" of a small-order point" if small else " of a valid point of full order")
                            ),
                        }
                    )
        self.put(
            "fixtures/dsse/point-vectors.json",
            pretty(
                {
                    "test_only": True,
                    "description": "Point-decoding vectors for the 'y < p' rule of statements.json dsse.signature_algorithm: every 32-byte encoding with y below 19 that decodes to a curve point, in its canonical form and in the non-canonical form y + p, with either sign bit. A verifier must reject a public key or commitment whose encoding is not canonical; for the points of full order no signature can exist, so these vectors, unlike dsse/signature-vectors.json, test the rule itself.",
                    "vectors": vectors,
                }
            ),
        )

    # -------------------------------------------------------------- deliveries
    def request(self, nonce: str) -> dict:
        return {
            "binding_method": self.binding["method"],
            "binding_sha256": self.binding["digest"]["sha256"],
            "nonce": nonce,
            "board_profile": "revpi-connect4",
            "os_version": OS_VERSION,
            "agent_abi": AGENT_ABI_RANGE,
        }

    def delivery(self, manifest_rel: str, ta: str, site: str, files: dict[str, str]) -> dict:
        return {
            "_type": "suderra.edge-provisioning-delivery.v1",
            "manifest": self.envelopes[manifest_rel],
            "release_statement": self.envelopes[self.REL_160],
            "trust_anchors": self.envelopes[ta],
            "site_config": self.envelopes[site],
            "rbac_manifest": self.envelopes[self.RBAC1],
            "site_files": {path: b64(self.site_bytes(rel)) for path, rel in sorted(files.items())},
        }

    def deliveries_and_requests(self) -> None:
        requests = {
            "revpi-connect4-first": self.request(self.nonce_first),
            "revpi-connect4-reprovision": self.request(self.nonce_again),
        }
        for name, doc in requests.items():
            rel = f"edge-provisioning-request/valid/{name}.json"
            self.put(f"fixtures/{rel}", pretty(doc))
            self.documents.append(
                {
                    "path": rel,
                    "document_type": "suderra.edge-provisioning-request.v1",
                    "expect": "accept",
                    "description": f"Query parameters of the {name} request.",
                }
            )
        bad_requests = {
            "token-in-query": (
                {**requests["revpi-connect4-first"], "token": "TEST-ONLY-token"},
                "The provisioning token belongs in X-Provisioning-Token, never in the URL (DEC-5.5).",
            ),
            "short-nonce": (
                {**requests["revpi-connect4-first"], "nonce": "7e57"},
                "A 16-bit nonce; at least 128 bits are required.",
            ),
        }
        for name, (doc, text) in bad_requests.items():
            rel = f"edge-provisioning-request/invalid/{name}.json"
            self.put(f"fixtures/{rel}", pretty(doc))
            self.documents.append(
                {
                    "path": rel,
                    "document_type": "suderra.edge-provisioning-request.v1",
                    "expect": "reject",
                    "reason": "schema-invalid",
                    "description": text,
                }
            )

        first = self.delivery(self.PROV_FIRST, self.TA1, self.SITE_FIRST, FILES_V1)
        again = self.delivery(self.PROV_AGAIN, self.TA2, self.SITE_SEQ2, FILES_V2)
        tampered = copy.deepcopy(again)
        tampered["site_files"]["config.yaml"] = b64(SITE_FILES["tampered/config.yaml"])
        missing = copy.deepcopy(again)
        del missing["rbac_manifest"]
        swapped = copy.deepcopy(again)
        swapped["manifest"] = self.envelopes[self.RECEIPT]
        cases = [
            (
                "valid/revpi-connect4-first.json",
                first,
                "revpi-factory",
                "revpi-connect4-first",
                "accept",
                None,
                "Golden first-provisioning response body: the manifest and every statement and file it names.",
            ),
            (
                "valid/revpi-connect4-reprovision.json",
                again,
                "revpi-active",
                "revpi-connect4-reprovision",
                "accept",
                None,
                "Golden re-provisioning response body in MAINTENANCE.",
            ),
            (
                "invalid/site-file-tampered.json",
                tampered,
                "revpi-active",
                "revpi-connect4-reprovision",
                "reject",
                "site-file-digest-mismatch",
                "config.yaml altered in transit; the site config's digest no longer matches.",
            ),
            (
                "invalid/missing-rbac-manifest.json",
                missing,
                "revpi-active",
                "revpi-connect4-reprovision",
                "reject",
                "schema-invalid",
                "The RBAC manifest the site config names is not delivered.",
            ),
            (
                "invalid/receipt-as-manifest.json",
                swapped,
                "revpi-active",
                "revpi-connect4-reprovision",
                "reject",
                "payload-type-mismatch",
                "An activation receipt in the manifest member.",
            ),
        ]
        for rel, doc, context, request, expect, reason, text in cases:
            path = f"edge-provisioning-delivery/{rel}"
            self.put(f"fixtures/{path}", pretty(doc))
            item: dict = {
                "path": path,
                "device_context": context,
                "request": f"edge-provisioning-request/valid/{request}.json",
                "expect": expect,
                "description": text,
            }
            if reason is not None:
                item["reason"] = reason
            self.deliveries.append(item)

    # ------------------------------------------------------- unsigned results
    def results(self) -> None:
        base = {
            "_type": "suderra.result.v1",
            "occurred_at": "2026-10-20T11:20:00Z",
            "time_state": "synced-nts",
            "board_profile": "revpi-connect4",
            "os_version": OS_VERSION,
        }
        valid = {
            "edge-install-ok": {
                "seq": 1,
                "kind": "edge-install",
                "outcome": "ok",
                "subject": {
                    "version": "1.6.0",
                    "security_version": 6,
                    "statement_type": ST_RELEASE,
                    "statement_digest": digest_of(self.payloads[self.REL_160]),
                },
            },
            "verify-current-rejected": {
                "seq": 2,
                "kind": "verify-current",
                "outcome": "rejected",
                "reason": "signature-invalid",
                "subject": {"version": "1.6.0", "statement_type": ST_RELEASE},
                "detail": "release statement signature did not verify; start refused",
            },
            "verify-current-site-file": {
                "seq": 3,
                "kind": "verify-current",
                "outcome": "rejected",
                "reason": "site-file-digest-mismatch",
                "subject": {"statement_type": ST_SITE, "update_seq": 2},
                "detail": "config.yaml differs from the install receipt; reload refused",
            },
            "lifecycle-active": {
                "seq": 4,
                "kind": "lifecycle",
                "outcome": "ok",
                "subject": {"lifecycle_from": "PROVISIONING", "lifecycle_to": "ACTIVE"},
            },
            "data-unlock-alarm": {
                "seq": 5,
                "kind": "data-unlock",
                "outcome": "alarm",
                "reason": "data-unmountable",
                "time_state": "unsynced",
                "subject": {"lifecycle_to": "LOCKED"},
                "detail": "LUKS2 unseal failed; lifecycle reads LOCKED (DEC-12)",
            },
            "edge-update-ok": {
                "seq": 6,
                "kind": "edge-update",
                "outcome": "ok",
                "subject": {
                    "version": "1.7.0",
                    "security_version": 7,
                    "statement_type": ST_EDGE_UPDATE,
                    "statement_digest": digest_of(self.payloads[self.EDGE_UPDATE]),
                    "update_seq": 4,
                },
            },
            "edge-update-maintenance-blocked": {
                "seq": 7,
                "kind": "edge-update",
                "outcome": "rejected",
                "reason": "maintenance-blocked",
                "subject": {
                    "statement_type": ST_EDGE_UPDATE,
                    "statement_digest": digest_of(self.payloads[self.EDGE_UPDATE]),
                    "update_seq": 4,
                },
                "detail": "update_blockers of the agent health view: active-alarm",
            },
            "edge-update-approval-missing": {
                "seq": 8,
                "kind": "edge-update",
                "outcome": "rejected",
                "reason": "approval-missing",
                "subject": {
                    "statement_type": ST_EDGE_UPDATE,
                    "statement_digest": digest_of(self.payloads[self.EDGE_UPDATE]),
                    "update_seq": 4,
                },
                "detail": "the window closed without a local operator approval",
            },
            "edge-rollback-health-window": {
                "seq": 9,
                "kind": "edge-rollback",
                "outcome": "failed",
                "reason": "health-window-failed",
                "subject": {"version": "1.7.0", "security_version": 7},
                "detail": "control loop heartbeat did not advance; release 1.6.0 and its site config restored",
            },
            "os-update-ok": {
                "seq": 10,
                "kind": "os-update",
                "outcome": "ok",
                "subject": {
                    "version": "1.1.0",
                    "statement_type": ST_OS_UPDATE,
                    "statement_digest": digest_of(self.payloads[self.OS_UPDATE]),
                    "update_seq": 3,
                },
            },
            "os-update-rauc-failed": {
                "seq": 11,
                "kind": "os-update",
                "outcome": "failed",
                "reason": "rauc-install-failed",
                "subject": {
                    "version": "1.1.0",
                    "statement_type": ST_OS_UPDATE,
                    "statement_digest": digest_of(self.payloads[self.OS_UPDATE]),
                    "update_seq": 3,
                },
                "detail": "rauc install refused the bundle: signature check failed; the running slot is untouched",
            },
            "os-update-compatible-mismatch": {
                "seq": 12,
                "kind": "os-update",
                "outcome": "rejected",
                "reason": "compatible-mismatch",
                "subject": {"statement_type": ST_OS_UPDATE, "update_seq": 3},
            },
            "site-config-ok": {
                "seq": 13,
                "kind": "site-config",
                "outcome": "ok",
                "subject": {
                    "statement_type": ST_SITE,
                    "statement_digest": digest_of(self.payloads[self.SITE_SEQ3]),
                    "update_seq": 3,
                },
            },
            "site-config-bundle-missing": {
                "seq": 14,
                "kind": "site-config",
                "outcome": "rejected",
                "reason": "site-bundle-missing",
                "subject": {"statement_type": ST_SITE, "update_seq": 3},
            },
            "site-config-rsc-load-failed": {
                "seq": 15,
                "kind": "site-config",
                "outcome": "failed",
                "reason": "config-rsc-load-failed",
                "subject": {"statement_type": ST_SITE, "update_seq": 3},
                "detail": "piControl refused revpi/config.rsc; site version 2 restored",
            },
            "site-netpolicy-firewall-load-failed": {
                "seq": 16,
                "kind": "site-netpolicy",
                "outcome": "alarm",
                "reason": "firewall-load-failed",
                "subject": {
                    "statement_type": ST_NETPOL,
                    "statement_digest": digest_of(self.payloads[self.NETPOL2]),
                    "update_seq": 2,
                },
                "detail": "nft -c refused the rendered ruleset; the last-known-good ruleset stays in force",
            },
            "trust-anchors-replay": {
                "seq": 17,
                "kind": "trust-anchors",
                "outcome": "rejected",
                "reason": "sequence-replay",
                "subject": {"statement_type": ST_TA},
            },
            "update-request-too-large": {
                "seq": 18,
                "kind": "update-request",
                "outcome": "rejected",
                "reason": "request-too-large",
                "detail": "entry is 65537 bytes; the limit is 65536",
            },
            "update-request-unsupported": {
                "seq": 19,
                "kind": "update-request",
                "outcome": "rejected",
                "reason": "request-unsupported",
                "detail": "payloadType application/vnd.suderra.edge-release.v1+json is not carried",
            },
            "lockdown-provisioning-mode-active": {
                "seq": 20,
                "kind": "lockdown",
                "outcome": "failed",
                "reason": "provisioning-mode-active",
                "detail": "the one-time-password shadow is still bound over /etc/shadow",
            },
            "lockdown-lifecycle-inconsistent": {
                "seq": 21,
                "kind": "lockdown",
                "outcome": "failed",
                "reason": "lifecycle-inconsistent",
                "subject": {"lifecycle_to": "LOCKED"},
            },
            "provisioning-usb-layout-invalid": {
                "seq": 22,
                "kind": "provisioning",
                "outcome": "rejected",
                "reason": "usb-layout-invalid",
                "detail": "suderra-provisioning/RPI-7E57C0DE holds 3 files; the limit is 2",
            },
        }
        for name, extra in valid.items():
            doc = {**base, **extra}
            rel = f"result/valid/{name}.json"
            self.put(f"fixtures/{rel}", pretty(doc))
            self.documents.append(
                {
                    "path": rel,
                    "document_type": "suderra.result.v1",
                    "expect": "accept",
                    "description": f"{extra['kind']} result, outcome {extra['outcome']}.",
                }
            )
        invalid = {
            "unknown-kind": (
                {**base, "seq": 9, "kind": "firmware-flash", "outcome": "ok"},
                "kind outside the DEC-27 result set.",
            ),
            "rejected-without-reason": (
                {**base, "seq": 9, "kind": "edge-update", "outcome": "rejected"},
                "A non-ok outcome must carry a reason code.",
            ),
            "ok-with-reason": (
                {**base, "seq": 9, "kind": "lockdown", "outcome": "ok", "reason": "io-error"},
                "An ok outcome carries no reason.",
            ),
            "reason-not-for-kind": (
                {
                    **base,
                    "seq": 9,
                    "kind": "data-unlock",
                    "outcome": "alarm",
                    "reason": "signature-invalid",
                },
                "data-unlock verifies no statement, so a statement rejection code is not one of its reasons.",
            ),
            "unknown-field": (
                {**base, "seq": 9, "kind": "lockdown", "outcome": "ok", "authority": "cloud"},
                "Unknown members are rejected.",
            ),
            "fractional-seconds": (
                {
                    **base,
                    "seq": 9,
                    "kind": "lockdown",
                    "outcome": "ok",
                    "occurred_at": "2026-10-20T11:20:00.000Z",
                },
                "toISOString() milliseconds are not the contract timestamp form.",
            ),
            "update-request-statement-reason": (
                {
                    **base,
                    "seq": 9,
                    "kind": "update-request",
                    "outcome": "rejected",
                    "reason": "signature-invalid",
                },
                "update-request verifies no statement, so a statement rejection code is not one of its reasons.",
            ),
            "os-update-compatibility-reason": (
                {
                    **base,
                    "seq": 9,
                    "kind": "os-update",
                    "outcome": "rejected",
                    "reason": "kernel-config-missing",
                },
                "kernel-config-missing is a release compatibility check; an OS update's compatibility reasons are compatible-mismatch, os-version-too-old and agent-abi-unsupported.",
            ),
            "lockdown-lifecycle-store-reason": (
                {
                    **base,
                    "seq": 9,
                    "kind": "lockdown",
                    "outcome": "failed",
                    "reason": "state-corrupt",
                },
                "state-corrupt is the lifecycle store's reason; a lockdown that cannot end provisioning mode reports provisioning-mode-active (EI-084).",
            ),
        }
        for name, (doc, text) in invalid.items():
            rel = f"result/invalid/{name}.json"
            self.put(f"fixtures/{rel}", pretty(doc))
            self.documents.append(
                {
                    "path": rel,
                    "document_type": "suderra.result.v1",
                    "expect": "reject",
                    "reason": "schema-invalid",
                    "description": text,
                }
            )
        surrogate = pretty(
            {
                **base,
                "seq": 9,
                "kind": "lockdown",
                "outcome": "failed",
                "reason": "io-error",
                "detail": "LONE-SURROGATE",
            }
        ).replace(b"LONE-SURROGATE", b"\\ud800")
        rel = "result/invalid/lone-surrogate.json"
        self.put(f"fixtures/{rel}", surrogate)
        self.documents.append(
            {
                "path": rel,
                "document_type": "suderra.result.v1",
                "expect": "reject",
                "reason": "payload-json-invalid",
                "description": "detail holds an unpaired surrogate escape, which JSON.parse and Python accept and serde_json refuses.",
            }
        )

    # ------------------------------------------------------------------ units
    SUDERRA_OS_UNIT = """\
# TEST-ONLY golden unit for the suderra-os profile (contracts/suderra-edge/v1/unit-directives.json).
[Unit]
Description=Suderra edge agent
Documentation=https://github.com/Okan-wqm/aquaculture_platform/tree/main/sens-api-gateway
After=nftables.service time-sync.target
Wants=time-sync.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
ExecStartPre=+/usr/bin/suderra-installer edge verify-current
ExecStart=/opt/suderra/edge/current/suderra-agent
ExecReload=+/usr/bin/suderra-installer edge verify-current
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=300s
TimeoutStopSec=90s
WatchdogSec=60s

User=suderra
Group=suderra
UMask=0077

LimitCORE=0
LimitNOFILE=4096
MemoryMax=256M
CPUQuota=75%
TasksMax=64

CapabilityBoundingSet=
NoNewPrivileges=true

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/var/lib/suderra-site
ReadWritePaths=/var/lib/suderra/state /var/lib/suderra/secrets /var/lib/suderra/queue
ReadWritePaths=/var/lib/suderra/scripts /var/lib/suderra/policy-cache /var/lib/suderra/update-requests
ReadWritePaths=/var/log/suderra /run/suderra/agent-health

ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid

RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=true
RemoveIPC=true
MemoryDenyWriteExecute=true

SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @module @raw-io @reboot @swap @privileged
SystemCallErrorNumber=EPERM

DevicePolicy=closed
DeviceAllow=char-rtc r

StandardInput=null
StandardOutput=journal
StandardError=journal
SyslogIdentifier=suderra-agent
SyslogLevelPrefix=true

[Install]
WantedBy=multi-user.target
"""
    FILTER = (
        "SystemCallFilter=@system-service\n"
        "SystemCallFilter=~@debug @mount @module @raw-io @reboot @swap @privileged\n"
    )

    def generic_unit(self) -> str:
        unit = self.SUDERRA_OS_UNIT.replace("suderra-os profile", "generic-Linux profile")
        unit = unit.replace("ExecStartPre=+/usr/bin/suderra-installer edge verify-current\n", "")
        unit = unit.replace("ExecReload=+/usr/bin/suderra-installer edge verify-current\n", "")
        unit = unit.replace(
            "ExecStart=/opt/suderra/edge/current/suderra-agent",
            "ExecStart=/usr/local/bin/suderra-agent",
        )
        rw = (
            "ReadOnlyPaths=/var/lib/suderra-site\n"
            "ReadWritePaths=/var/lib/suderra/state /var/lib/suderra/secrets /var/lib/suderra/queue\n"
            "ReadWritePaths=/var/lib/suderra/scripts /var/lib/suderra/policy-cache /var/lib/suderra/update-requests\n"
            "ReadWritePaths=/var/log/suderra /run/suderra/agent-health\n"
        )
        assert rw in unit
        unit = unit.replace(
            rw, "ReadOnlyPaths=/etc/suderra\nReadWritePaths=/var/lib/suderra /var/log/suderra\n"
        )
        devices = "".join(
            f"DeviceAllow={d}\n"
            for d in [
                "/dev/gpiomem rw",
                "/dev/i2c-1 rw",
                "/dev/spidev0.0 rw",
                "/dev/spidev0.1 rw",
                "/dev/ttyAMA0 rw",
                "/dev/ttyUSB0 rw",
            ]
        )
        unit = unit.replace("DeviceAllow=char-rtc r\n", devices + "DeviceAllow=char-rtc r\n")
        return unit

    def dropin(self, board: str) -> str:
        rows = self.unit_spec["profiles"]["suderra-os"]["board_dropins"]["boards"][board]
        lines = [f"# TEST-ONLY golden board drop-in for {board}.", "[Service]"]
        for name in ["DeviceAllow", "SupplementaryGroups", "RestrictAddressFamilies"]:
            if name not in rows:
                continue
            if name == "DeviceAllow":
                lines += [f"DeviceAllow={value}" for value in rows[name]]
            else:
                lines.append(f"{name}={' '.join(rows[name])}")
        return "\n".join(lines) + "\n"

    def unit_fixtures(self) -> None:
        base = "unit/valid/suderra-os/suderra-agent.service"
        self.put(f"fixtures/{base}", self.SUDERRA_OS_UNIT.encode())
        for board in sorted(self.unit_spec["profiles"]["suderra-os"]["board_dropins"]["boards"]):
            rel = f"unit/valid/suderra-os/suderra-agent.service.d/10-board-{board}.conf"
            self.put(f"fixtures/{rel}", self.dropin(board).encode())
            self.units.append(
                {
                    "profile": "suderra-os",
                    "board_profile": board,
                    "unit": base,
                    "dropin": rel,
                    "expect": "accept",
                    "description": f"Overlay unit plus the {board} drop-in.",
                }
            )
        generic = "unit/valid/generic/suderra-agent.service"
        self.put(f"fixtures/{generic}", self.generic_unit().encode())
        self.units.append(
            {
                "profile": "generic",
                "board_profile": None,
                "unit": generic,
                "dropin": None,
                "expect": "accept",
                "description": "Generic-Linux reference unit (DEC-1.9, DEC-28).",
            }
        )

        revpi_dropin = "unit/valid/suderra-os/suderra-agent.service.d/10-board-revpi-connect4.conf"
        cap_reset = "unit/valid/capability-reset/suderra-agent.service"
        self.put(
            f"fixtures/{cap_reset}",
            self.SUDERRA_OS_UNIT.replace(
                "CapabilityBoundingSet=\n",
                "CapabilityBoundingSet=CAP_NET_RAW\nCapabilityBoundingSet=\n",
                1,
            ).encode(),
        )
        self.units.append(
            {
                "profile": "suderra-os",
                "board_profile": "revpi-connect4",
                "unit": cap_reset,
                "dropin": revpi_dropin,
                "expect": "accept",
                "description": "CapabilityBoundingSet= after a capability: its empty assignment is the empty set and resets the earlier line (parsing.empty_value_keys).",
            }
        )
        verify = "ExecStartPre=+/usr/bin/suderra-installer edge verify-current\n"
        reload_verify = "ExecReload=+/usr/bin/suderra-installer edge verify-current\n"
        reload_kill = "ExecReload=/bin/kill -HUP $MAINPID\n"
        families = "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"
        cases = [
            (
                "watchdog-granted",
                "DeviceAllow=char-rtc r\n",
                "DeviceAllow=char-rtc r\nDeviceAllow=/dev/watchdog rw\n",
                ["exact:Service.DeviceAllow", "forbidden:Service.DeviceAllow"],
                "Grants the hardware watchdog, which PID1 owns (DEC-6.6, EI-042).",
            ),
            (
                "ambient-capabilities",
                "CapabilityBoundingSet=\n",
                "CapabilityBoundingSet=\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n",
                ["forbidden:Service.AmbientCapabilities"],
                "Ambient capability with an otherwise empty bounding set (DEC-1.8).",
            ),
            (
                "requires-time-sync",
                "Wants=time-sync.target\n",
                "Wants=time-sync.target\nRequires=time-sync.target\n",
                ["forbidden:Unit.Requires"],
                "Hard dependency on time-sync.target (DEC-7.4).",
            ),
            (
                "network-online-ordering",
                "After=nftables.service time-sync.target\nWants=time-sync.target\n",
                "After=nftables.service time-sync.target network-online.target\nWants=time-sync.target network-online.target\n",
                ["forbidden:Unit.After", "forbidden:Unit.Wants"],
                "Waits for network-online.target, so start and safe state wait for the network (DEC-6.2).",
            ),
            (
                "suderra-config-env",
                "NotifyAccess=main\n",
                "NotifyAccess=main\nEnvironment=SUDERRA_CONFIG=/var/lib/suderra/config/config.yaml\n",
                ["forbidden:Service.Environment"],
                "Selects the config path from the environment (DEC-4.5, DEC-19).",
            ),
            (
                "condition-on-current",
                "StartLimitBurst=5\n",
                "StartLimitBurst=5\nConditionPathExists=/opt/suderra/edge/current/suderra-agent\n",
                ["forbidden:Unit.ConditionPathExists"],
                "A missing release would become a silent condition failure (DEC-1.4).",
            ),
            (
                "reboot-on-failure",
                "StartLimitBurst=5\n",
                "StartLimitBurst=5\nFailureAction=reboot\n",
                ["forbidden:Unit.FailureAction"],
                "Escalates an agent failure to an OS reboot (DEC-6.5).",
            ),
            (
                "missing-verify-current",
                verify,
                "",
                ["exact:Service.ExecStartPre"],
                "Starts the binary without re-verifying it (DEC-1.5).",
            ),
            (
                "extra-root-pre-start",
                verify,
                verify + "ExecStartPre=+/usr/bin/suderra-installer site apply\n",
                ["exact:Service.ExecStartPre"],
                "A second root pre-start hook; edge verify-current is the only one (hooks).",
            ),
            (
                "reload-without-verify",
                reload_verify,
                "",
                ["exact:Service.ExecReload"],
                "SIGHUP reload without root verifying the site files first (DEC-4.10).",
            ),
            (
                "reload-order-swapped",
                reload_verify + reload_kill,
                reload_kill + reload_verify,
                ["exact:Service.ExecReload"],
                "Signals the agent before root verifies the site files; ExecReload= runs in order (hooks.reload).",
            ),
            (
                "agent-root-writable",
                "ReadWritePaths=/var/log/suderra /run/suderra/agent-health\n",
                "ReadWritePaths=/var/log/suderra /run/suderra/agent-health /var/lib/suderra\n",
                ["exact:Service.ReadWritePaths"],
                "Makes the whole agent data root writable instead of its subdirectories (DEC-4.11).",
            ),
            (
                "missing-start-limit",
                "StartLimitBurst=5\n",
                "",
                ["present:Unit.StartLimitBurst"],
                "Restart loop without a start limit (DEC-6.5).",
            ),
            (
                "unlisted-key",
                "RemoveIPC=true\n",
                "RemoveIPC=true\nPrivateNetwork=false\n",
                ["unknown:Service.PrivateNetwork"],
                "A key outside the allowlist, even a harmless-looking one.",
            ),
            (
                "reset-syscall-filter",
                self.FILTER,
                self.FILTER + "SystemCallFilter=\n",
                ["exact:Service.SystemCallFilter", "reset:Service.SystemCallFilter"],
                "An empty SystemCallFilter= drops the seccomp filter that the lines above set (parsing.reset_rule).",
            ),
            (
                "reset-then-restore-syscall-filter",
                self.FILTER,
                self.FILTER + "SystemCallFilter=\n" + self.FILTER,
                ["reset:Service.SystemCallFilter"],
                "Resets the filter and sets it again: the effective filter is right, the reset is still a violation.",
            ),
            (
                "syscall-filter-order",
                self.FILTER,
                "SystemCallFilter=~@debug @mount @module @raw-io @reboot @swap @privileged\nSystemCallFilter=@system-service\n",
                ["exact:Service.SystemCallFilter"],
                "Deny-list first: systemd then runs in deny-list mode and the second line un-denies @system-service (parsing.ordered_keys).",
            ),
            (
                "reset-address-families",
                families,
                families + "RestrictAddressFamilies=\n",
                ["exact:Service.RestrictAddressFamilies", "reset:Service.RestrictAddressFamilies"],
                "An empty RestrictAddressFamilies= allows every address family.",
            ),
            (
                "reset-read-only-paths",
                "ReadOnlyPaths=/var/lib/suderra-site\n",
                "ReadOnlyPaths=/var/lib/suderra-site\nReadOnlyPaths=\n",
                ["exact:Service.ReadOnlyPaths", "reset:Service.ReadOnlyPaths"],
                "An empty ReadOnlyPaths= drops the read-only site bind.",
            ),
            (
                "reset-protect-system",
                "ProtectSystem=strict\n",
                "ProtectSystem=strict\nProtectSystem=\n",
                ["exact:Service.ProtectSystem", "reset:Service.ProtectSystem"],
                "An empty ProtectSystem= restores the default, a writable /usr and /etc.",
            ),
        ]
        for name, old, new, violation, text in cases:
            unit = self.SUDERRA_OS_UNIT
            if unit.count(old) != 1:
                raise SystemExit(f"unit fixture {name}: anchor not found exactly once")
            rel = f"unit/invalid/{name}/suderra-agent.service"
            self.put(f"fixtures/{rel}", unit.replace(old, new, 1).encode())
            self.units.append(
                {
                    "profile": "suderra-os",
                    "board_profile": "revpi-connect4",
                    "unit": rel,
                    "dropin": revpi_dropin,
                    "expect": "reject",
                    "violations": violation,
                    "description": text,
                }
            )
        for name, text, violation, description in [
            (
                "dropin-extra-device",
                "DeviceAllow=/dev/gpiomem rw\n",
                ["dropin:Service.DeviceAllow"],
                "revpi drop-in also grants /dev/gpiomem, which races the kernel pibridge driver (DEC-8.8).",
            ),
            (
                "dropin-tpm",
                "DeviceAllow=/dev/tpmrm0 rw\n",
                ["dropin:Service.DeviceAllow", "forbidden:Service.DeviceAllow"],
                "Board drop-in grants the TPM resource manager before the P2 keystore (DEC-21).",
            ),
            (
                "dropin-reset-address-families",
                "RestrictAddressFamilies=\n",
                ["dropin:Service.RestrictAddressFamilies", "reset:Service.RestrictAddressFamilies"],
                "A drop-in that empties RestrictAddressFamilies= would allow every family on that board.",
            ),
        ]:
            rel = f"unit/invalid/{name}/suderra-agent.service.d/10-board-revpi-connect4.conf"
            self.put(f"fixtures/{rel}", (self.dropin("revpi-connect4") + text).encode())
            self.units.append(
                {
                    "profile": "suderra-os",
                    "board_profile": "revpi-connect4",
                    "unit": base,
                    "dropin": rel,
                    "expect": "reject",
                    "violations": violation,
                    "description": description,
                }
            )

    # ---------------------------------------------------------------- vectors
    def vectors(self) -> None:
        pae_cases = [
            ("http://example.com/HelloWorld", b"hello world", "The DSSE v1 protocol example."),
            (
                payload_type(ST_RELEASE),
                "ğüşıöç".encode(),
                "Six two-byte UTF-8 characters: LEN counts 12 bytes, not 6 characters.",
            ),
            (payload_type(ST_PROV), b"", "Empty body: LEN is 0."),
        ]
        self.put(
            "fixtures/dsse/pae-vectors.json",
            pretty(
                {
                    "test_only": True,
                    "vectors": [
                        {
                            "payload_type": t,
                            "payload": b64(body),
                            "pae_hex": pae(t, body).hex(),
                            "note": note,
                        }
                        for t, body, note in pae_cases
                    ],
                }
            ),
        )
        signer = key("edge-release")
        message = b"suderra-edge-contract signature vector"
        good = signer.sign(message)
        bad_s = good[:32] + (int.from_bytes(good[32:], "little") + ED25519_L).to_bytes(32, "little")

        def challenge(r: bytes, a: bytes) -> int:
            return int.from_bytes(hashlib.sha512(r + a + message).digest(), "little") % ED25519_L

        a_pub = signer.raw_public
        s_small_r = (challenge(IDENTITY, a_pub) * signer.scalar) % ED25519_L
        s_noncanon_r = (challenge(NON_CANONICAL_IDENTITY, a_pub) * signer.scalar) % ED25519_L
        s_noncanon_a = SIGVEC_R.scalar % ED25519_L
        vectors = [
            ("valid", a_pub, message, good, True, "edge-release/1 TEST-ONLY key."),
            (
                "non-canonical-s",
                a_pub,
                message,
                bad_s,
                False,
                "S + L: rejected because S is not reduced.",
            ),
            (
                "wrong-message",
                a_pub,
                message + b"!",
                good,
                False,
                "Signature of a different message.",
            ),
            (
                "small-order-public-key",
                IDENTITY,
                b"any message at all",
                IDENTITY + bytes(32),
                False,
                "A and R are the identity point and S is 0, so [S]B = R + [k]A holds for every message; verify_strict rejects small-order A and R.",
            ),
            (
                "small-order-r",
                a_pub,
                message,
                IDENTITY + s_small_r.to_bytes(32, "little"),
                False,
                "Valid A, R the identity, S = k*a mod L: the cofactorless equation holds, so a verifier without the small-order R check accepts it; verify_strict rejects it.",
            ),
            (
                "non-canonical-r",
                a_pub,
                message,
                NON_CANONICAL_IDENTITY + s_noncanon_r.to_bytes(32, "little"),
                False,
                "R encodes y = p + 1, a non-canonical encoding of the identity; the equation holds for the decoded point, verify_strict rejects the encoding.",
            ),
            (
                "non-canonical-a",
                NON_CANONICAL_IDENTITY,
                message,
                SIGVEC_R.raw_public + s_noncanon_a.to_bytes(32, "little"),
                False,
                "A encodes y = p + 1 (the identity, non-canonically) and S = r for R = [r]B, so [S]B = R + [k]A holds for every message; verify_strict rejects A.",
            ),
        ]
        self.put(
            "fixtures/dsse/signature-vectors.json",
            pretty(
                {
                    "test_only": True,
                    "vectors": [
                        {
                            "id": vid,
                            "public_key_hex": pk.hex(),
                            "message_hex": msg.hex(),
                            "signature_hex": sig.hex(),
                            "verify_strict": outcome,
                            "note": note,
                        }
                        for vid, pk, msg, sig, outcome, note in vectors
                    ],
                }
            ),
        )

    # ------------------------------------------------------------------ index
    def context(
        self,
        description: str,
        *,
        identity: bool,
        floor: int,
        accepted: dict,
        installed: str | None,
        os_floor: str = OS_ROLLBACK_FLOOR,
        agent_abi: int | None = INSTALLED_AGENT_ABI,
    ) -> dict:
        return {
            "description": description,
            "board_profile": "revpi-connect4",
            "arch": "aarch64",
            "device_binding": self.binding,
            "tenant_id": TENANT if identity else None,
            "device_id": DEVICE if identity else None,
            "security_version_floor": floor,
            "accepted": accepted,
            "ratchet": {
                purpose: 1
                for purpose in [
                    "command",
                    "config-integrity",
                    "device-lifecycle",
                    "edge-provisioning",
                    "edge-release",
                    "fleet-root",
                    "rbac-manifest",
                ]
            },
            "installed_manifest": installed,
            "os_release": {"VERSION_ID": OS_VERSION, "SUDERRA_AGENT_ABI": AGENT_ABI_RANGE},
            "kernel_config": KERNEL_CONFIG,
            "os_rollback_floor": os_floor,
            "os_compatible": self.boards["revpi-connect4"]["rauc_compatible"],
            "installed_agent_abi": agent_abi,
        }

    def index_file(self) -> None:
        def acc(rel: str, seq: int | None) -> dict:
            out: dict = {"statement_digest": digest_of(self.payloads[rel])}
            if seq is not None:
                out["seq"] = seq
            return out

        contexts = {
            "revpi-factory": self.context(
                "Factory-fresh revpi-connect4 in PROVISIONING: no identity bound, nothing accepted, floor 0, no agent installed.",
                identity=False,
                floor=0,
                accepted={},
                installed=None,
                os_floor="0.0.0",
                agent_abi=None,
            ),
            "revpi-provisioning": self.context(
                "The same device after root installed the first manifest, waiting for the activation receipt.",
                identity=True,
                floor=0,
                installed=self.PROV_FIRST,
                accepted={
                    ST_PROV: acc(self.PROV_FIRST, 1),
                    ST_RELEASE: acc(self.REL_160, None),
                    ST_TA: acc(self.TA1, 1),
                    ST_SITE: acc(self.SITE_FIRST, 1),
                    ST_RBAC: acc(self.RBAC1, 1),
                },
            ),
            "revpi-active": self.context(
                "ACTIVE revpi-connect4 with floor 5; accepted provisioning 3, lifecycle 2, bundle 1, the site config installed yesterday at 1, RBAC policy 1 and release 1.6.0.",
                identity=True,
                floor=5,
                installed=None,
                accepted={
                    ST_PROV: {
                        "seq": 3,
                        "statement_digest": {
                            "sha256": label_digest("accepted provisioning manifest 3")
                        },
                    },
                    ST_LIFE: {
                        "seq": 2,
                        "statement_digest": {
                            "sha256": label_digest("accepted lifecycle statement 2")
                        },
                    },
                    ST_RELEASE: acc(self.REL_160, None),
                    ST_TA: acc(self.TA1, 1),
                    ST_SITE: acc(self.SITE_INSTALLED, 1),
                    ST_RBAC: acc(self.RBAC1, 1),
                    ST_EDGE_UPDATE: {
                        "seq": 3,
                        "statement_digest": {"sha256": label_digest("accepted edge update 3")},
                    },
                    ST_OS_UPDATE: {
                        "seq": 2,
                        "statement_digest": {"sha256": label_digest("accepted os update 2")},
                    },
                    ST_NETPOL: acc(self.NETPOL1, 1),
                },
            ),
        }
        derived = {
            "revpi-active-ratchet-2": (
                "revpi-active",
                "revpi-active after a key-epoch-advance moved the edge-provisioning ratchet to 2.",
                {"edge-provisioning": 2},
            ),
            "revpi-active-ratchets-2": (
                "revpi-active",
                "revpi-active with every ratchet except fleet-root at 2.",
                {
                    p: 2
                    for p in [
                        "command",
                        "config-integrity",
                        "device-lifecycle",
                        "edge-provisioning",
                        "edge-release",
                        "rbac-manifest",
                    ]
                },
            ),
            "revpi-active-fleet-root-ratchet-2": (
                "revpi-active",
                "revpi-active with the fleet-root ratchet at 2.",
                {"fleet-root": 2},
            ),
            "revpi-provisioning-ratchets-2": (
                "revpi-provisioning",
                "revpi-provisioning with every ratchet except fleet-root at 2.",
                {
                    p: 2
                    for p in [
                        "command",
                        "config-integrity",
                        "device-lifecycle",
                        "edge-provisioning",
                        "edge-release",
                        "rbac-manifest",
                    ]
                },
            ),
        }
        for name, (parent, description, ratchets) in derived.items():
            ctx = copy.deepcopy(contexts[parent])
            ctx["description"] = description
            ctx["ratchet"].update(ratchets)
            contexts[name] = ctx
        no_agent = copy.deepcopy(contexts["revpi-active"])
        no_agent["description"] = (
            "revpi-active with no agent release installed (installed_agent_abi null): "
            "the OS update's agent ABI check has nothing to compare."
        )
        no_agent["installed_agent_abi"] = None
        contexts["revpi-no-agent"] = no_agent
        index = {
            "test_only": True,
            "description": "TEST-ONLY golden fixtures of contract v1. Evaluate every statement at evaluation_time against its device_context, inputs, verifier and mode; accept or reject exactly as listed, for exactly the listed reason. statement_type is the call site.",
            "evaluation_time": EVALUATION_TIME,
            "device_contexts": contexts,
            "statements": self.statements,
            "deliveries": self.deliveries,
            "documents": self.documents,
            "runtime_documents": self.runtime,
            "units": self.units,
            "pae_vectors": "dsse/pae-vectors.json",
            "signature_vectors": "dsse/signature-vectors.json",
            "point_vectors": "dsse/point-vectors.json",
            "spool_vectors": "update-channel/spool-vectors.json",
            "usb_layout_vectors": "delivery-usb/layout-vectors.json",
        }
        self.put("fixtures/index.json", pretty(index))

    # ------------------------------------------------------------------- main
    def run(self) -> dict[str, bytes]:
        for rel, data in SITE_FILES.items():
            self.put(f"fixtures/site-files/{rel}", data)
        self.keys()
        self.releases()
        self.trust_anchor_bundles()
        self.rbac_manifests()
        self.site_configs()
        self.provisioning_manifests()
        self.receipts()
        self.lifecycle()
        self.edge_updates()
        self.os_updates()
        self.netpolicies()
        self.site_updates()
        self.runtime_documents()
        self.deliveries_and_requests()
        self.results()
        self.unit_fixtures()
        self.vectors()
        self.point_vectors()
        self.channel_vectors()
        self.index_file()
        return self.files


def sha256sums(files: dict[str, bytes]) -> bytes:
    lines = [f"{sha256_hex(data)}  {rel}\n" for rel, data in sorted(files.items())]
    return "".join(lines).encode()


def hand_authored() -> dict[str, bytes]:
    out = {}
    for path in sorted(CONTRACT.rglob("*")):
        rel = path.relative_to(CONTRACT).as_posix()
        if not path.is_file() or rel == "SHA256SUMS" or rel.split("/")[0] in GENERATED_DIRS:
            continue
        if "__pycache__" in rel.split("/"):
            raise SystemExit(f"stray bytecode in the contract tree: {rel} (run with python3 -B)")
        out[rel] = path.read_bytes()
    return out


def on_disk_generated() -> dict[str, bytes]:
    out = {}
    for top in GENERATED_DIRS:
        for path in sorted((CONTRACT / top).rglob("*")):
            if path.is_file():
                out[path.relative_to(CONTRACT).as_posix()] = path.read_bytes()
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()

    generated = Generator().run()
    expected_sums = sha256sums({**hand_authored(), **generated})

    if args.check:
        problems = []
        disk = on_disk_generated()
        for rel in sorted(set(generated) | set(disk)):
            if rel not in disk:
                problems.append(f"missing: {rel}")
            elif rel not in generated:
                problems.append(f"not produced by the generator: {rel}")
            elif disk[rel] != generated[rel]:
                problems.append(f"differs from a fresh generation: {rel}")
        sums_path = CONTRACT / "SHA256SUMS"
        if not sums_path.is_file() or sums_path.read_bytes() != expected_sums:
            problems.append("SHA256SUMS does not match the tree")
        for line in problems:
            print(line, file=sys.stderr)
        return 1 if problems else 0

    for top in GENERATED_DIRS:
        shutil.rmtree(CONTRACT / top, ignore_errors=True)
    for rel, data in generated.items():
        target = CONTRACT / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (CONTRACT / "SHA256SUMS").write_bytes(expected_sums)
    print(
        f"wrote {len(generated)} generated files and SHA256SUMS ({len(expected_sums.splitlines())} entries)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

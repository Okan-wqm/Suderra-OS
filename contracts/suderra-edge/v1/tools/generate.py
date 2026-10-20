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

TENANT = "7e570000-0000-4000-8000-000000000001"
OTHER_TENANT = "7e570000-0000-4000-8000-000000000002"
DEVICE = "7e570000-0000-4000-8000-0000000000d1"
OTHER_DEVICE = "7e570000-0000-4000-8000-0000000000d2"
ACTIVATION = "7e570000-0000-4000-8000-0000000000a1"
PLATFORM_ACTOR = "7e570000-0000-4000-8000-0000000000c1"
DEVICE_CODE = "RPI-7E57C0DE"
RELEASE_HOST = "https://edge-releases.example.com/agent"

ST_RELEASE = "suderra.edge-release.v1"
ST_PROV = "suderra.edge-provisioning.v1"
ST_RECEIPT = "suderra.edge-activation-receipt.v1"
ST_TA = "suderra.trust-anchors.v1"
ST_LIFE = "suderra.device-lifecycle.v1"
ST_SITE = "suderra.site-config.v1"
ST_RBAC = "suderra.rbac-manifest.v1"

OS_VERSION = "1.0.0"
AGENT_ABI_RANGE = "1-1"
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
        b"device:\n  board_profile: revpi-connect4\nmodbus: []\n"
    ),
    "v1/revpi/config.rsc": b'{"TEST-ONLY": "PiCtory configuration of the contract fixtures"}\n',
    "v2/config.yaml": (
        b"# TEST-ONLY site config of the Suderra edge contract fixtures (version 2).\n"
        b"# config.yaml is the agent's configuration document; the contract binds it by digest.\n"
        b"device:\n  board_profile: revpi-connect4\nmodbus:\n  - name: pond-1-sensors\n    allow_writes: false\n"
    ),
    "tampered/config.yaml": (
        b"# TEST-ONLY site config of the Suderra edge contract fixtures (version 2).\n"
        b"# config.yaml is the agent's configuration document; the contract binds it by digest.\n"
        b"device:\n  board_profile: revpi-connect4\nmodbus:\n  - name: pond-1-sensors\n    allow_writes: true\n"
    ),
    "extra/hardware-inventory.yaml": b"# TEST-ONLY hardware inventory the site config does not name.\n",
}
FILES_V1 = {
    "config.yaml": "site-files/v1/config.yaml",
    "revpi/config.rsc": "site-files/v1/revpi/config.rsc",
}
FILES_V2 = {
    "config.yaml": "site-files/v2/config.yaml",
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
                "The command anchor's keyid is not the SHA-256 of its public key.",
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
        self, description: str, *, identity: bool, floor: int, accepted: dict, installed: str | None
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
        }

    def index_file(self) -> None:
        def acc(rel: str, seq: int | None) -> dict:
            out: dict = {"statement_digest": digest_of(self.payloads[rel])}
            if seq is not None:
                out["seq"] = seq
            return out

        contexts = {
            "revpi-factory": self.context(
                "Factory-fresh revpi-connect4 in PROVISIONING: no identity bound, nothing accepted, floor 0.",
                identity=False,
                floor=0,
                accepted={},
                installed=None,
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
        index = {
            "test_only": True,
            "description": "TEST-ONLY golden fixtures of contract v1. Evaluate every statement at evaluation_time against its device_context, inputs, verifier and mode; accept or reject exactly as listed, for exactly the listed reason. statement_type is the call site.",
            "evaluation_time": EVALUATION_TIME,
            "device_contexts": contexts,
            "statements": self.statements,
            "deliveries": self.deliveries,
            "documents": self.documents,
            "units": self.units,
            "pae_vectors": "dsse/pae-vectors.json",
            "signature_vectors": "dsse/signature-vectors.json",
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
        self.deliveries_and_requests()
        self.results()
        self.unit_fixtures()
        self.vectors()
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

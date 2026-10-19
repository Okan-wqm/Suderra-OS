#!/usr/bin/env python3
"""Regenerate the TEST-ONLY keys and golden fixtures of the Suderra edge contract.

Contract: contracts/suderra-edge/v1 (ADR-048 DEC-25). Requires Python >= 3.10 and
the `cryptography` package.

    python3 -B contracts/suderra-edge/v1/tools/generate.py          # rewrite + SHA256SUMS
    python3 -B contracts/suderra-edge/v1/tools/generate.py --check  # exit 1 on any drift

What it writes: test-keys/, fixtures/ and SHA256SUMS. Everything else in the
contract (VERSION, statements.json, boards.json, artifact-naming.json,
unit-directives.json, mutable-state.json, schemas/) is authored by hand and
only read here; the release fixtures take their features from boards.json and
their artifact names from artifact-naming.json, so a board-map or naming change
shows up as fixture drift.

TEST-ONLY KEY DERIVATION (public on purpose)
    seed = SHA-256(UTF-8 "suderra-edge-contract:v1:TEST-ONLY:<label>:<epoch>")
    key  = the Ed25519 private key whose RFC 8032 seed is `seed`
Anyone can re-derive these private keys from this docstring, which is exactly
why no production verifier may trust them: production pins come only from the
KMS/HSM or offline-ceremony keyid inventory (ADR-048 DEC-3.9), and
tests/invariants/suderra-edge-contracts.spec.ts re-derives every key in
test-keys/ from this rule. Only public keys are written to test-keys/; private
keys exist only in this process. Ed25519 signing is deterministic, so the same
inputs always produce byte-identical fixtures.
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

EVALUATION_TIME = "2026-10-20T12:00:00Z"
VALID_FROM, VALID_UNTIL = "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z"
EXPIRED_FROM, EXPIRED_UNTIL = "2026-10-19T00:00:00Z", "2026-10-19T06:00:00Z"
FUTURE_FROM, FUTURE_UNTIL = "2026-10-21T00:00:00Z", "2026-10-22T00:00:00Z"

TENANT = "7e570000-0000-4000-8000-000000000001"
OTHER_TENANT = "7e570000-0000-4000-8000-000000000002"
DEVICE = "7e570000-0000-4000-8000-0000000000d1"
OTHER_DEVICE = "7e570000-0000-4000-8000-0000000000d2"
ACTIVATION = "7e570000-0000-4000-8000-0000000000a1"
DEVICE_CODE = "RPI-7E57C0DE"
RELEASE_HOST = "https://edge-releases.example.com/agent"


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


# (purpose, epoch, pinned in the OS image). Bundle-only purposes are anchored in
# the trust-anchor bundle, never in /etc/suderra/keys (statements.json purposes).
PINNED_KEYS = [
    ("edge-release", 1, True),
    ("edge-provisioning", 1, True),
    ("edge-provisioning", 2, True),
    ("fleet-root", 1, True),
    ("device-lifecycle", 1, True),
    ("config-integrity", 1, False),
    ("rbac-manifest", 1, False),
    ("command", 1, False),
]
KEYS = {(purpose, epoch): TestKey.derive(purpose, epoch) for purpose, epoch, _ in PINNED_KEYS}
# Signs nothing a verifier knows: it is in no keyring and no OS image.
UNPINNED = TestKey.derive("unpinned", 1)


def key(purpose: str, epoch: int = 1) -> TestKey:
    return KEYS[(purpose, epoch)]


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


class Generator:
    def __init__(self) -> None:
        self.boards = {
            row["board_profile"]: row
            for row in json.loads((CONTRACT / "boards.json").read_text())["boards"]
        }
        self.naming = json.loads((CONTRACT / "artifact-naming.json").read_text())[
            "suderra_os_channel"
        ]
        self.files: dict[str, bytes] = {}
        self.statements: list[dict] = []
        self.documents: list[dict] = []
        self.units: list[dict] = []
        self.payloads: dict[str, bytes] = {}
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

    def statement(
        self,
        rel: str,
        statement_type: str,
        env: dict,
        body: bytes,
        *,
        expect: str,
        context: str | None,
        description: str,
        reason: str | None = None,
        inputs: dict | None = None,
    ) -> None:
        self.put(f"fixtures/{rel}", pretty(env))
        self.payloads[rel] = body
        self.index(
            rel,
            statement_type,
            expect=expect,
            context=context,
            description=description,
            reason=reason,
            inputs=inputs,
        )

    def index(
        self,
        rel: str,
        statement_type: str,
        *,
        expect: str,
        context: str | None,
        description: str,
        reason: str | None = None,
        inputs: dict | None = None,
    ) -> None:
        entry: dict = {
            "path": rel,
            "statement_type": statement_type,
            "expect": expect,
            "device_context": context,
            "inputs": inputs or {},
            "description": description,
        }
        if reason is not None:
            entry["reason"] = reason
        self.statements.append(entry)

    # -------------------------------------------------------------------- keys
    def keys(self) -> None:
        entries = []
        for purpose, epoch, pinned in PINNED_KEYS:
            k = key(purpose, epoch)
            rel = f"test-keys/{purpose}/{epoch}.pub"
            self.put(rel, k.pem)
            entries.append(
                {
                    "purpose": purpose,
                    "epoch": epoch,
                    "keyid": k.keyid,
                    "public_key": b64(k.raw_public),
                    "path": rel,
                    "os_pinned": pinned,
                    "seed_label": k.seed_label,
                }
            )
        keyring = {
            "test_only": True,
            "description": "TEST-ONLY keys of the Suderra edge contract fixtures. Dev, QEMU and CI images may pin the os_pinned keys under /etc/suderra/keys/<purpose>/<epoch>.pub; a production image or production keyid allowlist that contains any keyid listed here is a defect (ADR-048 DEC-3.9).",
            "derivation": "seed = SHA-256(UTF-8 seed_label); the Ed25519 private key is the RFC 8032 key with that seed. The derivation is public, so these keys prove nothing outside tests (tools/generate.py).",
            "keys": entries,
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
    def release(
        self, board: str, version: str, security_version: int, features: list[str] | None = None
    ) -> dict:
        row = self.boards[board]
        artifact = self.naming["artifact"].format(
            version=version, board_profile=board, arch=row["arch"]
        )
        kernel = ["CONFIG_SECCOMP_FILTER"] + {
            "revpi-connect4": [],
            "industrial-x86_64": ["CONFIG_CAN"],
            "rpi4-cm4": ["CONFIG_I2C_CHARDEV", "CONFIG_SPI_SPIDEV"],
            "qemu-x86_64": ["CONFIG_CAN"],
        }[board]
        return {
            "_type": "suderra.edge-release.v1",
            "name": "suderra-agent",
            "version": version,
            "security_version": security_version,
            "board_profile": board,
            "arch": row["arch"],
            "agent_profile": row["agent_profile"],
            "cargo_features": sorted(features if features is not None else row["cargo_features"]),
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
            "required_kernel_config": sorted(kernel),
            "provenance": {
                "predicate_type": "https://slsa.dev/provenance/v1",
                "digest": {"sha256": label_digest(f"provenance of {artifact}")},
            },
        }

    def trust_anchors(
        self,
        bundle_seq: int,
        scope: list[str] | None = None,
        provisioning_anchor: TestKey | None = None,
    ) -> dict:
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
            if purpose == "edge-provisioning" and epoch == 2 and provisioning_anchor is not None:
                k = provisioning_anchor
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
        return {
            "_type": "suderra.trust-anchors.v1",
            "bundle_seq": bundle_seq,
            "issued_at": "2026-10-19T00:00:00Z",
            "tenant_scope": scope if scope is not None else [TENANT],
            "anchors": anchors,
        }

    def provisioning(
        self, *, release_rel: str, ta_rel: str, nonce: str, update_seq: int, **changes: object
    ) -> dict:
        release = json.loads(self.payloads[release_rel])
        ta = json.loads(self.payloads[ta_rel])
        version = release["version"]
        base = f"{RELEASE_HOST}/{version}/{release['artifact']['name']}"
        manifest = {
            "_type": "suderra.edge-provisioning.v2",
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
            "not_before": VALID_FROM,
            "expires_at": VALID_UNTIL,
            "release_statement": {
                "url": f"{base}.release.dsse.json",
                "digest": {"sha256": sha256_hex(self.payloads[release_rel])},
            },
            "artifact_url": base,
            "config_payload": {
                "digest": {"sha256": sha256_hex(self.config_payload)},
                "size_bytes": len(self.config_payload),
            },
            "trust_anchors": {
                "digest": {"sha256": sha256_hex(self.payloads[ta_rel])},
                "bundle_seq": ta["bundle_seq"],
            },
        }
        manifest.update(changes)
        return manifest

    # -------------------------------------------------------------- statements
    def releases(self) -> None:
        st = "suderra.edge-release.v1"
        signer = key("edge-release")
        for board in ["revpi-connect4", "industrial-x86_64", "rpi4-cm4", "qemu-x86_64"]:
            arch = self.boards[board]["arch"]
            body = canonical(self.release(board, "1.6.0", 6))
            rel = f"edge-release/valid/{board}-{arch}-1.6.0.dsse.json"
            self.statement(
                rel,
                st,
                envelope(st, body, signer),
                body,
                expect="accept",
                context=None,
                description=f"Release statement for {board}/{arch} whose features and artifact name match boards.json.",
            )
        body = canonical(self.release("revpi-connect4", "1.4.0", 4))
        self.statement(
            "edge-release/valid/revpi-connect4-aarch64-1.4.0.dsse.json",
            st,
            envelope(st, body, signer),
            body,
            expect="accept",
            context=None,
            description="Older revpi-connect4 release (security_version 4) used by the rollback fixture.",
        )

        body = canonical(self.release("revpi-connect4", "1.6.0", 6))
        self.statement(
            "edge-release/invalid/signed-by-provisioning-key.dsse.json",
            st,
            envelope(st, body, key("edge-provisioning")),
            body,
            expect="reject",
            reason="key-purpose-mismatch",
            context=None,
            description="The online provisioning key cannot label a binary as a release (DEC-3.1, DEC-3.3).",
        )
        good = envelope(st, body, signer)
        self.statement(
            "edge-release/invalid/bad-signature.dsse.json",
            st,
            tamper(good),
            base64.b64decode(tamper(good)["payload"]),
            expect="reject",
            reason="signature-invalid",
            context=None,
            description="Payload bytes changed after signing (whitespace only, still valid JSON).",
        )
        missing_gpio = [f for f in self.boards["rpi4-cm4"]["cargo_features"] if f != "gpio"]
        body = canonical(self.release("rpi4-cm4", "1.6.0", 6, features=missing_gpio))
        self.statement(
            "edge-release/invalid/missing-board-feature.dsse.json",
            st,
            envelope(st, body, signer),
            body,
            expect="reject",
            reason="release-profile-mismatch",
            context=None,
            description="rpi4-cm4 release built without the gpio feature (INFRA-CRITICAL-236 class).",
        )
        unsafe = self.release("revpi-connect4", "1.6.0", 6)
        unsafe["version"] = "1.6.0-../../etc"
        body = canonical(unsafe)
        self.statement(
            "edge-release/invalid/path-unsafe-version.dsse.json",
            st,
            envelope(st, body, signer),
            body,
            expect="reject",
            reason="schema-invalid",
            context=None,
            description="version is a path component, so a traversal string fails the path-safe semver pattern (DEC-1.10).",
        )
        extra = self.release("revpi-connect4", "1.6.0", 6)
        extra["download_mirror"] = f"{RELEASE_HOST}/mirror"
        body = canonical(extra)
        self.statement(
            "edge-release/invalid/unknown-field.dsse.json",
            st,
            envelope(st, body, signer),
            body,
            expect="reject",
            reason="schema-invalid",
            context=None,
            description="Signed payload with a member the schema does not define; unknown members are rejected, never dropped (EI-054).",
        )

    def trust_anchor_bundles(self) -> None:
        st = "suderra.trust-anchors.v1"
        root = key("fleet-root")
        body = canonical(self.trust_anchors(1))
        self.statement(
            "trust-anchors/valid/bundle-seq-1.dsse.json",
            st,
            envelope(st, body, root),
            body,
            expect="accept",
            context="revpi-factory",
            description="P0 bundle (command, rbac-manifest, config-integrity, edge-release, edge-provisioning, mqtt-ca) signed by fleet-root.",
        )
        self.index(
            "trust-anchors/valid/bundle-seq-1.dsse.json",
            st,
            expect="reject",
            reason="sequence-replay",
            context="revpi-active",
            description="The same bundle on a device that already accepted bundle_seq 1: bundle_seq cannot go back or repeat.",
        )
        body = canonical(self.trust_anchors(2))
        self.statement(
            "trust-anchors/valid/bundle-seq-2.dsse.json",
            st,
            envelope(st, body, root),
            body,
            expect="accept",
            context="revpi-active",
            description="Next bundle for a device that accepted bundle_seq 1.",
        )
        self.statement(
            "trust-anchors/invalid/signed-by-provisioning-key.dsse.json",
            st,
            envelope(st, body, key("edge-provisioning")),
            body,
            expect="reject",
            reason="key-purpose-mismatch",
            context="revpi-active",
            description="An anchor bundle signed by the online provisioning key is rejected; only fleet-root roots agent trust (DEC-3.7).",
        )
        good = envelope(st, body, root)
        self.statement(
            "trust-anchors/invalid/bad-signature.dsse.json",
            st,
            tamper(good),
            base64.b64decode(tamper(good)["payload"]),
            expect="reject",
            reason="signature-invalid",
            context="revpi-active",
            description="Payload bytes changed after signing.",
        )
        body = canonical(self.trust_anchors(2, scope=[OTHER_TENANT]))
        self.statement(
            "trust-anchors/invalid/tenant-scope-excludes-device.dsse.json",
            st,
            envelope(st, body, root),
            body,
            expect="reject",
            reason="tenant-scope-mismatch",
            context="revpi-active",
            description="Correctly signed bundle whose tenant_scope does not contain the device's tenant (DEC-22).",
        )
        body = canonical(self.trust_anchors(2, provisioning_anchor=UNPINNED))
        self.statement(
            "trust-anchors/invalid/anchor-not-os-pinned.dsse.json",
            st,
            envelope(st, body, root),
            body,
            expect="reject",
            reason="anchor-not-os-pinned",
            context="revpi-active",
            description="edge-provisioning anchor whose keyid no OS image pins; root rejects the bundle (DEC-3.3).",
        )

    def provisioning_manifests(self) -> None:
        st = "suderra.edge-provisioning.v2"
        signer = key("edge-provisioning")
        rel_160 = "edge-release/valid/revpi-connect4-aarch64-1.6.0.dsse.json"
        rel_140 = "edge-release/valid/revpi-connect4-aarch64-1.4.0.dsse.json"
        rel_rpi = "edge-release/valid/rpi4-cm4-aarch64-1.6.0.dsse.json"
        ta1 = "trust-anchors/valid/bundle-seq-1.dsse.json"
        ta2 = "trust-anchors/valid/bundle-seq-2.dsse.json"
        config = "edge-provisioning/inputs/config-payload.txt"

        def inputs(release: str = rel_160, ta: str = ta2, nonce: str | None = None) -> dict:
            return {
                "release_statement": release,
                "config_payload": config,
                "trust_anchors": ta,
                "request_nonce": nonce or self.nonce_again,
            }

        first = canonical(
            self.provisioning(release_rel=rel_160, ta_rel=ta1, nonce=self.nonce_first, update_seq=1)
        )
        self.statement(
            "edge-provisioning/valid/revpi-connect4-first.dsse.json",
            st,
            envelope(st, first, signer),
            first,
            expect="accept",
            context="revpi-factory",
            inputs=inputs(ta=ta1, nonce=self.nonce_first),
            description="First provisioning of a factory-fresh revpi-connect4: binds tenant, device, binding and nonce to release 1.6.0, the config payload and bundle_seq 1.",
        )

        def manifest(**changes: object) -> dict:
            release = str(changes.pop("release_rel", rel_160))
            ta = str(changes.pop("ta_rel", ta2))
            nonce = str(changes.pop("nonce", self.nonce_again))
            return self.provisioning(
                release_rel=release,
                ta_rel=ta,
                nonce=nonce,
                update_seq=int(str(changes.pop("update_seq", 4))),
                **changes,
            )

        again = canonical(manifest())
        self.statement(
            "edge-provisioning/valid/revpi-connect4-reprovision.dsse.json",
            st,
            envelope(st, again, signer),
            again,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="Re-provisioning in MAINTENANCE: update_seq 4 after 3, security_version 6 above floor 5 (DEC-5.14).",
        )

        loose = dict(reversed(list(manifest().items())))
        loose_body = (json.dumps(loose, indent=4, ensure_ascii=False) + "\n").encode()
        self.statement(
            "edge-provisioning/valid/revpi-connect4-noncanonical-json.dsse.json",
            st,
            envelope(st, loose_body, signer),
            loose_body,
            expect="accept",
            context="revpi-active",
            inputs=inputs(),
            description="Same manifest with reversed member order, 4-space indentation and a trailing newline: the signature covers these exact bytes, so a verifier that re-serializes before verifying fails here (EI-054).",
        )

        epoch2 = canonical(manifest(key_epoch=2))
        self.statement(
            "edge-provisioning/valid/revpi-connect4-key-epoch-2.dsse.json",
            st,
            envelope(st, epoch2, key("edge-provisioning", 2)),
            epoch2,
            expect="accept",
            context="revpi-active-ratchet-2",
            inputs=inputs(),
            description="Signed with the epoch-2 provisioning key on a device whose ratchet is at 2 (DEC-3.5).",
        )

        good = envelope(st, again, signer)
        neg = [
            (
                "bad-signature",
                tamper(good),
                "signature-invalid",
                "revpi-active",
                inputs(),
                "Payload bytes changed after signing (one added space).",
            ),
            (
                "non-canonical-signature",
                malleate(good),
                "signature-invalid",
                "revpi-active",
                inputs(),
                "S replaced by S + L. verify_strict requires S < L; a verifier that reduces S accepts it.",
            ),
            (
                "wrong-payload-type",
                envelope(
                    st, again, signer, payload_type="application/vnd.suderra.edge-update.v1+json"
                ),
                "payload-type-mismatch",
                "revpi-active",
                inputs(),
                "Correctly signed by the provisioning key but as edge-update: a manifest cannot be replayed as another statement kind (DEC-2.4).",
            ),
            (
                "signed-by-release-key",
                envelope(st, again, key("edge-release")),
                "key-purpose-mismatch",
                "revpi-active",
                inputs(),
                "Manifest signed by the edge-release key, which signs only release statements (DEC-3.3).",
            ),
            (
                "unknown-keyid",
                envelope(st, again, UNPINNED),
                "key-unknown",
                "revpi-active",
                inputs(),
                "Signed by a key the device does not pin.",
            ),
            (
                "key-epoch-below-ratchet",
                good,
                "key-epoch-below-ratchet",
                "revpi-active-ratchet-2",
                inputs(),
                "Valid epoch-1 manifest on a device whose provisioning ratchet advanced to 2 (DEC-3.5).",
            ),
        ]
        two = copy.deepcopy(good)
        two["signatures"].append(envelope(st, again, key("edge-provisioning", 2))["signatures"][0])
        neg.append(
            (
                "two-signatures",
                two,
                "envelope-invalid",
                "revpi-active",
                inputs(),
                "Two signatures; contract 1.x envelopes carry exactly one.",
            )
        )
        for name, env, reason, context, inp, text in neg:
            self.statement(
                f"edge-provisioning/invalid/{name}.dsse.json",
                st,
                env,
                base64.b64decode(env["payload"]),
                expect="reject",
                reason=reason,
                context=context,
                inputs=inp,
                description=text,
            )

        dup = canonical(manifest())
        dup = b'{"board":"rpi4-cm4",' + dup[1:]
        self.statement(
            "edge-provisioning/invalid/duplicate-member.dsse.json",
            st,
            envelope(st, dup, signer),
            dup,
            expect="reject",
            reason="payload-json-invalid",
            context="revpi-active",
            inputs=inputs(),
            description="board appears twice; a last-member-wins parser would read revpi-connect4 and accept. Duplicate members are rejected.",
        )

        semantic = [
            (
                "unknown-field",
                {"debug_shell": True},
                "schema-invalid",
                {},
                "Signed payload with a member the schema does not define.",
            ),
            (
                "key-epoch-mismatch",
                {"key_epoch": 2},
                "key-epoch-mismatch",
                {},
                "Signed with the epoch-1 key but claims key_epoch 2; the claim never selects a key (DEC-3.4).",
            ),
            (
                "wrong-device-binding",
                {"device_binding": self.other_binding},
                "device-binding-mismatch",
                {},
                "Bound to another device's TPM EK hash: replay to a second device of the same board (EI-038).",
            ),
            (
                "wrong-device-id",
                {"device_id": OTHER_DEVICE},
                "device-id-mismatch",
                {},
                "device_id differs from the identity root recorded at first provisioning.",
            ),
            (
                "wrong-tenant",
                {"tenant_id": OTHER_TENANT},
                "tenant-mismatch",
                {},
                "Another tenant's manifest for this device (DEC-22).",
            ),
            (
                "nonce-mismatch",
                {"nonce": self.nonce_first},
                "nonce-mismatch",
                {},
                "Echoes the nonce of an earlier request instead of this one (DEC-5.5).",
            ),
            (
                "expired",
                {"not_before": EXPIRED_FROM, "expires_at": EXPIRED_UNTIL},
                "expired",
                {},
                "Validity window ended before the evaluation time.",
            ),
            (
                "not-yet-valid",
                {"not_before": FUTURE_FROM, "expires_at": FUTURE_UNTIL},
                "not-yet-valid",
                {},
                "Validity window starts after the evaluation time.",
            ),
            (
                "wrong-board",
                {"release_rel": rel_rpi},
                "board-mismatch",
                {"release": rel_rpi},
                "Consistent rpi4-cm4 manifest and release delivered to a revpi-connect4, whose CM4 GPIO lines drive PiBridge relays (DEC-8.2).",
            ),
            (
                "rollback-below-floor",
                {"release_rel": rel_140},
                "rollback-below-floor",
                {"release": rel_140},
                "Consistent manifest for release 1.4.0 (security_version 4) on a device whose floor is 5 (DEC-2.5).",
            ),
            (
                "sequence-replay",
                {"update_seq": 3},
                "sequence-replay",
                {},
                "update_seq equal to the last accepted one (DEC-2.4).",
            ),
            (
                "release-digest-mismatch",
                {
                    "release_statement": {
                        **manifest()["release_statement"],
                        "digest": {"sha256": sha256_hex(self.payloads[rel_140])},
                    }
                },
                "release-digest-mismatch",
                {},
                "Names the 1.4.0 release statement digest while release 1.6.0 is delivered.",
            ),
            (
                "release-mismatch",
                {"version": "1.6.1"},
                "release-mismatch",
                {},
                "Claims version 1.6.1 for the 1.6.0 release statement it names (DEC-3.1).",
            ),
            (
                "config-digest-mismatch",
                {
                    "config_payload": {
                        "digest": {"sha256": label_digest("another config payload")},
                        "size_bytes": len(self.config_payload),
                    }
                },
                "config-digest-mismatch",
                {},
                "The delivered config payload is not the one the manifest names.",
            ),
            (
                "trust-anchors-digest-mismatch",
                {"trust_anchors_seq": 3},
                "trust-anchors-digest-mismatch",
                {},
                "Names bundle_seq 3 for the bundle_seq 2 bundle it digests.",
            ),
            (
                "trust-anchors-tenant-scope",
                {"ta_rel": "trust-anchors/invalid/tenant-scope-excludes-device.dsse.json"},
                "tenant-scope-mismatch",
                {"ta": "trust-anchors/invalid/tenant-scope-excludes-device.dsse.json"},
                "Delivers, and binds by digest, a fleet-root bundle whose tenant_scope excludes the manifest's tenant (DEC-22).",
            ),
        ]
        for name, changes, reason, inp_changes, text in semantic:
            changes = dict(changes)
            ta_seq = changes.pop("trust_anchors_seq", None)
            body_dict = manifest(**changes)
            if ta_seq is not None:
                body_dict["trust_anchors"] = {**body_dict["trust_anchors"], "bundle_seq": ta_seq}
            body = canonical(body_dict)
            inp = inputs(
                release=str(inp_changes.get("release", rel_160)), ta=str(inp_changes.get("ta", ta2))
            )
            self.statement(
                f"edge-provisioning/invalid/{name}.dsse.json",
                st,
                envelope(st, body, signer),
                body,
                expect="reject",
                reason=reason,
                context="revpi-active",
                inputs=inp,
                description=text,
            )

    def receipts(self) -> None:
        st = "suderra.edge-activation-receipt.v1"
        signer = key("edge-provisioning")
        installed = self.payloads["edge-provisioning/valid/revpi-connect4-first.dsse.json"]
        other = self.payloads["edge-provisioning/valid/revpi-connect4-reprovision.dsse.json"]

        def receipt(**changes: object) -> bytes:
            body = {
                "_type": st,
                "tenant_id": TENANT,
                "device_id": DEVICE,
                "device_binding": self.binding,
                "manifest_digest": {"sha256": sha256_hex(installed)},
                "activation_id": ACTIVATION,
                "activated_at": "2026-10-20T11:30:00Z",
                "not_before": "2026-10-20T11:30:00Z",
                "expires_at": "2026-10-21T11:30:00Z",
            }
            body.update(changes)
            return canonical(body)

        body = receipt()
        self.statement(
            "edge-activation-receipt/valid/revpi-connect4.dsse.json",
            st,
            envelope(st, body, signer),
            body,
            expect="accept",
            context="revpi-provisioning",
            description="Receipt for the manifest root installed; root verifies it and moves the lifecycle to ACTIVE (DEC-5.8).",
        )
        cases = [
            (
                "wrong-manifest-digest",
                receipt(manifest_digest={"sha256": sha256_hex(other)}),
                signer,
                "manifest-digest-mismatch",
                "Names a manifest other than the one root installed.",
            ),
            (
                "wrong-device-binding",
                receipt(device_binding=self.other_binding),
                signer,
                "device-binding-mismatch",
                "Receipt for another device's binding.",
            ),
            (
                "signed-by-lifecycle-key",
                body,
                key("device-lifecycle"),
                "key-purpose-mismatch",
                "Receipts are signed by the provisioning key only (DEC-3.3).",
            ),
            (
                "expired",
                receipt(not_before=EXPIRED_FROM, expires_at=EXPIRED_UNTIL),
                signer,
                "expired",
                "Receipt presented after its window.",
            ),
        ]
        for name, payload, k, reason, text in cases:
            self.statement(
                f"edge-activation-receipt/invalid/{name}.dsse.json",
                st,
                envelope(st, payload, k),
                payload,
                expect="reject",
                reason=reason,
                context="revpi-provisioning",
                description=text,
            )

    def lifecycle(self) -> None:
        st = "suderra.device-lifecycle.v1"
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
        self.statement(
            "device-lifecycle/valid/enter-maintenance-reprovision.dsse.json",
            st,
            envelope(st, body, signer),
            body,
            expect="accept",
            context="revpi-active",
            description="ACTIVE -> MAINTENANCE for re-provisioning until expires_at (DEC-5.14, DEC-12).",
        )
        cases = [
            (
                "expired",
                statement(not_before=EXPIRED_FROM, expires_at=EXPIRED_UNTIL),
                signer,
                "expired",
                "Maintenance request presented after its window.",
            ),
            (
                "wrong-device-binding",
                statement(device_binding=self.other_binding),
                signer,
                "device-binding-mismatch",
                "Maintenance request for another device.",
            ),
            (
                "sequence-replay",
                statement(update_seq=2),
                signer,
                "sequence-replay",
                "update_seq equal to the last accepted lifecycle statement.",
            ),
            (
                "signed-by-provisioning-key",
                body,
                key("edge-provisioning"),
                "key-purpose-mismatch",
                "Opening the provisioning surface needs the separate device-lifecycle signer (DEC-12).",
            ),
            (
                "maintenance-without-purpose",
                statement(purpose=None),
                signer,
                "schema-invalid",
                "enter-maintenance must say why (reprovision or break-glass).",
            ),
        ]
        for name, payload, k, reason, text in cases:
            self.statement(
                f"device-lifecycle/invalid/{name}.dsse.json",
                st,
                envelope(st, payload, k),
                payload,
                expect="reject",
                reason=reason,
                context="revpi-active",
                description=text,
            )

    # ------------------------------------------------------- unsigned results
    def results(self) -> None:
        base = {
            "_type": "suderra.result.v1",
            "occurred_at": "2026-10-20T11:20:00Z",
            "time_state": "synced-nts",
            "board_profile": "revpi-connect4",
            "os_version": "1.0.0",
        }
        installed = sha256_hex(
            self.payloads["edge-release/valid/revpi-connect4-aarch64-1.6.0.dsse.json"]
        )
        valid = {
            "edge-install-ok": {
                "seq": 1,
                "kind": "edge-install",
                "outcome": "ok",
                "subject": {
                    "version": "1.6.0",
                    "security_version": 6,
                    "statement_type": "suderra.edge-release.v1",
                    "statement_digest": {"sha256": installed},
                },
            },
            "verify-current-rejected": {
                "seq": 2,
                "kind": "verify-current",
                "outcome": "rejected",
                "reason": "signature-invalid",
                "subject": {"version": "1.6.0", "statement_type": "suderra.edge-release.v1"},
                "detail": "release statement signature did not verify; start refused",
            },
            "lifecycle-active": {
                "seq": 3,
                "kind": "lifecycle",
                "outcome": "ok",
                "subject": {"lifecycle_from": "PROVISIONING", "lifecycle_to": "ACTIVE"},
            },
            "data-unlock-alarm": {
                "seq": 4,
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
                {**base, "seq": 5, "kind": "firmware-flash", "outcome": "ok"},
                "kind outside the DEC-27 result set.",
            ),
            "rejected-without-reason": (
                {**base, "seq": 5, "kind": "edge-update", "outcome": "rejected"},
                "A non-ok outcome must carry a reason code.",
            ),
            "ok-with-reason": (
                {**base, "seq": 5, "kind": "lockdown", "outcome": "ok", "reason": "done"},
                "An ok outcome carries no reason.",
            ),
            "unknown-field": (
                {**base, "seq": 5, "kind": "lockdown", "outcome": "ok", "authority": "cloud"},
                "Unknown members are rejected.",
            ),
            "fractional-seconds": (
                {
                    **base,
                    "seq": 5,
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
ReadWritePaths=/var/log/suderra

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

    def generic_unit(self) -> str:
        unit = self.SUDERRA_OS_UNIT.replace("suderra-os profile", "generic-Linux profile")
        unit = unit.replace("ExecStartPre=+/usr/bin/suderra-installer edge verify-current\n", "")
        unit = unit.replace(
            "ExecStart=/opt/suderra/edge/current/suderra-agent",
            "ExecStart=/usr/local/bin/suderra-agent",
        )
        rw = (
            "ReadOnlyPaths=/var/lib/suderra-site\n"
            "ReadWritePaths=/var/lib/suderra/state /var/lib/suderra/secrets /var/lib/suderra/queue\n"
            "ReadWritePaths=/var/lib/suderra/scripts /var/lib/suderra/policy-cache /var/lib/suderra/update-requests\n"
            "ReadWritePaths=/var/log/suderra\n"
        )
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
        rows = json.loads((CONTRACT / "unit-directives.json").read_text())["profiles"][
            "suderra-os"
        ]["board_dropins"]["boards"][board]
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
        for board in ["revpi-connect4", "industrial-x86_64", "rpi4-cm4", "qemu-x86_64"]:
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
                "ExecStartPre=+/usr/bin/suderra-installer edge verify-current\n",
                "",
                ["exact:Service.ExecStartPre"],
                "Starts the binary without re-verifying it (DEC-1.5).",
            ),
            (
                "agent-root-writable",
                "ReadWritePaths=/var/log/suderra\n",
                "ReadWritePaths=/var/log/suderra /var/lib/suderra\n",
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
        ]
        for name, old, new, violation, text in cases:
            unit = self.SUDERRA_OS_UNIT
            if old not in unit:
                raise SystemExit(f"unit fixture {name}: anchor not found")
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
                "application/vnd.suderra.edge-release.v1+json",
                "ğüşıöç".encode(),
                "Six two-byte UTF-8 characters: LEN counts 12 bytes, not 6 characters.",
            ),
            ("application/vnd.suderra.edge-provisioning.v2+json", b"", "Empty body: LEN is 0."),
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
        identity = bytes([1]) + bytes(31)
        self.put(
            "fixtures/dsse/signature-vectors.json",
            pretty(
                {
                    "test_only": True,
                    "vectors": [
                        {
                            "id": "valid",
                            "public_key_hex": signer.raw_public.hex(),
                            "message_hex": message.hex(),
                            "signature_hex": good.hex(),
                            "verify_strict": True,
                            "note": "edge-release/1 TEST-ONLY key.",
                        },
                        {
                            "id": "non-canonical-s",
                            "public_key_hex": signer.raw_public.hex(),
                            "message_hex": message.hex(),
                            "signature_hex": bad_s.hex(),
                            "verify_strict": False,
                            "note": "S + L: rejected because S is not reduced.",
                        },
                        {
                            "id": "wrong-message",
                            "public_key_hex": signer.raw_public.hex(),
                            "message_hex": (message + b"!").hex(),
                            "signature_hex": good.hex(),
                            "verify_strict": False,
                            "note": "Signature of a different message.",
                        },
                        {
                            "id": "small-order-public-key",
                            "public_key_hex": identity.hex(),
                            "message_hex": b"any message at all".hex(),
                            "signature_hex": (identity + bytes(32)).hex(),
                            "verify_strict": False,
                            "note": "A and R are the identity point and S is 0, so [S]B = R + [k]A holds for every message. OpenSSL and ed25519-dalek verify() accept it; verify_strict rejects small-order A and R.",
                        },
                    ],
                }
            ),
        )

    # ------------------------------------------------------------------ index
    def index_file(self) -> None:
        contexts = {
            "revpi-factory": {
                "description": "Factory-fresh revpi-connect4 in PROVISIONING: no tenant or device identity bound yet, no sequences, floor 0.",
                "board_profile": "revpi-connect4",
                "arch": "aarch64",
                "device_binding": self.binding,
                "tenant_id": None,
                "device_id": None,
                "security_version_floor": 0,
                "sequences": {},
                "ratchet": {
                    "edge-release": 1,
                    "edge-provisioning": 1,
                    "fleet-root": 1,
                    "device-lifecycle": 1,
                },
                "installed_manifest": None,
            },
            "revpi-provisioning": {
                "description": "The same device after root installed the first manifest, waiting for the activation receipt.",
                "board_profile": "revpi-connect4",
                "arch": "aarch64",
                "device_binding": self.binding,
                "tenant_id": TENANT,
                "device_id": DEVICE,
                "security_version_floor": 0,
                "sequences": {"suderra.edge-provisioning.v2": 1, "suderra.trust-anchors.v1": 1},
                "ratchet": {
                    "edge-release": 1,
                    "edge-provisioning": 1,
                    "fleet-root": 1,
                    "device-lifecycle": 1,
                },
                "installed_manifest": "edge-provisioning/valid/revpi-connect4-first.dsse.json",
            },
            "revpi-active": {
                "description": "ACTIVE revpi-connect4 with floor 5 and accepted sequences provisioning 3, lifecycle 2, bundle 1.",
                "board_profile": "revpi-connect4",
                "arch": "aarch64",
                "device_binding": self.binding,
                "tenant_id": TENANT,
                "device_id": DEVICE,
                "security_version_floor": 5,
                "sequences": {
                    "suderra.edge-provisioning.v2": 3,
                    "suderra.device-lifecycle.v1": 2,
                    "suderra.trust-anchors.v1": 1,
                },
                "ratchet": {
                    "edge-release": 1,
                    "edge-provisioning": 1,
                    "fleet-root": 1,
                    "device-lifecycle": 1,
                },
                "installed_manifest": None,
            },
        }
        contexts["revpi-active-ratchet-2"] = {
            **copy.deepcopy(contexts["revpi-active"]),
            "description": "revpi-active after a key-epoch-advance moved the edge-provisioning ratchet to 2.",
        }
        contexts["revpi-active-ratchet-2"]["ratchet"]["edge-provisioning"] = 2
        index = {
            "test_only": True,
            "description": "TEST-ONLY golden fixtures of contract v1. Evaluate every statement at evaluation_time against its device_context and inputs; accept or reject exactly as listed, for exactly the listed reason.",
            "evaluation_time": EVALUATION_TIME,
            "device_contexts": contexts,
            "statements": self.statements,
            "documents": self.documents,
            "units": self.units,
            "pae_vectors": "dsse/pae-vectors.json",
            "signature_vectors": "dsse/signature-vectors.json",
        }
        self.put("fixtures/index.json", pretty(index))

    # ------------------------------------------------------------------- main
    def run(self) -> dict[str, bytes]:
        self.config_payload = (
            b"TEST-ONLY opaque config payload of the suderra edge contract fixtures.\n"
            b"Contract 1.0.0 binds the config payload by sha256 and size only; its format, the\n"
            b"suderra.site-config.v1 statement (ADR-048 DEC-4.12), is not part of this version.\n"
        )
        self.put("fixtures/edge-provisioning/inputs/config-payload.txt", self.config_payload)
        self.keys()
        self.releases()
        self.trust_anchor_bundles()
        self.provisioning_manifests()
        self.receipts()
        self.lifecycle()
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

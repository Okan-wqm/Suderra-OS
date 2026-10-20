// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Test helpers: a fake image root, generated (non-contract) signing keys
//! and a complete signed provisioning delivery for install tests. The
//! contract's TEST-ONLY keys are used only by the golden fixture tests,
//! because the root key loader refuses them by design.

use crate::contracts::dsse::pae;
use crate::contracts::encoding::{encode_base64, sha256_hex};
use crate::contracts::keys::{KeyEntry, KeyStore};
use crate::contracts::registry::Purpose;
use crate::paths::Paths;
use crate::system::Runner;
use crate::variant::ImageFacts;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::Path;

/// Tenant, device and binding of the generated scenario.
pub(crate) const TENANT: &str = "11111111-1111-4111-8111-111111111111";
pub(crate) const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
pub(crate) const BINDING_HEX: &str =
    "7dc1225201ce83c48f502d0421ad7bfe59aaf9c0088fecab0c5a6bb80d360af4";

/// Writes a dev revpi-connect4 image root and loads its facts.
pub(crate) fn image(root: &Path) -> (Paths, ImageFacts) {
    let paths = Paths::under(root);
    std::fs::create_dir_all(root.join("etc/suderra")).unwrap();
    std::fs::write(
        paths.os_release(),
        "NAME=\"Suderra OS\"\nID=suderra-os\nVERSION_ID=1.0.0\nVARIANT=dev\nSUDERRA_AGENT_ABI=1-1\n",
    )
    .unwrap();
    std::fs::write(
        paths.board_file(),
        "BOARD_PROFILE=revpi-connect4\nARCH=aarch64\nRAUC_COMPATIBLE=suderra-os-revpi-connect4\nFEATURES=\"tpm\"\n",
    )
    .unwrap();
    std::fs::write(
        paths.kernel_config(),
        "CONFIG_SECCOMP_FILTER=y\nCONFIG_TCG_TPM=y\n",
    )
    .unwrap();
    // /data mounted with its layout applied (suderra-data-unlock).
    std::fs::create_dir_all(paths.os_state()).unwrap();
    let facts = ImageFacts::load(&paths).unwrap();
    (paths, facts)
}

/// Writes the hardware binding record suderra-identity would write.
pub(crate) fn write_binding(paths: &Paths, digest_prefix: &str) {
    let digest = format!("{digest_prefix:0<64}");
    std::fs::create_dir_all(paths.identity_dir()).unwrap();
    std::fs::write(
        paths.identity_dir().join("device-binding.json"),
        json!({"method": "tpm-ek-sha256", "digest": {"sha256": digest}}).to_string(),
    )
    .unwrap();
}

/// A deterministic generated signing key (never a contract TEST-ONLY key).
pub(crate) fn signing_key(label: &str) -> SigningKey {
    let seed: [u8; 32] = crate::contracts::encoding::sha256_raw(
        format!("suderra-installer-test:{label}").as_bytes(),
    );
    SigningKey::from_bytes(&seed)
}

/// Pins `key` as `/etc/suderra/keys/<purpose>/<epoch>.pub`.
pub(crate) fn pin_key(paths: &Paths, purpose: Purpose, epoch: u16, key: &SigningKey) {
    let dir = paths.key_pins().join(purpose.as_str());
    std::fs::create_dir_all(&dir).unwrap();
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.verifying_key().as_bytes());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    std::fs::write(dir.join(format!("{epoch}.pub")), pem).unwrap();
}

/// DSSE envelope JSON of `payload` signed by `key`.
pub(crate) fn sign(statement_kind: &str, payload: &Value, key: &SigningKey) -> Value {
    let body = serde_json::to_vec(payload).unwrap();
    let payload_type = format!("application/vnd.suderra.{statement_kind}.v1+json");
    let sig = key.sign(&pae(&payload_type, &body));
    json!({
        "payloadType": payload_type,
        "payload": encode_base64(&body),
        "signatures": [{"keyid": sha256_hex(key.verifying_key().as_bytes()), "sig": encode_base64(&sig.to_bytes())}],
    })
}

fn statement_digest(envelope: &Value) -> String {
    let body = base64::engine::general_purpose::STANDARD
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    sha256_hex(&body)
}

/// A tar.gz with the given (name, bytes) members.
pub(crate) fn tarball(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (name, bytes) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o4777);
        header.set_uid(4242);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, name, *bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Every key of a generated scenario.
pub(crate) struct Keys {
    pub release: SigningKey,
    pub provisioning: SigningKey,
    pub fleet_root: SigningKey,
    pub lifecycle: SigningKey,
    pub config: SigningKey,
    pub rbac: SigningKey,
    pub command: SigningKey,
}

impl Keys {
    pub(crate) fn new() -> Self {
        Self {
            release: signing_key("edge-release"),
            provisioning: signing_key("edge-provisioning"),
            fleet_root: signing_key("fleet-root"),
            lifecycle: signing_key("device-lifecycle"),
            config: signing_key("config-integrity"),
            rbac: signing_key("rbac-manifest"),
            command: signing_key("command"),
        }
    }

    /// The OS image pins of the scenario.
    pub(crate) fn os_pins(&self) -> KeyStore {
        KeyStore::from_entries(
            [
                (Purpose::EdgeRelease, &self.release),
                (Purpose::EdgeProvisioning, &self.provisioning),
                (Purpose::FleetRoot, &self.fleet_root),
                (Purpose::DeviceLifecycle, &self.lifecycle),
            ]
            .map(|(purpose, key)| KeyEntry {
                purpose,
                epoch: 1,
                raw: key.verifying_key().to_bytes(),
            }),
        )
        .unwrap()
    }

    /// Pins the scenario's OS keys on disk.
    pub(crate) fn pin(&self, paths: &Paths) {
        pin_key(paths, Purpose::EdgeRelease, 1, &self.release);
        pin_key(paths, Purpose::EdgeProvisioning, 1, &self.provisioning);
        pin_key(paths, Purpose::FleetRoot, 1, &self.fleet_root);
        pin_key(paths, Purpose::DeviceLifecycle, 1, &self.lifecycle);
    }
}

fn anchor(purpose: &str, key: &SigningKey) -> Value {
    json!({
        "purpose": purpose,
        "algorithm": "ed25519",
        "keyid": sha256_hex(key.verifying_key().as_bytes()),
        "epoch": 1,
        "public_key": encode_base64(key.verifying_key().as_bytes()),
    })
}

fn binding() -> Value {
    json!({"method": "tpm-ek-sha256", "digest": {"sha256": BINDING_HEX}})
}

/// Knobs of a generated delivery.
pub(crate) struct Spec {
    pub version: &'static str,
    pub security_version: u64,
    pub update_seq: u64,
    pub site_seq: u64,
    pub binary: Vec<u8>,
    pub artifact: Vec<u8>,
    pub nonce: String,
    pub binding_hex: &'static str,
    pub bundle_seq: u64,
}

impl Default for Spec {
    fn default() -> Self {
        let binary = b"\x7fELF suderra-agent test binary".to_vec();
        Self {
            version: "1.6.0",
            security_version: 6,
            update_seq: 1,
            site_seq: 1,
            artifact: tarball(&[("suderra-agent", &binary)]),
            binary,
            nonce: "0ab05211b2bb9ff799cce532f64ddbe3".into(),
            binding_hex: BINDING_HEX,
            bundle_seq: 1,
        }
    }
}

/// A signed delivery document and its pieces.
pub(crate) struct Built {
    pub delivery: Vec<u8>,
    pub manifest: Value,
    pub request: crate::contracts::delivery::ProvisioningRequest,
}

/// Builds a complete, valid delivery for `spec` signed by `keys`.
pub(crate) fn build_delivery(keys: &Keys, spec: &Spec) -> Built {
    let artifact_name = format!(
        "suderra-agent-os-{}-revpi-connect4-aarch64.tar.gz",
        spec.version
    );
    let release = sign(
        "edge-release",
        &json!({
            "_type": "suderra.edge-release.v1",
            "name": "suderra-agent",
            "version": spec.version,
            "security_version": spec.security_version,
            "board_profile": "revpi-connect4",
            "arch": "aarch64",
            "agent_profile": "suderra-os",
            "cargo_features": ["revpi-io", "scada-display", "suderra-os"],
            "artifact": {
                "name": artifact_name,
                "format": "tar.gz",
                "size_bytes": spec.artifact.len(),
                "digest": {"sha256": sha256_hex(&spec.artifact)},
                "binary_name": "suderra-agent",
                "binary_digest": {"sha256": sha256_hex(&spec.binary)},
            },
            "min_os_version": "1.0.0",
            "agent_abi": 1,
            "required_kernel_config": ["CONFIG_SECCOMP_FILTER"],
            "provenance": {"predicate_type": "https://slsa.dev/provenance/v1", "digest": {"sha256": "9".repeat(64)}},
        }),
        &keys.release,
    );
    let bundle = sign(
        "trust-anchors",
        &json!({
            "_type": "suderra.trust-anchors.v1",
            "bundle_seq": spec.bundle_seq,
            "issued_at": "2026-10-19T00:00:00Z",
            "tenant_scope": [TENANT],
            "anchors": [
                anchor("command", &keys.command),
                anchor("rbac-manifest", &keys.rbac),
                anchor("config-integrity", &keys.config),
                anchor("edge-release", &keys.release),
                anchor("edge-provisioning", &keys.provisioning),
            ],
        }),
        &keys.fleet_root,
    );
    let rbac = sign(
        "rbac-manifest",
        &json!({
            "_type": "suderra.rbac-manifest.v1",
            "tenant_id": TENANT,
            "policy_version": 1,
            "not_before": "2020-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "actors": [{
                "actor_id": "33333333-3333-4333-8333-333333333333",
                "kind": "platform",
                "keyid": sha256_hex(keys.command.verifying_key().as_bytes()),
                "public_key": encode_base64(keys.command.verifying_key().as_bytes()),
                "roles": ["platform-authenticated"],
            }],
            "roles": [{
                "name": "platform-authenticated",
                "permissions": ["ReadTag"],
                "not_before": "2020-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }],
        }),
        &keys.rbac,
    );
    let config = format!("site: test\nseq: {}\n", spec.site_seq).into_bytes();
    let site = sign(
        "site-config",
        &json!({
            "_type": "suderra.site-config.v1",
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": binding(),
            "update_seq": spec.site_seq,
            "not_before": "2020-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "files": {"config.yaml": {"digest": {"sha256": sha256_hex(&config)}, "size_bytes": config.len()}},
            "rbac_manifest": {"digest": {"sha256": statement_digest(&rbac)}, "policy_version": 1},
        }),
        &keys.config,
    );
    let manifest = sign(
        "edge-provisioning",
        &json!({
            "_type": "suderra.edge-provisioning.v1",
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_code": "RPI-TEST01",
            "device_binding": {"method": "tpm-ek-sha256", "digest": {"sha256": spec.binding_hex}},
            "nonce": spec.nonce,
            "board": "revpi-connect4",
            "arch": "aarch64",
            "agent_profile": "suderra-os",
            "version": spec.version,
            "security_version": spec.security_version,
            "key_epoch": 1,
            "update_seq": spec.update_seq,
            "not_before": "2020-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "release_statement": {"digest": {"sha256": statement_digest(&release)}},
            "artifact_url": format!("https://edge-releases.example.com/{artifact_name}"),
            "site_config": {"digest": {"sha256": statement_digest(&site)}, "update_seq": spec.site_seq},
            "trust_anchors": {"digest": {"sha256": statement_digest(&bundle)}, "bundle_seq": spec.bundle_seq},
        }),
        &keys.provisioning,
    );
    let delivery = json!({
        "_type": "suderra.edge-provisioning-delivery.v1",
        "manifest": manifest,
        "release_statement": release,
        "trust_anchors": bundle,
        "site_config": site,
        "rbac_manifest": rbac,
        "site_files": {"config.yaml": encode_base64(&config)},
    });
    let request = crate::contracts::delivery::ProvisioningRequest {
        binding_method: crate::contracts::registry::BindingMethod::TpmEkSha256,
        binding_sha256: BINDING_HEX.into(),
        nonce: spec.nonce.clone(),
        board_profile: crate::contracts::registry::BoardProfile::RevpiConnect4,
        os_version: "1.0.0".into(),
        agent_abi: "1-1".into(),
    };
    Built {
        delivery: delivery.to_string().into_bytes(),
        manifest,
        request,
    }
}

/// Activation receipt for an installed manifest.
pub(crate) fn receipt(keys: &Keys, manifest: &Value) -> Vec<u8> {
    sign(
        "edge-activation-receipt",
        &json!({
            "_type": "suderra.edge-activation-receipt.v1",
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": binding(),
            "manifest_digest": {"sha256": statement_digest(manifest)},
            "activation_id": "44444444-4444-4444-8444-444444444444",
            "activated_at": "2026-10-20T00:00:00Z",
            "not_before": "2020-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
        }),
        &keys.provisioning,
    )
    .to_string()
    .into_bytes()
}

/// enter-maintenance/reprovision lifecycle statement.
pub(crate) fn maintenance(keys: &Keys, update_seq: u64) -> Vec<u8> {
    sign(
        "device-lifecycle",
        &json!({
            "_type": "suderra.device-lifecycle.v1",
            "tenant_id": TENANT,
            "device_id": DEVICE,
            "device_binding": binding(),
            "action": "enter-maintenance",
            "purpose": "reprovision",
            "update_seq": update_seq,
            "not_before": "2020-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
        }),
        &keys.lifecycle,
    )
    .to_string()
    .into_bytes()
}

/// A scripted [`Runner`].
pub(crate) struct FakeRunner {
    /// `nft -c` fails for a program containing this text.
    pub fail_check_containing: Option<String>,
    /// Output of `systemctl is-active suderra-agent.service`.
    pub agent_state: String,
    /// Output of `nft list ruleset`.
    pub ruleset: Vec<u8>,
    /// Every call.
    pub calls: RefCell<Vec<String>>,
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self {
            fail_check_containing: None,
            agent_state: "active".into(),
            ruleset: b"table inet suderra {}\n".to_vec(),
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl FakeRunner {
    /// Hash of the scripted ruleset.
    pub(crate) fn ruleset_hash(&self) -> String {
        sha256_hex(&self.ruleset)
    }
}

impl Runner for FakeRunner {
    fn output(&self, program: &str, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        self.calls
            .borrow_mut()
            .push(format!("{program} {}", args.join(" ")));
        match (program, args) {
            ("nft", ["list", "ruleset"]) => Ok(self.ruleset.clone()),
            ("nft", ["-c", "-f", file]) => {
                let text = std::fs::read_to_string(file)?;
                match &self.fail_check_containing {
                    Some(needle) if text.contains(needle.as_str()) => {
                        anyhow::bail!("nft -c: syntax error")
                    }
                    _ => Ok(Vec::new()),
                }
            }
            ("nft", ["-f", _]) => Ok(Vec::new()),
            ("systemctl", ["is-active", _]) => Ok(format!("{}\n", self.agent_state).into_bytes()),
            _ => anyhow::bail!("unexpected call {program} {args:?}"),
        }
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed statement payloads (contracts/suderra-edge/v1/schemas/*.schema.json).
//!
//! Every struct denies unknown members and every constraint of the schema is
//! checked in `validate`, so a payload is accepted here exactly when the JSON
//! Schema accepts it; anything else is `schema-invalid`.

use super::encoding::{
    is_device_code, is_ed25519_public_key, is_https_url, is_kernel_symbol, is_nonce, is_os_version,
    is_pem_certificate, is_semver, is_sha256_hex, is_tag_id, is_timestamp, is_uuid,
};
use super::json::{check_strict_object, MAX_SAFE_INTEGER};
use super::registry::{
    AgentProfile, Arch, BindingMethod, BoardProfile, CargoFeature, Purpose, Reason, SitePath,
    StatementType,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Check = Result<(), String>;

fn ensure(ok: bool, what: &str) -> Check {
    if ok {
        Ok(())
    } else {
        Err(what.to_owned())
    }
}

/// Optional member that, when present, must not be `null`.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

fn unique<T: Ord>(items: &[T]) -> bool {
    items.iter().collect::<BTreeSet<_>>().len() == items.len()
}

fn sequence(value: u64, what: &str) -> Check {
    ensure((1..=MAX_SAFE_INTEGER).contains(&value), what)
}

fn epoch(value: u64, what: &str) -> Check {
    ensure((1..=65_535).contains(&value), what)
}

fn security_version(value: u64) -> Check {
    ensure(
        value <= u64::from(u32::MAX),
        "security_version out of range",
    )
}

fn uuid(value: &str, what: &str) -> Check {
    ensure(is_uuid(value), what)
}

fn window(not_before: &str, expires_at: &str) -> Check {
    ensure(
        is_timestamp(not_before),
        "not_before is not a contract timestamp",
    )?;
    ensure(
        is_timestamp(expires_at),
        "expires_at is not a contract timestamp",
    )
}

/// common.schema.json `digest`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Digest {
    /// Lowercase hex SHA-256.
    pub sha256: String,
}

impl Digest {
    fn validate(&self) -> Check {
        ensure(
            is_sha256_hex(&self.sha256),
            "digest is not lowercase hex SHA-256",
        )
    }
}

/// common.schema.json `device_binding`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceBinding {
    /// How the binding was derived.
    pub method: BindingMethod,
    /// Digest of the hardware identity.
    pub digest: Digest,
}

impl DeviceBinding {
    pub(crate) fn validate(&self) -> Check {
        self.digest.validate()
    }
}

/// Behaviour shared by every signed statement payload.
pub(crate) trait Statement: DeserializeOwned {
    /// The statement type this payload belongs to.
    const TYPE: StatementType;
    /// Every schema constraint serde does not already enforce.
    fn validate(&self) -> Check;
    /// `(not_before, expires_at)` when the statement has a window.
    fn window(&self) -> Option<(&str, &str)> {
        None
    }
    /// device_binding of a device-bound statement.
    fn binding(&self) -> Option<&DeviceBinding> {
        None
    }
    /// device_id of a device-bound statement.
    fn device_id(&self) -> Option<&str> {
        None
    }
    /// tenant_id of a tenant-bound statement (the bundle uses tenant_scope).
    fn tenant_id(&self) -> Option<&str> {
        None
    }
    /// Value of the sequence member, if the type has one.
    fn sequence(&self) -> Option<u64> {
        None
    }
}

/// Parses verified payload bytes as `T` (strict JSON, then schema).
pub(crate) fn parse_payload<T: Statement>(bytes: &[u8]) -> Result<T, Reason> {
    check_strict_object(bytes).map_err(|_| Reason::PayloadJsonInvalid)?;
    let value: T = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaInvalid)?;
    value.validate().map_err(|_| Reason::SchemaInvalid)?;
    Ok(value)
}

fn type_member(value: &str, expected: StatementType) -> Check {
    ensure(
        value == expected.type_member(),
        "_type differs from the statement type",
    )
}

// ------------------------------------------------------------- edge-release

/// suderra.edge-release.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdgeRelease {
    #[serde(rename = "_type")]
    type_: String,
    name: String,
    /// Path-safe semantic version.
    pub version: String,
    /// Monotonic rollback ordinal.
    pub security_version: u64,
    /// Board profile.
    pub board_profile: BoardProfile,
    /// Architecture.
    pub arch: Arch,
    /// Agent profile.
    pub agent_profile: AgentProfile,
    /// Exact cargo feature set.
    pub cargo_features: Vec<CargoFeature>,
    /// The release artifact.
    pub artifact: ReleaseArtifact,
    /// Oldest OS VERSION_ID it runs on.
    pub min_os_version: String,
    /// Agent ABI.
    pub agent_abi: u64,
    /// Kernel symbols it needs.
    pub required_kernel_config: Vec<String>,
    provenance: Provenance,
}

/// edge-release `artifact`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseArtifact {
    /// Artifact file name.
    pub name: String,
    format: String,
    /// Exact artifact size.
    pub size_bytes: u64,
    /// Artifact digest.
    pub digest: Digest,
    binary_name: String,
    /// Digest of the single suderra-agent member.
    pub binary_digest: Digest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    predicate_type: String,
    digest: Digest,
}

fn is_artifact_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("suderra-agent-os-")
        .and_then(|n| n.strip_suffix(".tar.gz"))
    else {
        return false;
    };
    let Some((head, arch)) = stem.rsplit_once('-') else {
        return false;
    };
    let arch_ok = arch == "aarch64" || arch == "x86_64";
    // ^suderra-agent-os-[0-9A-Za-z.-]+-[a-z0-9_-]+-(aarch64|x86_64)\.tar\.gz$
    // The version and board parts share '-', so split anywhere that fits.
    let fits = head.char_indices().any(|(i, c)| {
        c == '-'
            && i > 0
            && head[..i]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && !head[i + 1..].is_empty()
            && head[i + 1..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    });
    arch_ok && fits
}

impl Statement for EdgeRelease {
    const TYPE: StatementType = StatementType::EdgeRelease;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        ensure(self.name == "suderra-agent", "name must be suderra-agent")?;
        ensure(
            is_semver(&self.version),
            "version is not a path-safe semver",
        )?;
        security_version(self.security_version)?;
        ensure(
            !self.cargo_features.is_empty() && unique(&self.cargo_features),
            "cargo_features must be a non-empty set",
        )?;
        let a = &self.artifact;
        ensure(
            is_artifact_name(&a.name),
            "artifact.name does not match its pattern",
        )?;
        ensure(
            a.format == super::registry::naming::FORMAT,
            "artifact.format must be tar.gz",
        )?;
        ensure(
            (1..=268_435_456).contains(&a.size_bytes),
            "artifact.size_bytes out of range",
        )?;
        a.digest.validate()?;
        ensure(
            a.binary_name == "suderra-agent",
            "artifact.binary_name must be suderra-agent",
        )?;
        a.binary_digest.validate()?;
        ensure(
            is_os_version(&self.min_os_version),
            "min_os_version is not an OS version",
        )?;
        ensure(
            (1..=65_535).contains(&self.agent_abi),
            "agent_abi out of range",
        )?;
        ensure(
            unique(&self.required_kernel_config)
                && self
                    .required_kernel_config
                    .iter()
                    .all(|s| is_kernel_symbol(s)),
            "required_kernel_config must be unique CONFIG_ symbols",
        )?;
        ensure(
            self.provenance.predicate_type == "https://slsa.dev/provenance/v1",
            "provenance.predicate_type",
        )?;
        self.provenance.digest.validate()
    }
}

// --------------------------------------------------------- edge-provisioning

/// edge-provisioning `release_statement`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseRef {
    /// Statement digest of the delivered release statement.
    pub digest: Digest,
}

/// edge-provisioning `site_config`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SiteConfigRef {
    /// Statement digest of the delivered site config.
    pub digest: Digest,
    /// Its update_seq.
    pub update_seq: u64,
}

/// edge-provisioning `trust_anchors`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustAnchorsRef {
    /// Statement digest of the delivered bundle.
    pub digest: Digest,
    /// Its bundle_seq.
    pub bundle_seq: u64,
}

/// suderra.edge-provisioning.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdgeProvisioning {
    #[serde(rename = "_type")]
    type_: String,
    /// Tenant.
    pub tenant_id: String,
    /// Device.
    pub device_id: String,
    /// Device code.
    pub device_code: String,
    /// Hardware binding.
    pub device_binding: DeviceBinding,
    /// Echo of the request nonce.
    pub nonce: String,
    /// Board profile.
    pub board: BoardProfile,
    /// Architecture.
    pub arch: Arch,
    /// Agent profile.
    pub agent_profile: AgentProfile,
    /// Release version.
    pub version: String,
    /// Release security_version.
    pub security_version: u64,
    /// Epoch of the signing key (consistency check only).
    pub key_epoch: u64,
    /// Monotonic per device.
    pub update_seq: u64,
    /// Window start.
    pub not_before: String,
    /// Window end.
    pub expires_at: String,
    /// Delivered release statement.
    pub release_statement: ReleaseRef,
    /// Where the artifact is downloaded on the network path.
    pub artifact_url: String,
    /// Delivered site config.
    pub site_config: SiteConfigRef,
    /// Delivered trust-anchors bundle.
    pub trust_anchors: TrustAnchorsRef,
}

impl Statement for EdgeProvisioning {
    const TYPE: StatementType = StatementType::EdgeProvisioning;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        uuid(&self.tenant_id, "tenant_id is not a UUID")?;
        uuid(&self.device_id, "device_id is not a UUID")?;
        ensure(is_device_code(&self.device_code), "device_code")?;
        self.device_binding.validate()?;
        ensure(is_nonce(&self.nonce), "nonce")?;
        ensure(
            is_semver(&self.version),
            "version is not a path-safe semver",
        )?;
        security_version(self.security_version)?;
        epoch(self.key_epoch, "key_epoch out of range")?;
        sequence(self.update_seq, "update_seq out of range")?;
        window(&self.not_before, &self.expires_at)?;
        self.release_statement.digest.validate()?;
        ensure(
            is_https_url(&self.artifact_url),
            "artifact_url is not an https URL",
        )?;
        self.site_config.digest.validate()?;
        sequence(
            self.site_config.update_seq,
            "site_config.update_seq out of range",
        )?;
        self.trust_anchors.digest.validate()?;
        sequence(
            self.trust_anchors.bundle_seq,
            "trust_anchors.bundle_seq out of range",
        )
    }

    fn window(&self) -> Option<(&str, &str)> {
        Some((&self.not_before, &self.expires_at))
    }
    fn binding(&self) -> Option<&DeviceBinding> {
        Some(&self.device_binding)
    }
    fn device_id(&self) -> Option<&str> {
        Some(&self.device_id)
    }
    fn tenant_id(&self) -> Option<&str> {
        Some(&self.tenant_id)
    }
    fn sequence(&self) -> Option<u64> {
        Some(self.update_seq)
    }
}

// ---------------------------------------------------------- activation receipt

/// suderra.edge-activation-receipt.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationReceipt {
    #[serde(rename = "_type")]
    type_: String,
    /// Tenant.
    pub tenant_id: String,
    /// Device.
    pub device_id: String,
    /// Hardware binding.
    pub device_binding: DeviceBinding,
    /// Statement digest of the installed provisioning manifest.
    pub manifest_digest: Digest,
    /// Cloud activation id.
    pub activation_id: String,
    /// When the cloud committed the activation.
    pub activated_at: String,
    /// Window start.
    pub not_before: String,
    /// Window end.
    pub expires_at: String,
}

impl Statement for ActivationReceipt {
    const TYPE: StatementType = StatementType::EdgeActivationReceipt;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        uuid(&self.tenant_id, "tenant_id is not a UUID")?;
        uuid(&self.device_id, "device_id is not a UUID")?;
        self.device_binding.validate()?;
        self.manifest_digest.validate()?;
        uuid(&self.activation_id, "activation_id is not a UUID")?;
        ensure(is_timestamp(&self.activated_at), "activated_at")?;
        window(&self.not_before, &self.expires_at)
    }

    fn window(&self) -> Option<(&str, &str)> {
        Some((&self.not_before, &self.expires_at))
    }
    fn binding(&self) -> Option<&DeviceBinding> {
        Some(&self.device_binding)
    }
    fn device_id(&self) -> Option<&str> {
        Some(&self.device_id)
    }
    fn tenant_id(&self) -> Option<&str> {
        Some(&self.tenant_id)
    }
}

// --------------------------------------------------------------- trust anchors

/// An Ed25519 anchor of the bundle.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ed25519Anchor {
    /// Purpose the key serves.
    pub purpose: Purpose,
    algorithm: String,
    /// Declared keyid.
    pub keyid: String,
    /// Key epoch.
    pub epoch: u64,
    /// Standard base64 of the raw key.
    pub public_key: String,
}

/// The MQTT CA anchor of the bundle.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct X509Anchor {
    purpose: Purpose,
    algorithm: String,
    /// PEM root certificates.
    pub certificates: Vec<String>,
}

/// One bundle anchor (`oneOf` ed25519 / x509).
#[derive(Debug, Clone)]
pub(crate) enum Anchor {
    /// Ed25519 key anchor.
    Ed25519(Ed25519Anchor),
    /// X.509 root set.
    X509(X509Anchor),
}

impl<'de> Deserialize<'de> for Anchor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = Value::deserialize(d)?;
        match value.get("algorithm").and_then(Value::as_str) {
            Some("ed25519") => serde_json::from_value(value)
                .map(Anchor::Ed25519)
                .map_err(D::Error::custom),
            Some("x509") => serde_json::from_value(value)
                .map(Anchor::X509)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("anchor algorithm must be ed25519 or x509")),
        }
    }
}

/// suderra.trust-anchors.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustAnchors {
    #[serde(rename = "_type")]
    type_: String,
    /// Monotonic bundle sequence.
    pub bundle_seq: u64,
    issued_at: String,
    /// Tenants this bundle serves.
    pub tenant_scope: Vec<String>,
    /// Anchors.
    pub anchors: Vec<Anchor>,
}

impl Statement for TrustAnchors {
    const TYPE: StatementType = StatementType::TrustAnchors;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        sequence(self.bundle_seq, "bundle_seq out of range")?;
        ensure(is_timestamp(&self.issued_at), "issued_at")?;
        ensure(
            !self.tenant_scope.is_empty()
                && unique(&self.tenant_scope)
                && self.tenant_scope.iter().all(|t| is_uuid(t)),
            "tenant_scope must be a non-empty set of UUIDs",
        )?;
        ensure(!self.anchors.is_empty(), "anchors must not be empty")?;
        for anchor in &self.anchors {
            match anchor {
                Anchor::Ed25519(a) => {
                    ensure(a.algorithm == "ed25519", "anchor algorithm")?;
                    ensure(
                        a.purpose.anchored_in_bundle() && a.purpose != Purpose::MqttCa,
                        "ed25519 anchor purpose outside the bundle set",
                    )?;
                    ensure(is_sha256_hex(&a.keyid), "anchor keyid")?;
                    epoch(a.epoch, "anchor epoch out of range")?;
                    ensure(is_ed25519_public_key(&a.public_key), "anchor public_key")?;
                }
                Anchor::X509(a) => {
                    ensure(a.algorithm == "x509", "anchor algorithm")?;
                    ensure(
                        a.purpose == Purpose::MqttCa,
                        "x509 anchor purpose must be mqtt-ca",
                    )?;
                    ensure(
                        !a.certificates.is_empty()
                            && unique(&a.certificates)
                            && a.certificates.iter().all(|c| is_pem_certificate(c)),
                        "certificates must be a non-empty set of PEM certificates",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn sequence(&self) -> Option<u64> {
        Some(self.bundle_seq)
    }
}

// ------------------------------------------------------------ device lifecycle

/// device-lifecycle `action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LifecycleAction {
    /// Time-boxed maintenance.
    EnterMaintenance,
    /// Retire (P3).
    Decommission,
    /// Return for repair (P3).
    Rma,
}

/// device-lifecycle `purpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MaintenancePurpose {
    /// Reprovisioning (P0).
    Reprovision,
    /// Break-glass maintenance (P3).
    BreakGlass,
}

/// suderra.device-lifecycle.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceLifecycle {
    #[serde(rename = "_type")]
    type_: String,
    /// Tenant.
    pub tenant_id: String,
    /// Device.
    pub device_id: String,
    /// Hardware binding.
    pub device_binding: DeviceBinding,
    /// Requested transition.
    pub action: LifecycleAction,
    /// Purpose of enter-maintenance.
    #[serde(default, deserialize_with = "present")]
    pub purpose: Option<MaintenancePurpose>,
    /// Monotonic per device.
    pub update_seq: u64,
    /// Window start.
    pub not_before: String,
    /// Window end; also the end of the maintenance window.
    pub expires_at: String,
}

impl Statement for DeviceLifecycle {
    const TYPE: StatementType = StatementType::DeviceLifecycle;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        uuid(&self.tenant_id, "tenant_id is not a UUID")?;
        uuid(&self.device_id, "device_id is not a UUID")?;
        self.device_binding.validate()?;
        match self.action {
            LifecycleAction::EnterMaintenance => ensure(
                self.purpose.is_some(),
                "enter-maintenance requires a purpose",
            )?,
            LifecycleAction::Decommission | LifecycleAction::Rma => ensure(
                self.purpose.is_none(),
                "decommission and rma carry no purpose",
            )?,
        }
        sequence(self.update_seq, "update_seq out of range")?;
        window(&self.not_before, &self.expires_at)
    }

    fn window(&self) -> Option<(&str, &str)> {
        Some((&self.not_before, &self.expires_at))
    }
    fn binding(&self) -> Option<&DeviceBinding> {
        Some(&self.device_binding)
    }
    fn device_id(&self) -> Option<&str> {
        Some(&self.device_id)
    }
    fn tenant_id(&self) -> Option<&str> {
        Some(&self.tenant_id)
    }
    fn sequence(&self) -> Option<u64> {
        Some(self.update_seq)
    }
}

// ----------------------------------------------------------------- site config

/// A site file the site config names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SiteFile {
    /// Digest of the file bytes.
    pub digest: Digest,
    /// Exact size.
    pub size_bytes: u64,
}

/// site-config `rbac_manifest`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RbacRef {
    /// Statement digest of the delivered RBAC manifest.
    pub digest: Digest,
    /// Its policy_version.
    pub policy_version: u64,
}

/// suderra.site-config.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SiteConfig {
    #[serde(rename = "_type")]
    type_: String,
    /// Tenant.
    pub tenant_id: String,
    /// Device.
    pub device_id: String,
    /// Hardware binding.
    pub device_binding: DeviceBinding,
    /// Monotonic per device.
    pub update_seq: u64,
    /// Window start.
    pub not_before: String,
    /// Window end.
    pub expires_at: String,
    /// Every site file by fixed path.
    pub files: BTreeMap<SitePath, SiteFile>,
    /// The delivered RBAC manifest.
    pub rbac_manifest: RbacRef,
}

impl Statement for SiteConfig {
    const TYPE: StatementType = StatementType::SiteConfig;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        uuid(&self.tenant_id, "tenant_id is not a UUID")?;
        uuid(&self.device_id, "device_id is not a UUID")?;
        self.device_binding.validate()?;
        sequence(self.update_seq, "update_seq out of range")?;
        window(&self.not_before, &self.expires_at)?;
        ensure(
            self.files.contains_key(&SitePath::ConfigYaml),
            "files must name config.yaml",
        )?;
        for file in self.files.values() {
            file.digest.validate()?;
            ensure(
                file.size_bytes <= 1_048_576,
                "site file size_bytes out of range",
            )?;
        }
        self.rbac_manifest.digest.validate()?;
        sequence(
            self.rbac_manifest.policy_version,
            "policy_version out of range",
        )
    }

    fn window(&self) -> Option<(&str, &str)> {
        Some((&self.not_before, &self.expires_at))
    }
    fn binding(&self) -> Option<&DeviceBinding> {
        Some(&self.device_binding)
    }
    fn device_id(&self) -> Option<&str> {
        Some(&self.device_id)
    }
    fn tenant_id(&self) -> Option<&str> {
        Some(&self.tenant_id)
    }
    fn sequence(&self) -> Option<u64> {
        Some(self.update_seq)
    }
}

// --------------------------------------------------------------- RBAC manifest

/// RBAC actor (contract 1.x: exactly the platform actor).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Actor {
    actor_id: String,
    kind: String,
    /// Declared keyid.
    pub keyid: String,
    /// Standard base64 of the raw command key.
    pub public_key: String,
    roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    name: String,
    permissions: Vec<Value>,
    not_before: String,
    expires_at: String,
}

/// suderra.rbac-manifest.v1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RbacManifest {
    #[serde(rename = "_type")]
    type_: String,
    /// Tenant.
    pub tenant_id: String,
    /// Monotonic per tenant.
    pub policy_version: u64,
    /// Window start.
    pub not_before: String,
    /// Window end.
    pub expires_at: String,
    /// Actors.
    pub actors: Vec<Actor>,
    roles: Vec<Role>,
}

const PLAIN_PERMISSIONS: [&str; 10] = [
    "ReadTag",
    "ReadAuditLog",
    "FailoverControl",
    "ManagePolicy",
    "ManageIoConfig",
    "ManageCertPinning",
    "ManageLicense",
    "ManageUserTokenManifest",
    "WatchSubscribe",
    "DebugStep",
];

const PLAIN_ACTUATOR_CLASSES: [&str; 8] = [
    "Filtration",
    "Lighting",
    "Feeding",
    "Recirculation",
    "WasteRemoval",
    "Degassing",
    "EmergencyContainment",
    "Inventory",
];

/// The single member of an object, if it has exactly one.
fn single_member(value: &Value) -> Option<(&str, &Value)> {
    let map = value.as_object()?;
    if map.len() != 1 {
        return None;
    }
    map.iter().next().map(|(k, v)| (k.as_str(), v))
}

/// An object with exactly the given members.
fn exact_members<'a>(value: &'a Value, names: &[&str]) -> Option<Vec<&'a Value>> {
    let map = value.as_object()?;
    if map.len() != names.len() {
        return None;
    }
    names.iter().map(|n| map.get(*n)).collect()
}

fn uint_at_most(value: &Value, max: u64) -> bool {
    value.as_u64().is_some_and(|v| v <= max)
}

fn actuator_class_ok(value: &Value) -> bool {
    if let Some(text) = value.as_str() {
        return PLAIN_ACTUATOR_CLASSES.contains(&text);
    }
    match single_member(value) {
        Some(("Aeration", v)) => matches!(v.as_str(), Some("Normal" | "LifeSupport")),
        Some(("Chemistry", v)) => {
            matches!(
                v.as_str(),
                Some("Nutrient" | "PhAdjust" | "LifeSupportDose")
            )
        }
        Some(("Thermal", v)) => matches!(v.as_str(), Some("Heating" | "Cooling")),
        _ => false,
    }
}

/// rbac-manifest `$defs/permission`, plus the register-range order JSON
/// Schema cannot state (start must not exceed end).
fn permission_ok(value: &Value) -> bool {
    if let Some(text) = value.as_str() {
        return PLAIN_PERMISSIONS.contains(&text);
    }
    let Some((name, body)) = single_member(value) else {
        return false;
    };
    match name {
        "WriteTag" => {
            exact_members(body, &["tag_id"]).is_some_and(|m| m[0].as_str().is_some_and(is_tag_id))
        }
        "ModbusWrite" => exact_members(body, &["device_id", "register_range"]).is_some_and(|m| {
            uint_at_most(m[0], 255)
                && exact_members(m[1], &["start", "end"]).is_some_and(|r| {
                    uint_at_most(r[0], 65_535)
                        && uint_at_most(r[1], 65_535)
                        && r[0].as_u64() <= r[1].as_u64()
                })
        }),
        "GpioWrite" => exact_members(body, &["pin"]).is_some_and(|m| uint_at_most(m[0], 255)),
        "PwmWrite" => exact_members(body, &["channel"]).is_some_and(|m| uint_at_most(m[0], 255)),
        "SpiWrite" => exact_members(body, &["device_id"]).is_some_and(|m| uint_at_most(m[0], 255)),
        "AffectActuator" | "EmergencyActuator" => {
            exact_members(body, &["class"]).is_some_and(|m| actuator_class_ok(m[0]))
        }
        _ => false,
    }
}

impl Statement for RbacManifest {
    const TYPE: StatementType = StatementType::RbacManifest;

    fn validate(&self) -> Check {
        type_member(&self.type_, Self::TYPE)?;
        uuid(&self.tenant_id, "tenant_id is not a UUID")?;
        sequence(self.policy_version, "policy_version out of range")?;
        window(&self.not_before, &self.expires_at)?;
        ensure(self.actors.len() == 1, "exactly one actor")?;
        for actor in &self.actors {
            uuid(&actor.actor_id, "actor_id is not a UUID")?;
            ensure(actor.kind == "platform", "actor kind must be platform")?;
            ensure(is_sha256_hex(&actor.keyid), "actor keyid")?;
            ensure(is_ed25519_public_key(&actor.public_key), "actor public_key")?;
            ensure(
                actor.roles == ["platform-authenticated"],
                "actor roles must be [platform-authenticated]",
            )?;
        }
        ensure(self.roles.len() == 1, "exactly one role")?;
        for role in &self.roles {
            ensure(role.name == "platform-authenticated", "role name")?;
            ensure(
                !role.permissions.is_empty(),
                "permissions must not be empty",
            )?;
            let distinct: BTreeSet<String> =
                role.permissions.iter().map(Value::to_string).collect();
            ensure(
                distinct.len() == role.permissions.len(),
                "permissions must be unique",
            )?;
            ensure(
                role.permissions.iter().all(permission_ok),
                "permission outside the schema",
            )?;
            window(&role.not_before, &role.expires_at)?;
        }
        Ok(())
    }

    fn window(&self) -> Option<(&str, &str)> {
        Some((&self.not_before, &self.expires_at))
    }
    fn tenant_id(&self) -> Option<&str> {
        Some(&self.tenant_id)
    }
    fn sequence(&self) -> Option<u64> {
        Some(self.policy_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_names_follow_the_schema_pattern() {
        assert!(is_artifact_name(
            "suderra-agent-os-1.6.0-revpi-connect4-aarch64.tar.gz"
        ));
        assert!(is_artifact_name(
            "suderra-agent-os-1.0.0-rc.1-qemu-x86_64-x86_64.tar.gz"
        ));
        assert!(!is_artifact_name(
            "suderra-agent-os-1.6.0-revpi-connect4-armv7.tar.gz"
        ));
        assert!(!is_artifact_name("suderra-agent-1.6.0-x86_64-linux.tar.gz"));
        assert!(!is_artifact_name("suderra-agent-os--x-aarch64.tar.gz"));
    }

    #[test]
    fn permissions_follow_the_schema() {
        for ok in [
            r#""ReadTag""#,
            r#"{"WriteTag":{"tag_id":"pond.1:do"}}"#,
            r#"{"ModbusWrite":{"device_id":3,"register_range":{"start":10,"end":10}}}"#,
            r#"{"AffectActuator":{"class":{"Aeration":"LifeSupport"}}}"#,
            r#"{"EmergencyActuator":{"class":"Feeding"}}"#,
        ] {
            assert!(permission_ok(&serde_json::from_str(ok).unwrap()), "{ok}");
        }
        for bad in [
            r#""SafeStateTrigger""#,
            r#"{"ReadTag":null}"#,
            r#"{"ModbusWrite":{"device_id":3,"register_range":{"start":11,"end":10}}}"#,
            r#"{"GpioWrite":{"pin":256}}"#,
            r#"{"WriteTag":{"tag_id":"x","extra":1}}"#,
            r#"{"WriteTag":{"tag_id":"x"},"GpioWrite":{"pin":1}}"#,
        ] {
            assert!(!permission_ok(&serde_json::from_str(bad).unwrap()), "{bad}");
        }
    }

    #[test]
    fn lifecycle_purpose_rules() {
        let base = r#"{"_type":"suderra.device-lifecycle.v1","tenant_id":"7e570000-0000-4000-8000-000000000001","device_id":"7e570000-0000-4000-8000-0000000000d1","device_binding":{"method":"tpm-ek-sha256","digest":{"sha256":"7dc1225201ce83c48f502d0421ad7bfe59aaf9c0088fecab0c5a6bb80d360af4"}},"update_seq":3,"not_before":"2026-10-20T00:00:00Z","expires_at":"2026-10-21T00:00:00Z","#;
        let parse =
            |tail: &str| parse_payload::<DeviceLifecycle>(format!("{base}{tail}").as_bytes());
        assert!(parse(r#""action":"enter-maintenance","purpose":"reprovision"}"#).is_ok());
        assert_eq!(
            parse(r#""action":"enter-maintenance"}"#).unwrap_err(),
            Reason::SchemaInvalid
        );
        assert_eq!(
            parse(r#""action":"enter-maintenance","purpose":null}"#).unwrap_err(),
            Reason::SchemaInvalid
        );
        assert_eq!(
            parse(r#""action":"rma","purpose":"reprovision"}"#).unwrap_err(),
            Reason::SchemaInvalid
        );
        assert!(parse(r#""action":"rma"}"#).is_ok());
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! The OS root verifier of every signed statement (statements.json).
//!
//! `verification_order` runs first and stops at the first failure; after the
//! schema every check of the statement and of its nested statements is
//! evaluated and every failing one is reported (statements.json
//! `evaluation`). Each function pins exactly one statement type.

use super::dsse::{pae, verify_strict, Envelope};
use super::encoding::{decode_base64_array, sha256_hex};
use super::keys::{KeyEntry, KeyStore, KeyView};
use super::registry::{
    naming, Arch, BoardProfile, EqualSeq, Purpose, Reason, SitePath, StatementType,
};
use super::statements::{
    parse_payload, ActivationReceipt, Anchor, DeviceBinding, DeviceLifecycle, EdgeProvisioning,
    EdgeRelease, RbacManifest, SiteConfig, Statement, TrustAnchors,
};
use std::collections::{BTreeMap, BTreeSet};

/// Tenant and device a device is bound to (statements.json `identity`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    /// Tenant UUID.
    pub tenant_id: String,
    /// Device UUID.
    pub device_id: String,
}

/// Last accepted statement of one type (/data/suderra/os/seq/<kind>).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Accepted {
    /// Sequence value, for sequenced types.
    pub seq: Option<u64>,
    /// Statement digest.
    pub statement_digest: String,
}

/// What the running OS offers an agent release (statements.json `compatibility`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OsCompat {
    /// VERSION_ID as an integer tuple.
    pub version: (u64, u64, u64),
    /// Inclusive SUDERRA_AGENT_ABI range.
    pub abi: (u64, u64),
    /// Kernel symbols with a =y or =m line.
    pub kernel_config: BTreeSet<String>,
}

/// Root's view of the device a statement is verified on.
#[derive(Debug, Clone)]
pub(crate) struct DeviceRecord {
    /// board_profile of /etc/suderra/board.
    pub board: BoardProfile,
    /// arch of /etc/suderra/board.
    pub arch: Arch,
    /// The device's own hardware binding record.
    pub binding: DeviceBinding,
    /// Identity recorded at first provisioning.
    pub identity: Option<Identity>,
    /// Rollback floor (security_version).
    pub security_version_floor: u64,
    /// Accepted statements by type.
    pub accepted: BTreeMap<StatementType, Accepted>,
    /// Min-epoch ratchet per purpose.
    pub ratchet: BTreeMap<Purpose, u16>,
    /// Statement digest of the installed provisioning manifest.
    pub installed_manifest_digest: Option<String>,
    /// OS compatibility facts.
    pub os: OsCompat,
}

/// Acceptance or re-verification (statements.json `reverification`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// First acceptance: window and sequence apply.
    Accept,
    /// Re-verification of an installed statement.
    Reverify,
}

/// Everything a verification is evaluated against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope<'a> {
    /// Keys pinned in the OS image.
    pub os_keys: &'a KeyStore,
    /// The device, absent for release admission without one.
    pub device: Option<&'a DeviceRecord>,
    /// Evaluation time (contract timestamp form).
    pub now: &'a str,
    /// Acceptance or re-verification.
    pub mode: Mode,
}

/// A statement whose envelope, signature and schema verified.
#[derive(Debug, Clone)]
pub(crate) struct Verified<T> {
    /// The typed payload.
    pub statement: T,
    /// Statement digest (SHA-256 of the payload bytes).
    pub digest: String,
    /// Epoch of the key that verified it.
    pub key_epoch: u16,
}

/// Outcome of one statement verification.
#[derive(Debug, Clone)]
pub(crate) struct Verdict<T> {
    /// Every failing reason (empty when accepted).
    pub reasons: BTreeSet<Reason>,
    /// The payload, when verification got past the schema.
    pub verified: Option<Verified<T>>,
}

impl<T> Verdict<T> {
    fn halted(reason: Reason) -> Self {
        Self {
            reasons: BTreeSet::from([reason]),
            verified: None,
        }
    }

    /// The verified statement when no reason failed.
    pub(crate) fn accepted(self) -> Result<Verified<T>, BTreeSet<Reason>> {
        match self.verified {
            Some(v) if self.reasons.is_empty() => Ok(v),
            _ => Err(self.reasons),
        }
    }
}

/// Site file bytes by fixed path.
pub(crate) type SiteFiles = BTreeMap<SitePath, Vec<u8>>;

/// Runs `verification_order` for a payload of type `T`.
fn open<T: Statement>(
    env: &Envelope,
    keys: KeyView<'_>,
    scope: &Scope<'_>,
) -> Result<Verified<T>, Reason> {
    if env.payload_type != T::TYPE.payload_type() {
        return Err(Reason::PayloadTypeMismatch);
    }
    let key: &KeyEntry = keys.get(&env.keyid).ok_or(Reason::KeyUnknown)?;
    if key.purpose != T::TYPE.spec().signing_purpose {
        return Err(Reason::KeyPurposeMismatch);
    }
    if let Some(device) = scope.device {
        if device
            .ratchet
            .get(&key.purpose)
            .is_some_and(|min| key.epoch < *min)
        {
            return Err(Reason::KeyEpochBelowRatchet);
        }
    }
    if !verify_strict(
        &key.raw,
        &pae(&env.payload_type, &env.payload),
        &env.signature,
    ) {
        return Err(Reason::SignatureInvalid);
    }
    let statement = parse_payload::<T>(&env.payload)?;
    Ok(Verified {
        statement,
        digest: env.statement_digest(),
        key_epoch: key.epoch,
    })
}

/// Tenant and device the statement's identity is compared with.
fn bound<'a>(scope: &Scope<'a>, identity: Option<&'a Identity>) -> Option<&'a Identity> {
    scope.device.and_then(|d| d.identity.as_ref()).or(identity)
}

/// Window, sequence, binding and identity checks shared by every type.
fn generic_checks<T: Statement>(
    v: &Verified<T>,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
    reasons: &mut BTreeSet<Reason>,
) {
    let spec = T::TYPE.spec();
    let accepted = scope.device.and_then(|d| d.accepted.get(&T::TYPE));
    let mut reverify = scope.mode == Mode::Reverify;
    if reverify {
        if accepted.is_none_or(|a| a.statement_digest != v.digest) {
            reasons.insert(Reason::InstalledDigestMismatch);
        }
    } else if let (Some(rule), Some(last)) = (spec.sequence, accepted) {
        match (v.statement.sequence(), last.seq) {
            (Some(value), Some(last_seq)) if value > last_seq => {}
            (Some(value), Some(last_seq))
                if value == last_seq
                    && rule.equal == EqualSeq::IdenticalOnly
                    && last.statement_digest == v.digest =>
            {
                // An identical re-presentation is a re-verification.
                reverify = true;
            }
            _ => {
                reasons.insert(Reason::SequenceReplay);
            }
        }
    }
    if !reverify {
        if let Some((not_before, expires_at)) = v.statement.window() {
            if scope.now < not_before {
                reasons.insert(Reason::NotYetValid);
            }
            if scope.now >= expires_at {
                reasons.insert(Reason::Expired);
            }
        }
    }
    let bound = bound(scope, identity);
    if spec.device_bound {
        if let Some(device) = scope.device {
            if v.statement.binding() != Some(&device.binding) {
                reasons.insert(Reason::DeviceBindingMismatch);
            }
            if bound.is_some_and(|b| v.statement.device_id() != Some(b.device_id.as_str())) {
                reasons.insert(Reason::DeviceIdMismatch);
            }
        }
    }
    if spec.tenant_bound
        && T::TYPE != StatementType::TrustAnchors
        && bound.is_some_and(|b| v.statement.tenant_id() != Some(b.tenant_id.as_str()))
    {
        reasons.insert(Reason::TenantMismatch);
    }
}

/// An integer member of an unverified payload, for digest-reference checks.
fn loose_u64(payload: &[u8], field: &str) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()?
        .get(field)?
        .as_u64()
}

// ------------------------------------------------------------------ release

/// Verifies a suderra.edge-release.v1 statement.
pub(crate) fn verify_release(
    env: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
) -> Verdict<EdgeRelease> {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: None,
    };
    let v = match open::<EdgeRelease>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => return Verdict::halted(reason),
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, identity, &mut reasons);
    let r = &v.statement;
    let board = r.board_profile.spec();
    let features: BTreeSet<_> = r.cargo_features.iter().copied().collect();
    let expected: BTreeSet<_> = board.cargo_features.iter().copied().collect();
    if r.arch != board.arch
        || r.agent_profile != board.agent_profile
        || features != expected
        || r.artifact.name != naming::artifact_name(&r.version, r.board_profile, r.arch)
    {
        reasons.insert(Reason::ReleaseProfileMismatch);
    }
    if let Some(device) = scope.device {
        if r.board_profile != device.board || r.arch != device.arch {
            reasons.insert(Reason::BoardMismatch);
        }
        reasons.extend(compatibility(r, &device.os));
    }
    Verdict {
        reasons,
        verified: Some(v),
    }
}

/// DEC-23 compatibility of a release with an OS.
pub(crate) fn compatibility(release: &EdgeRelease, os: &OsCompat) -> BTreeSet<Reason> {
    let mut reasons = BTreeSet::new();
    match super::encoding::parse_version_core(&release.min_os_version) {
        Some(min) if os.version >= min => {}
        _ => {
            reasons.insert(Reason::OsVersionTooOld);
        }
    }
    if release.agent_abi < os.abi.0 || release.agent_abi > os.abi.1 {
        reasons.insert(Reason::AgentAbiUnsupported);
    }
    if release
        .required_kernel_config
        .iter()
        .any(|symbol| !os.kernel_config.contains(symbol))
    {
        reasons.insert(Reason::KernelConfigMissing);
    }
    reasons
}

// ------------------------------------------------------------ trust anchors

/// Bundle-only anchors of a bundle, as a key store; `None` when two anchors
/// share a keyid or a slot.
pub(crate) fn bundle_keys(bundle: &TrustAnchors) -> Option<KeyStore> {
    let entries = bundle.anchors.iter().filter_map(|anchor| match anchor {
        Anchor::Ed25519(a) if a.purpose.bundle_only() => Some((a.purpose, a.epoch, &a.public_key)),
        _ => None,
    });
    let mut keys = Vec::new();
    for (purpose, epoch, public_key) in entries {
        keys.push(KeyEntry {
            purpose,
            epoch: u16::try_from(epoch).ok()?,
            raw: decode_base64_array::<32>(public_key)?,
        });
    }
    KeyStore::from_entries(keys).ok()
}

/// Verifies a suderra.trust-anchors.v1 bundle against the fleet-root pin.
pub(crate) fn verify_trust_anchors(
    env: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
) -> Verdict<TrustAnchors> {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: None,
    };
    let v = match open::<TrustAnchors>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => return Verdict::halted(reason),
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, identity, &mut reasons);
    if let Some(b) = bound(scope, identity) {
        if !v.statement.tenant_scope.contains(&b.tenant_id) {
            reasons.insert(Reason::TenantScopeMismatch);
        }
    }
    let mut slots = BTreeSet::new();
    let mut keyids = BTreeSet::new();
    for anchor in &v.statement.anchors {
        let Anchor::Ed25519(a) = anchor else { continue };
        let raw = decode_base64_array::<32>(&a.public_key);
        let consistent = raw.is_some_and(|raw| sha256_hex(&raw) == a.keyid);
        // One keyid resolves to one (purpose, epoch): a key anchored twice is
        // as ambiguous as a slot anchored twice.
        if !consistent || !slots.insert((a.purpose, a.epoch)) || !keyids.insert(&a.keyid) {
            reasons.insert(Reason::AnchorInvalid);
        }
        if !a.purpose.bundle_only() {
            let pinned = scope.os_keys.get(&a.keyid);
            if pinned.is_none_or(|p| p.purpose != a.purpose || u64::from(p.epoch) != a.epoch) {
                reasons.insert(Reason::AnchorNotOsPinned);
            }
        }
    }
    Verdict {
        reasons,
        verified: Some(v),
    }
}

/// Verifies `ta` and returns its bundle-only keys, merging its reasons.
#[cfg(test)]
fn bundle_first(
    ta: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
    reasons: &mut BTreeSet<Reason>,
) -> Option<KeyStore> {
    let bundle = verify_trust_anchors(ta, scope, identity);
    reasons.extend(bundle.reasons.iter().copied());
    match bundle.accepted() {
        Ok(v) => bundle_keys(&v.statement).or_else(|| {
            reasons.insert(Reason::AnchorInvalid);
            None
        }),
        Err(_) => None,
    }
}

// ------------------------------------------------------------- RBAC manifest

/// Verifies a suderra.rbac-manifest.v1 statement against a verified bundle's
/// anchors.
pub(crate) fn verify_rbac(
    env: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
    bundle: &KeyStore,
) -> Verdict<RbacManifest> {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: Some(bundle),
    };
    let v = match open::<RbacManifest>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => return Verdict::halted(reason),
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, identity, &mut reasons);
    for actor in &v.statement.actors {
        let raw = decode_base64_array::<32>(&actor.public_key);
        let anchored = bundle.get(&actor.keyid);
        let ok = raw.is_some_and(|raw| {
            sha256_hex(&raw) == actor.keyid
                && anchored.is_some_and(|a| a.purpose == Purpose::Command && a.raw == raw)
        });
        if !ok {
            reasons.insert(Reason::ActorKeyNotAnchored);
        }
    }
    Verdict {
        reasons,
        verified: Some(v),
    }
}

/// Verifies an RBAC manifest whose anchors come from `ta`, verified first
/// (standalone form of statements.json key resolution).
#[cfg(test)]
pub(crate) fn verify_rbac_with_bundle(
    env: &Envelope,
    ta: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
) -> Verdict<RbacManifest> {
    if env.payload_type != StatementType::RbacManifest.payload_type() {
        return Verdict::halted(Reason::PayloadTypeMismatch);
    }
    let mut reasons = BTreeSet::new();
    let Some(keys) = bundle_first(ta, scope, identity, &mut reasons) else {
        return Verdict {
            reasons,
            verified: None,
        };
    };
    let mut verdict = verify_rbac(env, scope, identity, &keys);
    verdict.reasons.extend(reasons);
    verdict
}

// --------------------------------------------------------------- site config

/// Verifies a suderra.site-config.v1 statement, its RBAC manifest and the
/// delivered site files against a verified bundle's anchors.
pub(crate) fn verify_site_config(
    env: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
    bundle: &KeyStore,
    rbac: &Envelope,
    files: &SiteFiles,
) -> (Verdict<SiteConfig>, Option<Verdict<RbacManifest>>) {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: Some(bundle),
    };
    let v = match open::<SiteConfig>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => return (Verdict::halted(reason), None),
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, identity, &mut reasons);
    let named = &v.statement.files;
    let files_ok = named.keys().eq(files.keys())
        && named.iter().all(|(path, entry)| {
            files.get(path).is_some_and(|bytes| {
                sha256_hex(bytes) == entry.digest.sha256
                    && u64::try_from(bytes.len()).is_ok_and(|n| n == entry.size_bytes)
            })
        });
    if !files_ok {
        reasons.insert(Reason::SiteFileDigestMismatch);
    }
    let rbac_verdict = verify_rbac(rbac, scope, identity, bundle);
    reasons.extend(rbac_verdict.reasons.iter().copied());
    let reference = &v.statement.rbac_manifest;
    let policy_version = rbac_verdict
        .verified
        .as_ref()
        .map(|r| r.statement.policy_version)
        .or_else(|| loose_u64(&rbac.payload, "policy_version"));
    if reference.digest.sha256 != rbac.statement_digest()
        || policy_version != Some(reference.policy_version)
    {
        reasons.insert(Reason::RbacManifestDigestMismatch);
    }
    (
        Verdict {
            reasons,
            verified: Some(v),
        },
        Some(rbac_verdict),
    )
}

/// Verifies a site config whose anchors come from `ta`, verified first
/// (standalone form of statements.json key resolution).
#[cfg(test)]
pub(crate) fn verify_site_config_with_bundle(
    env: &Envelope,
    ta: &Envelope,
    scope: &Scope<'_>,
    identity: Option<&Identity>,
    rbac: &Envelope,
    files: &SiteFiles,
) -> Verdict<SiteConfig> {
    if env.payload_type != StatementType::SiteConfig.payload_type() {
        return Verdict::halted(Reason::PayloadTypeMismatch);
    }
    let mut reasons = BTreeSet::new();
    let Some(keys) = bundle_first(ta, scope, identity, &mut reasons) else {
        return Verdict {
            reasons,
            verified: None,
        };
    };
    let (mut verdict, _) = verify_site_config(env, scope, identity, &keys, rbac, files);
    verdict.reasons.extend(reasons);
    verdict
}

// --------------------------------------------------------- provisioning

/// The statements and files delivered with a provisioning manifest.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Delivered<'a> {
    /// suderra.edge-release.v1 envelope.
    pub release: &'a Envelope,
    /// suderra.trust-anchors.v1 envelope.
    pub trust_anchors: &'a Envelope,
    /// suderra.site-config.v1 envelope.
    pub site_config: &'a Envelope,
    /// suderra.rbac-manifest.v1 envelope.
    pub rbac: &'a Envelope,
    /// Site file bytes.
    pub site_files: &'a SiteFiles,
}

/// Every statement a provisioning delivery carries, once all verified.
#[derive(Debug, Clone)]
pub(crate) struct ProvisioningSet {
    /// The manifest.
    pub manifest: Verified<EdgeProvisioning>,
    /// Its release statement.
    pub release: Verified<EdgeRelease>,
    /// Its trust-anchors bundle.
    pub trust_anchors: Verified<TrustAnchors>,
    /// Its site config.
    pub site_config: Verified<SiteConfig>,
    /// The site config's RBAC manifest.
    pub rbac: Verified<RbacManifest>,
}

/// Outcome of a provisioning verification.
#[derive(Debug, Clone)]
pub(crate) struct ProvisioningVerdict {
    /// Every failing reason of the manifest and its delivered statements.
    pub reasons: BTreeSet<Reason>,
    /// The verified set when every reason passed.
    pub accepted: Option<ProvisioningSet>,
}

/// Verifies a suderra.edge-provisioning.v1 manifest and everything it
/// delivers on `device`.
pub(crate) fn verify_provisioning(
    env: &Envelope,
    delivered: Delivered<'_>,
    request_nonce: &str,
    scope: &Scope<'_>,
) -> ProvisioningVerdict {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: None,
    };
    let v = match open::<EdgeProvisioning>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => {
            return ProvisioningVerdict {
                reasons: BTreeSet::from([reason]),
                accepted: None,
            }
        }
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, None, &mut reasons);
    let m = &v.statement;
    if m.key_epoch != u64::from(v.key_epoch) {
        reasons.insert(Reason::KeyEpochMismatch);
    }
    if m.nonce != request_nonce {
        reasons.insert(Reason::NonceMismatch);
    }
    if let Some(device) = scope.device {
        if m.board != device.board || m.arch != device.arch {
            reasons.insert(Reason::BoardMismatch);
        }
        if m.security_version < device.security_version_floor {
            reasons.insert(Reason::RollbackBelowFloor);
        }
    }
    // First provisioning binds the identity of every delivered statement.
    let identity = bound(scope, None).cloned().unwrap_or_else(|| Identity {
        tenant_id: m.tenant_id.clone(),
        device_id: m.device_id.clone(),
    });

    let release = verify_release(delivered.release, scope, Some(&identity));
    reasons.extend(release.reasons.iter().copied());
    if m.release_statement.digest.sha256 != delivered.release.statement_digest() {
        reasons.insert(Reason::ReleaseDigestMismatch);
    }
    if let Some(r) = release.verified.as_ref().map(|r| &r.statement) {
        if m.version != r.version
            || m.board != r.board_profile
            || m.arch != r.arch
            || m.security_version != r.security_version
            || m.agent_profile != r.agent_profile
        {
            reasons.insert(Reason::ReleaseMismatch);
        }
    }

    let bundle = verify_trust_anchors(delivered.trust_anchors, scope, Some(&identity));
    reasons.extend(bundle.reasons.iter().copied());
    let bundle_seq = bundle
        .verified
        .as_ref()
        .map(|b| b.statement.bundle_seq)
        .or_else(|| loose_u64(&delivered.trust_anchors.payload, "bundle_seq"));
    if m.trust_anchors.digest.sha256 != delivered.trust_anchors.statement_digest()
        || bundle_seq != Some(m.trust_anchors.bundle_seq)
    {
        reasons.insert(Reason::TrustAnchorsDigestMismatch);
    }
    let site_seq = loose_u64(&delivered.site_config.payload, "update_seq");
    if m.site_config.digest.sha256 != delivered.site_config.statement_digest()
        || site_seq != Some(m.site_config.update_seq)
    {
        reasons.insert(Reason::SiteConfigDigestMismatch);
    }

    // The site config and its RBAC manifest verify only against a bundle
    // that verified.
    let mut site = None;
    if let Ok(bundle_verified) = bundle.accepted() {
        match bundle_keys(&bundle_verified.statement) {
            Some(keys) => {
                let (site_verdict, rbac_verdict) = verify_site_config(
                    delivered.site_config,
                    scope,
                    Some(&identity),
                    &keys,
                    delivered.rbac,
                    delivered.site_files,
                );
                reasons.extend(site_verdict.reasons.iter().copied());
                site = Some((bundle_verified, site_verdict, rbac_verdict));
            }
            None => {
                reasons.insert(Reason::AnchorInvalid);
            }
        }
    }

    let accepted = match (reasons.is_empty(), release.verified, site) {
        (true, Some(release), Some((trust_anchors, site_verdict, Some(rbac_verdict)))) => {
            match (site_verdict.verified, rbac_verdict.verified) {
                (Some(site_config), Some(rbac)) => Some(ProvisioningSet {
                    manifest: v,
                    release,
                    trust_anchors,
                    site_config,
                    rbac,
                }),
                _ => None,
            }
        }
        _ => None,
    };
    ProvisioningVerdict { reasons, accepted }
}

// ------------------------------------------------------- receipt, lifecycle

/// Verifies a suderra.edge-activation-receipt.v1 for the installed manifest.
pub(crate) fn verify_receipt(env: &Envelope, scope: &Scope<'_>) -> Verdict<ActivationReceipt> {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: None,
    };
    let v = match open::<ActivationReceipt>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => return Verdict::halted(reason),
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, None, &mut reasons);
    let installed = scope
        .device
        .and_then(|d| d.installed_manifest_digest.as_deref());
    if installed != Some(v.statement.manifest_digest.sha256.as_str()) {
        reasons.insert(Reason::ManifestDigestMismatch);
    }
    Verdict {
        reasons,
        verified: Some(v),
    }
}

/// Verifies a suderra.device-lifecycle.v1 statement.
pub(crate) fn verify_lifecycle(env: &Envelope, scope: &Scope<'_>) -> Verdict<DeviceLifecycle> {
    let keys = KeyView {
        os: scope.os_keys,
        bundle: None,
    };
    let v = match open::<DeviceLifecycle>(env, keys, scope) {
        Ok(v) => v,
        Err(reason) => return Verdict::halted(reason),
    };
    let mut reasons = BTreeSet::new();
    generic_checks(&v, scope, None, &mut reasons);
    Verdict {
        reasons,
        verified: Some(v),
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Provisioning request and delivery documents (delivery.json, DEC-5.5).

use super::dsse::{Envelope, RawEnvelope};
use super::encoding::{
    decode_canonical_base64, is_nonce, is_os_version, is_sha256_hex, parse_abi_range,
};
use super::json::check_strict_object;
use super::registry::{BindingMethod, BoardProfile, Reason, SitePath};
use super::verify::{verify_provisioning, Delivered, ProvisioningVerdict, Scope, SiteFiles};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// delivery.json `request_type`.
#[cfg(test)]
pub(crate) const REQUEST_TYPE: &str = "suderra.edge-provisioning-request.v1";
/// delivery.json `delivery_type`.
pub(crate) const DELIVERY_TYPE: &str = "suderra.edge-provisioning-delivery.v1";
/// delivery.json `network.request.path` (with `{device_code}`).
pub(crate) const REQUEST_PATH: &str = "/install/{device_code}/suderra-os";
/// delivery.json `network.request.headers`.
pub(crate) const TOKEN_HEADER: &str = "X-Provisioning-Token";
/// delivery.json `network.response.content_type`.
pub(crate) const DELIVERY_CONTENT_TYPE: &str =
    "application/vnd.suderra.edge-provisioning-delivery.v1+json";

/// Query parameters of the provisioning request
/// (schemas/edge-provisioning-request.schema.json).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisioningRequest {
    /// Binding method of the device record.
    pub binding_method: BindingMethod,
    /// Binding digest of the device record.
    pub binding_sha256: String,
    /// Fresh CSPRNG nonce.
    pub nonce: String,
    /// board_profile of /etc/suderra/board.
    pub board_profile: BoardProfile,
    /// VERSION_ID of /etc/os-release.
    pub os_version: String,
    /// SUDERRA_AGENT_ABI of /etc/os-release.
    pub agent_abi: String,
}

impl ProvisioningRequest {
    /// Schema constraints serde does not enforce.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !is_sha256_hex(&self.binding_sha256) {
            return Err("binding_sha256 is not lowercase hex SHA-256".into());
        }
        if !is_nonce(&self.nonce) {
            return Err("nonce must be 128 to 512 bits of lowercase hex".into());
        }
        if !is_os_version(&self.os_version) {
            return Err("os_version is not MAJOR.MINOR.PATCH".into());
        }
        if parse_abi_range(&self.agent_abi).is_none() {
            return Err("agent_abi is not MIN-MAX".into());
        }
        Ok(())
    }

    /// Parses a request document (golden documents, logged requests).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Reason> {
        check_strict_object(bytes).map_err(|_| Reason::PayloadJsonInvalid)?;
        let request: Self = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaInvalid)?;
        request.validate().map_err(|_| Reason::SchemaInvalid)?;
        Ok(request)
    }

    /// Query string pairs, in schema order.
    pub(crate) fn query(&self) -> [(&'static str, &str); 6] {
        [
            ("binding_method", self.binding_method.as_str()),
            ("binding_sha256", &self.binding_sha256),
            ("nonce", &self.nonce),
            ("board_profile", self.board_profile.as_str()),
            ("os_version", &self.os_version),
            ("agent_abi", &self.agent_abi),
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelivery {
    #[serde(rename = "_type")]
    type_: String,
    manifest: RawEnvelope,
    release_statement: RawEnvelope,
    trust_anchors: RawEnvelope,
    site_config: RawEnvelope,
    rbac_manifest: RawEnvelope,
    site_files: BTreeMap<SitePath, String>,
}

/// A schema-valid provisioning delivery
/// (schemas/edge-provisioning-delivery.schema.json).
#[derive(Debug, Clone)]
pub(crate) struct Delivery {
    /// suderra.edge-provisioning.v1 envelope.
    pub manifest: Envelope,
    /// suderra.edge-release.v1 envelope.
    pub release: Envelope,
    /// suderra.trust-anchors.v1 envelope.
    pub trust_anchors: Envelope,
    /// suderra.site-config.v1 envelope.
    pub site_config: Envelope,
    /// suderra.rbac-manifest.v1 envelope.
    pub rbac: Envelope,
    /// Decoded site files.
    pub site_files: SiteFiles,
}

impl Delivery {
    /// Parses a delivery document: strict JSON (`payload-json-invalid`), then
    /// the delivery schema including its embedded envelopes (`schema-invalid`).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Reason> {
        check_strict_object(bytes).map_err(|_| Reason::PayloadJsonInvalid)?;
        let raw: RawDelivery = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaInvalid)?;
        if raw.type_ != DELIVERY_TYPE || !raw.site_files.contains_key(&SitePath::ConfigYaml) {
            return Err(Reason::SchemaInvalid);
        }
        let envelope =
            |raw: RawEnvelope| Envelope::from_raw(raw).map_err(|_| Reason::SchemaInvalid);
        let site_files = raw
            .site_files
            .into_iter()
            .map(|(path, b64)| {
                decode_canonical_base64(&b64)
                    .map(|bytes| (path, bytes))
                    .ok_or(Reason::SchemaInvalid)
            })
            .collect::<Result<SiteFiles, Reason>>()?;
        Ok(Self {
            manifest: envelope(raw.manifest)?,
            release: envelope(raw.release_statement)?,
            trust_anchors: envelope(raw.trust_anchors)?,
            site_config: envelope(raw.site_config)?,
            rbac: envelope(raw.rbac_manifest)?,
            site_files,
        })
    }

    /// Verifies the manifest with the other members as its delivered
    /// statements and files.
    pub(crate) fn verify(&self, request_nonce: &str, scope: &Scope<'_>) -> ProvisioningVerdict {
        verify_provisioning(
            &self.manifest,
            Delivered {
                release: &self.release,
                trust_anchors: &self.trust_anchors,
                site_config: &self.site_config,
                rbac: &self.rbac,
                site_files: &self.site_files,
            },
            request_nonce,
            scope,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_delivery_json() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/suderra-edge/v1/delivery.json");
        let d: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(d["request_type"], REQUEST_TYPE);
        assert_eq!(d["delivery_type"], DELIVERY_TYPE);
        assert_eq!(d["network"]["request"]["method"], "GET");
        assert_eq!(d["network"]["request"]["path"], REQUEST_PATH);
        assert!(d["network"]["request"]["headers"]
            .get(TOKEN_HEADER)
            .is_some());
        assert_eq!(
            d["network"]["response"]["content_type"],
            DELIVERY_CONTENT_TYPE
        );
        assert_eq!(d["network"]["response"]["status"], 200);
    }
}

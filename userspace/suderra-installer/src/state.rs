// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Root-owned device records under /data/suderra/os (ADR-048 DEC-1.3,
//! DEC-2.4, DEC-2.5, DEC-3.5, DEC-3.6, DEC-22).
//!
//! | Record | Path | Writer |
//! |---|---|---|
//! | hardware binding | `identity/device-binding.json` | suderra-identity (first boot) |
//! | tenant/device identity | `identity/device.json` | installer, first provisioning |
//! | accepted statement | `seq/<kind>` | installer, lifecycle |
//! | min-epoch ratchet | `ratchet/<purpose>` | key-epoch-advance (DEC-15) |
//! | rollback floor | `edge/floor` | lifecycle activate |
//! | install receipt | `edge/receipt.json` (+ `receipt.previous.json`) | installer |
//! | installed release statement | `edge/release.dsse.json` | installer |
//!
//! Every record is strict JSON or one decimal line, written atomically; a
//! record that does not parse is an error, never a default.

use crate::contracts::encoding::{is_semver, is_uuid};
use crate::contracts::json::check_strict_object;
use crate::contracts::registry::{Arch, BoardProfile, Purpose, SitePath, StatementType};
use crate::contracts::statements::{DeviceBinding, Digest, SiteFile};
use crate::contracts::verify::{Accepted, DeviceRecord, Identity};
use crate::fsutil::{ensure_dir, read_root_file, write_atomic};
use crate::paths::Paths;
use crate::variant::ImageFacts;
use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_RECORD: u64 = 64 * 1024;

/// `_type` of the install receipt (OS-internal record).
pub(crate) const RECEIPT_TYPE: &str = "suderra.edge-install-receipt.v1";

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let Some(bytes) = read_root_file(path, MAX_RECORD)? else {
        return Ok(None);
    };
    check_strict_object(&bytes).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("{} is corrupt", path.display()))
}

fn read_decimal(path: &Path) -> Result<Option<u64>> {
    let Some(bytes) = read_root_file(path, 32)? else {
        return Ok(None);
    };
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|t| t.strip_suffix('\n'))
        .and_then(|t| t.parse::<u64>().ok())
        .map(Some)
        .with_context(|| format!("{} is corrupt", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    ensure_dir(path.parent().context("record has no parent")?, 0o700)?;
    write_atomic(path, &serde_json::to_vec(value)?, 0o600, None)
}

/// Tenant and device recorded at first provisioning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceIdentityRecord {
    /// Tenant UUID.
    pub tenant_id: String,
    /// Device UUID.
    pub device_id: String,
    /// Device code.
    pub device_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    statement_digest: Digest,
}

/// The install receipt (DEC-1.3): what root installed and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallReceipt {
    #[serde(rename = "_type")]
    pub type_: String,
    /// Release version (path-safe).
    pub version: String,
    /// Release security_version.
    pub security_version: u64,
    /// Board.
    pub board_profile: BoardProfile,
    /// Architecture.
    pub arch: Arch,
    /// Release agent_abi.
    pub agent_abi: u64,
    /// Artifact digest.
    pub artifact_digest: Digest,
    /// Digest of the installed suderra-agent binary.
    pub binary_digest: Digest,
    /// Statement digest of the release statement.
    pub release_statement_digest: Digest,
    /// Epoch of the edge-release key that signed it.
    pub release_key_epoch: u16,
    /// Statement digest of the installed provisioning manifest.
    pub manifest_digest: Digest,
    /// Epoch of the edge-provisioning key that signed it.
    pub manifest_key_epoch: u16,
    /// Statement digest of the installed bundle.
    pub trust_anchors_digest: Digest,
    /// Statement digest of the installed site config.
    pub site_config_digest: Digest,
    /// Statement digest of the installed RBAC manifest.
    pub rbac_manifest_digest: Digest,
    /// Site version directory name under /data/suderra/site/versions.
    pub site_version: String,
    /// Every installed site file.
    pub site_files: BTreeMap<SitePath, SiteFile>,
    /// When root installed it.
    pub installed_at: String,
}

impl InstallReceipt {
    fn validate(&self) -> Result<()> {
        if self.type_ != RECEIPT_TYPE || !is_semver(&self.version) {
            bail!("install receipt is corrupt");
        }
        if !site_version_name_ok(&self.site_version) {
            bail!("install receipt site_version is not path-safe");
        }
        Ok(())
    }
}

/// `<update_seq>-<12 hex>`: the only form of a site version directory.
pub(crate) fn site_version_name_ok(name: &str) -> bool {
    name.split_once('-').is_some_and(|(seq, hash)| {
        !seq.is_empty()
            && seq.bytes().all(|b| b.is_ascii_digit())
            && hash.len() == 12
            && hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// Root-owned records of one device.
pub(crate) struct Records<'a> {
    paths: &'a Paths,
}

impl<'a> Records<'a> {
    /// Records under `paths`.
    pub(crate) fn new(paths: &'a Paths) -> Self {
        Self { paths }
    }

    fn binding_path(&self) -> std::path::PathBuf {
        self.paths.identity_dir().join("device-binding.json")
    }

    fn identity_path(&self) -> std::path::PathBuf {
        self.paths.identity_dir().join("device.json")
    }

    fn seq_path(&self, statement: StatementType) -> std::path::PathBuf {
        self.paths.seq_dir().join(statement.kind())
    }

    fn receipt_path(&self) -> std::path::PathBuf {
        self.paths.edge_state().join("receipt.json")
    }

    /// The installed release statement's envelope path.
    pub(crate) fn release_statement_path(&self) -> std::path::PathBuf {
        self.paths.edge_state().join("release.dsse.json")
    }

    fn floor_path(&self) -> std::path::PathBuf {
        self.paths.edge_state().join("floor")
    }

    /// The hardware binding record (DEC-3.6); it must exist and use the
    /// board's binding method.
    pub(crate) fn binding(&self, board: BoardProfile) -> Result<DeviceBinding> {
        let binding: DeviceBinding = read_json(&self.binding_path())?.with_context(|| {
            format!(
                "{} is missing: suderra-identity has not recorded the hardware binding",
                self.binding_path().display()
            )
        })?;
        binding.validate().map_err(anyhow::Error::msg)?;
        if binding.method != board.spec().device_binding_method {
            bail!(
                "binding method {} differs from boards.json {} for {board}",
                binding.method,
                board.spec().device_binding_method
            );
        }
        Ok(binding)
    }

    /// Identity recorded at first provisioning.
    pub(crate) fn identity(&self) -> Result<Option<DeviceIdentityRecord>> {
        let record: Option<DeviceIdentityRecord> = read_json(&self.identity_path())?;
        if let Some(r) = &record {
            if !is_uuid(&r.tenant_id) || !is_uuid(&r.device_id) {
                bail!("{} is corrupt", self.identity_path().display());
            }
        }
        Ok(record)
    }

    /// Records the identity a first provisioning binds.
    pub(crate) fn write_identity(&self, record: &DeviceIdentityRecord) -> Result<()> {
        write_json(&self.identity_path(), record)
    }

    /// Last accepted statement of a type.
    pub(crate) fn accepted(&self, statement: StatementType) -> Result<Option<Accepted>> {
        let record: Option<AcceptedRecord> = read_json(&self.seq_path(statement))?;
        let sequenced = statement.spec().sequence.is_some();
        record
            .map(|r| {
                if r.seq.is_some() != sequenced {
                    bail!("{} is corrupt", self.seq_path(statement).display());
                }
                Ok(Accepted {
                    seq: r.seq,
                    statement_digest: r.statement_digest.sha256,
                })
            })
            .transpose()
    }

    /// Records an accepted statement (`seq/<kind>`, DEC-2.4).
    pub(crate) fn write_accepted(
        &self,
        statement: StatementType,
        seq: Option<u64>,
        digest: &str,
    ) -> Result<()> {
        write_json(
            &self.seq_path(statement),
            &AcceptedRecord {
                seq,
                statement_digest: Digest {
                    sha256: digest.to_owned(),
                },
            },
        )
    }

    /// Min-epoch ratchet of every purpose that has one (DEC-3.5).
    pub(crate) fn ratchets(&self) -> Result<BTreeMap<Purpose, u16>> {
        let mut out = BTreeMap::new();
        for purpose in Purpose::ALL {
            if let Some(value) = read_decimal(&self.paths.ratchet_dir().join(purpose.as_str()))? {
                let epoch = u16::try_from(value)
                    .ok()
                    .filter(|e| *e >= 1)
                    .with_context(|| format!("ratchet {purpose} is out of range"))?;
                out.insert(*purpose, epoch);
            }
        }
        Ok(out)
    }

    /// Rollback floor (security_version); 0 before the first activation.
    pub(crate) fn floor(&self) -> Result<u64> {
        Ok(read_decimal(&self.floor_path())?.unwrap_or(0))
    }

    /// Raises the rollback floor; it never goes down (DEC-2.5).
    pub(crate) fn raise_floor(&self, security_version: u64) -> Result<u64> {
        let current = self.floor()?;
        let next = current.max(security_version);
        if next != current {
            ensure_dir(&self.paths.edge_state(), 0o700)?;
            write_atomic(
                &self.floor_path(),
                format!("{next}\n").as_bytes(),
                0o600,
                None,
            )?;
        }
        Ok(next)
    }

    /// The install receipt.
    pub(crate) fn receipt(&self) -> Result<Option<InstallReceipt>> {
        let receipt: Option<InstallReceipt> = read_json(&self.receipt_path())?;
        if let Some(r) = &receipt {
            r.validate()?;
        }
        Ok(receipt)
    }

    /// Commits a new install receipt, keeping the previous one.
    pub(crate) fn write_receipt(&self, receipt: &InstallReceipt) -> Result<()> {
        receipt.validate()?;
        let path = self.receipt_path();
        if let Some(previous) = read_root_file(&path, MAX_RECORD)? {
            write_atomic(
                &self.paths.edge_state().join("receipt.previous.json"),
                &previous,
                0o600,
                None,
            )?;
        }
        write_json(&path, receipt)
    }

    /// Stores the installed release statement envelope.
    pub(crate) fn write_release_statement(&self, envelope_json: &[u8]) -> Result<()> {
        ensure_dir(&self.paths.edge_state(), 0o700)?;
        write_atomic(&self.release_statement_path(), envelope_json, 0o600, None)
    }

    /// Root's view of the device for statement verification.
    pub(crate) fn device_record(&self, facts: &ImageFacts) -> Result<DeviceRecord> {
        let board = facts.board.board;
        let receipt = self.receipt()?;
        let mut accepted = BTreeMap::new();
        for statement in StatementType::ALL {
            if statement.spec().sequence.is_some() {
                if let Some(a) = self.accepted(*statement)? {
                    accepted.insert(*statement, a);
                }
            }
        }
        if let Some(r) = &receipt {
            accepted.insert(
                StatementType::EdgeRelease,
                Accepted {
                    seq: None,
                    statement_digest: r.release_statement_digest.sha256.clone(),
                },
            );
        }
        Ok(DeviceRecord {
            board,
            arch: facts.board.arch,
            binding: self.binding(board)?,
            identity: self.identity()?.map(|r| Identity {
                tenant_id: r.tenant_id,
                device_id: r.device_id,
            }),
            security_version_floor: self.floor()?,
            accepted,
            ratchet: self.ratchets()?,
            installed_manifest_digest: receipt.map(|r| r.manifest_digest.sha256),
            os: facts.compat.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{image, write_binding};

    #[test]
    fn records_round_trip_and_fail_closed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let records = Records::new(&paths);
        assert!(records.device_record(&facts).is_err(), "no binding record");
        write_binding(&paths, "aa");
        let record = records.device_record(&facts).unwrap();
        assert!(record.identity.is_none());
        assert_eq!(record.security_version_floor, 0);

        records
            .write_accepted(StatementType::EdgeProvisioning, Some(4), &"b".repeat(64))
            .unwrap();
        assert_eq!(
            records
                .accepted(StatementType::EdgeProvisioning)
                .unwrap()
                .unwrap()
                .seq,
            Some(4)
        );
        assert_eq!(records.raise_floor(6).unwrap(), 6);
        assert_eq!(
            records.raise_floor(3).unwrap(),
            6,
            "the floor never goes down"
        );

        std::fs::create_dir_all(paths.ratchet_dir()).unwrap();
        std::fs::write(paths.ratchet_dir().join("edge-release"), "2\n").unwrap();
        assert_eq!(records.ratchets().unwrap()[&Purpose::EdgeRelease], 2);
        std::fs::write(paths.ratchet_dir().join("edge-release"), "zero\n").unwrap();
        assert!(
            records.ratchets().is_err(),
            "a corrupt ratchet is an error, not a default"
        );
    }

    #[test]
    fn site_version_names_are_path_safe() {
        assert!(site_version_name_ok("2-d097228b6ecc"));
        for bad in [
            "../x",
            "2-D097228B6ECC",
            "2-d097228b6ec",
            "-d097228b6ecc",
            "2_d097228b6ecc",
        ] {
            assert!(!site_version_name_ok(bad), "{bad}");
        }
    }
}

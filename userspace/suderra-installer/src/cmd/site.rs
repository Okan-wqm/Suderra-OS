// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Site directory installation and re-verification (ADR-048 DEC-4.2,
//! DEC-4.10, DEC-4.12; contracts delivery.json `installation`).
//!
//! `/data/suderra/site` is the stable source of the agent's read-only bind
//! at `/var/lib/suderra-site`, so it is never itself replaced (a renamed
//! directory would leave the bind on the old inode). Each verified site set
//! is written complete under `versions/<update_seq>-<set digest>/` and
//! activated by renaming the `current` symlink; the fixed names
//! (`config.yaml`, `site-config.dsse`, …) are relative symlinks into
//! `current`, so the agent's compile-time paths resolve to exactly one
//! complete set at any instant.
//!
//! A version directory is content-addressed: its name is derived from every
//! byte of every file of the set (the site config, trust-anchors and RBAC
//! envelopes and each site file), so two sets that differ in any statement
//! never share a directory, and an existing directory is reused only after
//! its files are proven byte-identical to the set being installed.

use crate::contracts::dsse::Envelope;
use crate::contracts::keys::KeyStore;
use crate::contracts::registry::{Reason, SitePath};
use crate::contracts::verify::{
    bundle_keys, verify_site_config, verify_trust_anchors, DeviceRecord, Identity, Mode,
    ProvisioningSet, Scope, SiteFiles,
};
use crate::fsutil::{ensure_dir, fsync_dir, read_root_file, symlink_atomic, write_atomic};
use crate::paths::Paths;
use crate::state::{site_version_name_ok, InstallReceipt};
use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Statement files of a site set.
pub(crate) const SITE_CONFIG_FILE: &str = "site-config.dsse";
/// See [`SITE_CONFIG_FILE`].
pub(crate) const TRUST_ANCHORS_FILE: &str = "trust-anchors.dsse";
/// See [`SITE_CONFIG_FILE`].
pub(crate) const RBAC_MANIFEST_FILE: &str = "rbac-manifest.dsse";

/// Largest statement or site file root reads back.
const MAX_SITE_FILE: u64 = 2 * 1024 * 1024;

/// Fixed names at the top of the site directory and their link targets.
fn fixed_links() -> Vec<(&'static str, String)> {
    let mut links: Vec<(&'static str, String)> =
        [SITE_CONFIG_FILE, TRUST_ANCHORS_FILE, RBAC_MANIFEST_FILE]
            .into_iter()
            .map(|name| (name, format!("current/{name}")))
            .collect();
    for path in SitePath::ALL {
        let top = path.as_str().split('/').next().unwrap_or(path.as_str());
        if !links.iter().any(|(name, _)| *name == top) {
            links.push((top, format!("current/{top}")));
        }
    }
    links
}

/// Mode of every file of a site set.
const SITE_FILE_MODE: u32 = 0o640;

/// Every file of a site set by its path relative to the version directory.
type SetEntries = BTreeMap<String, Vec<u8>>;

fn set_entries(envelopes: [&Envelope; 3], files: &SiteFiles) -> SetEntries {
    let [site_env, ta_env, rbac_env] = envelopes;
    let mut entries = SetEntries::new();
    entries.insert(SITE_CONFIG_FILE.to_owned(), site_env.to_json());
    entries.insert(TRUST_ANCHORS_FILE.to_owned(), ta_env.to_json());
    entries.insert(RBAC_MANIFEST_FILE.to_owned(), rbac_env.to_json());
    for (path, bytes) in files {
        entries.insert(path.as_str().to_owned(), bytes.clone());
    }
    entries
}

/// Version directory name of a site set: its site config's update_seq and
/// the first 12 hex digits of a SHA-256 over every (path, bytes) pair,
/// length-prefixed so no two sets encode alike.
fn version_name(update_seq: u64, entries: &SetEntries) -> String {
    let mut hasher = Sha256::new();
    for (path, bytes) in entries {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let digest = hex::encode(hasher.finalize());
    format!("{update_seq}-{}", &digest[..12])
}

/// Regular files under `dir`, by relative path; `None` when the tree holds
/// anything else (a symlink, a device, a FIFO).
fn tree_files(dir: &Path, prefix: &str, out: &mut BTreeMap<String, PathBuf>) -> Result<bool> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| anyhow::anyhow!("{} holds a non-UTF-8 name {n:?}", dir.display()))?;
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if !tree_files(&entry.path(), &rel, out)? {
                return Ok(false);
            }
        } else if kind.is_file() {
            out.insert(rel, entry.path());
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether the version directory `dir` holds exactly `entries`: the same
/// paths, the same bytes, root-owned with the site file mode and group.
fn holds_exactly(paths: &Paths, dir: &Path, entries: &SetEntries) -> Result<bool> {
    let mut found = BTreeMap::new();
    if !tree_files(dir, "", &mut found)? || !found.keys().eq(entries.keys()) {
        return Ok(false);
    }
    let uid = nix::unistd::geteuid().as_raw();
    for (rel, path) in &found {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.uid() != uid
            || meta.mode() & 0o7777 != SITE_FILE_MODE
            || paths
                .agent_group()
                .is_some_and(|gid| meta.gid() != gid.as_raw())
        {
            return Ok(false);
        }
        let bytes = read_root_file(path, MAX_SITE_FILE)?;
        if bytes.as_ref() != entries.get(rel) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn versions_dir(paths: &Paths) -> PathBuf {
    paths.site_root().join("versions")
}

fn site_dir_mode(paths: &Paths, dir: &Path) -> Result<()> {
    ensure_dir(dir, 0o750)?;
    if let Some(gid) = paths.agent_group() {
        std::os::unix::fs::chown(dir, None, Some(gid.as_raw()))
            .with_context(|| format!("cannot chgrp {}", dir.display()))?;
    }
    Ok(())
}

/// Writes a verified site set under `versions/` (not yet active) and
/// returns its version name. A directory of that name is reused only when it
/// holds exactly this set; anything else there (a torn or tampered set) is
/// replaced by a freshly staged copy.
pub(crate) fn stage(
    paths: &Paths,
    set: &ProvisioningSet,
    envelopes: [&Envelope; 3],
    files: &SiteFiles,
) -> Result<String> {
    let entries = set_entries(envelopes, files);
    let name = version_name(set.site_config.statement.update_seq, &entries);
    let root = paths.site_root();
    site_dir_mode(paths, &root)?;
    let versions = versions_dir(paths);
    site_dir_mode(paths, &versions)?;
    let final_dir = versions.join(&name);
    let existing = std::fs::symlink_metadata(&final_dir).ok();
    if let Some(meta) = &existing {
        if meta.file_type().is_dir() && holds_exactly(paths, &final_dir, &entries)? {
            return Ok(name);
        }
    }
    let nonce = hex::encode(crate::fsutil::random_bytes::<6>()?);
    let tmp = versions.join(format!(".{name}.tmp-{nonce}"));
    let stale = versions.join(format!(".{name}.stale-{nonce}"));
    let staged = (|| -> Result<()> {
        site_dir_mode(paths, &tmp)?;
        let group = paths.agent_group();
        for (rel, bytes) in &entries {
            let target = tmp.join(rel);
            if let Some(dir) = target.parent() {
                if dir != tmp {
                    site_dir_mode(paths, dir)?;
                }
            }
            write_atomic(&target, bytes, SITE_FILE_MODE, group)?;
        }
        fsync_dir(&tmp)?;
        if existing.is_some() {
            // rename(2) cannot replace a non-empty directory: move the
            // drifted one aside first. A crash in between leaves no
            // directory of this name, which the next install restages.
            std::fs::rename(&final_dir, &stale)
                .with_context(|| format!("cannot move aside {}", final_dir.display()))?;
        }
        std::fs::rename(&tmp, &final_dir)
            .with_context(|| format!("cannot activate {}", final_dir.display()))?;
        fsync_dir(&versions)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_dir_all(&tmp);
        if std::fs::symlink_metadata(&final_dir).is_err() {
            let _ = std::fs::rename(&stale, &final_dir);
        }
        return Err(e);
    }
    if existing.is_some() {
        remove_entry(&stale)?;
    }
    Ok(name)
}

/// Removes a directory tree, or a single non-directory entry, at `path`.
fn remove_entry(path: &Path) -> Result<()> {
    let is_dir = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot stat {}", path.display()))?
        .file_type()
        .is_dir();
    if is_dir {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
    .with_context(|| format!("cannot remove {}", path.display()))
}

/// Makes `version` the current site set and keeps only it and `keep`.
pub(crate) fn activate(paths: &Paths, version: &str, keep: Option<&str>) -> Result<()> {
    if !site_version_name_ok(version) {
        bail!("site version {version:?} is not path-safe");
    }
    let root = paths.site_root();
    for (name, target) in fixed_links() {
        let link = root.join(name);
        let current = std::fs::read_link(&link).ok();
        if current.as_deref() != Some(Path::new(&target)) {
            symlink_atomic(Path::new(&target), &link)?;
        }
    }
    symlink_atomic(&Path::new("versions").join(version), &root.join("current"))?;
    let versions = versions_dir(paths);
    for entry in std::fs::read_dir(&versions)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if name != version && Some(name.as_ref()) != keep {
            remove_entry(&versions.join(name.as_ref()))
                .with_context(|| format!("cannot prune site version {name}"))?;
        }
    }
    Ok(())
}

fn read_envelope(path: &Path) -> Result<Result<Envelope, Reason>> {
    let bytes = read_root_file(path, MAX_SITE_FILE)?
        .with_context(|| format!("{} is missing", path.display()))?;
    Ok(Envelope::parse(&bytes))
}

/// Re-verifies the installed site set (DEC-4.10): bundle, site config, RBAC
/// manifest and every site file. `device` is the receipt's installed record
/// (`Records::installed_record`), so each statement must be the one the
/// receipt recorded (installed-digest-mismatch otherwise).
pub(crate) fn reverify(
    paths: &Paths,
    keys: &KeyStore,
    device: &DeviceRecord,
    receipt: &InstallReceipt,
    now: &str,
) -> Result<BTreeSet<Reason>> {
    let current = paths.site_root().join("current");
    let target = std::fs::read_link(&current).ok();
    let expected = Path::new("versions").join(&receipt.site_version);
    let dir = versions_dir(paths).join(&receipt.site_version);
    if target.as_deref() != Some(expected.as_path()) {
        return Ok(BTreeSet::from([Reason::SiteFileDigestMismatch]));
    }
    let scope = Scope {
        os_keys: keys,
        device: Some(device),
        now,
        mode: Mode::Reverify,
    };
    let identity: Option<&Identity> = None;
    let ta = match read_envelope(&dir.join(TRUST_ANCHORS_FILE))? {
        Ok(env) => env,
        Err(reason) => return Ok(BTreeSet::from([reason])),
    };
    let bundle = verify_trust_anchors(&ta, &scope, identity);
    let mut reasons = bundle.reasons.clone();
    let Ok(bundle) = bundle.accepted() else {
        return Ok(reasons);
    };
    let Some(anchors) = bundle_keys(&bundle.statement) else {
        reasons.insert(Reason::AnchorInvalid);
        return Ok(reasons);
    };
    let site = match read_envelope(&dir.join(SITE_CONFIG_FILE))? {
        Ok(env) => env,
        Err(reason) => return Ok(BTreeSet::from([reason])),
    };
    let rbac = match read_envelope(&dir.join(RBAC_MANIFEST_FILE))? {
        Ok(env) => env,
        Err(reason) => return Ok(BTreeSet::from([reason])),
    };
    let mut files = SiteFiles::new();
    for path in SitePath::ALL {
        if let Some(bytes) = read_root_file(&dir.join(path.as_str()), MAX_SITE_FILE)? {
            files.insert(*path, bytes);
        }
    }
    let (verdict, _) = verify_site_config(&site, &scope, identity, &anchors, &rbac, &files);
    reasons.extend(verdict.reasons);
    Ok(reasons)
}

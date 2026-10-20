// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Site directory installation and re-verification (ADR-048 DEC-4.2,
//! DEC-4.10, DEC-4.12; contracts delivery.json `installation`).
//!
//! `/data/suderra/site` is the stable source of the agent's read-only bind
//! at `/var/lib/suderra-site`, so it is never itself replaced (a renamed
//! directory would leave the bind on the old inode). Each verified site set
//! is written complete under `versions/<update_seq>-<digest>/` and activated
//! by renaming the `current` symlink; the fixed names (`config.yaml`,
//! `site-config.dsse`, …) are relative symlinks into `current`, so the agent's
//! compile-time paths resolve to exactly one complete set at any instant.

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
use std::collections::BTreeSet;
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

/// Version directory name of a site config.
pub(crate) fn version_name(update_seq: u64, statement_digest: &str) -> String {
    format!("{update_seq}-{}", &statement_digest[..12])
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
/// returns its version name.
pub(crate) fn stage(
    paths: &Paths,
    set: &ProvisioningSet,
    envelopes: [&Envelope; 3],
    files: &SiteFiles,
) -> Result<String> {
    let [site_env, ta_env, rbac_env] = envelopes;
    let name = version_name(
        set.site_config.statement.update_seq,
        &set.site_config.digest,
    );
    let root = paths.site_root();
    site_dir_mode(paths, &root)?;
    let versions = versions_dir(paths);
    site_dir_mode(paths, &versions)?;
    let final_dir = versions.join(&name);
    if std::fs::symlink_metadata(&final_dir).is_ok() {
        // The same site config (same update_seq and digest) is already
        // staged; verify-current re-checks its files before every start.
        return Ok(name);
    }
    let nonce = crate::fsutil::random_bytes::<6>()?;
    let tmp = versions.join(format!(".{name}.tmp-{}", hex::encode(nonce)));
    let staged = (|| -> Result<()> {
        site_dir_mode(paths, &tmp)?;
        let group = paths.agent_group();
        write_atomic(
            &tmp.join(SITE_CONFIG_FILE),
            &site_env.to_json(),
            0o640,
            group,
        )?;
        write_atomic(
            &tmp.join(TRUST_ANCHORS_FILE),
            &ta_env.to_json(),
            0o640,
            group,
        )?;
        write_atomic(
            &tmp.join(RBAC_MANIFEST_FILE),
            &rbac_env.to_json(),
            0o640,
            group,
        )?;
        for (path, bytes) in files {
            let target = tmp.join(path.as_str());
            if let Some(dir) = target.parent() {
                if dir != tmp {
                    site_dir_mode(paths, dir)?;
                }
            }
            write_atomic(&target, bytes, 0o640, group)?;
        }
        fsync_dir(&tmp)?;
        std::fs::rename(&tmp, &final_dir)
            .with_context(|| format!("cannot activate {}", final_dir.display()))?;
        fsync_dir(&versions)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    Ok(name)
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
            std::fs::remove_dir_all(versions.join(name.as_ref()))
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

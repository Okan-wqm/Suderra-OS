// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer edge`: the single agent delivery channel (ADR-048
//! DEC-1, DEC-2.5, DEC-3, DEC-5.5, DEC-5.6, DEC-23, DEC-27).
//!
//! * `edge request` issues the provisioning request (binding from root's
//!   record, fresh CSPRNG nonce, board, OS version, agent ABI) into
//!   root-only /run/suderra-os and prints its nonce.
//! * `edge provision` fetches the delivery itself with the token in the
//!   `X-Provisioning-Token` header, verifies it, downloads and verifies the
//!   artifact and installs (delivery.json `network`).
//! * `edge install` installs a delivery and artifact already on disk; the
//!   delivery must answer the request root issued, which is read from its
//!   fixed root-only location, never from a caller-named file, and spent by
//!   the install (offline and USB paths).
//! * `edge verify-current` re-verifies the installed release before every
//!   agent start (`ExecStartPre=+`, DEC-1.5).
//!
//! Every step runs in Rust: no shell, no `tar` binary, no `ln -sfn`. The
//! archive must hold exactly the `suderra-agent` member, which root writes
//! itself (root:root 0755, never the archive's owner or mode) under a
//! path-safe version directory, and `current` switches with `rename(2)`.

use crate::cli::{EdgeArgs, EdgeCommand, EdgeInstallArgs, EdgeProvisionArgs};
use crate::cmd::{lifecycle, site};
use crate::contracts::delivery::{
    Delivery, ProvisioningRequest, DELIVERY_CONTENT_TYPE, REQUEST_PATH, TOKEN_HEADER,
};
use crate::contracts::dsse::Envelope;
use crate::contracts::encoding::{is_device_code, is_https_url, now_timestamp};
use crate::contracts::keys::KeyStore;
use crate::contracts::registry::{
    naming, LifecycleState, Outcome, Reason, ResultKind, StatementType,
};
use crate::contracts::statements::{Digest, SiteFile};
use crate::contracts::verify::{verify_release, Mode, ProvisioningSet, Scope};
use crate::fsutil::{
    ensure_dir, fsync_dir, libc_flags, random_bytes, read_root_file, symlink_atomic, write_atomic,
};
use crate::paths::Paths;
use crate::results::{record, Report, Subject};
use crate::state::{DeviceIdentityRecord, InstallReceipt, Records, RECEIPT_TYPE};
use crate::trust_anchors::load_os_pins;
use crate::variant::ImageFacts;
use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Largest delivery document root accepts.
const MAX_DELIVERY: u64 = 16 * 1024 * 1024;
/// Largest decompressed agent binary root writes.
const MAX_BINARY: u64 = 512 * 1024 * 1024;
/// Largest provisioning token.
const MAX_TOKEN: u64 = 4096;

/// A failure with its typed result reason.
#[derive(Debug)]
pub(crate) struct Rejection {
    /// Result outcome.
    pub outcome: Outcome,
    /// Result reason.
    pub reason: Reason,
    /// Operator detail.
    pub detail: String,
}

impl Rejection {
    fn rejected(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Rejected,
            reason,
            detail: detail.into(),
        }
    }

    fn failed(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Failed,
            reason,
            detail: detail.into(),
        }
    }
}

fn io(e: anyhow::Error) -> Rejection {
    Rejection::failed(Reason::IoError, format!("{e:#}"))
}

fn first(reasons: &BTreeSet<Reason>) -> Reason {
    reasons
        .iter()
        .next()
        .copied()
        .unwrap_or(Reason::SchemaInvalid)
}

/// Builds the provisioning request from root's own records (DEC-5.5).
pub(crate) fn build_request(paths: &Paths, facts: &ImageFacts) -> Result<ProvisioningRequest> {
    let binding = Records::new(paths).binding(facts.board.board)?;
    let nonce = random_bytes::<16>()?;
    let request = ProvisioningRequest {
        binding_method: binding.method,
        binding_sha256: binding.digest.sha256,
        nonce: hex::encode(nonce),
        board_profile: facts.board.board,
        os_version: facts.os_version.clone(),
        agent_abi: facts.agent_abi.clone(),
    };
    request.validate().map_err(anyhow::Error::msg)?;
    Ok(request)
}

/// Lifecycle states in which root installs a provisioning delivery; an
/// ended MAINTENANCE window is ACTIVE and closed.
fn provisionable(paths: &Paths, now: &str) -> Result<LifecycleState> {
    let state = lifecycle::effective(paths, now);
    if !matches!(
        state,
        LifecycleState::Provisioning | LifecycleState::Maintenance
    ) {
        bail!("provisioning is closed in lifecycle state {state} (DEC-12)");
    }
    Ok(state)
}

/// Parses and verifies a delivery for this device.
fn verify_delivery(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    bytes: &[u8],
    request: &ProvisioningRequest,
    now: &str,
) -> std::result::Result<(Delivery, ProvisioningSet), Rejection> {
    let delivery =
        Delivery::parse(bytes).map_err(|r| Rejection::rejected(r, "delivery document"))?;
    let device = Records::new(paths).device_record(facts).map_err(io)?;
    let scope = Scope {
        os_keys: keys,
        device: Some(&device),
        now,
        mode: Mode::Accept,
    };
    let verdict = delivery.verify(&request.nonce, &scope);
    match verdict.accepted {
        Some(set) if verdict.reasons.is_empty() => Ok((delivery, set)),
        _ => {
            let names: Vec<&str> = verdict.reasons.iter().map(|r| r.as_str()).collect();
            Err(Rejection::rejected(
                first(&verdict.reasons),
                names.join(" "),
            ))
        }
    }
}

/// Checks the artifact's size and digest against the release statement.
fn check_artifact(path: &Path, set: &ProvisioningSet) -> std::result::Result<(), Rejection> {
    let artifact = &set.release.statement.artifact;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
        .open(path)
        .map_err(|e| Rejection::failed(Reason::FetchFailed, format!("{}: {e}", path.display())))?;
    let meta = file.metadata().map_err(|e| io(e.into()))?;
    if !meta.file_type().is_file() || meta.len() != artifact.size_bytes {
        return Err(Rejection::rejected(
            Reason::ArtifactDigestMismatch,
            format!("artifact size {} != {}", meta.len(), artifact.size_bytes),
        ));
    }
    let mut hasher = Sha256::new();
    std::io::copy(&mut (&mut file).take(artifact.size_bytes), &mut hasher)
        .map_err(|e| io(e.into()))?;
    if hex::encode(hasher.finalize()) != artifact.digest.sha256 {
        return Err(Rejection::rejected(
            Reason::ArtifactDigestMismatch,
            "artifact sha256",
        ));
    }
    Ok(())
}

/// Extracts the single `suderra-agent` member into `dest` (created
/// exclusively, root-owned 0755) and returns its sha256.
pub(crate) fn extract_binary(
    artifact: &Path,
    dest: &Path,
) -> std::result::Result<String, Rejection> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
        .open(artifact)
        .map_err(|e| io(e.into()))?;
    let mut archive =
        tar::Archive::new(flate2::read::GzDecoder::new(std::io::BufReader::new(file)));
    let invalid = |detail: String| Rejection::rejected(Reason::ArchiveInvalid, detail);
    let mut digest = None;
    for entry in archive.entries().map_err(|e| invalid(format!("{e}")))? {
        let mut entry = entry.map_err(|e| invalid(format!("{e}")))?;
        if digest.is_some() {
            return Err(invalid("more than one archive member".into()));
        }
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(invalid(format!(
                "member type {:?} is not a regular file",
                entry.header().entry_type()
            )));
        }
        if naming::ARCHIVE_MEMBERS != [&*String::from_utf8_lossy(&entry.path_bytes())] {
            return Err(invalid(format!(
                "member {:?} is not exactly {}",
                String::from_utf8_lossy(&entry.path_bytes()),
                naming::BINARY_NAME
            )));
        }
        let size = entry.header().size().map_err(|e| invalid(format!("{e}")))?;
        if size > MAX_BINARY {
            return Err(invalid(format!("member of {size} bytes")));
        }
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
            .open(dest)
            .map_err(|e| io(anyhow::Error::new(e).context(dest.display().to_string())))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0_u8; 64 * 1024];
        let mut written = 0_u64;
        loop {
            let n = entry.read(&mut buf).map_err(|e| invalid(format!("{e}")))?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > size {
                return Err(invalid("member longer than its header".into()));
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(|e| io(e.into()))?;
        }
        if written != size {
            return Err(invalid("member shorter than its header".into()));
        }
        out.set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|e| io(e.into()))?;
        out.sync_all().map_err(|e| io(e.into()))?;
        digest = Some(hex::encode(hasher.finalize()));
    }
    digest.ok_or_else(|| invalid("archive has no member".into()))
}

fn file_sha256(path: &Path) -> Result<Option<String>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
        .open(path)
    {
        Ok(mut file) => {
            if !file.metadata()?.file_type().is_file() {
                bail!("{} is not a regular file", path.display());
            }
            let mut hasher = Sha256::new();
            std::io::copy(&mut file, &mut hasher)?;
            Ok(Some(hex::encode(hasher.finalize())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot open {}", path.display())),
    }
}

fn releases_dir(paths: &Paths) -> PathBuf {
    paths.edge_root().join("releases")
}

/// Places the verified binary under `releases/<version>/suderra-agent`.
fn place_binary(
    paths: &Paths,
    set: &ProvisioningSet,
    artifact: &Path,
) -> std::result::Result<(), Rejection> {
    let release = &set.release.statement;
    // The schema admits only path-safe semver, so the version is one path
    // component (DEC-1.10, EI-064).
    let dir = releases_dir(paths).join(&release.version);
    ensure_dir(&paths.edge_root(), 0o755).map_err(io)?;
    ensure_dir(&releases_dir(paths), 0o755).map_err(io)?;
    ensure_dir(&dir, 0o755).map_err(io)?;
    let target = dir.join(naming::BINARY_NAME);
    let expected = &release.artifact.binary_digest.sha256;
    match file_sha256(&target).map_err(io)? {
        Some(digest) if &digest == expected => return Ok(()),
        // A release version is immutable: replacing the binary of an
        // installed version would break the committed receipt that names it
        // if this install stopped before its own receipt.
        Some(_) => {
            return Err(Rejection::failed(
                Reason::IoError,
                format!(
                    "releases/{}/{} holds a different binary of the same version",
                    release.version,
                    naming::BINARY_NAME
                ),
            ))
        }
        None => {}
    }
    let nonce = random_bytes::<8>().map_err(io)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        naming::BINARY_NAME,
        hex::encode(nonce)
    ));
    let result = extract_binary(artifact, &tmp).and_then(|digest| {
        if &digest != expected {
            return Err(Rejection::rejected(
                Reason::BinaryDigestMismatch,
                "suderra-agent sha256",
            ));
        }
        std::fs::rename(&tmp, &target).map_err(|e| io(e.into()))?;
        fsync_dir(&dir).map_err(io)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// What a successful install produced.
#[derive(Debug, Clone)]
pub(crate) struct Installed {
    /// The committed receipt.
    pub receipt: InstallReceipt,
}

/// Everything an install writes before its commit point: the binary, the
/// staged site set, the identity, the update_seq records and the release
/// statement. None of it changes what the committed receipt installed, so an
/// install interrupted here leaves the previous install verifiable.
fn stage_install(
    paths: &Paths,
    delivery: &Delivery,
    set: &ProvisioningSet,
    artifact: &Path,
) -> std::result::Result<InstallReceipt, Rejection> {
    paths.require_os_state().map_err(io)?;
    check_artifact(artifact, set)?;
    place_binary(paths, set, artifact)?;
    let site_version = site::stage(
        paths,
        set,
        [
            &delivery.site_config,
            &delivery.trust_anchors,
            &delivery.rbac,
        ],
        &delivery.site_files,
    )
    .map_err(io)?;

    let records = Records::new(paths);
    let m = &set.manifest.statement;
    let r = &set.release.statement;
    if records.identity().map_err(io)?.is_none() {
        records
            .write_identity(&DeviceIdentityRecord {
                tenant_id: m.tenant_id.clone(),
                device_id: m.device_id.clone(),
                device_code: m.device_code.clone(),
            })
            .map_err(io)?;
    }
    // Anti-replay first: a delivery whose install is interrupted after this
    // point is spent and cannot be replayed (DEC-2.4).
    let accepted = [
        (
            StatementType::EdgeProvisioning,
            m.update_seq,
            &set.manifest.digest,
        ),
        (
            StatementType::TrustAnchors,
            set.trust_anchors.statement.bundle_seq,
            &set.trust_anchors.digest,
        ),
        (
            StatementType::SiteConfig,
            set.site_config.statement.update_seq,
            &set.site_config.digest,
        ),
        (
            StatementType::RbacManifest,
            set.rbac.statement.policy_version,
            &set.rbac.digest,
        ),
    ];
    for (statement, seq, digest) in accepted {
        records
            .write_accepted(statement, Some(seq), digest)
            .map_err(io)?;
    }
    let release_statement_digest = Digest {
        sha256: set.release.digest.clone(),
    };
    records
        .write_release_statement(&release_statement_digest, &delivery.release.to_json())
        .map_err(io)?;
    Ok(InstallReceipt {
        type_: RECEIPT_TYPE.to_owned(),
        version: r.version.clone(),
        security_version: r.security_version,
        board_profile: r.board_profile,
        arch: r.arch,
        agent_abi: r.agent_abi,
        artifact_digest: r.artifact.digest.clone(),
        binary_digest: r.artifact.binary_digest.clone(),
        release_statement_digest,
        release_key_epoch: set.release.key_epoch,
        manifest_digest: Digest {
            sha256: set.manifest.digest.clone(),
        },
        manifest_key_epoch: set.manifest.key_epoch,
        trust_anchors_digest: Digest {
            sha256: set.trust_anchors.digest.clone(),
        },
        site_config_digest: Digest {
            sha256: set.site_config.digest.clone(),
        },
        rbac_manifest_digest: Digest {
            sha256: set.rbac.digest.clone(),
        },
        site_version,
        site_files: set
            .site_config
            .statement
            .files
            .iter()
            .map(|(p, f)| (*p, f.clone()))
            .collect::<std::collections::BTreeMap<_, SiteFile>>(),
        installed_at: now_timestamp(),
    })
}

/// Points `current` and the site set at what `receipt` installed, then
/// keeps only its release and the previous receipt's (DEC-1.3, DEC-1.4).
fn switch_to(paths: &Paths, receipt: &InstallReceipt) -> Result<()> {
    let previous = Records::new(paths).previous_receipt()?;
    site::activate(
        paths,
        &receipt.site_version,
        previous.as_ref().map(|p| p.site_version.as_str()),
    )?;
    symlink_atomic(
        &Path::new("releases").join(&receipt.version),
        &paths.edge_root().join("current"),
    )?;
    prune_releases(
        paths,
        &receipt.version,
        previous.as_ref().map(|p| p.version.as_str()),
    )?;
    Records::new(paths).prune_release_statements()
}

/// Installs a verified provisioning set: everything is staged, the receipt
/// is written (the commit point), then the atomic switches. An install
/// interrupted after the commit is completed by `verify-current`
/// ([`complete_interrupted_switch`]).
fn install_verified(
    paths: &Paths,
    delivery: &Delivery,
    set: &ProvisioningSet,
    artifact: &Path,
) -> std::result::Result<Installed, Rejection> {
    let receipt = stage_install(paths, delivery, set, artifact)?;
    Records::new(paths).write_receipt(&receipt).map_err(io)?;
    switch_to(paths, &receipt).map_err(io)?;
    Ok(Installed { receipt })
}

/// Keeps at most the current and the previous release (DEC-1.3).
fn prune_releases(paths: &Paths, current: &str, previous: Option<&str>) -> Result<()> {
    for entry in std::fs::read_dir(releases_dir(paths))? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if name != current && Some(name.as_ref()) != previous {
            std::fs::remove_dir_all(releases_dir(paths).join(name.as_ref()))
                .with_context(|| format!("cannot prune release {name}"))?;
        }
    }
    Ok(())
}

/// Writes the provisioning result of `outcome` and turns a rejection into
/// an error.
fn report(
    paths: &Paths,
    facts: &ImageFacts,
    outcome: std::result::Result<Installed, Rejection>,
    manifest: Option<&Envelope>,
) -> Result<Installed> {
    match outcome {
        Ok(installed) => {
            let receipt = &installed.receipt;
            record(
                paths,
                facts,
                Report::ok(
                    ResultKind::Provisioning,
                    Some(Subject {
                        version: Some(receipt.version.clone()),
                        security_version: Some(receipt.security_version),
                        statement_type: Some(StatementType::EdgeProvisioning.as_str().to_owned()),
                        statement_digest: Some(receipt.manifest_digest.clone()),
                        ..Subject::default()
                    }),
                ),
            )?;
            Ok(installed)
        }
        Err(rejection) => {
            let mut report = Report::not_ok(
                ResultKind::Provisioning,
                rejection.outcome,
                rejection.reason,
            )
            .with_detail(rejection.detail.clone());
            if let Some(env) = manifest {
                report = report.with_subject(Subject::statement(
                    StatementType::EdgeProvisioning,
                    &env.statement_digest(),
                ));
            }
            record(paths, facts, report)?;
            bail!(
                "provisioning {}: {} ({})",
                rejection.outcome,
                rejection.reason,
                rejection.detail
            )
        }
    }
}

/// Holds `/run/suderra-update.lock` (shared with OS updates, DEC-2.3).
fn update_lock(paths: &Paths) -> Result<nix::fcntl::Flock<File>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
        .open(paths.update_lock())
        .context("cannot open the update lock")?;
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| anyhow::anyhow!("another update operation holds the update lock: {e}"))
}

/// Installs a delivery and artifact already on disk.
pub(crate) fn install_from_files(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    delivery_bytes: &[u8],
    request: &ProvisioningRequest,
    artifact: &Path,
    now: &str,
) -> Result<Installed> {
    provisionable(paths, now)?;
    let outcome = verify_delivery(paths, facts, keys, delivery_bytes, request, now);
    let manifest = outcome.as_ref().ok().map(|(d, _)| d.manifest.clone());
    let installed =
        outcome.and_then(|(delivery, set)| install_verified(paths, &delivery, &set, artifact));
    report(paths, facts, installed, manifest.as_ref())
}

fn cloud_endpoint(paths: &Paths) -> Result<String> {
    let bytes = read_root_file(&paths.cloud_endpoint(), 4096)?.with_context(|| {
        format!(
            "{} is missing from the image",
            paths.cloud_endpoint().display()
        )
    })?;
    let text = String::from_utf8(bytes).context("cloud endpoint is not UTF-8")?;
    let url = text
        .strip_suffix('\n')
        .unwrap_or(&text)
        .trim_end_matches('/');
    if !is_https_url(url) {
        bail!("cloud endpoint {url:?} is not an https URL");
    }
    Ok(url.to_owned())
}

/// HTTPS client of the provisioning path: https only, the image's extra
/// cloud CA (dev and QEMU images) added to the public roots.
fn http_client(
    paths: &Paths,
    redirect: reqwest::redirect::Policy,
    timeout: std::time::Duration,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(redirect)
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(timeout);
    if let Some(pem) = read_root_file(&paths.cloud_ca(), 64 * 1024)? {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&pem).context("cloud CA")?);
    }
    builder.build().context("cannot build the HTTPS client")
}

async fn fetch_limited(response: reqwest::Response, max: u64, mut sink: impl Write) -> Result<u64> {
    let mut response = response;
    let mut total = 0_u64;
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len() as u64;
        if total > max {
            bail!("response exceeds {max} bytes");
        }
        sink.write_all(&chunk)?;
    }
    Ok(total)
}

/// Fetches the delivery for `device_code` (delivery.json `network`).
async fn fetch_delivery(
    paths: &Paths,
    device_code: &str,
    token: &str,
    request: &ProvisioningRequest,
) -> Result<Vec<u8>> {
    let url = format!(
        "{}{}",
        cloud_endpoint(paths)?,
        REQUEST_PATH.replace("{device_code}", device_code)
    );
    let mut token_header =
        reqwest::header::HeaderValue::from_str(token).context("token is not a header value")?;
    token_header.set_sensitive(true);
    let response = http_client(
        paths,
        reqwest::redirect::Policy::none(),
        std::time::Duration::from_secs(600),
    )?
    .get(url)
    .query(&request.query())
    .header(TOKEN_HEADER, token_header)
    .send()
    .await
    .context("provisioning request failed")?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("provisioning endpoint answered {}", response.status());
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.split(';').next().map(str::trim) != Some(DELIVERY_CONTENT_TYPE) {
        bail!("provisioning endpoint answered content type {content_type:?}");
    }
    let mut body = Vec::new();
    fetch_limited(response, MAX_DELIVERY, &mut body).await?;
    Ok(body)
}

/// Downloads the artifact the manifest names into the installer's work
/// directory; integrity is checked against the release statement after.
async fn fetch_artifact(paths: &Paths, set: &ProvisioningSet) -> Result<PathBuf> {
    let work = paths.installer_work();
    paths.require_os_state()?;
    ensure_dir(&work, 0o700)?;
    let path = work.join("artifact.tar.gz");
    let _ = std::fs::remove_file(&path);
    // Release hosting redirects to object storage; integrity comes from the
    // release statement's digest, checked before anything is installed.
    let response = http_client(
        paths,
        reqwest::redirect::Policy::limited(5),
        std::time::Duration::from_secs(1800),
    )?
    .get(&set.manifest.statement.artifact_url)
    .send()
    .await
    .context("artifact download failed")?
    .error_for_status()
    .context("artifact download failed")?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
        .open(&path)?;
    let mut writer = std::io::BufWriter::new(file);
    fetch_limited(
        response,
        set.release.statement.artifact.size_bytes,
        &mut writer,
    )
    .await?;
    writer
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()?;
    Ok(path)
}

/// Network provisioning: request, fetch, verify, download, install.
pub(crate) async fn provision(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    device_code: &str,
    token_file: &Path,
) -> Result<Installed> {
    if !is_device_code(device_code) {
        bail!("device code {device_code:?} is not a contract device_code");
    }
    provisionable(paths, &now_timestamp())?;
    let token_bytes = read_root_file(token_file, MAX_TOKEN)?.context("token file is missing")?;
    let token = String::from_utf8(token_bytes).context("token is not UTF-8")?;
    let token = token.strip_suffix('\n').unwrap_or(&token).to_owned();
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("token is empty or not visible ASCII");
    }
    let request = build_request(paths, facts)?;
    let bytes = match fetch_delivery(paths, device_code, &token, &request).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return report(
                paths,
                facts,
                Err(Rejection::failed(Reason::FetchFailed, format!("{e:#}"))),
                None,
            )
        }
    };
    let now = now_timestamp();
    let (delivery, set) = match verify_delivery(paths, facts, keys, &bytes, &request, &now) {
        Ok(verified) => verified,
        Err(rejection) => return report(paths, facts, Err(rejection), None),
    };
    let artifact = match fetch_artifact(paths, &set).await {
        Ok(path) => path,
        Err(e) => {
            return report(
                paths,
                facts,
                Err(Rejection::failed(Reason::FetchFailed, format!("{e:#}"))),
                Some(&delivery.manifest),
            )
        }
    };
    let installed = install_verified(paths, &delivery, &set, &artifact);
    let _ = std::fs::remove_file(&artifact);
    report(paths, facts, installed, Some(&delivery.manifest))
}

/// Completes an install that committed its receipt but was interrupted
/// before `switch_to` finished. Only that exact state is completed: each of
/// `current` and the site set still points where the previous receipt put
/// it (nothing at all on a first install) or already where this receipt
/// puts it. Any other target is drift and stays a verify-current rejection.
/// Returns whether a switch was completed.
fn complete_interrupted_switch(paths: &Paths, receipt: &InstallReceipt) -> Result<bool> {
    let previous = Records::new(paths).previous_receipt()?;
    let link = std::fs::read_link(paths.edge_root().join("current")).ok();
    let site_link = std::fs::read_link(paths.site_root().join("current")).ok();
    let release_at = |version: &str| Path::new("releases").join(version);
    let site_at = |version: &str| Path::new("versions").join(version);
    let committed = (release_at(&receipt.version), site_at(&receipt.site_version));
    let before = previous
        .as_ref()
        .map(|p| (release_at(&p.version), site_at(&p.site_version)));
    let release_done = link.as_ref() == Some(&committed.0);
    let site_done = site_link.as_ref() == Some(&committed.1);
    let release_before = link.as_ref() == before.as_ref().map(|b| &b.0);
    let site_before = site_link.as_ref() == before.as_ref().map(|b| &b.1);
    let interrupted = !(release_done && site_done)
        && (release_done || release_before)
        && (site_done || site_before);
    if !interrupted {
        return Ok(false);
    }
    let binary = releases_dir(paths)
        .join(&receipt.version)
        .join(naming::BINARY_NAME);
    if std::fs::symlink_metadata(&binary).is_err()
        || std::fs::symlink_metadata(versions_dir_of(paths, &receipt.site_version)).is_err()
    {
        return Ok(false);
    }
    switch_to(paths, receipt)?;
    Ok(true)
}

fn versions_dir_of(paths: &Paths, site_version: &str) -> PathBuf {
    paths.site_root().join("versions").join(site_version)
}

/// What verify-current proved.
#[derive(Debug, Clone)]
pub(crate) struct Current {
    /// The receipt the installed release and site set match.
    pub receipt: InstallReceipt,
    /// An interrupted install's switch was completed first.
    pub completed_switch: bool,
}

/// Re-verifies the installed release, binary and site set (DEC-1.5,
/// DEC-4.10) against the committed receipt; every failure is a typed
/// verify-current result.
pub(crate) fn verify_current(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    now: &str,
) -> std::result::Result<Current, Rejection> {
    let records = Records::new(paths);
    let receipt = records
        .receipt()
        .map_err(io)?
        .ok_or_else(|| Rejection::rejected(Reason::ReleaseNotInstalled, "no install receipt"))?;
    let completed_switch = complete_interrupted_switch(paths, &receipt).map_err(io)?;
    let link = std::fs::read_link(paths.edge_root().join("current"))
        .map_err(|_| Rejection::rejected(Reason::ReleaseNotInstalled, "current is missing"))?;
    if link != Path::new("releases").join(&receipt.version) {
        return Err(Rejection::rejected(
            Reason::CurrentLinkMismatch,
            format!(
                "current -> {} but the receipt records {}",
                link.display(),
                receipt.version
            ),
        ));
    }
    let binary = releases_dir(paths)
        .join(&receipt.version)
        .join(naming::BINARY_NAME);
    match file_sha256(&binary) {
        Ok(Some(digest)) if digest == receipt.binary_digest.sha256 => {}
        Ok(Some(_)) => {
            return Err(Rejection::rejected(
                Reason::BinaryDigestMismatch,
                "suderra-agent sha256",
            ))
        }
        Ok(None) => {
            return Err(Rejection::rejected(
                Reason::ReleaseNotInstalled,
                "suderra-agent is missing",
            ))
        }
        Err(e) => {
            return Err(Rejection::rejected(
                Reason::BinaryDigestMismatch,
                format!("{e:#}"),
            ))
        }
    }
    let device = records.installed_record(facts, &receipt).map_err(io)?;
    let scope = Scope {
        os_keys: keys,
        device: Some(&device),
        now,
        mode: Mode::Reverify,
    };
    let statement_path = records
        .release_statement_path(&receipt.release_statement_digest)
        .map_err(io)?;
    let statement = read_root_file(&statement_path, MAX_DELIVERY)
        .map_err(io)?
        .ok_or_else(|| {
            Rejection::rejected(Reason::ReleaseNotInstalled, "release statement is missing")
        })?;
    let env =
        Envelope::parse(&statement).map_err(|r| Rejection::rejected(r, "release statement"))?;
    let verdict = verify_release(&env, &scope, None);
    let release = verdict
        .accepted()
        .map_err(|reasons| Rejection::rejected(first(&reasons), "release statement"))?;
    if release.statement.artifact.binary_digest != receipt.binary_digest {
        return Err(Rejection::rejected(
            Reason::BinaryDigestMismatch,
            "release binary_digest differs from the receipt",
        ));
    }
    let site_reasons = site::reverify(paths, keys, &device, &receipt, now).map_err(io)?;
    if !site_reasons.is_empty() {
        return Err(Rejection::rejected(first(&site_reasons), "site set"));
    }
    Ok(Current {
        receipt,
        completed_switch,
    })
}

/// Issues a fresh provisioning request into /run/suderra-os, replacing any
/// earlier one, so only the last nonce shown on the console is answerable.
pub(crate) fn issue_request(paths: &Paths, facts: &ImageFacts) -> Result<ProvisioningRequest> {
    let request = build_request(paths, facts)?;
    ensure_dir(&paths.run_os(), 0o700)?;
    write_atomic(
        &paths.provisioning_request(),
        &serde_json::to_vec(&request)?,
        0o600,
        None,
    )?;
    Ok(request)
}

/// Installs a delivery on disk against the request root issued; the
/// request is spent once the delivery is installed.
pub(crate) fn install_issued(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    delivery_bytes: &[u8],
    artifact: &Path,
    now: &str,
) -> Result<Installed> {
    let bytes = read_root_file(&paths.provisioning_request(), 64 * 1024)?
        .context("no provisioning request was issued: run `edge request` first")?;
    let request = ProvisioningRequest::parse(&bytes)
        .map_err(|r| anyhow::anyhow!("issued request document is invalid: {r}"))?;
    let installed =
        install_from_files(paths, facts, keys, delivery_bytes, &request, artifact, now)?;
    std::fs::remove_file(paths.provisioning_request())
        .context("cannot spend the provisioning request")?;
    Ok(installed)
}

/// `suderra-installer edge <command>`.
pub(crate) async fn run(args: EdgeArgs) -> Result<()> {
    let paths = Paths::system()?;
    let facts = ImageFacts::load(&paths)?;
    match args.command {
        EdgeCommand::Request => {
            println!("{}", issue_request(&paths, &facts)?.nonce);
            Ok(())
        }
        EdgeCommand::Provision(EdgeProvisionArgs {
            device_code,
            token_file,
        }) => {
            let keys = load_os_pins(&paths, facts.pin_policy())?;
            let _lock = update_lock(&paths)?;
            let installed = provision(&paths, &facts, &keys, &device_code, &token_file).await?;
            println!(
                "installed {} (waiting for activation)",
                installed.receipt.version
            );
            Ok(())
        }
        EdgeCommand::Install(EdgeInstallArgs { delivery, artifact }) => {
            let keys = load_os_pins(&paths, facts.pin_policy())?;
            let _lock = update_lock(&paths)?;
            let bytes = read_root_file(&delivery, MAX_DELIVERY)?
                .with_context(|| format!("{} is missing", delivery.display()))?;
            let installed =
                install_issued(&paths, &facts, &keys, &bytes, &artifact, &now_timestamp())?;
            println!(
                "installed {} (waiting for activation)",
                installed.receipt.version
            );
            Ok(())
        }
        EdgeCommand::VerifyCurrent => {
            let keys = load_os_pins(&paths, facts.pin_policy())?;
            match verify_current(&paths, &facts, &keys, &now_timestamp()) {
                Ok(Current {
                    receipt,
                    completed_switch,
                }) => {
                    let mut report = Report::ok(
                        ResultKind::VerifyCurrent,
                        Some(Subject {
                            version: Some(receipt.version.clone()),
                            security_version: Some(receipt.security_version),
                            statement_type: Some(StatementType::EdgeRelease.as_str().to_owned()),
                            statement_digest: Some(receipt.release_statement_digest.clone()),
                            ..Subject::default()
                        }),
                    );
                    if completed_switch {
                        report = report.with_detail(
                            "completed the switch of an install interrupted after its receipt",
                        );
                    }
                    record(&paths, &facts, report)?;
                    Ok(())
                }
                Err(rejection) => {
                    record(
                        &paths,
                        &facts,
                        Report::not_ok(
                            ResultKind::VerifyCurrent,
                            rejection.outcome,
                            rejection.reason,
                        )
                        .with_detail(rejection.detail.clone()),
                    )?;
                    bail!(
                        "verify-current {}: {} ({})",
                        rejection.outcome,
                        rejection.reason,
                        rejection.detail
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::ResultDocument;
    use crate::test_support::{
        build_delivery, image, maintenance, receipt, tarball, write_binding, Keys, Spec,
        BINDING_HEX,
    };
    use std::os::unix::fs::MetadataExt;

    const NOW: &str = "2026-10-20T12:00:00Z";

    struct Device {
        tmp: tempfile::TempDir,
        paths: Paths,
        facts: ImageFacts,
        keys: Keys,
        pins: KeyStore,
    }

    fn device(state: LifecycleState) -> Device {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        write_binding(&paths, BINDING_HEX);
        lifecycle::write(&paths, state, None).unwrap();
        let keys = Keys::new();
        let pins = keys.os_pins();
        Device {
            tmp,
            paths,
            facts,
            keys,
            pins,
        }
    }

    impl Device {
        fn install(&self, spec: &Spec) -> Result<Installed> {
            let built = build_delivery(&self.keys, spec);
            let artifact = self.tmp.path().join("artifact.tar.gz");
            std::fs::write(&artifact, &spec.artifact).unwrap();
            install_from_files(
                &self.paths,
                &self.facts,
                &self.pins,
                &built.delivery,
                &built.request,
                &artifact,
                NOW,
            )
        }

        fn last_result(&self) -> ResultDocument {
            let mut names: Vec<_> = std::fs::read_dir(self.paths.results_store())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.ends_with(".json"))
                .collect();
            names.sort();
            let bytes =
                std::fs::read(self.paths.results_store().join(names.last().unwrap())).unwrap();
            ResultDocument::parse(&bytes).unwrap()
        }

        fn current(&self) -> Option<PathBuf> {
            std::fs::read_link(self.paths.edge_root().join("current")).ok()
        }

        fn agent_file(&self, name: &str, bytes: &[u8]) {
            std::fs::create_dir_all(self.paths.agent_state()).unwrap();
            std::fs::write(self.paths.agent_state().join(name), bytes).unwrap();
        }
    }

    #[test]
    fn keys_pinned_in_the_image_verify_the_delivery() {
        let dev = device(LifecycleState::Provisioning);
        dev.keys.pin(&dev.paths);
        let pins = crate::trust_anchors::load_os_pins(&dev.paths, dev.facts.pin_policy()).unwrap();
        assert_eq!(pins, dev.pins);
        let spec = Spec::default();
        let built = build_delivery(&dev.keys, &spec);
        let artifact = dev.tmp.path().join("a.tgz");
        std::fs::write(&artifact, &spec.artifact).unwrap();
        install_from_files(
            &dev.paths,
            &dev.facts,
            &pins,
            &built.delivery,
            &built.request,
            &artifact,
            NOW,
        )
        .unwrap();
    }

    #[test]
    fn installs_atomically_and_verify_current_passes() {
        let dev = device(LifecycleState::Provisioning);
        let spec = Spec::default();
        let installed = dev.install(&spec).unwrap();
        assert_eq!(installed.receipt.version, "1.6.0");
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.6.0"));
        let binary = dev.paths.edge_root().join("current/suderra-agent");
        assert_eq!(std::fs::read(&binary).unwrap(), spec.binary);
        let meta = std::fs::metadata(&binary).unwrap();
        assert_eq!(
            meta.mode() & 0o7777,
            0o755,
            "archive mode (setuid 4777) is never applied"
        );
        assert_eq!(
            meta.uid(),
            nix::unistd::geteuid().as_raw(),
            "archive owner is never applied"
        );
        assert_eq!(
            std::fs::read_to_string(dev.paths.site_root().join("config.yaml")).unwrap(),
            "site: test\nseq: 1\n"
        );
        assert!(std::fs::read_link(dev.paths.site_root().join("current"))
            .unwrap()
            .starts_with("versions"));
        let records = Records::new(&dev.paths);
        assert_eq!(
            records.identity().unwrap().unwrap().device_code,
            "RPI-TEST01"
        );
        assert_eq!(
            records
                .accepted(StatementType::EdgeProvisioning)
                .unwrap()
                .unwrap()
                .seq,
            Some(1)
        );
        let result = dev.last_result();
        assert_eq!(
            (result.kind, result.outcome),
            (ResultKind::Provisioning, Outcome::Ok)
        );
        verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();
        assert_eq!(
            lifecycle::read(&dev.paths).state(),
            LifecycleState::Provisioning,
            "ACTIVE needs a receipt"
        );
    }

    #[test]
    fn replay_foreign_device_and_closed_lifecycle_are_refused() {
        let dev = device(LifecycleState::Provisioning);
        dev.install(&Spec::default()).unwrap();
        assert!(dev.install(&Spec::default()).is_err());
        assert_eq!(dev.last_result().reason.as_deref(), Some("sequence-replay"));

        let other = device(LifecycleState::Provisioning);
        let foreign = Spec {
            binding_hex: "1111111111111111111111111111111111111111111111111111111111111111",
            ..Spec::default()
        };
        assert!(other.install(&foreign).is_err());
        assert_eq!(
            other.last_result().reason.as_deref(),
            Some("device-binding-mismatch")
        );
        assert!(other.current().is_none());
        assert!(Records::new(&other.paths).receipt().unwrap().is_none());

        let wrong_nonce = device(LifecycleState::Provisioning);
        let built = build_delivery(&wrong_nonce.keys, &Spec::default());
        let mut request = built.request.clone();
        request.nonce = "ffffffffffffffffffffffffffffffff".into();
        let artifact = wrong_nonce.tmp.path().join("a.tgz");
        std::fs::write(&artifact, &Spec::default().artifact).unwrap();
        assert!(install_from_files(
            &wrong_nonce.paths,
            &wrong_nonce.facts,
            &wrong_nonce.pins,
            &built.delivery,
            &request,
            &artifact,
            NOW
        )
        .is_err());
        assert_eq!(
            wrong_nonce.last_result().reason.as_deref(),
            Some("nonce-mismatch")
        );

        for closed in [LifecycleState::Active, LifecycleState::Factory] {
            let dev = device(closed);
            let err = dev.install(&Spec::default()).unwrap_err().to_string();
            assert!(err.contains("provisioning is closed"), "{err}");
        }
    }

    fn raw_tarball(name: &[u8], kind: tar::EntryType, link: Option<&str>, data: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_old();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_entry_type(kind);
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        if let Some(link) = link {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        builder.append(&header, data).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn artifact_and_archive_defects_are_typed_and_activate_nothing() {
        let binary = Spec::default().binary;
        let cases: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
            (
                tarball(&[("suderra-agent", &binary), ("extra", b"x")]),
                binary.clone(),
                "archive-invalid",
            ),
            (
                raw_tarball(b"./suderra-agent", tar::EntryType::Regular, None, &binary),
                binary.clone(),
                "archive-invalid",
            ),
            (
                raw_tarball(b"suderra-agent/", tar::EntryType::Directory, None, b""),
                binary.clone(),
                "archive-invalid",
            ),
            (
                raw_tarball(b"../suderra-agent", tar::EntryType::Regular, None, &binary),
                binary.clone(),
                "archive-invalid",
            ),
            (
                raw_tarball(
                    b"suderra-agent",
                    tar::EntryType::Symlink,
                    Some("/etc/shadow"),
                    b"",
                ),
                binary.clone(),
                "archive-invalid",
            ),
            (
                tarball(&[("bin/suderra-agent", &binary)]),
                binary.clone(),
                "archive-invalid",
            ),
            (
                b"not a gzip stream".to_vec(),
                binary.clone(),
                "archive-invalid",
            ),
            (
                tarball(&[("suderra-agent", b"other bytes")]),
                binary.clone(),
                "binary-digest-mismatch",
            ),
        ];
        for (index, (artifact, binary, reason)) in cases.into_iter().enumerate() {
            let dev = device(LifecycleState::Provisioning);
            let spec = Spec {
                artifact,
                binary,
                ..Spec::default()
            };
            assert!(dev.install(&spec).is_err(), "case {index}: {reason}");
            assert_eq!(dev.last_result().reason.as_deref(), Some(reason));
            assert!(
                dev.current().is_none(),
                "{reason}: nothing may be activated"
            );
            assert!(
                Records::new(&dev.paths).receipt().unwrap().is_none(),
                "{reason}"
            );
            assert!(
                !dev.paths
                    .edge_root()
                    .join("releases/1.6.0/suderra-agent")
                    .exists(),
                "{reason}"
            );
        }

        // An artifact that is not the one the release statement names.
        let dev = device(LifecycleState::Provisioning);
        let spec = Spec::default();
        let built = build_delivery(&dev.keys, &spec);
        let artifact = dev.tmp.path().join("a.tgz");
        std::fs::write(&artifact, tarball(&[("suderra-agent", b"evil")])).unwrap();
        assert!(install_from_files(
            &dev.paths,
            &dev.facts,
            &dev.pins,
            &built.delivery,
            &built.request,
            &artifact,
            NOW
        )
        .is_err());
        assert_eq!(
            dev.last_result().reason.as_deref(),
            Some("artifact-digest-mismatch")
        );
        assert!(dev.current().is_none());
    }

    #[test]
    fn verify_current_refuses_every_drift() {
        let dev = device(LifecycleState::Provisioning);
        let spec = Spec::default();
        dev.install(&spec).unwrap();
        let reason = |dev: &Device| {
            verify_current(&dev.paths, &dev.facts, &dev.pins, NOW)
                .unwrap_err()
                .reason
        };

        let binary = dev.paths.edge_root().join("releases/1.6.0/suderra-agent");
        std::fs::write(&binary, b"patched").unwrap();
        assert_eq!(reason(&dev), Reason::BinaryDigestMismatch);
        std::fs::write(&binary, &spec.binary).unwrap();
        verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();

        std::fs::create_dir_all(dev.paths.edge_root().join("releases/9.9.9")).unwrap();
        crate::fsutil::symlink_atomic(
            Path::new("releases/9.9.9"),
            &dev.paths.edge_root().join("current"),
        )
        .unwrap();
        assert_eq!(reason(&dev), Reason::CurrentLinkMismatch);
        crate::fsutil::symlink_atomic(
            Path::new("releases/1.6.0"),
            &dev.paths.edge_root().join("current"),
        )
        .unwrap();

        let config = std::fs::canonicalize(dev.paths.site_root().join("config.yaml")).unwrap();
        std::fs::write(&config, "site: tampered\n").unwrap();
        assert_eq!(reason(&dev), Reason::SiteFileDigestMismatch);
        std::fs::write(&config, "site: test\nseq: 1\n").unwrap();

        let records = Records::new(&dev.paths);
        let installed = records.receipt().unwrap().unwrap();
        let statement = records
            .release_statement_path(&installed.release_statement_digest)
            .unwrap();
        let mut env: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&statement).unwrap()).unwrap();
        env["signatures"][0]["sig"] = serde_json::Value::String(format!("{}A==", "B".repeat(85)));
        std::fs::write(&statement, env.to_string()).unwrap();
        assert_eq!(reason(&dev), Reason::SignatureInvalid);

        std::fs::remove_file(dev.paths.edge_state().join("receipt.json")).unwrap();
        assert_eq!(reason(&dev), Reason::ReleaseNotInstalled);
    }

    #[test]
    fn activation_maintenance_and_reprovisioning() {
        let dev = device(LifecycleState::Provisioning);
        let built = build_delivery(&dev.keys, &Spec::default());
        dev.install(&Spec::default()).unwrap();

        dev.agent_file(
            "activation-receipt.dsse",
            &receipt(&dev.keys, &built.manifest),
        );
        assert_eq!(
            lifecycle::activate(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap(),
            LifecycleState::Active
        );
        assert_eq!(
            Records::new(&dev.paths).floor().unwrap(),
            6,
            "the floor rises with the activation"
        );
        assert!(
            dev.install(&Spec {
                update_seq: 2,
                ..Spec::default()
            })
            .is_err(),
            "ACTIVE is closed"
        );

        dev.agent_file("lifecycle-request.dsse", &maintenance(&dev.keys, 1));
        assert_eq!(
            lifecycle::request(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap(),
            LifecycleState::Maintenance
        );

        let older = Spec {
            update_seq: 2,
            site_seq: 2,
            version: "1.5.0",
            security_version: 5,
            ..Spec::default()
        };
        assert!(dev.install(&older).is_err());
        assert_eq!(
            dev.last_result().reason.as_deref(),
            Some("rollback-below-floor")
        );

        let newer = Spec {
            update_seq: 3,
            site_seq: 2,
            version: "1.7.0",
            security_version: 7,
            ..Spec::default()
        };
        dev.install(&newer).unwrap();
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.7.0"));
        let mut releases: Vec<_> = std::fs::read_dir(dev.paths.edge_root().join("releases"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        releases.sort();
        assert_eq!(releases, ["1.6.0", "1.7.0"], "current and previous only");
        verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();

        // A receipt for the old manifest no longer matches the installed one.
        dev.agent_file(
            "activation-receipt.dsse",
            &receipt(&dev.keys, &built.manifest),
        );
        assert!(lifecycle::activate(&dev.paths, &dev.facts, &dev.pins, NOW).is_err());
        assert_eq!(
            dev.last_result().reason.as_deref(),
            Some("manifest-digest-mismatch")
        );
    }

    /// Stages `spec` as an install that is cut off before its receipt.
    fn stage_only(dev: &Device, spec: &Spec) {
        let built = build_delivery(&dev.keys, spec);
        let artifact = dev.tmp.path().join("staged.tar.gz");
        std::fs::write(&artifact, &spec.artifact).unwrap();
        let (delivery, set) = verify_delivery(
            &dev.paths,
            &dev.facts,
            &dev.pins,
            &built.delivery,
            &built.request,
            NOW,
        )
        .unwrap();
        stage_install(&dev.paths, &delivery, &set, &artifact).unwrap();
    }

    /// Stages and commits `spec` as an install cut off before its switch.
    fn commit_only(dev: &Device, spec: &Spec) -> InstallReceipt {
        let built = build_delivery(&dev.keys, spec);
        let artifact = dev.tmp.path().join("committed.tar.gz");
        std::fs::write(&artifact, &spec.artifact).unwrap();
        let (delivery, set) = verify_delivery(
            &dev.paths,
            &dev.facts,
            &dev.pins,
            &built.delivery,
            &built.request,
            NOW,
        )
        .unwrap();
        let receipt = stage_install(&dev.paths, &delivery, &set, &artifact).unwrap();
        Records::new(&dev.paths).write_receipt(&receipt).unwrap();
        receipt
    }

    fn reprovisioning(dev: &Device) -> Spec {
        lifecycle::write(
            &dev.paths,
            LifecycleState::Maintenance,
            Some("2026-10-21T00:00:00Z".into()),
        )
        .unwrap();
        Spec {
            update_seq: 2,
            site_seq: 2,
            version: "1.7.0",
            security_version: 7,
            ..Spec::default()
        }
    }

    #[test]
    fn an_install_cut_off_before_its_receipt_leaves_the_installed_release_verifiable() {
        let dev = device(LifecycleState::Provisioning);
        dev.install(&Spec::default()).unwrap();
        let newer = reprovisioning(&dev);
        stage_only(&dev, &newer);

        // The update_seq records already name the new statements and the new
        // release statement is on disk, but the committed receipt still names
        // 1.6.0: verify-current re-verifies exactly that install.
        let current = verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();
        assert_eq!(current.receipt.version, "1.6.0");
        assert!(!current.completed_switch);
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.6.0"));

        // The staged delivery is spent: its update_seq was recorded first.
        assert!(dev.install(&newer).is_err());
        assert_eq!(dev.last_result().reason.as_deref(), Some("sequence-replay"));
    }

    #[test]
    fn an_install_cut_off_after_its_receipt_is_completed_by_verify_current() {
        let dev = device(LifecycleState::Provisioning);
        dev.install(&Spec::default()).unwrap();
        let newer = reprovisioning(&dev);
        let receipt = commit_only(&dev, &newer);
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.6.0"));

        let current = verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();
        assert!(current.completed_switch);
        assert_eq!(current.receipt, receipt);
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.7.0"));
        assert_eq!(
            std::fs::read_link(dev.paths.site_root().join("current")).unwrap(),
            Path::new("versions").join(&receipt.site_version)
        );
        let again = verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();
        assert!(!again.completed_switch, "completed once");
    }

    #[test]
    fn a_first_install_cut_off_after_its_receipt_is_completed() {
        let dev = device(LifecycleState::Provisioning);
        commit_only(&dev, &Spec::default());
        assert!(dev.current().is_none());
        let current = verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();
        assert!(current.completed_switch);
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.6.0"));
        assert_eq!(
            std::fs::read_to_string(dev.paths.site_root().join("config.yaml")).unwrap(),
            "site: test\nseq: 1\n"
        );
    }

    #[test]
    fn only_the_interrupted_switch_state_is_completed() {
        let dev = device(LifecycleState::Provisioning);
        dev.install(&Spec::default()).unwrap();
        let newer = reprovisioning(&dev);
        commit_only(&dev, &newer);
        // current points neither where the previous receipt put it nor where
        // the committed one puts it: drift, not an interrupted switch.
        std::fs::create_dir_all(dev.paths.edge_root().join("releases/9.9.9")).unwrap();
        crate::fsutil::symlink_atomic(
            Path::new("releases/9.9.9"),
            &dev.paths.edge_root().join("current"),
        )
        .unwrap();
        assert_eq!(
            verify_current(&dev.paths, &dev.facts, &dev.pins, NOW)
                .unwrap_err()
                .reason,
            Reason::CurrentLinkMismatch
        );
    }

    #[test]
    fn an_ended_maintenance_window_refuses_provisioning() {
        let dev = device(LifecycleState::Provisioning);
        dev.install(&Spec::default()).unwrap();
        let newer = reprovisioning(&dev);
        lifecycle::write(
            &dev.paths,
            LifecycleState::Maintenance,
            Some("2026-10-20T11:00:00Z".into()),
        )
        .unwrap();
        assert!(dev.install(&newer).is_err());
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.6.0"));
    }

    #[test]
    fn install_answers_only_the_request_root_issued() {
        let dev = device(LifecycleState::Provisioning);
        let spec = Spec::default();
        let artifact = dev.tmp.path().join("usb.tar.gz");
        std::fs::write(&artifact, &spec.artifact).unwrap();
        let built = build_delivery(&dev.keys, &spec);
        let install = |dev: &Device| {
            install_issued(
                &dev.paths,
                &dev.facts,
                &dev.pins,
                &built.delivery,
                &artifact,
                NOW,
            )
        };
        assert!(install(&dev).is_err(), "nothing was issued");
        assert!(dev.current().is_none());

        // A fresh nonce the delivery does not echo.
        let issued = issue_request(&dev.paths, &dev.facts).unwrap();
        assert_ne!(issued.nonce, spec.nonce);
        assert!(install(&dev).is_err());
        assert_eq!(dev.last_result().reason.as_deref(), Some("nonce-mismatch"));

        // The delivery generated for the issued nonce installs and spends it.
        let answered = build_delivery(
            &dev.keys,
            &Spec {
                nonce: issued.nonce.clone(),
                ..Spec::default()
            },
        );
        install_issued(
            &dev.paths,
            &dev.facts,
            &dev.pins,
            &answered.delivery,
            &artifact,
            NOW,
        )
        .unwrap();
        assert!(!dev.paths.provisioning_request().exists(), "spent");
        assert_eq!(dev.current().unwrap(), Path::new("releases/1.6.0"));
    }

    #[test]
    fn an_installed_version_is_never_rewritten_with_another_binary() {
        let dev = device(LifecycleState::Provisioning);
        let spec = Spec::default();
        dev.install(&spec).unwrap();
        reprovisioning(&dev);
        let other = b"\x7fELF another build of 1.6.0".to_vec();
        let same_version = Spec {
            update_seq: 2,
            site_seq: 2,
            artifact: tarball(&[("suderra-agent", &other)]),
            binary: other,
            ..Spec::default()
        };
        assert!(dev.install(&same_version).is_err());
        assert_eq!(dev.last_result().reason.as_deref(), Some("io-error"));
        assert_eq!(
            std::fs::read(dev.paths.edge_root().join("releases/1.6.0/suderra-agent")).unwrap(),
            spec.binary
        );
        verify_current(&dev.paths, &dev.facts, &dev.pins, NOW).unwrap();
    }

    #[test]
    fn release_statements_are_kept_for_the_current_and_previous_receipt_only() {
        let dev = device(LifecycleState::Provisioning);
        dev.install(&Spec::default()).unwrap();
        let newer = reprovisioning(&dev);
        dev.install(&newer).unwrap();
        lifecycle::write(
            &dev.paths,
            LifecycleState::Maintenance,
            Some("2026-10-21T00:00:00Z".into()),
        )
        .unwrap();
        dev.install(&Spec {
            update_seq: 3,
            site_seq: 3,
            version: "1.8.0",
            security_version: 8,
            ..Spec::default()
        })
        .unwrap();
        let records = Records::new(&dev.paths);
        let keep: Vec<_> = [records.receipt(), records.previous_receipt()]
            .into_iter()
            .map(|r| {
                records
                    .release_statement_path(&r.unwrap().unwrap().release_statement_digest)
                    .unwrap()
            })
            .collect();
        let mut stored: Vec<_> = std::fs::read_dir(dev.paths.edge_state().join("statements"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        stored.sort();
        let mut keep_sorted = keep.clone();
        keep_sorted.sort();
        assert_eq!(stored, keep_sorted);
    }
}

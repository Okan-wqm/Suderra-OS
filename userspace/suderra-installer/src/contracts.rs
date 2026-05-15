// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed signed contracts for appliance installation and provisioning.

use crate::cli::{
    EdgeManifestArgs, EdgeManifestCommand, EdgeManifestPlanArgs, EdgeManifestVerifyArtifactArgs,
    UsbPayloadArgs, UsbPayloadCommand, UsbPayloadSignArgs, UsbPayloadVerifyArgs,
};
use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const USB_INDEX_KIND: &str = "suderra.usb-payload-index.v1";
const EDGE_MANIFEST_KIND: &str = "suderra.edge-provisioning.v1";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub(crate) fn run_usb_payload(args: UsbPayloadArgs) -> Result<()> {
    match args.command {
        UsbPayloadCommand::Verify(args) => {
            let validated = verify_usb_payload(&args)?;
            if let Some(path) = args.write_plan.as_deref() {
                write_usb_plan(path, &validated)?;
            } else {
                println!("{}", validated.image_path.display());
            }
            Ok(())
        }
        UsbPayloadCommand::Sign(args) => sign_json_with_openssl_ed25519(&args),
    }
}

pub(crate) fn run_edge_manifest(args: EdgeManifestArgs) -> Result<()> {
    match args.command {
        EdgeManifestCommand::Plan(args) => {
            let manifest = verify_edge_manifest_for_plan(&args)?;
            check_edge_target(&manifest, args.board.as_deref(), args.arch.as_deref())?;
            if let Some(path) = args.config_output.as_deref() {
                write_edge_config_payload(&manifest, path)?;
            }
            if let Some(path) = args.write_plan.as_deref() {
                write_edge_plan(path, &manifest, args.config_output.as_deref())?;
            } else {
                println!("{}", manifest.artifact.url);
            }
            Ok(())
        }
        EdgeManifestCommand::VerifyArtifact(args) => verify_edge_artifact(&args),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsbPayloadIndex {
    schema_version: u32,
    kind: String,
    board_family: String,
    compatible_models: Vec<String>,
    payloads: Vec<UsbImagePayload>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    key_epoch: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsbImagePayload {
    name: String,
    board_family: String,
    compatible_models: Vec<String>,
    arch: String,
    image_path: String,
    compressed_sha256: String,
    compressed_size_bytes: u64,
    uncompressed_sha256: String,
    uncompressed_size_bytes: u64,
    min_storage_bytes: u64,
    #[serde(default)]
    rollback_floor: Option<String>,
}

#[derive(Debug)]
struct ValidatedUsbPayload {
    index: UsbPayloadIndex,
    payload: UsbImagePayload,
    image_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EdgeProvisioningManifest {
    schema_version: u32,
    kind: String,
    device_id: String,
    device_code: String,
    tenant_id: String,
    version: String,
    board: String,
    arch: String,
    artifact: EdgeArtifact,
    #[serde(default)]
    config: Option<EdgeConfigPayload>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    rollback_floor: String,
    key_epoch: u32,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EdgeArtifact {
    url: String,
    sha256: String,
    size_bytes: u64,
    signature: String,
    binary_name: String,
    format: EdgeArtifactFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum EdgeArtifactFormat {
    #[serde(rename = "tar.gz")]
    TarGz,
    #[serde(rename = "tgz")]
    Tgz,
    #[serde(rename = "raw")]
    Raw,
    #[serde(rename = "bin")]
    Bin,
}

impl EdgeArtifactFormat {
    fn as_shell_value(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Tgz => "tgz",
            Self::Raw => "raw",
            Self::Bin => "bin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EdgeConfigPayload {
    sha256: String,
    payload: String,
}

fn verify_usb_payload(args: &UsbPayloadVerifyArgs) -> Result<ValidatedUsbPayload> {
    let payload_dir = &args.payload_dir;
    let manifest_path = payload_dir.join("manifest.json");
    let signature_path = payload_dir.join("manifest.sig");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("USB payload manifest missing: {}", manifest_path.display()))?;
    let index: UsbPayloadIndex =
        serde_json::from_slice(&manifest_bytes).context("USB payload manifest JSON is invalid")?;

    ensure_schema(index.schema_version, &index.kind, USB_INDEX_KIND)?;
    let canonical = canonical_json_bytes(&index)?;
    let sig = read_signature(&signature_path)?;
    let key = read_public_key(&args.public_key)?;
    verify_ed25519(&key, &canonical, &sig).with_context(|| {
        format!(
            "USB payload manifest signature verification failed: {}",
            manifest_path.display()
        )
    })?;

    ensure_not_expired(index.expires_at, "USB payload manifest")?;
    ensure_key_epoch_at_least(index.key_epoch, args.min_key_epoch, "USB payload manifest")?;
    ensure_nonempty("board_family", &index.board_family)?;
    ensure_nonempty_vec("compatible_models", &index.compatible_models)?;
    ensure_nonempty_vec("payloads", &index.payloads)?;
    if !index
        .compatible_models
        .iter()
        .any(|model| model == &args.target_board)
    {
        bail!(
            "target board '{}' is not compatible with USB payload index '{}'",
            args.target_board,
            index.board_family
        );
    }

    let payload = index
        .payloads
        .iter()
        .find(|payload| {
            payload.board_family == args.target_board
                || payload
                    .compatible_models
                    .iter()
                    .any(|model| model == &args.target_board)
        })
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no payload entry matches target board '{}'",
                args.target_board
            )
        })?;

    validate_payload_metadata(&payload)?;
    if payload.arch != args.target_arch {
        bail!(
            "payload arch '{}' does not match target arch '{}'",
            payload.arch,
            args.target_arch
        );
    }
    ensure_rollback_floor_at_least(&payload, &args.min_rollback_floor)?;
    let image_path = safe_join(payload_dir, &payload.image_path)?;
    verify_file_size(
        &image_path,
        payload.compressed_size_bytes,
        "compressed payload",
    )?;
    verify_file_sha256(
        &image_path,
        &payload.compressed_sha256,
        "compressed payload",
    )?;
    verify_xz_uncompressed(&image_path, &payload)?;

    Ok(ValidatedUsbPayload {
        index,
        payload,
        image_path,
    })
}

fn sign_json_with_openssl_ed25519(args: &UsbPayloadSignArgs) -> Result<()> {
    let manifest_bytes = fs::read(&args.manifest)
        .with_context(|| format!("manifest not readable: {}", args.manifest.display()))?;
    let index: UsbPayloadIndex =
        serde_json::from_slice(&manifest_bytes).context("USB payload manifest JSON invalid")?;
    let canonical = canonical_json_bytes(&index)?;

    let mut canonical_file = tempfile::NamedTempFile::new()?;
    canonical_file.write_all(&canonical)?;
    canonical_file.flush()?;

    let output = Command::new("openssl")
        .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
        .arg(&args.private_key)
        .arg("-in")
        .arg(canonical_file.path())
        .arg("-out")
        .arg(&args.signature)
        .output()
        .context("openssl pkeyutl could not be started")?;
    if !output.status.success() {
        bail!(
            "openssl Ed25519 signing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn verify_edge_manifest_for_plan(args: &EdgeManifestPlanArgs) -> Result<EdgeProvisioningManifest> {
    verify_edge_manifest_common(
        &args.manifest,
        &args.public_key,
        args.min_key_epoch,
        &args.min_rollback_floor,
    )
}

fn verify_edge_manifest_common(
    manifest_path: &Path,
    public_key_path: &Path,
    min_key_epoch: u32,
    min_rollback_floor: &str,
) -> Result<EdgeProvisioningManifest> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("edge manifest not readable: {}", manifest_path.display()))?;
    let manifest: EdgeProvisioningManifest =
        serde_json::from_slice(&bytes).context("edge provisioning manifest JSON is invalid")?;

    ensure_schema(manifest.schema_version, &manifest.kind, EDGE_MANIFEST_KIND)?;
    let canonical = canonical_without_signature(&manifest)?;
    let sig = decode_signature_value(&manifest.signature)?;
    let key = read_public_key(public_key_path)?;
    verify_ed25519(&key, &canonical, &sig).with_context(|| {
        format!(
            "edge provisioning manifest signature verification failed: {}",
            manifest_path.display()
        )
    })?;

    ensure_nonempty("device_id", &manifest.device_id)?;
    ensure_nonempty("device_code", &manifest.device_code)?;
    ensure_nonempty("tenant_id", &manifest.tenant_id)?;
    ensure_nonempty("version", &manifest.version)?;
    ensure_nonempty("board", &manifest.board)?;
    ensure_nonempty("arch", &manifest.arch)?;
    ensure_sha256(&manifest.artifact.sha256, "artifact.sha256")?;
    ensure_url_https(&manifest.artifact.url)?;
    ensure_nonempty("artifact.binary_name", &manifest.artifact.binary_name)?;
    ensure_now_in_window(
        manifest.not_before,
        manifest.expires_at,
        "edge provisioning manifest",
    )?;
    ensure_key_epoch_at_least(
        manifest.key_epoch,
        min_key_epoch,
        "edge provisioning manifest",
    )?;
    ensure_version_floor_at_least(
        &manifest.rollback_floor,
        min_rollback_floor,
        "edge provisioning manifest rollback_floor",
    )?;
    if let Some(config) = &manifest.config {
        ensure_sha256(&config.sha256, "config.sha256")?;
        let actual = sha256_bytes(config.payload.as_bytes());
        if actual != config.sha256 {
            bail!("edge config payload digest mismatch");
        }
    }

    Ok(manifest)
}

fn check_edge_target(
    manifest: &EdgeProvisioningManifest,
    board: Option<&str>,
    arch: Option<&str>,
) -> Result<()> {
    if let Some(board) = board {
        if board != manifest.board {
            bail!(
                "edge manifest board mismatch: manifest={}, target={}",
                manifest.board,
                board
            );
        }
    }
    if let Some(arch) = arch {
        if arch != manifest.arch {
            bail!(
                "edge manifest arch mismatch: manifest={}, target={}",
                manifest.arch,
                arch
            );
        }
    }
    Ok(())
}

fn verify_edge_artifact(args: &EdgeManifestVerifyArtifactArgs) -> Result<()> {
    let manifest = verify_edge_manifest_common(
        &args.manifest,
        &args.public_key,
        args.min_key_epoch,
        &args.min_rollback_floor,
    )?;
    check_edge_target(&manifest, args.board.as_deref(), args.arch.as_deref())?;
    verify_file_size(
        &args.artifact,
        manifest.artifact.size_bytes,
        "edge artifact",
    )?;
    verify_file_sha256(&args.artifact, &manifest.artifact.sha256, "edge artifact")?;
    let sig = decode_signature_value(&manifest.artifact.signature)?;
    let key = read_public_key(&args.public_key)?;
    let bytes = fs::read(&args.artifact)
        .with_context(|| format!("edge artifact not readable: {}", args.artifact.display()))?;
    verify_ed25519(&key, &bytes, &sig).context("edge artifact signature verification failed")?;
    Ok(())
}

fn write_usb_plan(path: &Path, validated: &ValidatedUsbPayload) -> Result<()> {
    let mut vars = BTreeMap::new();
    vars.insert(
        "SUDERRA_PAYLOAD_INDEX_BOARD_FAMILY",
        validated.index.board_family.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_BOARD_FAMILY",
        validated.payload.board_family.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_IMAGE_PATH",
        validated.image_path.display().to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_IMAGE_NAME",
        validated.payload.image_path.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_COMPRESSED_SHA256",
        validated.payload.compressed_sha256.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_COMPRESSED_SIZE_BYTES",
        validated.payload.compressed_size_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_UNCOMPRESSED_SHA256",
        validated.payload.uncompressed_sha256.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_UNCOMPRESSED_SIZE_BYTES",
        validated.payload.uncompressed_size_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_MIN_STORAGE_BYTES",
        validated.payload.min_storage_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_KEY_EPOCH",
        validated.index.key_epoch.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_EXPIRES_AT",
        validated.index.expires_at.to_rfc3339(),
    );
    if let Some(rollback_floor) = &validated.payload.rollback_floor {
        vars.insert("SUDERRA_PAYLOAD_ROLLBACK_FLOOR", rollback_floor.clone());
    }
    write_shell_env(path, &vars)
}

fn write_edge_plan(
    path: &Path,
    manifest: &EdgeProvisioningManifest,
    config_output: Option<&Path>,
) -> Result<()> {
    let mut vars = BTreeMap::new();
    vars.insert("SUDERRA_EDGE_VERSION", manifest.version.clone());
    vars.insert("SUDERRA_EDGE_DEVICE_ID", manifest.device_id.clone());
    vars.insert("SUDERRA_EDGE_DEVICE_CODE", manifest.device_code.clone());
    vars.insert("SUDERRA_EDGE_TENANT_ID", manifest.tenant_id.clone());
    vars.insert("SUDERRA_EDGE_BOARD", manifest.board.clone());
    vars.insert("SUDERRA_EDGE_ARCH", manifest.arch.clone());
    vars.insert("SUDERRA_EDGE_ARTIFACT_URL", manifest.artifact.url.clone());
    vars.insert("SUDERRA_EDGE_SHA256", manifest.artifact.sha256.clone());
    vars.insert(
        "SUDERRA_EDGE_SIZE_BYTES",
        manifest.artifact.size_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_EDGE_BINARY_NAME",
        manifest.artifact.binary_name.clone(),
    );
    vars.insert(
        "SUDERRA_EDGE_ARTIFACT_FORMAT",
        manifest.artifact.format.as_shell_value().to_string(),
    );
    vars.insert("SUDERRA_EDGE_KEY_EPOCH", manifest.key_epoch.to_string());
    vars.insert(
        "SUDERRA_EDGE_ROLLBACK_FLOOR",
        manifest.rollback_floor.clone(),
    );
    if let Some(config_output) = config_output {
        vars.insert(
            "SUDERRA_EDGE_CONFIG_PAYLOAD_FILE",
            config_output.display().to_string(),
        );
    }
    write_shell_env(path, &vars)
}

fn write_edge_config_payload(manifest: &EdgeProvisioningManifest, path: &Path) -> Result<()> {
    if let Some(config) = &manifest.config {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &config.payload)?;
    }
    Ok(())
}

fn write_shell_env(path: &Path, vars: &BTreeMap<&str, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut content = String::new();
    for (key, value) in vars {
        content.push_str(key);
        content.push('=');
        content.push_str(&shell_quote(value));
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn ensure_schema(version: u32, kind: &str, expected_kind: &str) -> Result<()> {
    if version != 1 {
        bail!("unsupported schema_version: {version}");
    }
    if kind != expected_kind {
        bail!("unsupported manifest kind: {kind}");
    }
    Ok(())
}

fn ensure_not_expired(expires_at: DateTime<Utc>, label: &str) -> Result<()> {
    if Utc::now() > expires_at {
        bail!("{label} expired at {expires_at}");
    }
    Ok(())
}

fn ensure_key_epoch_at_least(actual: u32, minimum: u32, label: &str) -> Result<()> {
    if actual < minimum {
        bail!("{label} key_epoch {actual} is below required epoch {minimum}");
    }
    Ok(())
}

fn ensure_now_in_window(
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    label: &str,
) -> Result<()> {
    let now = Utc::now();
    if now < not_before {
        bail!("{label} is not valid before {not_before}");
    }
    if now > expires_at {
        bail!("{label} expired at {expires_at}");
    }
    Ok(())
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} is required");
    }
    Ok(())
}

fn ensure_nonempty_vec<T>(field: &str, value: &[T]) -> Result<()> {
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(())
}

fn ensure_url_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("artifact.url must use https");
    }
    Ok(())
}

fn validate_payload_metadata(payload: &UsbImagePayload) -> Result<()> {
    ensure_nonempty("payload.name", &payload.name)?;
    ensure_nonempty("payload.board_family", &payload.board_family)?;
    ensure_nonempty_vec("payload.compatible_models", &payload.compatible_models)?;
    ensure_nonempty("payload.arch", &payload.arch)?;
    ensure_nonempty("payload.image_path", &payload.image_path)?;
    ensure_sha256(&payload.compressed_sha256, "payload.compressed_sha256")?;
    ensure_sha256(&payload.uncompressed_sha256, "payload.uncompressed_sha256")?;
    if payload.compressed_size_bytes == 0 {
        bail!("payload.compressed_size_bytes must be greater than zero");
    }
    if payload.uncompressed_size_bytes == 0 {
        bail!("payload.uncompressed_size_bytes must be greater than zero");
    }
    if payload.min_storage_bytes < payload.uncompressed_size_bytes {
        bail!("payload.min_storage_bytes is smaller than the image");
    }
    Ok(())
}

fn ensure_rollback_floor_at_least(payload: &UsbImagePayload, required_floor: &str) -> Result<()> {
    let floor = payload
        .rollback_floor
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("payload.rollback_floor is required"))?;
    ensure_nonempty("payload.rollback_floor", floor)?;
    ensure_version_floor_at_least(floor, required_floor, "payload.rollback_floor")
}

fn ensure_version_floor_at_least(actual: &str, required: &str, label: &str) -> Result<()> {
    ensure_nonempty(label, actual)?;
    ensure_nonempty("required rollback floor", required)?;
    if compare_versions(actual, required).with_context(|| {
        format!("could not compare {label} '{actual}' with required floor '{required}'")
    })? == std::cmp::Ordering::Less
    {
        bail!("{label} {actual} is below required floor {required}");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedVersion<'a> {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<&'a str>,
}

fn compare_versions(left: &str, right: &str) -> Result<std::cmp::Ordering> {
    let left = parse_version(left)?;
    let right = parse_version(right)?;
    Ok(left
        .major
        .cmp(&right.major)
        .then(left.minor.cmp(&right.minor))
        .then(left.patch.cmp(&right.patch))
        .then_with(|| compare_prerelease(left.pre, right.pre)))
}

fn parse_version(value: &str) -> Result<ParsedVersion<'_>> {
    let value = value.trim().trim_start_matches('v');
    let (core, pre) = value.split_once('-').unwrap_or((value, ""));
    let mut parts = core.split('.');
    let major = parse_version_part(parts.next(), value)?;
    let minor = parse_version_part(parts.next(), value)?;
    let patch = parse_version_part(parts.next(), value)?;
    if parts.next().is_some() {
        bail!("version has too many numeric components: {value}");
    }
    Ok(ParsedVersion {
        major,
        minor,
        patch,
        pre: if pre.is_empty() { None } else { Some(pre) },
    })
}

fn parse_version_part(part: Option<&str>, value: &str) -> Result<u64> {
    part.filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("version must use major.minor.patch form: {value}"))?
        .parse()
        .with_context(|| format!("version contains a non-numeric component: {value}"))
}

fn compare_prerelease(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    match (left, right) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(left), Some(right)) => compare_prerelease_segments(left, right),
    }
}

fn compare_prerelease_segments(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_parts = left.split('.');
    let mut right_parts = right.split('.');
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => {
                let ord = match (left.parse::<u64>(), right.parse::<u64>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => left.cmp(right),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

fn ensure_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} must be a 64-character hex SHA256 digest");
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute() {
        bail!("manifest image_path must be relative");
    }
    let mut joined = PathBuf::from(root);
    for component in path.components() {
        match component {
            Component::Normal(part) => joined.push(part),
            _ => bail!("manifest image_path contains unsafe component: {relative}"),
        }
    }
    Ok(joined)
}

fn verify_file_size(path: &Path, expected: u64, label: &str) -> Result<()> {
    let actual = fs::metadata(path)
        .with_context(|| format!("{label} not readable: {}", path.display()))?
        .len();
    if actual != expected {
        bail!("{label} size mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_file_sha256(path: &Path, expected: &str, label: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("{label} SHA256 mismatch");
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("file not readable: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn verify_xz_uncompressed(path: &Path, payload: &UsbImagePayload) -> Result<()> {
    let mut child = Command::new("xz")
        .arg("-dc")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("xz could not decompress {}", path.display()))?;
    let mut stdout = child.stdout.take().context("xz stdout unavailable")?;
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = stdout.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        hasher.update(&buffer[..read]);
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "xz payload decompression failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if count != payload.uncompressed_size_bytes {
        bail!(
            "uncompressed payload size mismatch: expected {}, got {}",
            payload.uncompressed_size_bytes,
            count
        );
    }
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(&payload.uncompressed_sha256) {
        bail!("uncompressed payload SHA256 mismatch");
    }
    Ok(())
}

fn read_public_key(path: &Path) -> Result<VerifyingKey> {
    let bytes =
        fs::read(path).with_context(|| format!("public key not readable: {}", path.display()))?;
    let raw = if bytes.starts_with(b"-----BEGIN PUBLIC KEY-----") {
        parse_ed25519_public_key_pem(&bytes)?
    } else {
        decode_hex_array::<32>(std::str::from_utf8(&bytes)?.trim(), "public key")?
    };
    VerifyingKey::from_bytes(&raw).context("invalid Ed25519 public key")
}

fn parse_ed25519_public_key_pem(bytes: &[u8]) -> Result<[u8; 32]> {
    let text = std::str::from_utf8(bytes).context("public key PEM is not UTF-8")?;
    let b64: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("public key PEM base64 decode failed")?;
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(ED25519_SPKI_PREFIX) {
        bail!("public key PEM is not an Ed25519 SubjectPublicKeyInfo");
    }
    let mut raw = [0_u8; 32];
    raw.copy_from_slice(&der[ED25519_SPKI_PREFIX.len()..]);
    Ok(raw)
}

fn read_signature(path: &Path) -> Result<Signature> {
    let bytes =
        fs::read(path).with_context(|| format!("signature not readable: {}", path.display()))?;
    decode_signature_bytes(&bytes)
}

fn decode_signature_value(value: &str) -> Result<Signature> {
    let raw = decode_hex_array::<64>(value.trim(), "signature")?;
    Ok(Signature::from_bytes(&raw))
}

fn decode_signature_bytes(bytes: &[u8]) -> Result<Signature> {
    if bytes.len() == 64 {
        let mut raw = [0_u8; 64];
        raw.copy_from_slice(bytes);
        return Ok(Signature::from_bytes(&raw));
    }
    let text = std::str::from_utf8(bytes)
        .context("signature must be raw 64 bytes or hex text")?
        .trim();
    decode_signature_value(text)
}

fn decode_hex_array<const N: usize>(text: &str, label: &str) -> Result<[u8; N]> {
    let decoded = hex::decode(text).with_context(|| format!("{label} is not valid hex"))?;
    if decoded.len() != N {
        bail!("{label} must decode to {N} bytes");
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn verify_ed25519(key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    key.verify(message, signature).map_err(Into::into)
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    canonical_value_bytes(&value)
}

fn canonical_without_signature<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    canonical_value_bytes(&value)
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    write_canonical_value(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(value) => out.push_str(&serde_json::to_string(value)?),
        Value::Array(values) => {
            out.push('[');
            for (idx, value) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_value(value, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut first = true;
            for (key, value) in map.iter().collect::<BTreeMap<_, _>>() {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical_value(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;

    fn keypair() -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        (key, public)
    }

    fn write_xz_payload(dir: &Path) -> (String, u64, String, u64) {
        let raw = b"suderra target image bytes";
        let raw_path = dir.join("target.img");
        let xz_path = dir.join("suderra-rpi4-target.img.xz");
        fs::write(&raw_path, raw).unwrap();
        let status = Command::new("xz")
            .args(["-z", "-k", "-f"])
            .arg(&raw_path)
            .status()
            .unwrap();
        assert!(status.success());
        fs::rename(dir.join("target.img.xz"), &xz_path).unwrap();
        let compressed_sha = sha256_file(&xz_path).unwrap();
        let compressed_size = fs::metadata(&xz_path).unwrap().len();
        let uncompressed_sha = sha256_bytes(raw);
        let uncompressed_size = raw.len() as u64;
        (
            compressed_sha,
            compressed_size,
            uncompressed_sha,
            uncompressed_size,
        )
    }

    fn usb_index(
        compressed_sha: String,
        compressed_size: u64,
        uncompressed_sha: String,
        uncompressed_size: u64,
    ) -> UsbPayloadIndex {
        UsbPayloadIndex {
            schema_version: 1,
            kind: USB_INDEX_KIND.into(),
            board_family: "pi-cm4-revpi".into(),
            compatible_models: vec!["rpi4-cm4".into(), "revpi4".into()],
            payloads: vec![UsbImagePayload {
                name: "rpi4".into(),
                board_family: "rpi4-cm4".into(),
                compatible_models: vec!["rpi4-cm4".into()],
                arch: "aarch64".into(),
                image_path: "suderra-rpi4-target.img.xz".into(),
                compressed_sha256: compressed_sha,
                compressed_size_bytes: compressed_size,
                uncompressed_sha256: uncompressed_sha,
                uncompressed_size_bytes: uncompressed_size,
                min_storage_bytes: 8 * 1024 * 1024 * 1024,
                rollback_floor: Some("v0.1.0-alpha".into()),
            }],
            created_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            key_epoch: 1,
        }
    }

    fn sign_usb_index(dir: &Path, index: &UsbPayloadIndex, key: &SigningKey, public: &str) {
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(index).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("payload.pub"), public).unwrap();
        let canonical = canonical_json_bytes(index).unwrap();
        let sig = key.sign(&canonical);
        fs::write(dir.join("manifest.sig"), hex::encode(sig.to_bytes())).unwrap();
    }

    fn usb_verify_args(dir: &Path, target_board: &str) -> UsbPayloadVerifyArgs {
        UsbPayloadVerifyArgs {
            payload_dir: dir.into(),
            public_key: dir.join("payload.pub"),
            target_board: target_board.into(),
            target_arch: "aarch64".into(),
            min_key_epoch: 1,
            min_rollback_floor: "v0.1.0-alpha".into(),
            write_plan: None,
        }
    }

    #[test]
    fn usb_payload_verifies_and_writes_plan() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let plan = tmp.path().join("plan.env");
        let mut args = usb_verify_args(tmp.path(), "rpi4-cm4");
        args.write_plan = Some(plan.clone());
        let result = verify_usb_payload(&args).unwrap();
        assert_eq!(result.payload.board_family, "rpi4-cm4");
        write_usb_plan(&plan, &result).unwrap();
        let plan_text = fs::read_to_string(plan).unwrap();
        assert!(plan_text.contains("SUDERRA_PAYLOAD_IMAGE_PATH="));
    }

    #[test]
    fn usb_payload_rejects_board_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "unknown-board")).unwrap_err();
        assert!(err.to_string().contains("not compatible"));
    }

    #[test]
    fn usb_payload_rejects_expired_index() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let mut index = usb_index(c_sha, c_size, u_sha, u_size);
        index.expires_at = "2000-01-01T00:00:00Z".parse().unwrap();
        sign_usb_index(tmp.path(), &index, &key, &public);

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "rpi4-cm4")).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn usb_payload_rejects_key_epoch_floor() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let mut args = usb_verify_args(tmp.path(), "rpi4-cm4");
        args.min_key_epoch = 2;
        let err = verify_usb_payload(&args).unwrap_err();
        assert!(err.to_string().contains("below required epoch"));
    }

    #[test]
    fn usb_payload_rejects_rollback_floor() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let mut args = usb_verify_args(tmp.path(), "rpi4-cm4");
        args.min_rollback_floor = "v0.2.0".into();
        let err = verify_usb_payload(&args).unwrap_err();
        assert!(err.to_string().contains("below required floor"));
    }

    #[test]
    fn usb_payload_rejects_path_traversal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let mut index = usb_index(c_sha, c_size, u_sha, u_size);
        index.payloads[0].image_path = "../target.img.xz".into();
        sign_usb_index(tmp.path(), &index, &key, &public);

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "rpi4-cm4")).unwrap_err();
        assert!(err.to_string().contains("unsafe component"));
    }

    #[test]
    fn usb_payload_rejects_wrong_signature() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let mut index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);
        index.key_epoch = 2;
        fs::write(
            tmp.path().join("manifest.json"),
            serde_json::to_string_pretty(&index).unwrap(),
        )
        .unwrap();

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "rpi4-cm4")).unwrap_err();
        assert!(format!("{err:#}").contains("signature verification failed"));
    }

    fn signed_edge_manifest(tmp: &Path) -> (EdgeProvisioningManifest, String, SigningKey) {
        let (key, public) = keypair();
        let artifact = b"edge artifact bytes";
        let artifact_sig = key.sign(artifact);
        fs::write(tmp.join("artifact.bin"), artifact).unwrap();
        let mut manifest = EdgeProvisioningManifest {
            schema_version: 1,
            kind: EDGE_MANIFEST_KIND.into(),
            device_id: "device-1".into(),
            device_code: "CODE-1".into(),
            tenant_id: "tenant-1".into(),
            version: "v1.0.0".into(),
            board: "rpi4-cm4".into(),
            arch: "aarch64".into(),
            artifact: EdgeArtifact {
                url: "https://releases.example/edge.bin".into(),
                sha256: sha256_bytes(artifact),
                size_bytes: artifact.len() as u64,
                signature: hex::encode(artifact_sig.to_bytes()),
                binary_name: "suderra-agent".into(),
                format: EdgeArtifactFormat::Raw,
            },
            config: Some(EdgeConfigPayload {
                sha256: sha256_bytes(b"device_id: device-1\n"),
                payload: "device_id: device-1\n".into(),
            }),
            not_before: "2026-01-01T00:00:00Z".parse().unwrap(),
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            rollback_floor: "v0.1.0-alpha".into(),
            key_epoch: 1,
            signature: String::new(),
        };
        let canonical = canonical_without_signature(&manifest).unwrap();
        manifest.signature = hex::encode(key.sign(&canonical).to_bytes());
        fs::write(
            tmp.join("edge-manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(tmp.join("edge.pub"), &public).unwrap();
        (manifest, public, key)
    }

    fn edge_verify_args(tmp: &Path) -> EdgeManifestVerifyArtifactArgs {
        EdgeManifestVerifyArtifactArgs {
            manifest: tmp.join("edge-manifest.json"),
            public_key: tmp.join("edge.pub"),
            artifact: tmp.join("artifact.bin"),
            board: Some("rpi4-cm4".into()),
            arch: Some("aarch64".into()),
            min_key_epoch: 1,
            min_rollback_floor: "v0.1.0-alpha".into(),
        }
    }

    #[test]
    fn edge_manifest_verifies_artifact() {
        let tmp = tempfile::TempDir::new().unwrap();
        signed_edge_manifest(tmp.path());
        verify_edge_artifact(&edge_verify_args(tmp.path())).unwrap();
    }

    #[test]
    fn edge_manifest_rejects_wrong_artifact_hash() {
        let tmp = tempfile::TempDir::new().unwrap();
        signed_edge_manifest(tmp.path());
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(tmp.path().join("artifact.bin"))
            .unwrap();
        file.write_all(b"tampered").unwrap();
        let err = verify_edge_artifact(&edge_verify_args(tmp.path())).unwrap_err();
        assert!(err.to_string().contains("size mismatch"));
    }

    #[test]
    fn edge_manifest_rejects_key_epoch_floor() {
        let tmp = tempfile::TempDir::new().unwrap();
        signed_edge_manifest(tmp.path());
        let mut args = edge_verify_args(tmp.path());
        args.min_key_epoch = 2;
        let err = verify_edge_artifact(&args).unwrap_err();
        assert!(err.to_string().contains("below required epoch"));
    }

    #[test]
    fn edge_manifest_rejects_rollback_floor() {
        let tmp = tempfile::TempDir::new().unwrap();
        signed_edge_manifest(tmp.path());
        let mut args = edge_verify_args(tmp.path());
        args.min_rollback_floor = "v0.2.0".into();
        let err = verify_edge_artifact(&args).unwrap_err();
        assert!(err.to_string().contains("below required floor"));
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value: Value = serde_json::from_str(r#"{"b":2,"a":{"d":4,"c":3}}"#).unwrap();
        let canonical = String::from_utf8(canonical_value_bytes(&value).unwrap()).unwrap();
        assert_eq!(canonical, r#"{"a":{"c":3,"d":4},"b":2}"#);
    }
}

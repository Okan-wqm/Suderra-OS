// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-ota` owns production OS updates.
//!
//! It validates a signed OS update manifest, checks anti-rollback policy,
//! delegates bundle installation to RAUC, records typed JSON evidence, and
//! requests reboot only after the inactive slot install succeeds.
//!
//! Production mode and the device's OTA target are facts of the signed
//! image (`/etc/os-release` `VARIANT` and `IMAGE_ROLE` on the verity
//! rootfs), never of the environment (ADR-048 DEC-19): anything but
//! `VARIANT=dev`, or an unreadable os-release, is production, and on
//! production images every `SUDERRA_OTA_*` override is ignored.

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info};

const MANIFEST_SCHEMA: &str = "suderra.os-update-manifest.v1";
const STATE_SCHEMA: &str = "suderra.ota-state.v1";
const EVENT_SCHEMA: &str = "suderra.ota-event.v1";

#[derive(Parser, Debug)]
#[command(
    name = "suderra-ota",
    version,
    about = "Suderra OS RAUC OTA orchestrator"
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify a signed manifest and install a RAUC bundle into the inactive slot.
    Install(InstallArgs),
    /// Emit current OTA state.
    Status(StatusArgs),
    /// Mark the current boot attempt bad and request RAUC fallback.
    Rollback(RollbackArgs),
    /// Mark the current slot good after health checks pass.
    MarkGood(MarkGoodArgs),
}

#[derive(Args, Debug)]
struct InstallArgs {
    /// Signed OS update manifest JSON.
    manifest: PathBuf,
    /// RAUC bundle referenced by the manifest.
    bundle: PathBuf,
    /// Ed25519 public key used to verify the manifest signature (dev
    /// images only; production verifies against the image's pinned key).
    #[arg(long)]
    manifest_pubkey: Option<PathBuf>,
    /// Do not request reboot after a successful inactive-slot install.
    #[arg(long, default_value_t = false)]
    no_reboot: bool,
}

#[derive(Args, Debug)]
struct StatusArgs {
    /// Print JSON. Kept explicit so scripts can assert stable machine output.
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Debug)]
struct RollbackArgs {
    /// Operator or health-gate reason for rollback.
    #[arg(long)]
    reason: String,
    /// Do not request reboot after marking the slot bad.
    #[arg(long, default_value_t = false)]
    no_reboot: bool,
}

#[derive(Args, Debug)]
struct MarkGoodArgs {
    /// Version to mark good. Defaults to the pending version from state.
    #[arg(long)]
    version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SignedManifest {
    schema_version: String,
    version: String,
    target: String,
    artifact_sha256: String,
    bundle: BundleRef,
    key_epoch: u64,
    expires_at: String,
    #[serde(alias = "minimum_current_version")]
    min_current_version: String,
    rollback_floor: String,
    #[serde(default)]
    release_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<ManifestSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BundleRef {
    name: String,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ManifestSignature {
    algorithm: String,
    key_id: String,
    public_key_sha256: String,
    signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OtaState {
    schema_version: String,
    target: String,
    current_version: String,
    rollback_floor: String,
    pending_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_boot_slot: Option<String>,
    reboot_required: bool,
    last_event: Option<Value>,
    last_error: Option<String>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match run(cli.command).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            error!("{err:#}");
            let event = event_json("error", "failed", None, Some(err.to_string()));
            let _ = persist_last_event(&event, Some(err.to_string()));
            eprintln!(
                "{}",
                serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string())
            );
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Install(args) => install(args),
        Commands::Status(args) => status(args),
        Commands::Rollback(args) => rollback(args),
        Commands::MarkGood(args) => mark_good(args),
    }
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "info" };
    let filter = image()
        .dev_override("RUST_LOG")
        .and_then(|spec| tracing_subscriber::EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
}

fn install(args: InstallArgs) -> Result<()> {
    let mut state = load_state()?;
    let manifest = load_manifest(&args.manifest)?;
    verify_manifest_signature(&manifest, args.manifest_pubkey.as_deref())?;
    verify_manifest_policy(&manifest, &state)?;
    verify_bundle(&manifest, &args.bundle)?;

    info!(version = %manifest.version, target = %manifest.target, "installing RAUC bundle");
    run_rauc(&["install", path_str(&args.bundle)?]).context("rauc install failed")?;
    let pending_boot_slot = pending_boot_slot_after_install()
        .context("cannot prove inactive RAUC slot selected for next boot")?;

    state.pending_version = Some(manifest.version.clone());
    state.pending_boot_slot = Some(pending_boot_slot.clone());
    state.reboot_required = !args.no_reboot;
    state.last_error = None;
    let event = event_json(
        "install",
        "passed",
        Some(json!({
            "version": manifest.version,
            "target": manifest.target,
            "bundle": {
                "path": args.bundle,
                "sha256": manifest.bundle.sha256,
                "bytes": manifest.bundle.bytes,
            },
            "pending_boot_slot": pending_boot_slot,
            "reboot_requested": !args.no_reboot,
        })),
        None,
    );
    state.last_event = Some(event.clone());
    save_state(&state)?;
    print_json(&event)?;

    if !args.no_reboot {
        request_reboot("suderra-ota install")?;
    }
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    let state = load_state()?;
    if args.json {
        print_json(&serde_json::to_value(state)?)?;
    } else {
        println!("target={}", state.target);
        println!("current_version={}", state.current_version);
        println!("rollback_floor={}", state.rollback_floor);
        println!(
            "pending_version={}",
            state.pending_version.as_deref().unwrap_or("")
        );
        println!("reboot_required={}", state.reboot_required);
    }
    Ok(())
}

fn rollback(args: RollbackArgs) -> Result<()> {
    if args.reason.trim().is_empty() {
        bail!("rollback --reason must be non-empty");
    }
    run_rauc(&["status", "mark-bad"]).context("rauc mark-bad failed")?;
    let mut state = load_state()?;
    state.pending_version = None;
    state.pending_boot_slot = None;
    state.reboot_required = !args.no_reboot;
    state.last_error = Some(args.reason.clone());
    let event = event_json(
        "rollback",
        "passed",
        Some(json!({
            "reason": args.reason,
            "reboot_requested": !args.no_reboot,
        })),
        None,
    );
    state.last_event = Some(event.clone());
    save_state(&state)?;
    print_json(&event)?;
    if !args.no_reboot {
        request_reboot("suderra-ota rollback")?;
    }
    Ok(())
}

/// The OTA pending in the state file at `path`, if any. It is read without
/// the production anti-rollback guard of [`load_state`] because confirming a
/// booted slot no OTA is pending for changes neither a version nor a floor.
fn pending_version_in(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let state: OtaState = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
    )
    .with_context(|| format!("invalid OTA state JSON: {}", path.display()))?;
    if state.schema_version != STATE_SCHEMA {
        bail!("OTA state schema_version must be {STATE_SCHEMA}");
    }
    Ok(state.pending_version)
}

/// The single mark-good path runs after the health gate on every boot
/// (suderra-rauc-mark-good, ADR-048 DEC-6.8). On a normal boot no OTA is
/// pending: mark-good then only confirms the booted slot to RAUC, which is
/// idempotent, instead of failing and rolling a healthy slot back (EI-012).
/// With an OTA pending it completes that OTA: version, slot and floor checks,
/// then the floor rises.
fn mark_good(args: MarkGoodArgs) -> Result<()> {
    if args.version.is_none() && pending_version_in(&state_path())?.is_none() {
        run_rauc(&["status", "mark-good"]).context("rauc mark-good failed")?;
        print_json(&event_json(
            "mark-good",
            "passed",
            Some(json!({ "pending_version": null, "boot_slot": active_boot_slot() })),
            None,
        ))?;
        return Ok(());
    }
    let mut state = load_state()?;
    let requested_version = args.version;
    let version = requested_version
        .or_else(|| state.pending_version.clone())
        .ok_or_else(|| anyhow!("no pending version to mark good"))?;
    if let Some(pending) = state.pending_version.as_deref() {
        if pending != version {
            bail!("mark-good version {version} does not match pending version {pending}");
        }
    }
    if let Some(expected_slot) = state.pending_boot_slot.as_deref() {
        let active_slot = active_boot_slot().ok_or_else(|| {
            anyhow!("cannot prove active boot slot for pending slot {expected_slot}")
        })?;
        if active_slot != expected_slot {
            bail!("active boot slot {active_slot} does not match pending slot {expected_slot}");
        }
    }
    if compare_versions(&version, &state.rollback_floor)? == Ordering::Less {
        bail!(
            "refusing to mark version {version} good below rollback floor {}",
            state.rollback_floor
        );
    }
    run_rauc(&["status", "mark-good"]).context("rauc mark-good failed")?;
    state.current_version = version.clone();
    if compare_versions(&version, &state.rollback_floor)? == Ordering::Greater {
        state.rollback_floor = version.clone();
    }
    state.pending_version = None;
    state.pending_boot_slot = None;
    state.reboot_required = false;
    state.last_error = None;
    let event = event_json(
        "mark-good",
        "passed",
        Some(json!({
            "version": version,
            "rollback_floor": state.rollback_floor,
            "boot_slot": active_boot_slot(),
        })),
        None,
    );
    state.last_event = Some(event.clone());
    save_state(&state)?;
    persist_rollback_floor(&state.rollback_floor)?;
    print_json(&event)?;
    Ok(())
}

fn load_manifest(path: &Path) -> Result<SignedManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("cannot read update manifest: {}", path.display()))?;
    let manifest: SignedManifest = serde_json::from_str(&text)
        .with_context(|| format!("invalid update manifest JSON: {}", path.display()))?;
    if manifest.schema_version != MANIFEST_SCHEMA {
        bail!(
            "manifest schema_version must be {MANIFEST_SCHEMA}, got {}",
            manifest.schema_version
        );
    }
    Ok(manifest)
}

/// The image's pinned OS update manifest key.
const MANIFEST_PUBKEY: &str = "/etc/suderra/os-update-manifest.ed25519.pub";

/// The manifest key to verify with: on production images only the pinned
/// image key, on dev images a `--manifest-pubkey` or override path first.
fn manifest_key_path(image: &Image, flag: Option<&Path>) -> Result<PathBuf> {
    if image.variant == Variant::Production {
        if let Some(path) = flag {
            bail!(
                "--manifest-pubkey {} is refused on production images: the manifest key is the image pin {MANIFEST_PUBKEY}",
                path.display()
            );
        }
        return Ok(PathBuf::from(MANIFEST_PUBKEY));
    }
    Ok(flag
        .map(PathBuf::from)
        .or_else(|| {
            image
                .dev_override("SUDERRA_OTA_MANIFEST_PUBKEY")
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(MANIFEST_PUBKEY)))
}

fn verify_manifest_signature(manifest: &SignedManifest, key_path: Option<&Path>) -> Result<()> {
    let signature = manifest
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("OS update manifest must carry an Ed25519 signature"))?;
    if signature.algorithm != "ed25519-suderra-os-update-manifest-v1" {
        bail!(
            "unsupported manifest signature algorithm: {}",
            signature.algorithm
        );
    }
    if signature.key_id.trim().is_empty() {
        bail!("manifest signature key_id must be non-empty");
    }
    let key_path = manifest_key_path(image(), key_path)?;
    let public_key = read_public_key(&key_path)?;
    let public_key_sha256 = hex::encode(Sha256::digest(public_key.as_bytes()));
    if signature.public_key_sha256 != public_key_sha256 {
        bail!("manifest public_key_sha256 does not match configured key");
    }
    let signature_bytes = decode_fixed_hex::<64>(&signature.signature_hex, "signature_hex")?;
    let signature = Signature::from_bytes(&signature_bytes);
    public_key
        .verify(&manifest_signing_bytes(manifest)?, &signature)
        .context("manifest signature verification failed")?;
    Ok(())
}

fn manifest_signing_bytes(manifest: &SignedManifest) -> Result<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned).context("cannot canonicalize unsigned manifest")
}

fn read_public_key(path: &Path) -> Result<VerifyingKey> {
    let raw = fs::read(path)
        .with_context(|| format!("cannot read manifest public key: {}", path.display()))?;
    let trimmed = String::from_utf8_lossy(&raw);
    let bytes =
        if trimmed.trim().len() == 64 && trimmed.trim().chars().all(|c| c.is_ascii_hexdigit()) {
            decode_fixed_hex::<32>(trimmed.trim(), "public key")?
        } else {
            let mut key = [0_u8; 32];
            if raw.len() != key.len() {
                bail!("manifest public key must be 32 raw bytes or 64 hex characters");
            }
            key.copy_from_slice(&raw);
            key
        };
    VerifyingKey::from_bytes(&bytes).context("invalid manifest Ed25519 public key")
}

fn decode_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{field} must be lowercase hex"))?;
    if bytes.len() != N {
        bail!("{field} must decode to {N} bytes");
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn verify_manifest_policy(manifest: &SignedManifest, state: &OtaState) -> Result<()> {
    let device_target = device_target()?;
    if manifest.target != device_target {
        bail!(
            "manifest target {} does not match device target {}",
            manifest.target,
            device_target
        );
    }
    // Anahtar epoch tabanı 1'dir; yalnız dev imajında override edilebilir
    // (DEC-19: prod'da env yok sayılır).
    let minimum_epoch = image()
        .dev_override("SUDERRA_OTA_MIN_KEY_EPOCH")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    if manifest.key_epoch < minimum_epoch {
        bail!(
            "manifest key_epoch {} is below required epoch {}",
            manifest.key_epoch,
            minimum_epoch
        );
    }
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .with_context(|| format!("invalid expires_at {}", manifest.expires_at))?
        .with_timezone(&Utc);
    if expires_at <= now_utc()? {
        bail!("manifest expired at {}", manifest.expires_at);
    }
    if compare_versions(&state.current_version, &manifest.min_current_version)? == Ordering::Less {
        bail!(
            "current version {} is below manifest minimum {}",
            state.current_version,
            manifest.min_current_version
        );
    }
    if compare_versions(&manifest.version, &state.rollback_floor)? == Ordering::Less {
        bail!(
            "refusing downgrade: manifest version {} is below rollback floor {}",
            manifest.version,
            state.rollback_floor
        );
    }
    if compare_versions(&manifest.version, &manifest.rollback_floor)? == Ordering::Less {
        bail!(
            "manifest version {} is below its rollback_floor {}",
            manifest.version,
            manifest.rollback_floor
        );
    }
    if compare_versions(&manifest.rollback_floor, &state.rollback_floor)? == Ordering::Less {
        bail!(
            "manifest rollback_floor {} is below device rollback floor {}",
            manifest.rollback_floor,
            state.rollback_floor
        );
    }
    if manifest.artifact_sha256 != manifest.bundle.sha256 {
        bail!("manifest artifact_sha256 must match bundle.sha256");
    }
    Ok(())
}

fn verify_bundle(manifest: &SignedManifest, bundle: &Path) -> Result<()> {
    let meta =
        fs::metadata(bundle).with_context(|| format!("bundle missing: {}", bundle.display()))?;
    if !meta.is_file() || meta.len() == 0 {
        bail!("bundle is missing or empty: {}", bundle.display());
    }
    if meta.len() != manifest.bundle.bytes {
        bail!(
            "bundle byte count mismatch: manifest {}, actual {}",
            manifest.bundle.bytes,
            meta.len()
        );
    }
    if bundle.file_name().and_then(|name| name.to_str()) != Some(manifest.bundle.name.as_str()) {
        bail!(
            "bundle filename mismatch: manifest {}, actual {}",
            manifest.bundle.name,
            bundle.display()
        );
    }
    let digest = sha256_file(bundle)?;
    if digest != manifest.bundle.sha256 {
        bail!(
            "bundle sha256 mismatch: manifest {}, actual {}",
            manifest.bundle.sha256,
            digest
        );
    }
    Ok(())
}

fn run_rauc(args: &[&str]) -> Result<()> {
    run_rauc_output(args).map(|_| ())
}

fn run_rauc_output(args: &[&str]) -> Result<String> {
    let rauc = dev_override("SUDERRA_OTA_RAUC").unwrap_or_else(|| "rauc".to_string());
    let output = Command::new(&rauc)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {rauc}"))?;
    if !output.status.success() {
        bail!(
            "rauc {:?} exited with {}: {}{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn request_reboot(reason: &str) -> Result<()> {
    if image().dev_override("SUDERRA_OTA_NO_REBOOT").as_deref() == Some("1") {
        return Ok(());
    }
    let reboot = dev_override("SUDERRA_OTA_REBOOT").unwrap_or_else(|| "/sbin/reboot".to_string());
    let output = Command::new(&reboot)
        .arg(reason)
        .output()
        .with_context(|| format!("failed to execute reboot command {reboot}"))?;
    if !output.status.success() {
        bail!(
            "reboot command exited with {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn load_state() -> Result<OtaState> {
    production_rollback_floor_requires_monotonic_state()?;
    let path = state_path();
    let mut state = if path.exists() {
        let state: OtaState = serde_json::from_str(
            &fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?,
        )
        .with_context(|| format!("invalid OTA state JSON: {}", path.display()))?;
        if state.schema_version != STATE_SCHEMA {
            bail!("OTA state schema_version must be {STATE_SCHEMA}");
        }
        state
    } else {
        // State dosyası yok (ilk boot ya da /data sıfırlandı). Fallback floor'u
        // env'den (yalnız dev) veya /data'daki floor aynasından seed'liyoruz;
        // prod'da bunların ikisi de güvenilmezdir ama aşağıdaki trusted-floor
        // alt sınırı state'i yine de gerçek monotonic floor'a çeker.
        let fallback_floor = dev_override("SUDERRA_OTA_ROLLBACK_FLOOR")
            .or_else(read_rollback_floor)
            .unwrap_or_else(|| "v0.1.0-alpha".to_string());
        let current_version = dev_override("SUDERRA_OTA_CURRENT_VERSION")
            .or_else(running_image_version)
            .unwrap_or_else(|| fallback_floor.clone());
        OtaState {
            schema_version: STATE_SCHEMA.to_string(),
            target: device_target()?,
            current_version,
            rollback_floor: fallback_floor,
            pending_version: None,
            pending_boot_slot: None,
            reboot_required: false,
            last_event: None,
            last_error: None,
        }
    };

    // Güvenilir (TPM NV / bootloader monotonic) floor bir ALT SINIRDIR: state'teki
    // floor bunun altına ASLA inemez. Böylece saldırgan /data'daki state.json ve
    // floor aynasını silse/düşürse bile downgrade koruması korunur. Prod'da
    // production_rollback_floor_requires_monotonic_state() bu kaynağın varlığını
    // ve okunabilirliğini zaten garanti eder.
    if let Some(trusted) = trusted_rollback_floor()? {
        if compare_versions(&trusted, &state.rollback_floor)? == Ordering::Greater {
            state.rollback_floor = trusted;
        }
    }
    Ok(state)
}

fn save_state(state: &OtaState) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "cannot atomically rename {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn persist_last_event(event: &Value, error: Option<String>) -> Result<()> {
    let mut state = load_state()?;
    state.last_event = Some(event.clone());
    state.last_error = error;
    save_state(&state)
}

fn persist_rollback_floor(version: &str) -> Result<()> {
    production_rollback_floor_requires_monotonic_state()?;
    let path = rollback_floor_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        writeln!(file, "{version}")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn read_rollback_floor() -> Option<String> {
    let path = rollback_floor_path();
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Image variant (`/etc/os-release` `VARIANT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// `VARIANT=dev`.
    Dev,
    /// Everything else, and an unreadable os-release (fail-safe).
    Production,
}

/// The facts of the signed image this binary runs on (DEC-19).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Image {
    variant: Variant,
    /// `IMAGE_ROLE`: the defconfig the image was built from.
    image_role: Option<String>,
}

/// The image's os-release, on the verity rootfs.
const OS_RELEASE: &str = "/etc/os-release";

/// os-release(5) `KEY=value` lines; a value may sit in one pair of quotes.
fn os_release_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (k, v) = line.trim().split_once('=')?;
        if k != key {
            return None;
        }
        let v = v.trim();
        let unquoted = v
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')))
            .unwrap_or(v);
        Some(unquoted)
    })
}

impl Image {
    fn from_os_release(text: Option<&str>) -> Self {
        let value = |key| text.and_then(|t| os_release_value(t, key));
        Self {
            variant: match value("VARIANT") {
                Some("dev") => Variant::Dev,
                _ => Variant::Production,
            },
            image_role: value("IMAGE_ROLE").map(str::to_owned),
        }
    }

    fn load() -> Self {
        Self::from_os_release(fs::read_to_string(OS_RELEASE).ok().as_deref())
    }

    /// A test/dev override: the environment value on dev images, `None` on
    /// production images, so expiry, slot proof, the rauc/reboot binaries,
    /// the rollback floor and the target cannot be steered by env there.
    fn dev_override(&self, key: &str) -> Option<String> {
        match self.variant {
            Variant::Dev => std::env::var(key).ok(),
            Variant::Production => None,
        }
    }
}

/// The image this process runs on, read once.
fn image() -> &'static Image {
    static IMAGE: std::sync::OnceLock<Image> = std::sync::OnceLock::new();
    IMAGE.get_or_init(Image::load)
}

fn dev_override(key: &str) -> Option<String> {
    image().dev_override(key)
}

/// OTA target of each RAUC-updatable image, by `IMAGE_ROLE` (the defconfig
/// name post-build.sh writes); the same table as post-image.sh's
/// `ota_target` case, which `ota_targets_match_post_image` keeps in step.
const OTA_TARGETS: [(&str, &str); 4] = [
    ("suderra_x86_64", "x86_64"),
    ("suderra_qemu_x86_64_prod_ab", "qemu-x86_64-prod-ab"),
    ("suderra_aarch64_rpi4_prod_ab", "rpi4-prod-ab"),
    ("suderra_aarch64_revpi4_prod_ab", "revpi4-prod-ab"),
];

/// The device's OTA target from the image; an image without one cannot
/// take an OTA (no default target, EI-030).
fn device_target_in(image: &Image) -> Result<String> {
    if let Some(target) = image.dev_override("SUDERRA_OTA_TARGET") {
        return Ok(target);
    }
    let role = image
        .image_role
        .as_deref()
        .ok_or_else(|| anyhow!("{OS_RELEASE} has no IMAGE_ROLE, so the OTA target is unknown"))?;
    OTA_TARGETS
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, target)| (*target).to_string())
        .ok_or_else(|| anyhow!("image role {role} has no OTA target"))
}

fn device_target() -> Result<String> {
    device_target_in(image())
}

/// Prod'da anti-rollback floor'un okunacağı GÜVENİLİR kaynak: yalnız
/// platformun monotonik deposu (TPM NV aynası veya bootloader monotonic
/// counter). Bu kaynak env'den gelemez (DEC-19); imajın onu beyan edeceği
/// TPM NV floor'u P1'de gelir (DEC-21, EI-031). Dev imajında testler için
/// env override'larıyla verilebilir.
fn trusted_floor_source(image: &Image) -> Option<(String, PathBuf)> {
    Some((
        image.dev_override("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE")?,
        PathBuf::from(image.dev_override("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH")?),
    ))
}

/// Güvenilir kaynaktan floor değerini okur ve SemVer olarak doğrular. Kaynak
/// yoksa `None`; ayarlı ama okunamıyorsa/boşsa/geçersizse hata (fail-closed).
fn trusted_rollback_floor_in(image: &Image) -> Result<Option<String>> {
    let Some((_, path)) = trusted_floor_source(image) else {
        return Ok(None);
    };
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("cannot read trusted rollback floor {}", path.display()))?;
    let value = raw.trim().to_string();
    if value.is_empty() {
        bail!("trusted rollback floor {} is empty", path.display());
    }
    ParsedVersion::parse(&value)
        .with_context(|| format!("trusted rollback floor {value} is not valid SemVer"))?;
    Ok(Some(value))
}

fn trusted_rollback_floor() -> Result<Option<String>> {
    trusted_rollback_floor_in(image())
}

/// Çalışan imajın sürümünü `/etc/os-release`'ten okur (prod'da güvenilir
/// `current_version` tohumu — env yerine gerçekten boot edilen imaj).
fn running_image_version() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VERSION_ID=") {
            let v = rest.trim().trim_matches('"').trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Production OTA needs a monotonic rollback floor outside the writable
/// state directory. No production image declares one before the TPM NV
/// floor (DEC-21, EI-031), and the environment cannot (DEC-19), so until
/// then every production OTA command fails closed here.
fn production_rollback_floor_requires_monotonic_state_in(image: &Image) -> Result<()> {
    if image.variant != Variant::Production {
        return Ok(());
    }
    let (kind, path) = trusted_floor_source(image).ok_or_else(|| {
        anyhow!("production anti-rollback requires a monotonic floor source (TPM NV or bootloader counter) declared by the image; none is declared (ADR-048 DEC-21)")
    })?;
    if !matches!(kind.as_str(), "tpm-nv" | "bootloader-monotonic") {
        bail!("production anti-rollback requires TPM NV or bootloader monotonic state, got {kind}");
    }
    let sdir = state_dir();
    if path.starts_with(&sdir) {
        bail!(
            "rollback floor source path {} must not live under the writable state dir {}",
            path.display(),
            sdir.display()
        );
    }
    trusted_rollback_floor_in(image)?.ok_or_else(|| {
        anyhow!("production rollback floor source is configured but produced no value")
    })?;
    Ok(())
}

fn production_rollback_floor_requires_monotonic_state() -> Result<()> {
    production_rollback_floor_requires_monotonic_state_in(image())
}

fn state_dir() -> PathBuf {
    // Prod'da state konumu sabittir; dev/CI'de SUDERRA_OTA_STATE_DIR ile taşınabilir.
    dev_override("SUDERRA_OTA_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/data/suderra/ota"))
}

fn state_path() -> PathBuf {
    state_dir().join("state.json")
}

fn rollback_floor_path() -> PathBuf {
    state_dir().join("rollback-floor")
}

fn configured_pending_boot_slot() -> Option<String> {
    dev_override("SUDERRA_OTA_PENDING_BOOT_SLOT")
        .map(|value| value.trim().to_string())
        .filter(|value| matches!(value.as_str(), "A" | "B"))
}

fn pending_boot_slot_after_install() -> Result<String> {
    if let Some(slot) = configured_pending_boot_slot() {
        return Ok(slot);
    }
    let status = run_rauc_output(&["status", "--output-format=json"])
        .context("rauc status did not expose pending boot slot")?;
    let payload: Value = serde_json::from_str(&status).context("rauc status JSON is invalid")?;
    find_slot_value(
        &payload,
        &["pending_boot_slot", "bootname", "boot_slot", "slot"],
    )
    .filter(|slot| matches!(slot.as_str(), "A" | "B"))
    .ok_or_else(|| anyhow!("rauc status JSON does not prove pending boot slot A/B"))
}

fn find_slot_value(value: &Value, names: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for name in names {
                if let Some(Value::String(slot)) = map.get(*name) {
                    let trimmed = slot.trim();
                    if matches!(trimmed, "A" | "B") {
                        return Some(trimmed.to_string());
                    }
                }
            }
            for child in map.values() {
                if let Some(slot) = find_slot_value(child, names) {
                    return Some(slot);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| find_slot_value(item, names)),
        _ => None,
    }
}

fn active_boot_slot() -> Option<String> {
    if let Some(value) = dev_override("SUDERRA_OTA_ACTIVE_BOOT_SLOT") {
        let slot = value.trim();
        if matches!(slot, "A" | "B") {
            return Some(slot.to_string());
        }
    }
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    for token in cmdline.split_whitespace() {
        match token {
            "rauc.slot=A" => return Some("A".to_string()),
            "rauc.slot=B" => return Some("B".to_string()),
            _ => {}
        }
    }
    None
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))
}

fn event_json(action: &str, status: &str, details: Option<Value>, error: Option<String>) -> Value {
    json!({
        "schema_version": EVENT_SCHEMA,
        "action": action,
        "status": status,
        "target": device_target().ok(),
        "generated_at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "details": details.unwrap_or_else(|| json!({})),
        "error": error,
    })
}

fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    let mut file = fs::File::open(path)?;
    std::io::copy(&mut file, &mut digest)?;
    Ok(hex::encode(digest.finalize()))
}

fn now_utc() -> Result<DateTime<Utc>> {
    // SUDERRA_OTA_NOW yalnız test/dev'de saat sabitlemek içindir; prod'da yok
    // sayılır ki süresi geçmiş/imzalı bir manifest replay edilemesin.
    if let Some(value) = dev_override("SUDERRA_OTA_NOW") {
        return Ok(DateTime::parse_from_rfc3339(&value)
            .with_context(|| format!("invalid SUDERRA_OTA_NOW {value}"))?
            .with_timezone(&Utc));
    }
    Ok(Utc::now())
}

fn compare_versions(a: &str, b: &str) -> Result<Ordering> {
    let a = ParsedVersion::parse(a)?;
    let b = ParsedVersion::parse(b)?;
    Ok(a.cmp(&b))
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedVersion {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<Vec<PrereleaseIdentifier>>,
}

impl ParsedVersion {
    fn parse(value: &str) -> Result<Self> {
        let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
        let (numbers, pre) = value
            .split_once('-')
            .map_or((value, None), |(left, right)| (left, Some(right)));
        let mut parts = numbers.split('.');
        let major = parse_version_part(parts.next(), value)?;
        let minor = parse_version_part(parts.next(), value)?;
        let patch = parse_version_part(parts.next(), value)?;
        if parts.next().is_some() {
            bail!("unsupported SemVer version: {value}");
        }
        Ok(Self {
            major,
            minor,
            patch,
            pre: pre.map(parse_prerelease).transpose()?,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PrereleaseIdentifier {
    Numeric(u64),
    Text(String),
}

impl Ord for PrereleaseIdentifier {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(left), Self::Numeric(right)) => left.cmp(right),
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for PrereleaseIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(left), Some(right)) => compare_prerelease(left, right),
            })
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_version_part(part: Option<&str>, original: &str) -> Result<u64> {
    part.ok_or_else(|| anyhow!("unsupported SemVer version: {original}"))?
        .parse::<u64>()
        .with_context(|| format!("unsupported SemVer version: {original}"))
}

fn parse_prerelease(value: &str) -> Result<Vec<PrereleaseIdentifier>> {
    if value.trim().is_empty() {
        bail!("unsupported SemVer prerelease: {value}");
    }
    value
        .split('.')
        .map(|part| {
            if part.is_empty() {
                bail!("unsupported SemVer prerelease: {value}");
            }
            if part.chars().all(|c| c.is_ascii_digit()) {
                if part.len() > 1 && part.starts_with('0') {
                    bail!("numeric SemVer prerelease identifiers must not contain leading zeroes");
                }
                return Ok(PrereleaseIdentifier::Numeric(part.parse::<u64>()?));
            }
            if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                bail!("unsupported SemVer prerelease: {value}");
            }
            Ok(PrereleaseIdentifier::Text(part.to_string()))
        })
        .collect()
}

fn compare_prerelease(left: &[PrereleaseIdentifier], right: &[PrereleaseIdentifier]) -> Ordering {
    for (left_item, right_item) in left.iter().zip(right.iter()) {
        let ordering = left_item.cmp(right_item);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env değiştiren testleri serileştir (process-global env yarışlarını önle).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn dev_image() -> Image {
        Image::from_os_release(Some("VARIANT=dev\nIMAGE_ROLE=suderra_qemu_x86_64\n"))
    }

    fn prod_image(role: &str) -> Image {
        Image::from_os_release(Some(&format!(
            "NAME=\"Suderra OS\"\nVARIANT=\"prod\"\nIMAGE_ROLE=\"{role}\"\n"
        )))
    }

    #[test]
    fn mark_good_completes_only_a_recorded_pending_ota() {
        let tmp = std::env::temp_dir().join(format!("suderra-ota-pending-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("state.json");
        assert_eq!(
            pending_version_in(&path).unwrap(),
            None,
            "no state: a normal boot"
        );
        let mut state = OtaState {
            schema_version: STATE_SCHEMA.to_string(),
            target: "x86_64".into(),
            current_version: "1.0.0".into(),
            rollback_floor: "1.0.0".into(),
            pending_version: None,
            pending_boot_slot: None,
            reboot_required: false,
            last_event: None,
            last_error: None,
        };
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(pending_version_in(&path).unwrap(), None, "nothing pending");
        state.pending_version = Some("1.1.0".into());
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(pending_version_in(&path).unwrap().as_deref(), Some("1.1.0"));
        state.schema_version = "suderra.ota-state.v0".into();
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(
            pending_version_in(&path).is_err(),
            "a foreign state is not read as nothing pending"
        );
        fs::write(&path, b"{").unwrap();
        assert!(
            pending_version_in(&path).is_err(),
            "corrupt state is an error"
        );
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn production_comes_from_the_image_and_fails_safe() {
        assert_eq!(dev_image().variant, Variant::Dev);
        for text in [
            Some("VARIANT=prod\n"),
            Some("VARIANT=lab\n"),
            Some("VARIANT=\n"),
            Some("ID=suderra-os\n"),
            None,
        ] {
            assert_eq!(
                Image::from_os_release(text).variant,
                Variant::Production,
                "{text:?}"
            );
        }
    }

    #[test]
    fn dev_override_ignored_in_production() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SUDERRA_OTA_NOW", "2000-01-01T00:00:00Z");
        std::env::set_var("SUDERRA_OTA_TARGET", "x86_64");
        let prod = prod_image("suderra_aarch64_revpi4_prod_ab");
        assert!(
            prod.dev_override("SUDERRA_OTA_NOW").is_none(),
            "prod'da test override yok sayılmalı"
        );
        assert_eq!(device_target_in(&prod).unwrap(), "revpi4-prod-ab");
        assert_eq!(
            dev_image().dev_override("SUDERRA_OTA_NOW").as_deref(),
            Some("2000-01-01T00:00:00Z"),
            "dev imajında override etkin olmalı"
        );
        std::env::remove_var("SUDERRA_OTA_NOW");
        std::env::remove_var("SUDERRA_OTA_TARGET");
    }

    #[test]
    fn the_target_comes_from_the_image_role_with_no_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        for (role, target) in OTA_TARGETS {
            assert_eq!(device_target_in(&prod_image(role)).unwrap(), target);
        }
        assert!(device_target_in(&prod_image("suderra_aarch64_revpi4")).is_err());
        assert!(device_target_in(&Image::from_os_release(Some("VARIANT=prod\n"))).is_err());
        assert!(device_target_in(&Image::from_os_release(None)).is_err());
    }

    #[test]
    fn ota_targets_match_post_image() {
        let script = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../board/suderra/common/post-image.sh"),
        )
        .unwrap();
        let mut found = Vec::new();
        for line in script.lines() {
            let line = line.trim();
            let Some((role, rest)) = line.split_once(") ota_target=\"") else {
                continue;
            };
            let target = rest.split('"').next().unwrap();
            found.push((role.to_string(), target.to_string()));
        }
        let ours: Vec<(String, String)> = OTA_TARGETS
            .iter()
            .map(|(r, t)| ((*r).to_string(), (*t).to_string()))
            .collect();
        assert_eq!(found, ours);
    }

    #[test]
    fn production_verifies_only_against_the_image_key() {
        let prod = prod_image("suderra_aarch64_revpi4_prod_ab");
        assert_eq!(
            manifest_key_path(&prod, None).unwrap(),
            PathBuf::from(MANIFEST_PUBKEY)
        );
        assert!(manifest_key_path(&prod, Some(Path::new("/tmp/attacker.pub"))).is_err());
        assert_eq!(
            manifest_key_path(&dev_image(), Some(Path::new("/tmp/dev.pub"))).unwrap(),
            PathBuf::from("/tmp/dev.pub")
        );
    }

    #[test]
    fn trusted_floor_read_and_validated() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dev = dev_image();
        let path = std::env::temp_dir().join(format!("suderra-ota-floor-{}", std::process::id()));
        std::fs::write(&path, "v2.3.4\n").unwrap();
        std::env::set_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE", "tpm-nv");
        std::env::set_var(
            "SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH",
            path.to_str().unwrap(),
        );
        assert_eq!(
            trusted_rollback_floor_in(&dev).unwrap().as_deref(),
            Some("v2.3.4")
        );
        assert!(
            trusted_rollback_floor_in(&prod_image("suderra_x86_64"))
                .unwrap()
                .is_none(),
            "prod'da floor kaynağı env'den okunmaz"
        );

        std::fs::write(&path, "not-a-version\n").unwrap();
        assert!(
            trusted_rollback_floor_in(&dev).is_err(),
            "geçersiz SemVer floor reddedilmeli"
        );
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE");
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH");
        std::fs::remove_file(&path).ok();
        assert!(trusted_rollback_floor_in(&dev).unwrap().is_none());
    }

    #[test]
    fn production_fails_closed_without_an_image_declared_floor_source() {
        let _guard = ENV_LOCK.lock().unwrap();
        let path = std::env::temp_dir().join(format!("suderra-ota-prod-{}", std::process::id()));
        std::fs::write(&path, "v9.9.9\n").unwrap();
        std::env::set_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE", "tpm-nv");
        std::env::set_var(
            "SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH",
            path.to_str().unwrap(),
        );
        let err = production_rollback_floor_requires_monotonic_state_in(&prod_image(
            "suderra_aarch64_revpi4_prod_ab",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("declared by the image"), "{err}");
        assert!(production_rollback_floor_requires_monotonic_state_in(&dev_image()).is_ok());
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE");
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn version_order_handles_prerelease_floor() {
        assert_eq!(
            compare_versions("v1.0.0", "v1.0.0-rc.1").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("v1.0.0-alpha.2", "v1.0.0-alpha.10").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("v1.2.0", "v1.1.9").unwrap(),
            Ordering::Greater
        );
    }

    #[test]
    fn unsigned_manifest_bytes_exclude_signature() {
        let manifest = SignedManifest {
            schema_version: MANIFEST_SCHEMA.to_string(),
            version: "v1.2.3".to_string(),
            target: "x86_64".to_string(),
            artifact_sha256: "a".repeat(64),
            bundle: BundleRef {
                name: "update.raucb".to_string(),
                sha256: "a".repeat(64),
                bytes: 1,
            },
            key_epoch: 1,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            min_current_version: "v1.0.0".to_string(),
            rollback_floor: "v1.0.0".to_string(),
            release_notes: None,
            signature: Some(ManifestSignature {
                algorithm: "ed25519-suderra-os-update-manifest-v1".to_string(),
                key_id: "test".to_string(),
                public_key_sha256: "b".repeat(64),
                signature_hex: "c".repeat(128),
            }),
        };
        let text = String::from_utf8(manifest_signing_bytes(&manifest).unwrap()).unwrap();
        assert!(!text.contains("signature_hex"));
        assert!(text.contains(MANIFEST_SCHEMA));
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-ota` owns production OS updates.
//!
//! It validates a signed OS update manifest, checks anti-rollback policy,
//! delegates bundle installation to RAUC, records typed JSON evidence, and
//! requests reboot only after the inactive slot install succeeds.

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

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
    /// Sync the TPM-NV-anchored anti-rollback floor into the runtime path (RT-6).
    Floor(FloorArgs),
}

#[derive(Args, Debug)]
struct FloorArgs {
    #[command(subcommand)]
    action: FloorAction,
}

#[derive(Subcommand, Debug)]
enum FloorAction {
    /// Read the TPM-NV monotonic counter, cross-check the image epoch, and write
    /// the trusted SemVer floor to the runtime path (fail-closed on downgrade).
    Sync,
}

#[derive(Args, Debug)]
struct InstallArgs {
    /// Signed OS update manifest JSON.
    manifest: PathBuf,
    /// RAUC bundle referenced by the manifest.
    bundle: PathBuf,
    /// Ed25519 public key used to verify the manifest signature.
    #[arg(long, env = "SUDERRA_OTA_MANIFEST_PUBKEY")]
    manifest_pubkey: Option<PathBuf>,
    /// Do not request reboot after a successful inactive-slot install.
    #[arg(long, env = "SUDERRA_OTA_NO_REBOOT", default_value_t = false)]
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
    #[arg(long, env = "SUDERRA_OTA_NO_REBOOT", default_value_t = false)]
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

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match run(cli.command) {
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

fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Install(args) => install(args),
        Commands::Status(args) => status(args),
        Commands::Rollback(args) => rollback(args),
        Commands::MarkGood(args) => mark_good(args),
        Commands::Floor(args) => match args.action {
            FloorAction::Sync => floor_sync(),
        },
    }
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
}

fn install(args: InstallArgs) -> Result<()> {
    let mut state = load_state()?;
    // C-7: cihazın kendi sürümü SemVer değilse her karşılaştırma derin policy
    // katmanında anlaşılmaz biçimde ölürdü — burada erken ve eyleme dönük teşhis.
    // (Kaynağında önleme: post-build.sh, SemVer-dışı SUDERRA_VERSION ile imaj
    // build'ini keser; bu dal yalnız bozuk/elle yazılmış state için kalır.)
    ParsedVersion::parse(&state.current_version).with_context(|| {
        format!(
            "device current_version '{}' is not SemVer (source: /etc/os-release VERSION_ID \
             or /data OTA state) — the image build violated the C-7 contract; \
             no update can be policy-checked until the image/state is fixed",
            state.current_version
        )
    })?;
    let manifest = load_manifest(&args.manifest)?;
    verify_manifest_signature(&manifest, args.manifest_pubkey.as_deref())?;
    verify_manifest_policy(&manifest, &state)?;
    verify_bundle(&manifest, &args.bundle)?;
    let staged_bundle = stage_bundle_for_install(&manifest, &args.bundle)?;

    info!(version = %manifest.version, target = %manifest.target, "installing RAUC bundle");
    let rauc_result =
        run_rauc(&["install", path_str(&staged_bundle)?]).context("rauc install failed");
    // Staging temizliği her iki sonuçta da best-effort (bundle tüketildi).
    let _ = fs::remove_file(&staged_bundle);
    if let Some(dir) = staged_bundle.parent() {
        let _ = fs::remove_dir(dir);
    }
    rauc_result?;
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

fn mark_good(args: MarkGoodArgs) -> Result<()> {
    let mut state = load_state()?;
    // mark-good YALNIZCA gerçekten pending (doğrulanmış install ile stage edilmiş)
    // bir sürümü onaylar. `--version` verildiyse pending ile ÖRTÜŞMELİDİR; aksi
    // halde pending olmayan keyfi bir sürüm current_version/rollback_floor'u
    // yükseltip cihazı bu değerin altındaki her meşru update'e karşı kalıcı olarak
    // kilitleyebilirdi (install olmadan tetiklenen DoS).
    let version = state
        .pending_version
        .clone()
        .ok_or_else(|| anyhow!("no pending version to mark good"))?;
    if let Some(requested) = args.version.as_deref() {
        if requested != version {
            bail!("mark-good version {requested} does not match pending version {version}");
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
    // RT-6: onaylanmış (mark-good) bir ileri-sürüm, donanım çıpasını (TPM-NV
    // monotonic counter) da ilerletir. YALNIZ başarı yolunda — başarısız bir
    // güncelleme sayacı yakmaz. Sayaç yalnız artar; sonraki bir downgrade denemesi
    // floor_sync tarafından (image epoch < nv) fail-closed yakalanır.
    if let Err(err) = advance_rollback_anchor() {
        // Çıpa ilerletme başarısızlığı mark-good'u geri almaz (boot zaten iyi);
        // ama görünür şekilde uyar — bir sonraki floor_sync tutarsızlığı yakalar.
        warn!(error = %err, "TPM-NV rollback çıpası ilerletilemedi (mark-good yine de geçerli)");
    }
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

fn verify_manifest_signature(manifest: &SignedManifest, key_path: Option<&Path>) -> Result<()> {
    let signature = manifest
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("OS update manifest must carry an Ed25519 signature"))?;
    // -v2: imza baytları sorted-key kanonik JSON'dur (suderra_config::canonical,
    // installer ile aynı form). -v1 (struct-alan-sıralı bayt) temiz kırılımla
    // kaldırıldı — sahada cihaz yok (production_ready:false), dual-accept ölü
    // güvenlik kodu olurdu. Eski manifest'ler burada teşhis edilebilir hatayla düşer.
    if signature.algorithm != "ed25519-suderra-os-update-manifest-v2" {
        bail!(
            "unsupported manifest signature algorithm: {} (expected ed25519-suderra-os-update-manifest-v2; \
             v1 manifests must be re-signed with scripts/create-os-update-manifest.py)",
            signature.algorithm
        );
    }
    if signature.key_id.trim().is_empty() {
        bail!("manifest signature key_id must be non-empty");
    }
    let key_path = key_path
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("SUDERRA_OTA_MANIFEST_PUBKEY")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("/etc/suderra/os-update-manifest.ed25519.pub"));
    let public_key = read_public_key(&key_path)?;
    let public_key_sha256 = hex::encode(Sha256::digest(public_key.as_bytes()));
    if signature.public_key_sha256 != public_key_sha256 {
        bail!("manifest public_key_sha256 does not match configured key");
    }
    let signature_bytes = decode_fixed_hex::<64>(&signature.signature_hex, "signature_hex")?;
    let signature = Signature::from_bytes(&signature_bytes);
    // `verify_strict`: non-canonical imza / karışık-sıra key reddedilir (malleability
    // kapatılır). Meşru imzalayıcı canonical imza ürettiğinden gerçek manifest'ler
    // etkilenmez.
    public_key
        .verify_strict(&manifest_signing_bytes(manifest)?, &signature)
        .context("manifest signature verification failed")?;
    Ok(())
}

/// İmza baytları: üst-düzey `signature` alanı düşülmüş, anahtarları sıralı kanonik
/// JSON (paylaşılan sözleşme — struct alan sırasına bağımlılık yok; Python
/// imzalayıcı `sort_keys=True` ile aynı baytları üretir, golden vektörlerle sınanır).
fn manifest_signing_bytes(manifest: &SignedManifest) -> Result<Vec<u8>> {
    suderra_config::canonical::canonical_without_signature(manifest)
        .context("cannot canonicalize unsigned manifest")
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
    let device_target = device_target();
    if manifest.target != device_target {
        bail!(
            "manifest target {} does not match device target {}",
            manifest.target,
            device_target
        );
    }
    // Anahtar epoch tabanı: env ile YÜKSELTİLEBİLİR ama prod'da 1'in altına
    // İNDİRİLEMEZ (saldırgan SUDERRA_OTA_MIN_KEY_EPOCH=0 ile revoke edilmiş
    // eski anahtarı geçemesin).
    let minimum_epoch = std::env::var("SUDERRA_OTA_MIN_KEY_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    let minimum_epoch = if is_production() {
        minimum_epoch.max(1)
    } else {
        minimum_epoch
    };
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

/// C-6 (verify→use TOCTOU): doğrulanmış bundle'ı 0700 izinli bir staging
/// dizinine ATOMİK `rename` ile alır (aynı dosya sistemi: bundle'ın kendi
/// dizini altı) ve staged dosyayı AÇIK fd üzerinden yeniden hash'ler; rauc'a
/// staged path verilir. Böylece hash ile rauc'un dosyayı açması arasındaki
/// path-tabanlı swap penceresi kapanır (ayrıcalıksız yazar staging'e erişemez).
/// Kalan risk dürüstçe: doğrulamadan ÖNCE elde tutulmuş bir yazma-fd'si aynı
/// inode'a hâlâ yazabilir — derinlemesine savunma olarak RAUC, bundle imzasını
/// keyring'e karşı bağımsız doğrular (verity bundle format).
fn stage_bundle_for_install(manifest: &SignedManifest, bundle: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let parent = match bundle.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let staging = parent.join(".suderra-ota-staging");
    fs::create_dir_all(&staging)
        .with_context(|| format!("cannot create staging dir: {}", staging.display()))?;
    let mut perms = fs::metadata(&staging)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&staging, perms)?;

    let staged = staging.join(&manifest.bundle.name);
    fs::rename(bundle, &staged).with_context(|| {
        format!(
            "cannot stage bundle {} -> {}",
            bundle.display(),
            staged.display()
        )
    })?;

    // Yeniden doğrulama AÇIK fd üzerinden — path bir daha çözülmez.
    let mut file = fs::File::open(&staged)
        .with_context(|| format!("cannot open staged bundle: {}", staged.display()))?;
    let meta = file.metadata()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).context("cannot hash staged bundle")?;
    let digest = hex::encode(hasher.finalize());
    if meta.len() != manifest.bundle.bytes || digest != manifest.bundle.sha256 {
        let _ = fs::remove_file(&staged);
        let _ = fs::remove_dir(&staging);
        bail!(
            "staged bundle failed re-verification (size {} vs {}, sha256 {} vs {})",
            meta.len(),
            manifest.bundle.bytes,
            digest,
            manifest.bundle.sha256
        );
    }
    Ok(staged)
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
    if std::env::var("SUDERRA_OTA_NO_REBOOT").ok().as_deref() == Some("1") {
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
            target: device_target(),
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

/// Cihazın gerçekten bir ÜRETİM cihazı olup olmadığı. GÜVEN KÖKÜ, dm-verity
/// altındaki imzalı, salt-okunur `/etc/os-release`'in `VARIANT`/`VARIANT_ID`
/// alanıdır — sözleşme `suderra_config::variant`'ta paylaşılır (ADR-0008 §1
/// çıkarması; installer aynı kökü kullanır). Bu bayrak `dev_override()`'ı
/// kapılar: gerçek prod cihazda hiçbir env güvenlik davranışını GEVŞETEMEZ.
///
/// Env `SUDERRA_OTA_PRODUCTION=1` yalnız sınıflandırmayı ÜRETİM yönünde
/// SIKILAŞTIRABİLİR (CI/dev'de prod davranışını zorlamak için); prod'u dev'e
/// çekemez. VARIANT hiç yoksa (Suderra olmayan host / CI) dev sayılır; gerçek
/// prod imajın `VARIANT=prod` taşıdığı `enforce_production_contract` build
/// kapısıyla garanti edilir (fail-open residual'ı build katmanında kapatır).
fn is_production() -> bool {
    if suderra_config::variant::os_release_is_prod() {
        return true;
    }
    std::env::var("SUDERRA_OTA_PRODUCTION").ok().as_deref() == Some("1")
}

/// Test/dev-only env override okuyucu. Prod'da `None` döner; böylece expiry,
/// slot ispatı, rauc/reboot binary'si, rollback floor gibi güvenlik davranışları
/// prod'da environment ile geçilemez.
fn dev_override(key: &str) -> Option<String> {
    if is_production() {
        None
    } else {
        std::env::var(key).ok()
    }
}

/// Prod'da anti-rollback floor'un okunacağı GÜVENİLİR kaynak yolu. Bu yol
/// yazılabilir state dizininin (`/data/...`) DIŞINDA olmalı ve platform (TPM NV
/// aynası veya bootloader monotonic counter) tarafından doldurulmalıdır. Değer
/// buradan okunur; yazılabilir `/data` üzerindeki floor dosyası prod'da yalnız
/// bir ayna/cache'tir, güven çıpası DEĞİLDİR.
fn trusted_floor_path() -> Option<PathBuf> {
    // RT-6: prod GÜVEN KÖKÜ imzalı `/etc/suderra/ota.conf`'tur; env yalnız
    // dev/CI override (prod'da `dev_override` None döner → env prod'da yol
    // beyan EDEMEZ, aksi halde saldırgan floor'u /tmp'ye yönlendirebilirdi).
    ota_conf_value("rollback_floor_path")
        .or_else(|| dev_override("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH"))
        .map(PathBuf::from)
}

/// İmzalı, dm-verity altındaki salt-okunur OTA config yolu. `SUDERRA_OTA_CONF`
/// yeniden konumlandırma/test seam'idir; gerçek prod imajda dosya sabittir.
fn ota_conf_path() -> PathBuf {
    std::env::var("SUDERRA_OTA_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/suderra/ota.conf"))
}

/// `/etc/suderra/ota.conf`'tan `key=value` okur (yorum `#`, tırnak soyulur).
fn ota_conf_value(key: &str) -> Option<String> {
    let content = fs::read_to_string(ota_conf_path()).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim().trim_matches('"').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Anti-rollback floor kaynağı: imzalı config (prod kök) VEYA dev env override.
fn rollback_floor_source() -> Option<String> {
    ota_conf_value("rollback_floor_source")
        .or_else(|| dev_override("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE"))
}

/// TPM-NV counter index'i (RT-6). Config'ten okunur; yoksa TCG owner-range
/// varsayılanı.
fn rollback_nv_index() -> u32 {
    ota_conf_value("rollback_nv_index")
        .and_then(|s| {
            let s = s.trim();
            let s = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            u32::from_str_radix(s, 16).ok()
        })
        .unwrap_or(0x0150_0001)
}

/// Bu imajın beyan ettiği anti-rollback epoch'u (config `rollback_epoch`).
/// Güvenlik-ilgili her sürümde artan ordinal; TPM-NV counter'ın SemVer floor'a
/// eşlemesidir (ADR-0009).
fn image_rollback_epoch() -> Option<u64> {
    ota_conf_value("rollback_epoch").and_then(|s| s.trim().parse::<u64>().ok())
}

/// RT-6 floor sync: TPM-NV monotonic counter'ı okur, imaj epoch'uyla çapraz
/// doğrular ve güvenilir SemVer floor'u runtime yoluna yazar. Downgrade
/// (imaj epoch'u < donanım counter'ı) fail-closed: floor YAZILMAZ → install
/// yolu #84 invariantıyla fail-closed olur.
fn floor_sync() -> Result<()> {
    // Yalnız TPM-NV kaynağı bu sync'e ihtiyaç duyar; diğer kaynaklar (bootloader
    // monotonic) çıpayı kendileri sağlar, Tier-1 (kaynak yok) no-op.
    match rollback_floor_source().as_deref() {
        Some("tpm-nv") => {}
        _ => {
            info!("rollback floor kaynağı tpm-nv değil; floor sync no-op");
            return Ok(());
        }
    }
    let floor = ota_conf_value("rollback_floor")
        .ok_or_else(|| anyhow!("ota.conf tpm-nv beyan ediyor ama rollback_floor yok"))?;
    ParsedVersion::parse(&floor)
        .with_context(|| format!("ota.conf rollback_floor '{floor}' geçerli SemVer değil"))?;
    let epoch = image_rollback_epoch()
        .ok_or_else(|| anyhow!("ota.conf tpm-nv beyan ediyor ama rollback_epoch yok"))?;
    let path = trusted_floor_path()
        .ok_or_else(|| anyhow!("ota.conf tpm-nv beyan ediyor ama rollback_floor_path yok"))?;

    let tpm = suderra_config::tpm::Tpm::new(is_production());
    let index = rollback_nv_index();
    let nv = tpm
        .nv_read_counter(index)
        .with_context(|| format!("TPM-NV rollback counter {index:#x} okunamadı (fail-closed)"))?;

    if epoch < nv {
        // Bu imaj, donanımın onayladığı nesilden ESKİ → downgrade. Floor yazma.
        bail!(
            "downgrade tespit edildi: imaj epoch {epoch} < TPM-NV counter {nv} — \
             güvenilir floor YAZILMADI, güncelleme yolu fail-closed olacak"
        );
    }

    // İmaj çıpa kadar veya daha ileri → güvenilir floor'u runtime yoluna yaz.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        writeln!(file, "{floor}")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    info!(floor = %floor, epoch, nv, "TPM-NV rollback floor senkronize edildi");
    Ok(())
}

/// mark-good başarısında donanım çıpasını (TPM-NV counter) imaj epoch'una kadar
/// ilerletir. Yalnız `tpm-nv` kaynağında ve counter < epoch iken artırır.
fn advance_rollback_anchor() -> Result<()> {
    if rollback_floor_source().as_deref() != Some("tpm-nv") {
        return Ok(());
    }
    let Some(epoch) = image_rollback_epoch() else {
        return Ok(());
    };
    let tpm = suderra_config::tpm::Tpm::new(is_production());
    let index = rollback_nv_index();
    let mut nv = tpm.nv_read_counter(index)?;
    // Sayaç yalnız artar; epoch'a ulaşana dek increment.
    while nv < epoch {
        tpm.nv_increment(index)?;
        nv = tpm.nv_read_counter(index)?;
    }
    Ok(())
}

/// Güvenilir kaynaktan floor değerini okur ve SemVer olarak doğrular. Kaynak yolu
/// yoksa `None`; ayarlı ama okunamıyorsa/boşsa/geçersizse hata (prod fail-closed).
fn trusted_rollback_floor() -> Result<Option<String>> {
    let Some(path) = trusted_floor_path() else {
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

/// Prod anti-rollback KATMANLI bir politikadır (ADR-0008):
///
/// - **Tier 2 (donanım-çıpalı, güçlü):** `SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE`
///   `tpm-nv`/`bootloader-monotonic` olarak BEYAN edilmişse KATI doğrulanır:
///   kaynak yolu zorunludur, yazılabilir state dizininin DIŞINDA yaşamalı ve
///   okunabilir+geçerli SemVer üretmelidir. Aksi halde fail-closed.
/// - **Tier 1 (userspace floor — bugünün dürüst durumu):** kaynak beyan
///   edilmemişse `/data` üzerindeki monotonik floor tek anti-rollback katmanıdır
///   (HW-5'te "userspace-only" olarak dokümante). Cihaz KİLİTLENMEZ; ama bu, bir
///   donanım çıpası olmadığını `degraded` seviyesinde AÇIKÇA sinyaller. Kritik
///   olan: bu cihazda `is_production()` true olduğundan `dev_override` KAPALIDIR
///   — yani floor env ile kurcalanamaz. Tier 2'ye geçiş G5 donanım kanıtıyla
///   `production_ready` flip'inde tamamlanır.
///
/// Bu ayrım, NEW-1'in kök nedenini kapatır: eskiden tek bir env bayrağı hem
/// dev-override reddini hem de TPM-NV zorunluluğunu birden kapılıyor ve hiçbir
/// cihazda set edilmediğinden ikisi de ölüydü.
fn production_rollback_floor_requires_monotonic_state() -> Result<()> {
    if !is_production() {
        return Ok(());
    }
    match rollback_floor_source().as_deref() {
        Some("tpm-nv") | Some("bootloader-monotonic") => {
            // Tier 2: kaynak beyan edildi → KATI doğrula. Floor'un GERÇEKTEN
            // okunacağı yol zorunlu ve yazılabilir state dizininin dışında olmalı;
            // yoksa "TPM-destekli" iddia teatral kalır (saldırgan /data'daki
            // dosyayı silip floor'u düşüremesin).
            let path = trusted_floor_path().ok_or_else(|| {
                anyhow!("declared monotonic rollback floor source requires SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH")
            })?;
            let sdir = state_dir();
            if path.starts_with(&sdir) {
                bail!(
                    "rollback floor source path {} must not live under the writable state dir {}",
                    path.display(),
                    sdir.display()
                );
            }
            trusted_rollback_floor()?.ok_or_else(|| {
                anyhow!("monotonic rollback floor source is configured but produced no value")
            })?;
            Ok(())
        }
        Some(other) => bail!(
            "SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE must be tpm-nv or bootloader-monotonic, got {other}"
        ),
        None => {
            // Tier 1: donanım çıpası beyan edilmemiş → userspace /data floor tek
            // katman. Kilitlemek yerine degraded-mode sinyali ver (sessiz değil).
            warn!(
                tier = "userspace-floor",
                "anti-rollback donanım çıpası (TPM-NV/bootloader) yapılandırılmamış; \
                 /data üzerindeki monotonik floor tek katman (HW-5, G5'te kapanır). \
                 dev_override bu cihazda kapalı olduğundan floor env ile kurcalanamaz."
            );
            Ok(())
        }
    }
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

fn device_target() -> String {
    std::env::var("SUDERRA_OTA_TARGET").unwrap_or_else(|_| "x86_64".to_string())
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
        "target": device_target(),
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
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex;

    // Env değiştiren testleri serileştir (process-global env yarışlarını önle).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn fake_tpm2(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh\n{body}").unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }

    #[test]
    fn floor_sync_writes_floor_and_rejects_downgrade() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("suderra-floor-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bindir = dir.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let floor_path = dir.join("rollback-epoch");
        let conf = dir.join("ota.conf");

        // NV counter = 3 döndüren sahte tpm2_nvread (big-endian).
        fake_tpm2(
            &bindir,
            "tpm2_nvread",
            "printf '\\000\\000\\000\\000\\000\\000\\000\\003'",
        );
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", &bindir);

        // İmaj epoch 5 (>= 3) → floor yazılmalı.
        std::fs::write(
            &conf,
            "rollback_floor_source=tpm-nv\nrollback_epoch=5\n\
             rollback_floor=v1.2.0\nrollback_floor_path="
                .to_string()
                + floor_path.to_str().unwrap()
                + "\n",
        )
        .unwrap();
        std::env::set_var("SUDERRA_OTA_CONF", &conf);

        floor_sync().expect("epoch >= nv → floor yazılmalı");
        assert_eq!(
            std::fs::read_to_string(&floor_path).unwrap().trim(),
            "v1.2.0"
        );

        // İmaj epoch 2 (< 3) → downgrade → fail-closed, floor DEĞİŞMEMELİ.
        std::fs::remove_file(&floor_path).ok();
        std::fs::write(
            &conf,
            "rollback_floor_source=tpm-nv\nrollback_epoch=2\n\
             rollback_floor=v0.9.0\nrollback_floor_path="
                .to_string()
                + floor_path.to_str().unwrap()
                + "\n",
        )
        .unwrap();
        let err = floor_sync().unwrap_err();
        assert!(err.to_string().contains("downgrade"), "{err}");
        assert!(!floor_path.exists(), "downgrade'de floor yazılmamalı");

        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
        std::env::remove_var("SUDERRA_OTA_CONF");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dev_override_ignored_in_production() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SUDERRA_OTA_PRODUCTION", "1");
        std::env::set_var("SUDERRA_OTA_NOW", "2000-01-01T00:00:00Z");
        assert!(
            dev_override("SUDERRA_OTA_NOW").is_none(),
            "prod'da test override yok sayılmalı"
        );
        std::env::remove_var("SUDERRA_OTA_PRODUCTION");
        assert_eq!(
            dev_override("SUDERRA_OTA_NOW").as_deref(),
            Some("2000-01-01T00:00:00Z"),
            "non-prod'da override etkin olmalı"
        );
        std::env::remove_var("SUDERRA_OTA_NOW");
    }

    #[test]
    fn trusted_floor_read_and_validated() {
        let _guard = ENV_LOCK.lock().unwrap();
        let path = std::env::temp_dir().join(format!("suderra-ota-floor-{}", std::process::id()));
        std::fs::write(&path, "v2.3.4\n").unwrap();
        std::env::set_var(
            "SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH",
            path.to_str().unwrap(),
        );
        assert_eq!(trusted_rollback_floor().unwrap().as_deref(), Some("v2.3.4"));

        std::fs::write(&path, "not-a-version\n").unwrap();
        assert!(
            trusted_rollback_floor().is_err(),
            "geçersiz SemVer floor reddedilmeli"
        );
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH");
        std::fs::remove_file(&path).ok();
        assert!(trusted_rollback_floor().unwrap().is_none());
    }

    /// Test için geçici imzalı-config vekili yazar ve `SUDERRA_OTA_CONF`'a bağlar.
    /// (RT-6: prod'da kaynak beyanı env'den değil imzalı config'ten gelir.)
    fn write_ota_conf(lines: &[&str]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "suderra-ota-conf-{}-{}",
            std::process::id(),
            lines.len()
        ));
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        std::env::set_var("SUDERRA_OTA_CONF", &path);
        path
    }

    #[test]
    fn production_gate_rejects_writable_floor_source() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SUDERRA_OTA_PRODUCTION", "1");
        // Kaynak imzalı config'ten beyan edilir; floor yolu yazılabilir state
        // dizininin altında → reddedilmeli.
        let inside = state_dir().join("rollback-floor");
        let conf = write_ota_conf(&[
            "rollback_floor_source=tpm-nv",
            &format!("rollback_floor_path={}", inside.to_str().unwrap()),
        ]);
        assert!(
            production_rollback_floor_requires_monotonic_state().is_err(),
            "yazılabilir state dizinindeki floor kaynağı prod'da reddedilmeli"
        );
        std::env::remove_var("SUDERRA_OTA_PRODUCTION");
        std::env::remove_var("SUDERRA_OTA_CONF");
        std::fs::remove_file(&conf).ok();
    }

    #[test]
    fn tier1_userspace_floor_does_not_brick_prod() {
        // Prod cihaz + donanım çıpası BEYAN EDİLMEMİŞ → Tier 1: gate kilitlemez
        // (Ok), userspace /data floor tek katman olarak enforce edilmeye devam eder.
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SUDERRA_OTA_PRODUCTION", "1");
        std::env::remove_var("SUDERRA_OTA_CONF");
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE");
        std::env::remove_var("SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE_PATH");
        assert!(
            production_rollback_floor_requires_monotonic_state().is_ok(),
            "kaynak beyan edilmediğinde prod OTA kilitlenmemeli (Tier 1)"
        );
        // Beyan edilen ama geçersiz bir kaynak tipi ise fail-closed.
        let conf = write_ota_conf(&["rollback_floor_source=file"]);
        assert!(
            production_rollback_floor_requires_monotonic_state().is_err(),
            "geçersiz kaynak tipi reddedilmeli"
        );
        std::env::remove_var("SUDERRA_OTA_PRODUCTION");
        std::env::remove_var("SUDERRA_OTA_CONF");
        std::fs::remove_file(&conf).ok();
    }

    #[test]
    fn variant_classification_matches_installer_contract() {
        // Sözleşme artık paylaşılan modülde — burada yalnız aynı kökü
        // kullandığımızı sabitleyen bir duman testi kalır.
        use suderra_config::variant::value_is_prod;
        assert!(value_is_prod("prod-eu"));
        assert!(!value_is_prod("preprod"));
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
                algorithm: "ed25519-suderra-os-update-manifest-v2".to_string(),
                key_id: "test".to_string(),
                public_key_sha256: "b".repeat(64),
                signature_hex: "c".repeat(128),
            }),
        };
        let text = String::from_utf8(manifest_signing_bytes(&manifest).unwrap()).unwrap();
        assert!(!text.contains("signature_hex"));
        assert!(text.contains(MANIFEST_SCHEMA));
        // -v2 sözleşmesi: imza baytları anahtar-sıralıdır; struct alan sırası
        // (schema_version, version, target, artifact_sha256, ...) DEĞİL.
        let artifact_pos = text.find("artifact_sha256").unwrap();
        let version_pos = text.find("\"version\"").unwrap();
        assert!(
            artifact_pos < version_pos,
            "kanonik form anahtar-sıralı olmalı: {text}"
        );
    }

    /// Diller-arası uçtan uca kanıt: `scripts/create-os-update-manifest.py` ile
    /// imzalanmış committed fixture, Rust doğrulayıcıdan geçmeli.
    /// (Fixture'ı yeniden üretmek için: tests/ota/fixtures/signed-manifest/README.md)
    #[test]
    fn python_signed_fixture_verifies_in_rust() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/ota/fixtures/signed-manifest");
        let manifest_path = dir.join("manifest.json");
        let manifest = load_manifest(&manifest_path).expect("fixture manifest parse edilmeli");
        verify_manifest_signature(&manifest, Some(&dir.join("test-key.ed25519.pub")))
            .expect("Python imzalı fixture Rust'ta doğrulanmalı");
    }
}

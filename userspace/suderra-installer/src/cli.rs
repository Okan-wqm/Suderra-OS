// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI argümanları — clap derive ile yapılandırılmış.

use clap::{Parser, Subcommand};

/// Suderra OS root installer.
#[derive(Parser, Debug)]
#[command(
    name = "suderra-installer",
    version,
    about,
    long_about = "Suderra OS root installer (ADR-048): the single delivery channel of the\n\
                  edge agent, its signed site configuration and the device lifecycle.\n\n\
                  Every input is a signed statement of the Suderra edge contract,\n\
                  verified against keys pinned in the verity rootfs."
)]
pub struct Cli {
    /// Detailed log (DEBUG level)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Commands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Edge agent delivery: request, provision, install, verify-current.
    Edge(EdgeArgs),
    /// Root-owned device lifecycle.
    Lifecycle(LifecycleArgs),
    /// OS and agent health predicate of the health gate.
    Health(HealthArgs),
    /// Firewall mode selection.
    Policy(PolicyArgs),
    /// Typed result documents for root helper scripts.
    Result(ResultArgs),
    /// Verify and sign universal USB installer payload indexes.
    UsbPayload(UsbPayloadArgs),
    /// Paket kur (latest veya belirli sürüm) — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    Install(InstallArgs),
    /// Paketi en son sürüme yükselt — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    Upgrade(UpgradeArgs),
    /// Paketi önceki sürüme döndür — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    Rollback(RollbackArgs),
    /// Paketleri listele — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    List(ListArgs),
    /// Paket durumu — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    Status(StatusArgs),
    /// Paketi kaldır — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    Remove(RemoveArgs),
    /// Validate a release package manifest — dev-only package path.
    #[cfg(any(test, feature = "package-commands"))]
    ValidateManifest(ValidateManifestArgs),
}

/// `edge <command>`
#[derive(clap::Args, Debug)]
pub struct EdgeArgs {
    /// Edge operation.
    #[command(subcommand)]
    pub command: EdgeCommand,
}

/// Edge agent delivery operations (ADR-048 DEC-1, DEC-5).
#[derive(Subcommand, Debug)]
pub enum EdgeCommand {
    /// Issue a provisioning request (binding, fresh nonce, board, OS
    /// version, agent ABI) into /run/suderra-os and print its nonce.
    Request,
    /// Fetch, verify and install this device's provisioning delivery.
    Provision(EdgeProvisionArgs),
    /// Verify and install a delivery and artifact already on disk.
    Install(EdgeInstallArgs),
    /// Re-verify the installed release before an agent start.
    VerifyCurrent,
}

/// `edge provision`
#[derive(clap::Args, Debug)]
pub struct EdgeProvisionArgs {
    /// Device code of GET /install/{device_code}/suderra-os.
    #[arg(long)]
    pub device_code: String,
    /// Root-only file holding the provisioning token (sent only in the
    /// X-Provisioning-Token header).
    #[arg(long, value_name = "FILE")]
    pub token_file: std::path::PathBuf,
}

/// `edge install`
#[derive(clap::Args, Debug)]
pub struct EdgeInstallArgs {
    /// Delivery document (suderra.edge-provisioning-delivery.v1).
    #[arg(long, value_name = "FILE")]
    pub delivery: std::path::PathBuf,
    /// Release artifact the delivery's release statement names. The
    /// delivery must echo the nonce of the request `edge request` issued.
    #[arg(long, value_name = "FILE")]
    pub artifact: std::path::PathBuf,
}

/// `lifecycle <command>`
#[derive(clap::Args, Debug)]
pub struct LifecycleArgs {
    /// Lifecycle operation.
    #[command(subcommand)]
    pub command: LifecycleCommand,
}

/// Lifecycle operations (ADR-048 DEC-12).
#[derive(Subcommand, Debug)]
pub enum LifecycleCommand {
    /// Print the lifecycle state in force now (LOCKED when unknown; ACTIVE
    /// once a MAINTENANCE window has ended).
    Status,
    /// Create the store as FACTORY on the boot that formatted /data
    /// (suderra-data-unlock; needs /run/suderra-os/data-created).
    Factory,
    /// Boot-time and periodic evaluation: record FACTORY -> PROVISIONING
    /// and the end of a MAINTENANCE window, and mirror the state to
    /// /run/suderra/lifecycle.
    Init,
    /// Verify the agent's activation receipt and record ACTIVE.
    Activate,
    /// Verify the agent's device-lifecycle request and transition.
    Request,
}

/// `health check|preflight`
#[derive(clap::Args, Debug)]
pub struct HealthArgs {
    /// Health operation.
    #[command(subcommand)]
    pub command: HealthCommand,
}

/// Health operations (ADR-048 DEC-6.8).
#[derive(Subcommand, Debug)]
pub enum HealthCommand {
    /// Evaluate the OS and agent predicate and write a health-gate result.
    Check,
    /// Record the agent's health before an OS update
    /// (/data/rauc/pre-update.json; suderra-ota install runs it).
    Preflight,
}

/// `policy apply`
#[derive(clap::Args, Debug)]
pub struct PolicyArgs {
    /// Policy operation.
    #[command(subcommand)]
    pub command: PolicyCommand,
}

/// Firewall policy operations (ADR-048 DEC-11).
#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Load the ruleset the lifecycle selects.
    Apply,
    /// Exit 0 only when the loaded ruleset is the one `apply` checked and
    /// recorded this boot.
    Verify,
}

/// `result write`
#[derive(clap::Args, Debug)]
pub struct ResultArgs {
    /// Result operation.
    #[command(subcommand)]
    pub command: ResultCommand,
}

/// Result operations (ADR-048 DEC-27).
#[derive(Subcommand, Debug)]
pub enum ResultCommand {
    /// Write one typed result (lockdown, data-unlock, time-state helpers).
    Write(ResultWriteArgs),
}

/// `result write`
#[derive(clap::Args, Debug)]
pub struct ResultWriteArgs {
    /// Result kind (result.schema.json `kind`).
    #[arg(long)]
    pub kind: String,
    /// Outcome: ok, rejected, failed or alarm.
    #[arg(long)]
    pub outcome: String,
    /// Reason code; required unless the outcome is ok.
    #[arg(long)]
    pub reason: Option<String>,
    /// Operator detail (at most 512 characters).
    #[arg(long)]
    pub detail: Option<String>,
}

#[cfg(any(test, feature = "package-commands"))]
/// `validate-manifest`
#[derive(clap::Args, Debug)]
pub struct ValidateManifestArgs {
    /// Release manifest JSON file.
    #[arg(value_name = "FILE")]
    pub manifest: std::path::PathBuf,
}

/// `usb-payload <command>`
#[derive(clap::Args, Debug)]
pub struct UsbPayloadArgs {
    /// USB payload operation.
    #[command(subcommand)]
    pub command: UsbPayloadCommand,
}

/// USB payload manifest operations.
#[derive(Subcommand, Debug)]
pub enum UsbPayloadCommand {
    /// Verify a signed payload index and write a shell-safe install plan.
    Verify(UsbPayloadVerifyArgs),
    /// Sign a JSON payload index with an Ed25519 private key through OpenSSL.
    Sign(UsbPayloadSignArgs),
}

/// `usb-payload verify`
#[derive(clap::Args, Debug)]
pub struct UsbPayloadVerifyArgs {
    /// Directory containing manifest.json, manifest.sig and payload images.
    #[arg(long, value_name = "DIR")]
    pub payload_dir: std::path::PathBuf,

    /// Ed25519 public key, either raw hex or PEM SubjectPublicKeyInfo.
    #[arg(long, value_name = "FILE")]
    pub public_key: std::path::PathBuf,

    /// Board family to install, for example rpi4-cm4 or revpi4.
    #[arg(long)]
    pub target_board: String,

    /// Expected payload architecture, for example aarch64.
    #[arg(long)]
    pub target_arch: String,

    /// Minimum accepted signing key epoch for this payload index.
    #[arg(long, default_value_t = 1)]
    pub min_key_epoch: u32,

    /// Minimum rollback floor this payload must preserve.
    #[arg(long, default_value = "v0.1.0-alpha")]
    pub min_rollback_floor: String,

    /// Write validated payload metadata as a shell-safe environment file.
    #[arg(long, value_name = "FILE")]
    pub write_plan: Option<std::path::PathBuf>,
}

/// `usb-payload sign`
#[derive(clap::Args, Debug)]
pub struct UsbPayloadSignArgs {
    /// JSON manifest to canonicalize and sign.
    #[arg(long, value_name = "FILE")]
    pub manifest: std::path::PathBuf,

    /// Ed25519 private key in OpenSSL PEM format.
    #[arg(long, value_name = "FILE")]
    pub private_key: std::path::PathBuf,

    /// Destination detached signature file.
    #[arg(long, value_name = "FILE")]
    pub signature: std::path::PathBuf,
}

#[cfg(any(test, feature = "package-commands"))]
/// `install <package>`
#[derive(clap::Args, Debug)]
pub struct InstallArgs {
    /// Paket adı (`edge` veya `edge-plugin-*`)
    pub package: String,

    /// Belirli sürüm (default: latest)
    #[arg(long, short = 'V')]
    pub version: Option<String>,

    /// Cosign signature doğrulama (default: aktif)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub verify_signature: bool,

    /// Yerel dosyadan kur (air-gapped / offline)
    #[arg(long, value_name = "FILE")]
    pub from_file: Option<std::path::PathBuf>,

    /// Yerel signature dosyası (--from-file ile birlikte)
    #[arg(long, value_name = "SIG", requires = "from_file")]
    pub signature: Option<std::path::PathBuf>,

    /// Yerel cosign certificate dosyası (--from-file ile birlikte)
    #[arg(long, value_name = "CERT", requires = "from_file")]
    pub certificate: Option<std::path::PathBuf>,

    /// Onay sorusunu atla (CI / scripting)
    #[arg(long, short)]
    pub yes: bool,

    /// Mirror tercihi — default: github (otomatik fallback suderra.com'a)
    #[arg(long, value_enum, default_value_t = sources::Mirror::Github)]
    pub mirror: sources::Mirror,

    /// Kurulum sonrası servisi başlat (default: aktif)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub start_service: bool,
}

#[cfg(any(test, feature = "package-commands"))]
/// `upgrade <package>`
#[derive(clap::Args, Debug)]
pub struct UpgradeArgs {
    /// Paket adı
    pub package: String,

    /// Onay sorusunu atla
    #[arg(long, short)]
    pub yes: bool,

    /// Cosign signature doğrulama (default: aktif)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub verify_signature: bool,
}

#[cfg(any(test, feature = "package-commands"))]
/// `rollback <package>`
#[derive(clap::Args, Debug)]
pub struct RollbackArgs {
    /// Paket adı
    pub package: String,

    /// Belirli sürüme rollback (default: önceki kurulu sürüm)
    #[arg(long, short = 'V')]
    pub to_version: Option<String>,

    /// Onay sorusunu atla
    #[arg(long, short)]
    pub yes: bool,
}

#[cfg(any(test, feature = "package-commands"))]
/// `list <package>` veya `list`
#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Paket adı (boş bırakılırsa: bilinen tüm paketler)
    pub package: Option<String>,

    /// Mevcut sürümleri remote'tan listele (kurulu olanlar değil)
    #[arg(long)]
    pub available: bool,

    /// Mirror tercihi
    #[arg(long, value_enum, default_value_t = sources::Mirror::Github)]
    pub mirror: sources::Mirror,

    /// JSON çıktısı
    #[arg(long)]
    pub json: bool,
}

#[cfg(any(test, feature = "package-commands"))]
/// `status [<package>]`
#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// Paket adı (boş: tüm paketler)
    pub package: Option<String>,

    /// JSON çıktısı (scripting için)
    #[arg(long)]
    pub json: bool,
}

#[cfg(any(test, feature = "package-commands"))]
/// `remove <package>`
#[derive(clap::Args, Debug)]
pub struct RemoveArgs {
    /// Paket adı
    pub package: String,

    /// Konfigürasyonu da sil (default: koru — re-install için)
    #[arg(long)]
    pub purge: bool,

    /// Onay sorusunu atla
    #[arg(long, short)]
    pub yes: bool,
}

#[cfg(any(test, feature = "package-commands"))]
use crate::sources;

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI argümanları — clap derive ile yapılandırılmış.

use clap::{Parser, Subcommand};

/// Suderra OS paket yükleyici.
#[derive(Parser, Debug)]
#[command(
    name = "suderra-installer",
    version,
    about,
    long_about = "Suderra OS paket yükleyici — Ubuntu apt benzeri bir arayüzle\n\
                  Edge Agent ve plugin'lerin indirilmesi, doğrulanması ve\n\
                  kurulması.\n\n\
                  Tüm paketler imzalıdır (cosign keyless via Sigstore).\n\
                  Her kurulum /var/log/suderra/installer.log'a yazılır."
)]
pub struct Cli {
    /// Detaylı log (DEBUG level)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Kullanılabilir komutlar
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Paket kur (latest veya belirli sürüm)
    Install(InstallArgs),
    /// Paketi en son sürüme yükselt
    Upgrade(UpgradeArgs),
    /// Paketi önceki sürüme döndür
    Rollback(RollbackArgs),
    /// Paketleri listele (kurulu veya available)
    List(ListArgs),
    /// Paket durumu
    Status(StatusArgs),
    /// Paketi kaldır
    Remove(RemoveArgs),
    /// Verify and sign universal USB installer payload indexes.
    UsbPayload(UsbPayloadArgs),
    /// Verify signed Edge provisioning manifests and artifacts.
    EdgeManifest(EdgeManifestArgs),
    /// Validate a release package manifest against the Rust schema.
    ValidateManifest(ValidateManifestArgs),
}

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

/// `edge-manifest <command>`
#[derive(clap::Args, Debug)]
pub struct EdgeManifestArgs {
    /// Edge provisioning manifest operation.
    #[command(subcommand)]
    pub command: EdgeManifestCommand,
}

/// Edge provisioning manifest operations.
#[derive(Subcommand, Debug)]
pub enum EdgeManifestCommand {
    /// Verify a signed manifest and write a shell-safe download/install plan.
    Plan(EdgeManifestPlanArgs),
    /// Verify a downloaded artifact against the signed manifest.
    VerifyArtifact(EdgeManifestVerifyArtifactArgs),
}

/// `edge-manifest plan`
#[derive(clap::Args, Debug)]
pub struct EdgeManifestPlanArgs {
    /// Signed edge provisioning manifest JSON.
    #[arg(long, value_name = "FILE")]
    pub manifest: std::path::PathBuf,

    /// Ed25519 public key, either raw hex or PEM SubjectPublicKeyInfo.
    #[arg(long, value_name = "FILE")]
    pub public_key: std::path::PathBuf,

    /// Expected board family, for example rpi4-cm4 or revpi4.
    #[arg(long)]
    pub board: Option<String>,

    /// Expected artifact architecture, for example aarch64.
    #[arg(long)]
    pub arch: Option<String>,

    /// Minimum accepted signing key epoch for this provisioning manifest.
    #[arg(long, default_value_t = 1)]
    pub min_key_epoch: u32,

    /// Minimum rollback floor this provisioning manifest must preserve.
    #[arg(long, default_value = "v0.1.0-alpha")]
    pub min_rollback_floor: String,

    /// Write validated manifest fields as a shell-safe environment file.
    #[arg(long, value_name = "FILE")]
    pub write_plan: Option<std::path::PathBuf>,

    /// Write manifest config payload to this path after digest verification.
    #[arg(long, value_name = "FILE")]
    pub config_output: Option<std::path::PathBuf>,
}

/// `edge-manifest verify-artifact`
#[derive(clap::Args, Debug)]
pub struct EdgeManifestVerifyArtifactArgs {
    /// Signed edge provisioning manifest JSON.
    #[arg(long, value_name = "FILE")]
    pub manifest: std::path::PathBuf,

    /// Ed25519 public key, either raw hex or PEM SubjectPublicKeyInfo.
    #[arg(long, value_name = "FILE")]
    pub public_key: std::path::PathBuf,

    /// Downloaded artifact file to verify.
    #[arg(long, value_name = "FILE")]
    pub artifact: std::path::PathBuf,

    /// Expected board family, for example rpi4-cm4 or revpi4.
    #[arg(long)]
    pub board: Option<String>,

    /// Expected artifact architecture, for example aarch64.
    #[arg(long)]
    pub arch: Option<String>,

    /// Minimum accepted signing key epoch for this provisioning manifest.
    #[arg(long, default_value_t = 1)]
    pub min_key_epoch: u32,

    /// Minimum rollback floor this provisioning manifest must preserve.
    #[arg(long, default_value = "v0.1.0-alpha")]
    pub min_rollback_floor: String,
}

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

/// `status [<package>]`
#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// Paket adı (boş: tüm paketler)
    pub package: Option<String>,

    /// JSON çıktısı (scripting için)
    #[arg(long)]
    pub json: bool,
}

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

use crate::sources;

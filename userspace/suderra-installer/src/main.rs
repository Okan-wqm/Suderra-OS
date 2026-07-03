// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer` — Suderra OS paket yükleyici (Ubuntu apt-like UX).
//!
//! Sistem boot ettikten sonra Edge Agent ve diğer Suderra paketleri bu binary
//! ile kurulur. OS minimal kalır, Edge Agent ayrı bir release artifact'i
//! olarak indirilir + doğrulanır + kurulur.
//!
//! Komutlar:
//!   - `install <package>`      Paket kur (latest veya --version)
//!   - `upgrade <package>`      En son sürüme yükselt
//!   - `rollback <package>`     Önceki sürüme geri dön
//!   - `list <package>`         Mevcut sürümleri listele (--available ile remote)
//!   - `status [<package>]`     Kurulu paket durumu
//!   - `remove <package>`       Paketi kaldır
//!
//! Desteklenen paketler:
//!   - `edge`         Suderra Edge Agent (RAUC bundle)
//!   - `edge-plugin-<name>`  Edge Agent eklentileri (Faz 3+)
//!
//! Güvenlik:
//!   - SHA256 + cosign keyless (Sigstore) ile imza doğrulaması
//!   - Audit log (/var/log/suderra/installer.log)
//!   - Bundle integrity yalnızca `--verify=skip` ile devre dışı (NEVER in prod)
//!
//! Örnek:
//!   sudo suderra-installer install edge
//!   sudo suderra-installer install edge --version 1.6.0 --verify-signature
//!   sudo suderra-installer rollback edge

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod audit;
mod cli;
mod cmd;
mod contracts;
mod download;
mod manifest;
mod sources;
mod variant;
mod verify;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use tracing::error;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!("hata: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Logging — INFO default, --verbose ile DEBUG
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .compact()
        .init();

    audit::init()?;

    match cli.command {
        Commands::Install(args) => cmd::install::run(args).await,
        Commands::Upgrade(args) => cmd::upgrade::run(args).await,
        Commands::Rollback(args) => cmd::rollback::run(args).await,
        Commands::List(args) => cmd::list::run(args).await,
        Commands::Status(args) => cmd::status::run(args).await,
        Commands::Remove(args) => cmd::remove::run(args).await,
        Commands::UsbPayload(args) => contracts::run_usb_payload(args),
        Commands::EdgeManifest(args) => contracts::run_edge_manifest(args),
        Commands::ValidateManifest(args) => {
            let json = std::fs::read_to_string(&args.manifest)?;
            let manifest = manifest::Manifest::from_json(&json)?;
            println!(
                "manifest {}: {} package(s)",
                manifest.version,
                manifest.packages.len()
            );
            Ok(())
        }
    }
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer` — Suderra OS root installer (ADR-048).
//!
//! The single delivery channel of the edge agent (`edge`), the root-owned
//! device lifecycle (`lifecycle`), the health predicate (`health`), the
//! firewall mode (`policy`) and typed results (`result`). Every input is a
//! DSSE statement of the Suderra edge contract verified against keys pinned
//! in the verity rootfs; production mode and every path are image facts,
//! never environment (DEC-19).
//!
//! The apt-like package commands (`install`, `upgrade`, `rollback`, `list`,
//! `status`, `remove`, `validate-manifest`; cosign keyless) are a dev-only
//! path compiled in only with the `package-commands` feature, which no image
//! build enables (DEC-2.2 path 5).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cli;
mod cmd;
mod contracts;
mod fsutil;
mod paths;
mod results;
mod state;
mod system;
mod trust_anchors;
mod usb_payload;
mod variant;

#[cfg(any(test, feature = "package-commands"))]
mod audit;
#[cfg(any(test, feature = "package-commands"))]
mod download;
#[cfg(any(test, feature = "package-commands"))]
mod manifest;
#[cfg(any(test, feature = "package-commands"))]
mod sources;
#[cfg(any(test, feature = "package-commands"))]
mod verify;

#[cfg(test)]
mod test_support;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use tracing::error;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .with_target(false)
        .compact()
        .init();

    match cli.command {
        Commands::Edge(args) => cmd::edge::run(args).await,
        Commands::Lifecycle(args) => cmd::lifecycle::run(args),
        Commands::Health(args) => cmd::health::run(args),
        Commands::Policy(args) => cmd::policy::run(args),
        Commands::Result(args) => cmd::result::run(args),
        Commands::UsbPayload(args) => usb_payload::run_usb_payload(args),
        #[cfg(any(test, feature = "package-commands"))]
        Commands::Install(args) => {
            audit::init()?;
            cmd::install::run(args).await
        }
        #[cfg(any(test, feature = "package-commands"))]
        Commands::Upgrade(args) => {
            audit::init()?;
            cmd::upgrade::run(args).await
        }
        #[cfg(any(test, feature = "package-commands"))]
        Commands::Rollback(args) => {
            audit::init()?;
            cmd::rollback::run(args).await
        }
        #[cfg(any(test, feature = "package-commands"))]
        Commands::List(args) => {
            audit::init()?;
            cmd::list::run(args).await
        }
        #[cfg(any(test, feature = "package-commands"))]
        Commands::Status(args) => {
            audit::init()?;
            cmd::status::run(args).await
        }
        #[cfg(any(test, feature = "package-commands"))]
        Commands::Remove(args) => {
            audit::init()?;
            cmd::remove::run(args).await
        }
        #[cfg(any(test, feature = "package-commands"))]
        Commands::ValidateManifest(args) => {
            audit::init()?;
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

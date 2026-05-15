// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `remove <package>` — paketi kaldır.

use crate::audit::{Event, EventKind, EventResult};
use crate::cli::RemoveArgs;
use crate::manifest::InstalledState;
use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

/// `remove` çalıştır
pub async fn run(args: RemoveArgs) -> Result<()> {
    info!("paket kaldırma: {}", args.package);

    let mut state = InstalledState::load().unwrap_or_default();
    if !state.installed.contains_key(&args.package) {
        println!("'{}' kurulu değil.", args.package);
        return Ok(());
    }

    if !args.yes {
        use dialoguer::Confirm;
        let prompt = if args.purge {
            format!("'{}' kaldırılsın MI (config dahil — purge)?", args.package)
        } else {
            format!("'{}' kaldırılsın MI (config korunur)?", args.package)
        };
        if !Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .unwrap_or(false)
        {
            info!("kaldırma iptal edildi");
            Event::new(EventKind::Remove, &args.package, EventResult::Aborted)
                .record()
                .ok();
            return Ok(());
        }
    }

    // Faz 2-D MVP: /opt/suderra/<package>/ dizinini sil
    let pkg_dir = PathBuf::from("/opt/suderra").join(&args.package);
    if pkg_dir.exists() {
        tokio::fs::remove_dir_all(&pkg_dir).await?;
        info!("silindi: {}", pkg_dir.display());
    }

    // Purge: config dahil
    if args.purge {
        let config_dir = PathBuf::from("/etc/suderra").join(&args.package);
        if config_dir.exists() {
            tokio::fs::remove_dir_all(&config_dir).await?;
            info!("config silindi: {}", config_dir.display());
        }
    }

    // TODO Faz 4: systemctl disable + stop

    state.record_remove(&args.package);
    state.save()?;

    Event::new(EventKind::Remove, &args.package, EventResult::Success)
        .with_meta("purge", args.purge)
        .record()
        .ok();

    println!("✓ {} kaldırıldı", args.package);
    Ok(())
}

// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `rollback <package>` — önceki sürüme geri dön.
//!
//! Şu an stub: previous_version mevcutsa o sürümü install eder.
//! Faz 4 RAUC integration ile A/B slot switch yapacak.

use crate::audit::{Event, EventKind, EventResult};
use crate::cli::RollbackArgs;
use crate::manifest::InstalledState;
use anyhow::{bail, Result};
use tracing::info;

/// `rollback` çalıştır
pub async fn run(args: RollbackArgs) -> Result<()> {
    info!("paket rollback: {}", args.package);

    let state = InstalledState::load().unwrap_or_default();
    let current = state.installed.get(&args.package).ok_or_else(|| {
        anyhow::anyhow!(
            "'{}' kurulu değil — rollback için önce bir sürüm kurmalısın",
            args.package
        )
    })?;

    let target_version = if let Some(v) = args.to_version {
        v
    } else {
        current.previous_version.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "'{}' için önceki sürüm kaydı yok — --to-version <ver> belirt",
                args.package
            )
        })?
    };

    println!();
    println!("ROLLBACK:");
    println!("  Paket:       {}", args.package);
    println!("  Şu anki:     {}", current.version);
    println!("  Hedef:       {target_version}");
    println!();

    if !args.yes {
        use dialoguer::Confirm;
        if !Confirm::new()
            .with_prompt("Rollback yapılsın mı?")
            .default(false)
            .interact()
            .unwrap_or(false)
        {
            info!("rollback iptal edildi");
            Event::new(EventKind::Rollback, &args.package, EventResult::Aborted)
                .with_meta("from", current.version.clone())
                .with_meta("to", target_version)
                .record()
                .ok();
            return Ok(());
        }
    }

    // Faz 2-D MVP: install komutu ile target_version yükle
    // Faz 4: RAUC mark-bad + reboot to previous slot

    bail!(
        "Rollback şu an placeholder — Faz 4 RAUC integration sonrası tam çalışır.\n\
         Şimdilik manuel: suderra-installer install {} --version {target_version}",
        args.package
    );
}

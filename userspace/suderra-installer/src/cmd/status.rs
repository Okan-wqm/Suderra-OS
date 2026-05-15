// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `status [<package>]` — kurulu paket durumu.

use crate::cli::StatusArgs;
use crate::manifest::InstalledState;
use anyhow::Result;

/// `status` çalıştır
pub async fn run(args: StatusArgs) -> Result<()> {
    let state = InstalledState::load().unwrap_or_default();

    if args.json {
        let filtered: serde_json::Value = if let Some(pkg) = &args.package {
            match state.installed.get(pkg) {
                Some(p) => serde_json::to_value(p)?,
                None => serde_json::Value::Null,
            }
        } else {
            serde_json::to_value(&state)?
        };
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    if state.installed.is_empty() {
        println!("Kurulu paket yok.");
        println!();
        println!("Bir paket kurmak için:");
        println!("  sudo suderra-installer install edge");
        return Ok(());
    }

    let filtered: Vec<_> = state
        .installed
        .iter()
        .filter(|(name, _)| {
            args.package
                .as_deref()
                .map(|p| p == name.as_str())
                .unwrap_or(true)
        })
        .collect();

    if filtered.is_empty() {
        if let Some(pkg) = &args.package {
            println!("'{pkg}' kurulu değil.");
            return Ok(());
        }
    }

    for (_, pkg) in filtered {
        println!("Paket:        {}", pkg.name);
        println!("  Sürüm:       {}", pkg.version);
        if let Some(prev) = &pkg.previous_version {
            println!("  Önceki:      {prev} (rollback hedefi)");
        }
        println!("  Kurulum:     {}", pkg.installed_at.to_rfc3339());
        println!(
            "  SHA256:      {}...",
            &pkg.sha256[..16.min(pkg.sha256.len())]
        );
        println!(
            "  İmza:        {}",
            if pkg.signature_verified {
                "✓ doğrulandı (cosign keyless)"
            } else {
                "✗ doğrulanmadı"
            }
        );
        println!();
    }

    Ok(())
}

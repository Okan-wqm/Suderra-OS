// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `list [<package>]` — kurulu veya mevcut paketleri listele.

use crate::cli::ListArgs;
use crate::download::fetch_text;
use crate::manifest::InstalledState;
use crate::sources::{Arch, Mirror, PackageRelease};
use anyhow::Result;
use serde::Serialize;
use tracing::info;

#[derive(Serialize)]
struct ListOutput {
    installed: Vec<InstalledRow>,
    available: Vec<AvailableRow>,
}

#[derive(Serialize)]
struct InstalledRow {
    package: String,
    version: String,
    installed_at: String,
    signature_verified: bool,
}

#[derive(Serialize)]
struct AvailableRow {
    package: String,
    version: String,
    published_at: String,
}

/// `list` komutu çalıştır
pub async fn run(args: ListArgs) -> Result<()> {
    let installed = list_installed(&args)?;
    let available = if args.available {
        list_available(&args).await?
    } else {
        vec![]
    };

    if args.json {
        let out = ListOutput {
            installed,
            available,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_human(&installed, &available);
    }
    Ok(())
}

fn list_installed(args: &ListArgs) -> Result<Vec<InstalledRow>> {
    let state = InstalledState::load().unwrap_or_default();
    let mut rows: Vec<InstalledRow> = state
        .installed
        .into_iter()
        .filter(|(name, _)| args.package.as_deref().map(|p| p == name).unwrap_or(true))
        .map(|(_, pkg)| InstalledRow {
            package: pkg.name,
            version: pkg.version,
            installed_at: pkg.installed_at.to_rfc3339(),
            signature_verified: pkg.signature_verified,
        })
        .collect();
    rows.sort_by(|a, b| a.package.cmp(&b.package));
    Ok(rows)
}

async fn list_available(args: &ListArgs) -> Result<Vec<AvailableRow>> {
    let pkg_name = args.package.clone().unwrap_or_else(|| "edge".to_string());
    info!("mevcut sürümler indiriliyor: {pkg_name}");

    let release = PackageRelease {
        package: pkg_name.clone(),
        version: "latest".into(),
        arch: Arch::detect(),
    };

    match args.mirror {
        Mirror::Github | Mirror::Auto => fetch_available_from_github(&release).await,
        Mirror::Suderra => fetch_available_from_suderra(&release).await,
    }
}

async fn fetch_available_from_github(release: &PackageRelease) -> Result<Vec<AvailableRow>> {
    let url = "https://api.github.com/repos/Okan-wqm/Suderra-OS/releases";
    let json = fetch_text(url).await?;
    let releases: Vec<serde_json::Value> = serde_json::from_str(&json)?;
    let mut rows = vec![];
    for r in releases {
        let tag = r.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
        let published = r.get("published_at").and_then(|v| v.as_str()).unwrap_or("");
        rows.push(AvailableRow {
            package: release.package.clone(),
            version: tag.to_string(),
            published_at: published.to_string(),
        });
    }
    Ok(rows)
}

async fn fetch_available_from_suderra(release: &PackageRelease) -> Result<Vec<AvailableRow>> {
    let url = release.versions_url(Mirror::Suderra);
    let json = fetch_text(&url).await?;
    let versions: Vec<serde_json::Value> = serde_json::from_str(&json)?;
    let mut rows = vec![];
    for v in versions {
        let version = v
            .get("version")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let date = v
            .get("released_at")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        rows.push(AvailableRow {
            package: release.package.clone(),
            version,
            published_at: date,
        });
    }
    Ok(rows)
}

fn print_human(installed: &[InstalledRow], available: &[AvailableRow]) {
    if !installed.is_empty() {
        println!("KURULU PAKETLER:");
        println!("  {:<20} {:<15} {:<25} SIG", "Paket", "Sürüm", "Kurulum");
        for r in installed {
            let sig = if r.signature_verified { "✓" } else { "✗" };
            println!(
                "  {:<20} {:<15} {:<25} {}",
                r.package,
                r.version,
                &r.installed_at[..19.min(r.installed_at.len())],
                sig
            );
        }
        println!();
    } else {
        println!("Kurulu paket yok.");
        println!();
    }

    if !available.is_empty() {
        println!("MEVCUT SÜRÜMLER (remote):");
        println!("  {:<20} {:<15} Yayın", "Paket", "Sürüm");
        for r in available {
            println!(
                "  {:<20} {:<15} {}",
                r.package,
                r.version,
                &r.published_at[..19.min(r.published_at.len())]
            );
        }
        println!();
    }
}

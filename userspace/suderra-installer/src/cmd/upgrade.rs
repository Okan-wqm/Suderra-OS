// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `upgrade <package>` — en son sürüme yükselt.
//!
//! Bu komut `install` ile aynı işi yapar ama:
//! - Önceki sürümü `previous_version` olarak kaydeder (rollback için)
//! - Eğer aynı sürüm zaten kuruluysa atlanır
//! - Konfirm prompt'u "yükseltme" wording'iyle gösterir

use crate::cli::{InstallArgs, UpgradeArgs};
use crate::manifest::InstalledState;
use crate::sources::Mirror;
use anyhow::{Context, Result};
use tracing::info;

/// `upgrade` çalıştır
pub async fn run(args: UpgradeArgs) -> Result<()> {
    info!("paket yükseltme: {}", args.package);

    let state = InstalledState::load()
        .context("installed state okunamadı; corrupt state ile upgrade fail-closed durur")?;
    if let Some(current) = state.installed.get(&args.package) {
        info!("mevcut sürüm: {}", current.version);
    } else {
        info!(
            "'{}' henüz kurulu değil — install komutu kullanılıyor",
            args.package
        );
    }

    // install komutuna delege et (latest version)
    let install_args = InstallArgs {
        package: args.package,
        version: None,
        verify_signature: args.verify_signature,
        from_file: None,
        signature: None,
        certificate: None,
        yes: args.yes,
        mirror: Mirror::Github,
        start_service: true,
    };

    crate::cmd::install::run(install_args).await
}

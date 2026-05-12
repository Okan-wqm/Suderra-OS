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
